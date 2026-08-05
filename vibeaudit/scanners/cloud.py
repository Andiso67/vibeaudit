"""Escaneo de nube de solo lectura (AWS/Azure/GCP/Vercel/Supabase).

Ejecuta consultas seguras a las APIs del proveedor para detectar configuraciones
inseguras (buckets S3 públicos, security groups abiertos, previews de Vercel
sin protección, PITR deshabilitado en Supabase, etc.). Nunca modifica
recursos y no exige permisos de escritura. Sin credenciales configuradas lanza
un error limpio (RuntimeError) que el CLI propaga como exit 1.

AWS/Azure/GCP usan SDK (boto3); Vercel y Supabase usan sus APIs REST con
token (``urllib``, sin dependencias extra).
"""

import json
import os
import urllib.request
from typing import Dict, List, Optional

from rich.console import Console

from vibeaudit.models import CloudIssue, Severity

console = Console()

# Variables de entorno que el escaneo de nube respeta por proveedor
PROVIDER_ENV_VARS: Dict[str, List[str]] = {
    "aws": ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_PROFILE", "AWS_SESSION_TOKEN"],
    "azure": ["AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID", "AZURE_SUBSCRIPTION_ID"],
    "gcp": ["GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_PROJECT"],
    "vercel": ["VERCEL_TOKEN"],
    "supabase": ["SUPABASE_ACCESS_TOKEN", "SUPABASE_PROJECT_REF"],
}

# Base URLs de las APIs REST de solo lectura
REST_API_BASE: Dict[str, str] = {
    "vercel": "https://api.vercel.com",
    "supabase": "https://api.supabase.com",
}

OPEN_SG_RECOMMENDATION = (
    "El security group permite tráfico desde 0.0.0.0/0. Restrinje la "
    "entrada al rango de IPs necesario y preferí el acceso por VPC/VPNS."
)
PUBLIC_S3_RECOMMENDATION = (
    "El bucket S3 permite acceso anónimo. Recomendado: bloquear el acceso "
    "público del bucket y usar IAM para acceso autenticado."
)
VERCEL_PROTECTION_RECOMMENDATION = (
    "Activa la protección por contraseña (o SSO) en el proyecto de Vercel "
    "para que los deployments de preview no sean accesibles públicamente."
)
VERCEL_PUBLIC_SECRET_RECOMMENDATION = (
    "Las variables con prefijo NEXT_PUBLIC_ viajan al navegador. Renombra y "
    "sustituye el secreto por una variable de servidor (sin NEXT_PUBLIC_) y "
    "usa un backend proxy si el cliente lo necesita."
)
VERCEL_TARGET_RECOMMENDATION = (
    "Restringe los secrets de entorno únicamente al target 'production' en "
    "Vercel (target 'preview'/'development' los expone a despliegues de "
    "pruebas y a más personas con acceso al equipo)."
)
SUPABASE_PITR_RECOMMENDATION = (
    "Activa el Point-in-Time Recovery (PITR) en Supabase para poder restaurar "
    "la base de datos ante errores o incidentes (mantiene daily backups y "
    "logs de redo)."
)
SUPABASE_SSL_RECOMMENDATION = (
    "Fuerza conexiones SSL/TLS a la base de datos de Supabase "
    "(connection_ssl en el config de Postgres)."
)
SUPABASE_SIGNUP_RECOMMENDATION = (
    "Desactiva el registro público (enable_signup) si el alta de usuarios se "
    "gestiona de forma controlada, y aplica reglas de confirmación de email."
)
SUPABASE_NETWORK_RECOMMENDATION = (
    "Define network restrictions (allowlist de CIDRs) en Supabase para "
    "restringir qué direcciones IP pueden conectar con la API y la base de datos."
)


class CloudScanner:
    """Escanea proveedores de nube (solo lectura) y devuelve configs inseguras
    como :class:`CloudIssue`.

    Solo consulta APIs de lectura (boto3 y APIs REST). El constructor acepta
    un dict ``clients`` (provider -> cliente fake) para los tests, sin red.
    """

    def __init__(
        self,
        providers: Optional[List[str]] = None,
        clients: Optional[Dict[str, object]] = None,
    ):
        self.providers = providers or ["aws", "azure", "gcp", "vercel", "supabase"]
        self.clients = clients or {}
        self.resources: List[dict] = []

    def configured_providers(self) -> List[str]:
        """Devuelve los proveedores que tienen credenciales configuradas."""
        return [
            provider
            for provider in self.providers
            if provider == "aws"
            and self._aws_configured()
            or provider != "aws"
            and self._env_configured(provider)
        ]

    @staticmethod
    def _env_configured(provider: str) -> bool:
        """True si alguna variable de entorno del proveedor está presente."""
        return any(os.environ.get(var) for var in PROVIDER_ENV_VARS[provider])

    def _aws_configured(self) -> bool:
        """Detecta credenciales AWS sin hacer llamadas de red (env, perfil/credenciales).
        Si el caller pasó clientes fake, asumimos que hay credenciales."""
        if any(key in self.clients for key in ("s3", "ec2")):
            return True
        try:
            import botocore.session
        except ImportError:
            return False
        try:
            session = botocore.session.get_session()
            if session.get_credentials() is not None:
                return True
        except Exception:  # noqa: BLE001 - credenciales parciales/inválidas
            pass
        return any(
            os.environ.get(var)
            for var in PROVIDER_ENV_VARS["aws"]
        )

    def scan(self) -> List[CloudIssue]:
        """Ejecuta el escaneo de los proveedores con credenciales configuradas.

        Raises:
            RuntimeError: si ningún proveedor está configurado (fail limpio).
        """
        providers = self.configured_providers()
        if not providers:
            raise RuntimeError(
                "No hay credenciales de nube configuradas. Define AWS_ACCESS_KEY_ID/"
                "AWS_SECRET_ACCESS_KEY (o --profile), AZURE_CLIENT_ID/..., "
                "GOOGLE_APPLICATION_CREDENTIALS, VERCEL_TOKEN o "
                "SUPABASE_ACCESS_TOKEN y reintenta."
            )

        issues: List[CloudIssue] = []
        for provider in providers:
            try:
                issues.extend(
                    {
                        "aws": self.scan_aws,
                        "azure": self.scan_azure,
                        "gcp": self.scan_gcp,
                        "vercel": self.scan_vercel,
                        "supabase": self.scan_supabase,
                    }[provider]()
                )
            except NotImplementedError as exc:
                console.print(f"[yellow]Advertencia:[/] {exc}")
        return issues

    def scan_aws(self) -> List[CloudIssue]:
        """Consulta S3 (ACL pública) y EC2 (security groups abiertos). Solo lectura."""
        try:
            import boto3
        except ImportError as exc:
            raise RuntimeError(
                "Para escanear AWS instala: pip install boto3"
            ) from exc

        issues: List[CloudIssue] = []

        s3 = self.clients.get("s3") or boto3.client("s3")
        try:
            buckets_response = s3.list_buckets()
        except Exception as exc:  # noqa: BLE001 - errores de API se traducen a warning
            console.print(f"[yellow]Advertencia:[/] no se pudo listar S3: {exc}")
            buckets_response = {}

        for bucket in buckets_response.get("Buckets") or []:
            name = bucket.get("Name")
            if not name:
                continue
            try:
                acl = s3.get_bucket_acl(Bucket=name)
            except Exception as exc:  # noqa: BLE001
                console.print(f"[yellow]Advertencia:[/] ACL de {name}: {exc}")
                continue
            public_permissions = self._public_acl_permissions(acl)
            self.resources.append(
                {
                    "provider": "aws",
                    "resource_type": "s3-bucket",
                    "resource": f"s3://{name}",
                    "region": "",
                    "status": "issue" if public_permissions else "ok",
                }
            )
            if public_permissions:
                issues.append(
                    CloudIssue(
                        provider="aws",
                        rule="aws-s3-bucket-public",
                        resource=f"s3://{name}",
                        resource_type="s3-bucket",
                        severity=Severity.HIGH,
                        description=(
                            f"ACL de bucket público; grants anónimos: "
                            f"{', '.join(sorted(public_permissions))}."
                        ),
                        recommendation=PUBLIC_S3_RECOMMENDATION,
                    )
                )

        ec2 = self.clients.get("ec2") or boto3.client(
            "ec2", region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
        )
        for region in self._aws_regions(ec2):
            try:
                regional = (
                    self.clients.get(f"ec2:{region}")
                    or (ec2 if region == os.environ.get("AWS_DEFAULT_REGION", "us-east-1") else None)
                    or boto3.client("ec2", region_name=region)
                )
                sg_response = regional.describe_security_groups()
            except Exception as exc:  # noqa: BLE001 - región sin permiso o deshabilitada
                console.print(
                    f"[yellow]Advertencia:[/] no se pudo consultar EC2 en "
                    f"[cyan]{region}[/]: {exc}"
                )
                continue
            for group in sg_response.get("SecurityGroups") or []:
                group_id = group.get("GroupId")
                if not group_id:
                    continue
                open_ports = self._open_ingress_ports(group.get("IpPermissions") or [])
                self.resources.append(
                    {
                        "provider": "aws",
                        "resource_type": "security-group",
                        "resource": group_id,
                        "region": region,
                        "status": "issue" if open_ports else "ok",
                    }
                )
                if open_ports:
                    issues.append(
                        CloudIssue(
                            provider="aws",
                            rule="aws-ec2-security-group-open",
                            resource=group_id,
                            resource_type="security-group",
                            region=region,
                            severity=Severity.HIGH,
                            description=(
                                f"Security group abierto a Internet "
                                f"(0.0.0.0/0): {', '.join(open_ports)}."
                            ),
                            recommendation=OPEN_SG_RECOMMENDATION,
                        )
                    )
        return issues

    def _aws_regions(self, default_ec2) -> List[str]:
        """Regiones AWS habilitadas; fallback a la región por defecto.

        Usa ``ec2.describe_regions`` (solo lectura) y, si no está permitido o
        el cliente no lo implementa (fakes de test), devuelve únicamente la
        región de ``AWS_DEFAULT_REGION`` (o us-east-1).
        """
        default = os.environ.get("AWS_DEFAULT_REGION") or "us-east-1"
        try:
            response = default_ec2.describe_regions()
        except Exception as exc:  # noqa: BLE001
            console.print(
                f"[yellow]Advertencia:[/] no se pudieron listar regiones "
                f"({exc}); escaneando solo {default}."
            )
            return [default]
        regions = [
            r.get("RegionName")
            for r in (response.get("Regions") or [])
            if r.get("RegionName")
        ]
        if not regions:
            return [default]
        if default in regions:
            regions.remove(default)
            regions.insert(0, default)
        return regions

    def scan_azure(self) -> List[CloudIssue]:
        """Placeholder Azure (solo lectura): requiere SDK y credenciales."""
        raise NotImplementedError(
            "El escaneo Azure requiere el SDK azure-mgmt y credenciales "
            "(AZURE_*); se omitirá hasta configurarlo."
        )

    def scan_gcp(self) -> List[CloudIssue]:
        """Placeholder GCP (solo lectura): requiere SDK y credenciales."""
        raise NotImplementedError(
            "El escaneo GCP requiere el SDK google-cloud-storage y credenciales "
            "(GOOGLE_APPLICATION_CREDENTIALS); se omitirá hasta configurarlo."
        )

    # --- Proveedores REST (Vercel / Supabase) --------------------------------

    def _api_get(self, provider: str, path: str, headers: Dict[str, str]) -> Optional[dict]:
        """GET de solo lectura a la API REST del proveedor; JSON o None.

        En tests se inyecta un cliente fake con ``clients[provider]`` que
        implementa ``request(method, url, headers)`` y devuelve una respuesta
        con ``.status`` y ``.json()``. Errores de red o status >= 400 devuelven
        None (se omiten, con advertencia en consola).
        """
        url = REST_API_BASE[provider] + path
        fake = self.clients.get(provider)
        if fake is not None:
            response = fake.request("GET", url, headers)
            if response.status >= 400:
                return None
            return response.json()
        try:
            with urllib.request.urlopen(
                urllib.request.Request(url, headers=headers), timeout=15
            ) as resp:
                status = resp.status
                body = resp.read().decode("utf-8", "replace")
        except Exception as exc:  # noqa: BLE001 - errores de red/API se omiten
            console.print(f"[yellow]Advertencia:[/] {provider}: {path}: {exc}")
            return None
        if status >= 400:
            console.print(
                f"[yellow]Advertencia:[/] {provider}: {path}: HTTP {status}"
            )
            return None
        return json.loads(body) if body else None

    def scan_vercel(self) -> List[CloudIssue]:
        """Consulta la API de Vercel (solo lectura) para detectar previews sin
        protección y env vars con secretos expuestos (NEXT_PUBLIC_)."""
        token = os.environ.get("VERCEL_TOKEN")
        if not token:
            raise RuntimeError(
                "VERCEL_TOKEN no configurado; el escaneo de Vercel requiere el "
                "token de la cuenta (Settings > Tokens)."
            )
        headers = {"Authorization": f"Bearer {token}"}
        issues: List[CloudIssue] = []

        projects = self._api_get("vercel", "/v9/projects", headers) or {}
        for project in projects.get("projects") or []:
            pid = project.get("id")
            name = project.get("name") or pid or "proyecto-desconocido"
            if not pid:
                continue
            self.resources.append(
                {
                    "provider": "vercel",
                    "resource_type": "vercel-project",
                    "resource": name,
                    "region": "",
                    "status": "ok",
                }
            )

            password = self._api_get(
                "vercel", f"/v1/projects/{pid}/password-protection", headers
            ) or {}
            sso = self._api_get(
                "vercel", f"/v1/projects/{pid}/sso-protection", headers
            ) or {}
            protected = bool(
                password.get("protectionEnabled")
                or sso.get("ssoEnabled")
            )
            if not protected:
                self.resources[-1]["status"] = "issue"
                issues.append(
                    CloudIssue(
                        provider="vercel",
                        rule="vercel-preview-protection-disabled",
                        resource=name,
                        resource_type="vercel-project",
                        severity=Severity.MEDIUM,
                        description=(
                            f"El proyecto '{name}' tiene deployments de "
                            f"preview accesibles públicamente (protección por "
                            f"contraseña y SSO deshabilitados)."
                        ),
                        recommendation=VERCEL_PROTECTION_RECOMMENDATION,
                    )
                )

            envs = self._api_get(
                "vercel", f"/v9/projects/{pid}/env", headers
            ) or {}
            for env in envs.get("envs") or []:
                key = env.get("key") or ""
                targets = env.get("target") or []
                secret_hint = any(
                    hint in key.upper()
                    for hint in ("SECRET", "SERVICE_ROLE", "PRIVATE", "TOKEN", "PASSWORD", "API_KEY")
                )
                if key.startswith("NEXT_PUBLIC_") and secret_hint:
                    self.resources[-1]["status"] = "issue"
                    issues.append(
                        CloudIssue(
                            provider="vercel",
                            rule="vercel-public-env-secret",
                            resource=f"{name}:{key}",
                            resource_type="vercel-env",
                            severity=Severity.HIGH,
                            description=(
                                f"La variable '{key}' del proyecto '{name}' "
                                f"es pública (NEXT_PUBLIC_) y su nombre sugiere "
                                f"un secreto: se envía al navegador."
                            ),
                            recommendation=VERCEL_PUBLIC_SECRET_RECOMMENDATION,
                        )
                    )
                elif secret_hint and (
                    "preview" in targets or "development" in targets
                ):
                    self.resources[-1]["status"] = "issue"
                    issues.append(
                        CloudIssue(
                            provider="vercel",
                            rule="vercel-env-secret-unprotected-targets",
                            resource=f"{name}:{key}",
                            resource_type="vercel-env",
                            severity=Severity.LOW,
                            description=(
                                f"El secreto '{key}' del proyecto '{name}' "
                                f"está disponible en targets "
                                f"{', '.join(targets) or 'no-production'}."
                            ),
                            recommendation=VERCEL_TARGET_RECOMMENDATION,
                        )
                    )
        return issues

    def scan_supabase(self) -> List[CloudIssue]:
        """Consulta la Management API de Supabase (solo lectura) para detectar
        PITR deshabilitado, SSL de conexión apagado, signup público y red sin
        restricciones."""
        token = os.environ.get("SUPABASE_ACCESS_TOKEN")
        if not token:
            raise RuntimeError(
                "SUPABASE_ACCESS_TOKEN no configurado; el escaneo de Supabase "
                "requiere el access token de la cuenta (Dashboard > Account "
                "Settings > Access Tokens)."
            )
        headers = {"Authorization": f"Bearer {token}"}
        issues: List[CloudIssue] = []

        ref = os.environ.get("SUPABASE_PROJECT_REF")
        if ref:
            refs = [ref]
        else:
            projects = self._api_get("supabase", "/v1/projects", headers) or {}
            refs = [
                p.get("ref")
                for p in (projects.get("projects") or [])
                if p.get("ref")
            ]

        for ref in refs:
            self.resources.append(
                {
                    "provider": "supabase",
                    "resource_type": "supabase-project",
                    "resource": ref,
                    "region": "",
                    "status": "ok",
                }
            )

            backups = self._api_get(
                "supabase", f"/v1/projects/{ref}/backups", headers
            ) or {}
            if backups.get("pitr_enabled") is False:
                self.resources[-1]["status"] = "issue"
                issues.append(
                    CloudIssue(
                        provider="supabase",
                        rule="supabase-pitr-disabled",
                        resource=ref,
                        resource_type="supabase-project",
                        severity=Severity.HIGH,
                        description=(
                            f"El proyecto '{ref}' tiene el Point-in-Time "
                            f"Recovery deshabilitado; ante un error o ataque "
                            f"solo se puede restaurar al último backup diario."
                        ),
                        recommendation=SUPABASE_PITR_RECOMMENDATION,
                    )
                )

            pg = self._api_get(
                "supabase",
                f"/v1/projects/{ref}/config/database/postgres",
                headers,
            ) or {}
            if pg.get("connection_ssl") is False:
                self.resources[-1]["status"] = "issue"
                issues.append(
                    CloudIssue(
                        provider="supabase",
                        rule="supabase-connection-ssl-disabled",
                        resource=ref,
                        resource_type="supabase-project",
                        severity=Severity.MEDIUM,
                        description=(
                            f"El proyecto '{ref}' no fuerza SSL/TLS en las "
                            f"conexiones a Postgres."
                        ),
                        recommendation=SUPABASE_SSL_RECOMMENDATION,
                    )
                )

            auth = self._api_get(
                "supabase", f"/v1/projects/{ref}/config/auth", headers
            ) or {}
            if auth.get("enable_signup") is True:
                self.resources[-1]["status"] = "issue"
                issues.append(
                    CloudIssue(
                        provider="supabase",
                        rule="supabase-public-signup-enabled",
                        resource=ref,
                        resource_type="supabase-project",
                        severity=Severity.LOW,
                        description=(
                            f"El proyecto '{ref}' permite el registro público "
                            f"de usuarios sin validación adicional."
                        ),
                        recommendation=SUPABASE_SIGNUP_RECOMMENDATION,
                    )
                )

            net = self._api_get(
                "supabase",
                f"/v1/projects/{ref}/config/network-restrictions",
                headers,
            )
            if net is not None and not (net.get("config") or {}).get(
                "allowedCidrs"
            ):
                self.resources[-1]["status"] = "issue"
                issues.append(
                    CloudIssue(
                        provider="supabase",
                        rule="supabase-network-restrictions-off",
                        resource=ref,
                        resource_type="supabase-project",
                        severity=Severity.LOW,
                        description=(
                            f"El proyecto '{ref}' no tiene restricciones de "
                            f"red (allowlist de IPs) configuradas."
                        ),
                        recommendation=SUPABASE_NETWORK_RECOMMENDATION,
                    )
                )
        return issues

    @staticmethod
    def _public_acl_permissions(acl: dict) -> List[str]:
        """Permisos del ACL concedidos a grantees públicos (AllUsers/AuthenticatedUsers)."""
        permissions = []
        for grant in acl.get("Grants") or []:
            grantee = grant.get("Grantee") or {}
            uri = grantee.get("URI") or ""
            if "global/AllUsers" in uri or "AllUsers" in uri:
                permissions.append(f"AllUsers:{grant.get('Permission')}")
            elif "global/AuthenticatedUsers" in uri:
                permissions.append(f"AuthenticatedUsers:{grant.get('Permission')}")
        return permissions

    @staticmethod
    def _open_ingress_ports(permissions: List[dict]) -> List[str]:
        """Puertos expuestos a 0.0.0.0/0 (o ::/0) en las IpPermissions."""
        open_rules = []
        for permission in permissions:
            ranges = (permission.get("IpRanges") or []) + (
                permission.get("Ipv6Ranges") or []
            )
            if not any(
                rng.get("CidrIp") == "0.0.0.0/0" or rng.get("CidrIpv6") == "::/0"
                for rng in ranges
            ):
                continue
            from_port = permission.get("FromPort")
            if from_port is None or from_port == -1:
                open_rules.append("all")
            else:
                to_port = permission.get("ToPort")
                port_label = str(from_port)
                if to_port is not None and to_port != from_port:
                    port_label += f"-{to_port}"
                open_rules.append(port_label)
        return open_rules