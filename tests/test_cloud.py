"""Tests del escaneo de nube (solo lectura) sin red real ni credenciales."""

import pytest

from vibeaudit.models import Severity
from vibeaudit.scanners.cloud import CloudScanner


class _FakeHTTPResponse:
    """Respuesta de la API REST fake: status + JSON."""

    def __init__(self, status, data):
        self.status = status
        self._data = data

    def json(self):
        return self._data


class FakeHTTP:
    """Cliente HTTP fake para Vercel/Supabase: url -> (status, json)."""

    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def request(self, method, url, headers):
        self.calls.append((method, url))
        for prefix, (status, data) in sorted(
            self.routes.items(), key=lambda kv: len(kv[0]), reverse=True
        ):
            if url.startswith(prefix):
                return _FakeHTTPResponse(status, data)
        return _FakeHTTPResponse(404, {})


class FakeS3:
    """Cliente S3 fake: un bucket público y otro privado."""

    def __init__(self):
        self.list_buckets_called = False
        self.acl_calls = []

    def list_buckets(self):
        self.list_buckets_called = True
        return {"Buckets": [{"Name": "public-bucket"}, {"Name": "private-bucket"}]}

    def get_bucket_acl(self, Bucket):
        self.acl_calls.append(Bucket)
        if Bucket == "public-bucket":
            return {
                "Grants": [
                    {
                        "Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"},
                        "Permission": "READ",
                    }
                ]
            }
        return {"Grants": []}


class FakeEC2:
    """Cliente EC2 fake: un security group abierto y otro cerrado."""

    def __init__(self):
        self.called = False

    def describe_security_groups(self):
        self.called = True
        return {
            "SecurityGroups": [
                {
                    "GroupId": "sg-open",
                    "GroupName": "open-to-world",
                    "IpPermissions": [
                        {
                            "FromPort": 22,
                            "ToPort": 22,
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        }
                    ],
                },
                {
                    "GroupId": "sg-safe",
                    "GroupName": "restricted",
                    "IpPermissions": [
                        {
                            "FromPort": 22,
                            "ToPort": 22,
                            "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
                        }
                    ],
                },
            ]
        }


class TestCloudScannerAws:
    def test_scan_detecta_bucket_publico_y_sg_abierto(self):
        fake_s3 = FakeS3()
        fake_ec2 = FakeEC2()
        scanner = CloudScanner(providers=["aws"], clients={"s3": fake_s3, "ec2": fake_ec2})
        issues = scanner.scan()

        assert fake_s3.list_buckets_called is True
        assert fake_ec2.called is True

        rules = {issue.rule: issue for issue in issues}
        assert set(rules) == {"aws-s3-bucket-public", "aws-ec2-security-group-open"}

        s3_issue = rules["aws-s3-bucket-public"]
        assert s3_issue.resource == "s3://public-bucket"
        assert s3_issue.provider == "aws"
        assert s3_issue.severity == Severity.HIGH
        assert "AllUsers" in s3_issue.description

        sg_issue = rules["aws-ec2-security-group-open"]
        assert sg_issue.resource == "sg-open"
        assert "22" in sg_issue.description
        assert sg_issue.severity == Severity.HIGH

    def test_scan_registra_recursos_analizados_con_estado(self):
        fake_s3 = FakeS3()
        fake_ec2 = FakeEC2()
        scanner = CloudScanner(providers=["aws"], clients={"s3": fake_s3, "ec2": fake_ec2})
        scanner.scan()

        by_resource = {r["resource"]: r for r in scanner.resources}
        assert by_resource["s3://public-bucket"]["status"] == "issue"
        assert by_resource["s3://private-bucket"]["status"] == "ok"
        assert by_resource["sg-open"]["status"] == "issue"
        assert by_resource["sg-safe"]["status"] == "ok"

    def test_scan_reusa_clientes_privados_sin_issue_s3(self):
        fake_s3 = FakeS3()
        fake_ec2 = FakeEC2()
        # el bucket "private-bucket" no genera issue; el público sí
        scanner = CloudScanner(providers=["aws"], clients={"s3": fake_s3, "ec2": fake_ec2})
        issues = scanner.scan()
        s3_issues = [i for i in issues if i.rule == "aws-s3-bucket-public"]
        assert [i.resource for i in s3_issues] == ["s3://public-bucket"]

    def test_public_acl_permissions_filtra_grantees_anonimos(self):
        acl = {
            "Grants": [
                {"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"}, "Permission": "WRITE"},
                {"Grantee": {"Type": "CanonicalUser", "ID": "x"}, "Permission": "READ"},
                {"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"}, "Permission": "READ"},
            ]
        }
        perms = CloudScanner._public_acl_permissions(acl)
        assert perms == ["AllUsers:WRITE", "AuthenticatedUsers:READ"]

    def test_open_ingress_ports_ignora_sg_cerrado(self):
        permissions = [
            {"FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "203.0.113.0/24"}]},
            {"FromPort": 80, "ToPort": 80, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
            {"FromPort": -1, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
        ]
        ports = CloudScanner._open_ingress_ports(permissions)
        assert ports == ["80", "all"]

    def test_scan_azure_y_gcp_placeholder_advierten_sin_crash(self, monkeypatch):
        monkeypatch.setenv("AZURE_CLIENT_ID", "fake")
        monkeypatch.setenv("GCLOUD_PROJECT", "fake")
        scanner = CloudScanner(
            providers=["azure", "gcp"], clients={"s3": FakeS3()}
        )
        issues = scanner.scan()
        assert issues == []

    def test_multi_region_escanea_security_groups_por_region(self):
        class FakeEC2Multi:  # noqa: N801 - clase en test, nombre local
            """describe_security_groups devuelve un SG distinto por región."""

            def __init__(self, region):
                self.region = region

            def describe_security_groups(self):
                return {
                    "SecurityGroups": [
                        {"GroupId": f"sg-{self.region}", "IpPermissions": []}
                    ]
                }

        class FakeRegions:
            def describe_regions(self):
                return {
                    "Regions": [
                        {"RegionName": "us-east-1"},
                        {"RegionName": "eu-west-1"},
                    ]
                }

        scanner = CloudScanner(
            providers=["aws"],
            clients={
                "s3": FakeS3(),
                "ec2": FakeRegions(),
                "ec2:us-east-1": FakeEC2Multi("us-east-1"),
                "ec2:eu-west-1": FakeEC2Multi("eu-west-1"),
            },
        )
        scanner.scan()
        by_resource = {r["resource"]: r for r in scanner.resources}
        assert {"sg-us-east-1", "sg-eu-west-1"} <= set(by_resource)
        assert by_resource["sg-us-east-1"]["region"] == "us-east-1"
        assert by_resource["sg-eu-west-1"]["region"] == "eu-west-1"

    def test_sin_describe_regions_fallback_region_por_defecto(self, monkeypatch):
        monkeypatch.setenv("AWS_DEFAULT_REGION", "us-west-2")
        fake_ec2 = FakeEC2()
        scanner = CloudScanner(
            providers=["aws"], clients={"s3": FakeS3(), "ec2": fake_ec2}
        )
        issues = scanner.scan()
        assert any(i.rule == "aws-ec2-security-group-open" for i in issues)


class TestCloudScannerCredenciales:
    def test_sin_credenciales_lanza_error_limpio(self, monkeypatch):
        for var in (
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_PROFILE",
            "AWS_SESSION_TOKEN",
            "AZURE_CLIENT_ID",
            "AZURE_CLIENT_SECRET",
            "AZURE_TENANT_ID",
            "AZURE_SUBSCRIPTION_ID",
            "GOOGLE_APPLICATION_CREDENTIALS",
            "GCLOUD_PROJECT",
            "GOOGLE_PROJECT",
            "VERCEL_TOKEN",
            "SUPABASE_ACCESS_TOKEN",
            "SUPABASE_PROJECT_REF",
        ):
            monkeypatch.delenv(var, raising=False)
        scanner = CloudScanner()
        assert scanner.configured_providers() == []
        with pytest.raises(RuntimeError, match="No hay credenciales de nube"):
            scanner.scan()

    def test_aws_configurado_por_env(self, monkeypatch):
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAFAKE")
        scanner = CloudScanner(providers=["aws"])
        assert scanner.configured_providers() == ["aws"]

    def test_azure_configurado_por_env(self, monkeypatch):
        monkeypatch.setenv("AZURE_TENANT_ID", "fake-tenant")
        scanner = CloudScanner(providers=["azure"])
        assert scanner.configured_providers() == ["azure"]

    def test_vercel_configurado_por_env(self, monkeypatch):
        monkeypatch.setenv("VERCEL_TOKEN", "fake-token")
        scanner = CloudScanner(providers=["vercel"])
        assert scanner.configured_providers() == ["vercel"]

    def test_supabase_configurado_por_env(self, monkeypatch):
        monkeypatch.setenv("SUPABASE_ACCESS_TOKEN", "fake-token")
        scanner = CloudScanner(providers=["supabase"])
        assert scanner.configured_providers() == ["supabase"]


class TestCloudScannerVercel:
    ROUTES = {
        "https://api.vercel.com/v9/projects": (
            200,
            {"projects": [{"id": "prj_1", "name": "bojuboard"}]},
        ),
        "https://api.vercel.com/v1/projects/prj_1/password-protection": (
            200,
            {"protectionEnabled": False},
        ),
        "https://api.vercel.com/v1/projects/prj_1/sso-protection": (
            200,
            {"ssoEnabled": False},
        ),
        "https://api.vercel.com/v9/projects/prj_1/env": (
            200,
            {
                "envs": [
                    {"key": "NEXT_PUBLIC_SUPABASE_URL", "target": ["production"]},
                    {
                        "key": "NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY",
                        "target": ["production"],
                    },
                    {
                        "key": "SUPABASE_SERVICE_ROLE_KEY",
                        "target": ["preview", "development"],
                    },
                ]
            },
        ),
    }

    def test_detecta_previews_sin_proteccion(self, monkeypatch):
        monkeypatch.setenv("VERCEL_TOKEN", "t")
        fake = FakeHTTP(self.ROUTES)
        scanner = CloudScanner(providers=["vercel"], clients={"vercel": fake})
        issues = scanner.scan()

        rules = {i.rule: i for i in issues}
        assert "vercel-preview-protection-disabled" in rules
        issue = rules["vercel-preview-protection-disabled"]
        assert issue.resource == "bojuboard"
        assert issue.severity == Severity.MEDIUM
        assert any(r["resource"] == "bojuboard" and r["status"] == "issue" for r in scanner.resources)

    def test_env_secret_publico_y_targets_no_protegidos(self, monkeypatch):
        monkeypatch.setenv("VERCEL_TOKEN", "t")
        fake = FakeHTTP(self.ROUTES)
        scanner = CloudScanner(providers=["vercel"], clients={"vercel": fake})
        issues = scanner.scan()

        rules = {i.rule: i for i in issues}
        public = rules["vercel-public-env-secret"]
        assert public.resource == "bojuboard:NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY"
        assert public.severity == Severity.HIGH

        targets = rules["vercel-env-secret-unprotected-targets"]
        assert targets.resource == "bojuboard:SUPABASE_SERVICE_ROLE_KEY"
        assert targets.severity == Severity.LOW

    def test_proyecto_protegido_no_genera_issue_de_preview(self, monkeypatch):
        routes = dict(self.ROUTES)
        routes["https://api.vercel.com/v1/projects/prj_1/password-protection"] = (
            200,
            {"protectionEnabled": True},
        )
        routes["https://api.vercel.com/v9/projects/prj_1/env"] = (
            200,
            {"envs": []},
        )
        monkeypatch.setenv("VERCEL_TOKEN", "t")
        scanner = CloudScanner(
            providers=["vercel"], clients={"vercel": FakeHTTP(routes)}
        )
        issues = scanner.scan()
        assert not any(i.rule == "vercel-preview-protection-disabled" for i in issues)
        assert not any(i.rule == "vercel-public-env-secret" for i in issues)


class TestCloudScannerSupabase:
    ROUTES = {
        "https://api.supabase.com/v1/projects": (
            200,
            {"projects": [{"ref": "abc123"}]},
        ),
        "https://api.supabase.com/v1/projects/abc123/backups": (
            200,
            {"pitr_enabled": False},
        ),
        "https://api.supabase.com/v1/projects/abc123/config/database/postgres": (
            200,
            {"connection_ssl": False},
        ),
        "https://api.supabase.com/v1/projects/abc123/config/auth": (
            200,
            {"enable_signup": True},
        ),
        "https://api.supabase.com/v1/projects/abc123/config/network-restrictions": (
            200,
            {"config": {"allowedCidrs": []}},
        ),
    }

    def test_detecta_pitr_ssl_signup_y_red(self, monkeypatch):
        monkeypatch.setenv("SUPABASE_ACCESS_TOKEN", "t")
        fake = FakeHTTP(self.ROUTES)
        scanner = CloudScanner(providers=["supabase"], clients={"supabase": fake})
        issues = scanner.scan()

        rules = {i.rule: i for i in issues}
        assert rules["supabase-pitr-disabled"].severity == Severity.HIGH
        assert rules["supabase-pitr-disabled"].resource == "abc123"
        assert rules["supabase-connection-ssl-disabled"].severity == Severity.MEDIUM
        assert rules["supabase-public-signup-enabled"].severity == Severity.LOW
        assert rules["supabase-network-restrictions-off"].severity == Severity.LOW
        assert all(r["status"] == "issue" for r in scanner.resources)

    def test_project_ref_por_env_omite_listado(self, monkeypatch):
        monkeypatch.setenv("SUPABASE_ACCESS_TOKEN", "t")
        monkeypatch.setenv("SUPABASE_PROJECT_REF", "xyz789")
        routes = {
            "https://api.supabase.com/v1/projects/xyz789/backups": (
                200,
                {"pitr_enabled": True},
            ),
            "https://api.supabase.com/v1/projects/xyz789/config/database/postgres": (
                200,
                {"connection_ssl": True},
            ),
            "https://api.supabase.com/v1/projects/xyz789/config/auth": (
                200,
                {"enable_signup": False},
            ),
            "https://api.supabase.com/v1/projects/xyz789/config/network-restrictions": (
                200,
                {"config": {"allowedCidrs": ["10.0.0.0/8"]}},
            ),
        }
        fake = FakeHTTP(routes)
        scanner = CloudScanner(providers=["supabase"], clients={"supabase": fake})
        issues = scanner.scan()

        assert issues == []
        assert not any(url == "https://api.supabase.com/v1/projects" for _, url in fake.calls)
        assert all(r["resource"] == "xyz789" for r in scanner.resources)

    def test_errores_api_no_generan_falsos_positivos(self, monkeypatch):
        monkeypatch.setenv("SUPABASE_ACCESS_TOKEN", "t")
        routes = {
            "https://api.supabase.com/v1/projects": (200, {"projects": []}),
        }
        scanner = CloudScanner(
            providers=["supabase"], clients={"supabase": FakeHTTP(routes)}
        )
        issues = scanner.scan()
        assert issues == []