# Despliegue en AWS EC2 con Terraform + Docker Compose

Stack de producción independiente: `docker-compose.prod.yml` (Postgres + API +
Dashboard + SonarQube opcional). La infraestructura se crea con **Terraform**
(directorio `terraform/`); el entorno dev (`docker-compose.dev.yml`) es
independiente y puede seguir corriendo en la máquina de desarrollo.

## 1. Prerrequisitos

- Cuenta AWS con credenciales CLI (permiso EC2, VPC, EIP):
  ```bash
  aws configure   # Access Key + Secret Key, region us-east-1
  ```
- Hostname y token de **DuckDNS** (https://www.duckdns.org).
- Terraform ≥ 1.5 (macOS: `brew tap hashicorp/tap && brew install hashicorp/tap/terraform`).

## 2. Desplegar la infraestructura (Terraform)

Todo lo que el antiguo proceso manual hacía — AMI Amazon Linux 2023, instancia
**t3.medium**, disco **gp3 20 GiB**, key pair SSH (guardada como
`vibeaudit-key.pem` en la raíz del repo), Security Group (SSH 22 desde tu IP +
3000/8000/9000 abiertos), **IP elástica** y registro A de DuckDNS — lo crea
Terraform automáticamente.

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars   # ← rellena hostname, token y postgres_password
terraform init
terraform plan
terraform apply -auto-approve
```

El `user_data` instalado en la instancia (script `user-data.sh.tpl`) hace el
resto automáticamente al arrancar:

1. Instala Docker + Compose plugin y un cron que **renueva la IP de DuckDNS
   cada 5 min**.
2. Clona el repositorio y genera `.env` con `NEXT_PUBLIC_API_URL` y
   `VIBEAUDIT_CORS_ORIGINS` apuntando a `http://<host>.duckdns.org`.
3. Despliega `docker compose -f docker-compose.prod.yml --profile sonar
   up -d --build` (retries si Docker aún no está listo).

Ver el resultado con `terraform output` (URLs dashboard/API/Sonar + SSH).

### Gestión y destrucción

```bash
cd terraform
terraform output        # ver URLs
terraform plan          # ver cambios (p. ej. tras tocar variables)
terraform apply         # aplicar cambios
terraform destroy       # destruir TODO (instancia, EIP, SG, key). ¡Ojo: borra datos!
```

- Cambiar `instance_type`/`volume_size_gb` y `terraform apply` solo recrea lo
  necesario; `user_data_replace_on_change` re-aplica el script si lo editas.
- `terraform.tfvars` está en `.gitignore` (no sube contraseñas al repo).
- La clave `vibeaudit-key.pem` se regenera si borras el state: descárgala a un
  sitio seguro tras el `apply` si la necesitas fuera de la máquina dev.

## 3. Verificación

- `terraform output api_health_url` → `{"status":"ok", ...}`
- Abrir `http://miApp.duckdns.org:3000` y lanzar un análisis de prueba.
- La consola debe cargar el listado y seguir el análisis en directo
  (reloj + ETA). Si la API no responde desde el navegador, revisa:
  - Security Group (puertos 3000/8000 abiertos)
  - `NEXT_PUBLIC_API_URL` (la URL embebida en el bundle es la del build;
    si cambia hay que reconstruir: `docker compose -f docker-compose.prod.yml build dashboard`)
  - `VIBEAUDIT_CORS_ORIGINS`
- SonarQube: `http://miApp.duckdns.org:9000` (admin/admin por defecto,
  cambia el password).

## 4. Datos y backups

Los datos viven en volúmenes Docker nombrados: `pgdata` (Postgres),
`artifacts` (reportes + entregables) y `history` (memoria de recurrencias).
Sobreviven a `docker compose down` y a actualizaciones de imágenes; se
pierden con `down -v` (¡no lo hagas por accidente!) o con
`terraform destroy`.

Backup de la BD (cron diario recomendado):

```bash
docker exec vibeaudit-postgres-1 \
  pg_dump -U vibeaudit vibeaudit | gzip > ~/backups/vibeaudit-$(date +%F).sql.gz
```

## 5. Actualizar el despliegue

```bash
# En la instancia (o por SSH):
cd ~/vibeaudit && git pull
docker compose -f docker-compose.prod.yml up -d --build
```

## 6. Prueba local del stack de producción (sin tocar el dev)

Desde la máquina de desarrollo (el stack dev en :3000/:8000 sigue intacto):

```bash
NEXT_PUBLIC_API_URL=http://localhost:8100 \
VIBEAUDIT_CORS_ORIGINS=http://localhost:3100 \
API_PORT=8100 DASHBOARD_PORT=3100 POSTGRES_PASSWORD=x \
docker compose -f docker-compose.prod.yml -p vibeaudit-prod up -d --build

# Consola: http://localhost:3100 · API: http://localhost:8100
# Parar: docker compose -f docker-compose.prod.yml -p vibeaudit-prod down
```

Nota: el stack prod **no monta `/tmp` del host** (eso es solo del dev), así
que en la prueba local usa una URL git (clone) o crea el repo dentro del
contenedor.
