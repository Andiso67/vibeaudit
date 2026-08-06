# Despliegue en AWS EC2 con Docker Compose

Stack de producción independiente: `docker-compose.prod.yml` (Postgres + API +
Dashboard, SonarQube opcional). El entorno dev (`docker-compose.dev.yml`) es
independiente y puede seguir corriendo en la máquina de desarrollo.

## 1. Crear la instancia EC2

- AMI: **Amazon Linux 2023** (o Ubuntu 22.04/24.04), t3.medium o superior
  (el escáner corre semgrep/checkov, consume CPU).
- Disco: gp3, **al menos 20 GiB** (las imágenes + volúmenes Docker).
- **IP elástica (Elastic IP)** y asociarla a la instancia: DuckDNS no puede
  seguir una IP pública que cambie en cada arranque.
- Security Group, puertos de entrada:
  - `3000` (dashboard) — desde tu IP o abierto (DuckDNS)
  - `8000` (API) — desde tu IP o abierto (DuckDNS). La consola corre en el
    navegador del cliente y llama a la API directamente.
  - `22` (SSH) — solo desde tu IP.

## 2. DuckDNS

1. Crea un hostname en https://www.duckdns.org (p. ej. `miApp.duckdns.org`).
2. Apunta el registro A a la **IP elástica** de la instancia.
3. El router/local NAT no interviene: la instancia ya tiene la IP elástica
   pública, DuckDNS solo resuelve el nombre → IP.

## 3. Instalar Docker + Compose

```bash
# Amazon Linux 2023
sudo dnf install -y docker git
sudo systemctl enable --now docker
sudo usermod -aG docker ec2-user
# Compose plugin
sudo mkdir -p /usr/local/lib/docker/cli-plugins
sudo curl -SL \
  "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" \
  -o /usr/local/lib/docker/cli-plugins/docker-compose
sudo chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
```

Cierra sesión y vuelve a entrar (para el grupo `docker`).

## 4. Desplegar

```bash
git clone https://github.com/Andiso67/vibeaudit.git
cd vibeaudit
cp .env.prod.example .env
nano .env   # ← OBLIGATORIO:
            #   POSTGRES_PASSWORD   (nueva contraseña fuerte)
            #   NEXT_PUBLIC_API_URL = http://miApp.duckdns.org:8000
            #   VIBEAUDIT_CORS_ORIGINS = http://miApp.duckdns.org:3000
docker compose -f docker-compose.prod.yml up -d --build
docker compose -f docker-compose.prod.yml ps
```

> `docker-compose.prod.yml` usa `:?` para `POSTGRES_PASSWORD` y
> `NEXT_PUBLIC_API_URL`: si faltan, el comando falla antes de arrancar nada
> (fail fast). Por eso los comandos de gestión (`ps`, `down`, `logs`)
> también requieren tener el `.env` presente.

Opcional, SonarQube:

```bash
docker compose -f docker-compose.prod.yml --profile sonar up -d
# SonarQube: http://IP:9000 (admin/admin por defecto, cambia el password)
```

## 5. Verificación

- `curl http://localhost:8000/api/health` → `{"status":"ok", ...}`
- Abrir `http://miApp.duckdns.org:3000` y lanzar un análisis de prueba.
- La consola debe cargar el listado y seguir el análisis en directo
  (reloj + ETA). Si la API no responde desde el navegador, revisa:
  - Security Group (puertos 3000/8000 abiertos)
  - `NEXT_PUBLIC_API_URL` (la URL embebida en el bundle es la del build;
    si cambia hay que reconstruir: `docker compose -f docker-compose.prod.yml build dashboard`)
  - `VIBEAUDIT_CORS_ORIGINS`

## 6. Datos y backups

Los datos viven en volúmenes Docker nombrados: `pgdata` (Postgres),
`artifacts` (reportes + entregables) y `history` (memoria de recurrencias).
Sobreviven a `docker compose down` y a actualizaciones de imágenes; se
pierden con `down -v` (¡no lo hagas por accidente!).

Backup de la BD (cron diario recomendado):

```bash
docker exec vibeaudit-prod-postgres-1 \
  pg_dump -U vibeaudit vibeaudit | gzip > ~/backups/vibeaudit-$(date +%F).sql.gz
```

## 7. Actualizar el despliegue

```bash
cd vibeaudit && git pull
docker compose -f docker-compose.prod.yml up -d --build
```

## 8. Prueba local del stack de producción (sin tocar el dev)

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
