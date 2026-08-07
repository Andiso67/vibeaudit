#!/bin/bash
# Bootstrap de la instancia EC2 (Amazon Linux 2023) para VibeAudit.
# Ejecutado una vez por cloud-init en el primer arranque.
exec > /var/log/vibeaudit-bootstrap.log 2>&1
set -euo pipefail

echo "==> Instalando Docker, git y cronie (antes de configurar el cron)"
dnf install -y docker git cronie >/dev/null
systemctl enable --now docker crond

echo "==> DuckDNS: cron de renovación cada 5 min"
cat > /usr/local/bin/duckdns-update.sh <<'DUCK'
#!/bin/bash
curl -s "https://www.duckdns.org/update?domains=${duckdns_host}&token=${duckdns_token}" >/dev/null
DUCK
chmod +x /usr/local/bin/duckdns-update.sh
(crontab -l 2>/dev/null; echo "*/5 * * * * /usr/local/bin/duckdns-update.sh") | crontab -
/usr/local/bin/duckdns-update.sh || true

echo "==> Instalando Compose plugin"
mkdir -p /usr/local/lib/docker/cli-plugins
curl -SL \
  "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" \
  -o /usr/local/lib/docker/cli-plugins/docker-compose
chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
docker compose version

echo "==> Instalando Ollama"
curl -fsSL https://ollama.com/install.sh | sh
systemctl enable ollama
ollama pull llama3.1

echo "==> Clonando repositorio"
cd /home/ec2-user
git clone ${git_url} vibeaudit || (cd vibeaudit && git pull)
cd /home/ec2-user/vibeaudit

echo "==> Generando .env"
# El password puede contener caracteres especiales (@&:...): se percent-encodes
# para la URL de conexión de la API (VIBEAUDIT_DATABASE_URL) con urlencode
# de Terraform (variable pass_enc).
cat > .env <<EOF
POSTGRES_USER=vibeaudit
POSTGRES_PASSWORD=${postgres_password}
POSTGRES_DB=vibeaudit
NEXT_PUBLIC_API_URL=http://${duckdns_host}.duckdns.org:8000
VIBEAUDIT_CORS_ORIGINS=http://${duckdns_host}.duckdns.org:3000
VIBEAUDIT_DATABASE_URL=postgresql://vibeaudit:${pass_enc}@postgres:5432/vibeaudit
API_PORT=8000
DASHBOARD_PORT=3000
SONAR_PORT=9000
SONAR_PASSWORD=${sonar_password}
VERCEL_TOKEN=
SUPABASE_ACCESS_TOKEN=
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
AWS_DEFAULT_REGION=us-east-1
EOF
chmod 600 .env

echo "==> Desplegando stack completo (incluido SonarQube)"
for i in $(seq 1 30); do
  if docker compose -f docker-compose.prod.yml --profile sonar up -d --build; then
    break
  fi
  echo "    Intento $i fallido, reintentando en 30s..."
  sleep 30
done

echo "==> Estado final"
docker compose -f docker-compose.prod.yml --profile sonar ps
