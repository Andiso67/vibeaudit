#!/bin/bash
# Bootstrap de la instancia EC2 (Amazon Linux 2023) para VibeAudit.
# Ejecutado una vez por cloud-init en el primer arranque.
exec > /var/log/vibeaudit-bootstrap.log 2>&1
set -euo pipefail

echo "==> DuckDNS: cron de renovación cada 5 min"
cat > /usr/local/bin/duckdns-update.sh <<'DUCK'
#!/bin/bash
curl -s "https://www.duckdns.org/update?domains=${duckdns_host}&token=${duckdns_token}" >/dev/null
DUCK
chmod +x /usr/local/bin/duckdns-update.sh
(crontab -l 2>/dev/null; echo "*/5 * * * * /usr/local/bin/duckdns-update.sh") | crontab -
/usr/local/bin/duckdns-update.sh || true

echo "==> Instalando Docker y git"
dnf install -y docker git >/dev/null
systemctl enable --now docker
usermod -aG docker ec2-user
mkdir -p /usr/local/lib/docker/cli-plugins
curl -SL \
  "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" \
  -o /usr/local/lib/docker/cli-plugins/docker-compose
chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
docker compose version

echo "==> Clonando repositorio"
cd /home/ec2-user
git clone ${git_url} vibeaudit || (cd vibeaudit && git pull)
cd /home/ec2-user/vibeaudit

echo "==> Generando .env"
cat > .env <<EOF
POSTGRES_USER=vibeaudit
POSTGRES_PASSWORD=${postgres_password}
POSTGRES_DB=vibeaudit
NEXT_PUBLIC_API_URL=http://${duckdns_host}.duckdns.org:8000
VIBEAUDIT_CORS_ORIGINS=http://${duckdns_host}.duckdns.org:3000
API_PORT=8000
DASHBOARD_PORT=3000
SONAR_PORT=9000
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
