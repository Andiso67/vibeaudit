#!/bin/bash
# Bootstrap de la instancia EC2 (Amazon Linux 2023) para VibeAudit.
# Ejecutado una vez por cloud-init en el primer arranque.
exec > /var/log/vibeaudit-bootstrap.log 2>&1
set -euo pipefail

echo "==> Instalando Docker, git y cronie (antes de configurar el cron)"
dnf install -y docker git cronie >/dev/null
systemctl enable --now docker crond

echo "==> Swap 4 GiB (el LLM 8B excede la RAM física en t3.large)"
if ! swapon --show | grep -q /swapfile; then
  fallocate -l 4G /swapfile
  chmod 600 /swapfile
  mkswap /swapfile >/dev/null
  swapon /swapfile
  echo "/swapfile none swap sw 0 0" >> /etc/fstab
fi

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
# Ollama accesible desde los contenedores y con memoria contenida
# (t3.large: 8 GB RAM; swap 4 GB; contexto reducido para evitar OOM)
mkdir -p /etc/systemd/system/ollama.service.d
cat > /etc/systemd/system/ollama.service.d/override.conf <<'EOF'
[Service]
Environment="OLLAMA_HOST=0.0.0.0"
Environment="OLLAMA_CONTEXT_LENGTH=8192"
Environment="OLLAMA_NUM_PARALLEL=1"
EOF
systemctl daemon-reload
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
# Motor LLM: Ollama corre en el host; la API lo alcanza por host.docker.internal
VIBEAUDIT_LLM_BASE_URL=http://host.docker.internal:11434/v1
VIBEAUDIT_LLM_MODEL=llama3.1
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
