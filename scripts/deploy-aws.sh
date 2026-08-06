#!/usr/bin/env bash
# Despliega VibeAudit en AWS EC2 (Amazon Linux 2023, t3.medium, 20 GiB gp3).
#
# Uso:
#   ./scripts/deploy-aws.sh
#   (requiere: aws configure hecho, y hostname+token de DuckDNS a mano)
#
# Variables opcionales para no contestar interactivo:
#   VIBEAUDIT_DUCKDNS_HOST  (sin .duckdns.org)
#   VIBEAUDIT_DUCKDNS_TOKEN
#   VIBEAUDIT_POSTGRES_PASSWORD
#   VIBEAUDIT_GIT_URL       (default: https://github.com/Andiso67/vibeaudit.git)
set -euo pipefail

STACK="vibeaudit"
REGION="${AWS_REGION:-us-east-1}"
AMI=$(aws ec2 describe-images --region "$REGION" --owners amazon \
  --filters "Name=name,Values=al2023-ami-2023.*-x86_64" \
  --query "sort_by(Images, &CreationDate)[-1].ImageId" --output text)
INSTANCE_TYPE=t3.medium
VOLUME_GB=20
KEY_NAME="vibeaudit-key"
GIT_URL="${VIBEAUDIT_GIT_URL:-https://github.com/Andiso67/vibeaudit.git}"

echo "==> Verificando credenciales AWS"
aws sts get-caller-identity >/dev/null

echo "==> Datos DuckDNS"
DUCKDNS_HOST="${VIBEAUDIT_DUCKDNS_HOST:-}"
DUCKDNS_TOKEN="${VIBEAUDIT_DUCKDNS_TOKEN:-}"
if [ -z "$DUCKDNS_HOST" ]; then read -rp "Hostname DuckDNS (sin .duckdns.org): " DUCKDNS_HOST; fi
if [ -z "$DUCKDNS_TOKEN" ]; then read -rp "Token DuckDNS: " DUCKDNS_TOKEN; fi

echo "==> Contraseña de Postgres"
PGPASS="${VIBEAUDIT_POSTGRES_PASSWORD:-}"
if [ -z "$PGPASS" ]; then read -rsp "Nueva contraseña para Postgres: " PGPASS; echo; fi

echo "==> Clave SSH"
if ! aws ec2 describe-key-pairs --region "$REGION" --key-names "$KEY_NAME" >/dev/null 2>&1; then
  aws ec2 create-key-pair --region "$REGION" --key-name "$KEY_NAME" \
    --query "KeyMaterial" --output text > "${KEY_NAME}.pem"
  chmod 600 "${KEY_NAME}.pem"
  echo "    Creada ${KEY_NAME}.pem (¡guárdala!)"
else
  [ -f "${KEY_NAME}.pem" ] || {
    echo "    ERROR: la key '$KEY_NAME' ya existe en AWS pero no hay ${KEY_NAME}.pem local."
    echo "    Crea otra key o descarga la existente y vuelve a ejecutar."
    exit 1
  }
fi

echo "==> Security Group (22, 3000, 8000, 9000 abiertos)"
SG_ID=$(aws ec2 describe-security-groups --region "$REGION" \
  --filters "Name=group-name,Values=$STACK" \
  --query "SecurityGroups[0].GroupId" --output text 2>/dev/null || true)
if [ -z "$SG_ID" ] || [ "$SG_ID" = "None" ]; then
  SG_ID=$(aws ec2 create-security-group --region "$REGION" \
    --group-name "$STACK" --description "VibeAudit web+api+sonar" \
    --query "GroupId" --output text)
  for PORT in 22 3000 8000 9000; do
    aws ec2 authorize-security-group-ingress --region "$REGION" \
      --group-id "$SG_ID" --protocol tcp --port "$PORT" --cidr 0.0.0.0/0 \
      >/dev/null || true
  done
  echo "    Creado $SG_ID"
else
  echo "    Reutilizado $SG_ID"
fi

echo "==> Lanzando instancia $INSTANCE_TYPE ($VOLUME_GB GiB, AMI $AMI)"
INSTANCE_ID=$(aws ec2 run-instances --region "$REGION" \
  --image-id "$AMI" --instance-type "$INSTANCE_TYPE" \
  --key-name "$KEY_NAME" --security-group-ids "$SG_ID" \
  --block-device-mappings "DeviceName=/dev/xvda,VolumeSize=$VOLUME_GB,VolumeType=gp3" \
  --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$STACK}]" \
  --query "Instances[0].InstanceId" --output text)
echo "    Instancia $INSTANCE_ID"
aws ec2 wait instance-running --region "$REGION" --instance-ids "$INSTANCE_ID"

echo "==> IP elástica + asociación"
EIP_ALLOC=$(aws ec2 describe-addresses --region "$REGION" \
  --filters "Name=tag:Name,Values=$STACK" \
  --query "Addresses[0].AllocationId" --output text 2>/dev/null || true)
if [ -z "$EIP_ALLOC" ] || [ "$EIP_ALLOC" = "None" ]; then
  EIP_ALLOC=$(aws ec2 allocate-address --region "$REGION" --query "AllocationId" --output text)
  aws ec2 create-tags --region "$REGION" --resources "$EIP_ALLOC" \
    --tags "Key=Name,Value=$STACK" >/dev/null
fi
aws ec2 associate-address --region "$REGION" --allocation-id "$EIP_ALLOC" \
  --instance-id "$INSTANCE_ID" >/dev/null
PUBLIC_IP=$(aws ec2 describe-addresses --region "$REGION" --allocation-ids "$EIP_ALLOC" \
  --query "Addresses[0].PublicIp" --output text)
echo "    IP pública: $PUBLIC_IP"

echo "==> DuckDNS: $DUCKDNS_HOST.duckdns.org -> $PUBLIC_IP"
RESP=$(curl -s "https://www.duckdns.org/update?domains=${DUCKDNS_HOST}&token=${DUCKDNS_TOKEN}&ip=${PUBLIC_IP}")
echo "    Respuesta DuckDNS: $RESP"

SSH="ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -i ${KEY_NAME}.pem ec2-user@${PUBLIC_IP}"
SCP="scp -o StrictHostKeyChecking=no -o ConnectTimeout=10 -i ${KEY_NAME}.pem"

echo "==> Esperando SSH (hasta 10 min)"
READY=false
for i in $(seq 1 60); do
  if $SSH true 2>/dev/null; then READY=true; break; fi
  sleep 10
done
$READY || { echo "ERROR: la instancia no acepta SSH"; exit 1; }

echo "==> Instalando Docker + Compose + cron DuckDNS"
$SSH <<REMOTE
set -e
sudo dnf install -y docker git >/dev/null
sudo systemctl enable --now docker
sudo usermod -aG docker ec2-user
sudo mkdir -p /usr/local/lib/docker/cli-plugins
sudo curl -SL \
  "https://github.com/docker/compose/releases/latest/download/docker-compose-\$(uname -s)-\$(uname -m)" \
  -o /usr/local/lib/docker/cli-plugins/docker-compose
sudo chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
# DuckDNS: renovar el A record cada 5 minutos
sudo tee /usr/local/bin/duckdns-update.sh >/dev/null <<'DUCK'
#!/bin/bash
curl -s "https://www.duckdns.org/update?domains=${DUCKDNS_HOST}&token=${DUCKDNS_TOKEN}" >/dev/null
DUCK
sudo chmod +x /usr/local/bin/duckdns-update.sh
(crontab -l 2>/dev/null; echo "*/5 * * * * /usr/local/bin/duckdns-update.sh") | crontab -
REMOTE

echo "==> Clonando y desplegando"
$SSH "git clone $GIT_URL /home/ec2-user/vibeaudit 2>/dev/null || (cd /home/ec2-user/vibeaudit && git pull)"
$SSH "cd /home/ec2-user/vibeaudit && cp .env.prod.example .env \
  && sed -i 's/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$PGPASS/' .env \
  && sed -i 's|^NEXT_PUBLIC_API_URL=.*|NEXT_PUBLIC_API_URL=http://$DUCKDNS_HOST.duckdns.org:8000|' .env \
  && sed -i 's|^VIBEAUDIT_CORS_ORIGINS=.*|VIBEAUDIT_CORS_ORIGINS=http://$DUCKDNS_HOST.duckdns.org:3000|' .env \
  && sed -i '/^# ── Puertos/,$ s/^# //' .env"
$SSH "cd /home/ec2-user/vibeaudit && docker compose -f docker-compose.prod.yml up -d --build 2>&1 | tail -5"
$SSH "cd /home/ec2-user/vibeaudit && docker compose -f docker-compose.prod.yml --profile sonar up -d 2>&1 | tail -3"

echo
echo "==> DESPLIEGUE COMPLETO =="
echo "    Dashboard: http://$DUCKDNS_HOST.duckdns.org:3000"
echo "    API:       http://$DUCKDNS_HOST.duckdns.org:8000/api/health"
echo "    SonarQube: http://$DUCKDNS_HOST.duckdns.org:9000  (admin/admin → cambia el password)"
echo "    SSH:       ssh -i ${KEY_NAME}.pem ec2-user@$PUBLIC_IP"
