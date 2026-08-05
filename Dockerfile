FROM python:3.11-slim

# Herramientas del pipeline: git (clone), gitleaks (secretos), semgrep y
# checkov (SAST/IaC) se instalan en la imagen de producción.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates curl unzip \
    && rm -rf /var/lib/apt/lists/*

ARG GITLEAKS_VERSION=8.24.3
RUN curl -fsSL \
    "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
    -o /tmp/gitleaks.tar.gz \
    && tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks \
    && rm /tmp/gitleaks.tar.gz \
    && gitleaks version

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir semgrep checkov boto3

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY vibeaudit/ ./vibeaudit/
COPY .gitignore .

# El runner necesita repos temporales y artefactos en disco.
ENV VIBEAUDIT_ARTIFACTS=/data/artifacts
ENV VIBEAUDIT_API_HOST=0.0.0.0
ENV VIBEAUDIT_API_PORT=8000
VOLUME /data

EXPOSE 8000
CMD ["python", "-m", "vibeaudit.api"]
