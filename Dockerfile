# VibeAudit: imagen autocontenida con Python + gitleaks + semgrep + checkov
FROM python:3.12-slim

ARG GITLEAKS_VERSION=8.30.1
ARG TARGETARCH

# git es necesario para que GitPython pueda clonar repositorios
# ca-certificates se mantiene: pip necesita HTTPS para PyPI
# TARGETARCH (buildx) selecciona el binario de gitleaks correcto (x64/arm64)
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates git \
    && case "$TARGETARCH" in \
         arm64) GITLEAKS_ARCH="arm64" ;; \
         *) GITLEAKS_ARCH="x64" ;; \
       esac \
    && curl -sL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GITLEAKS_ARCH}.tar.gz" \
        -o /tmp/gitleaks.tar.gz \
    && tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks \
    && chmod +x /usr/local/bin/gitleaks \
    && rm /tmp/gitleaks.tar.gz \
    && apt-get purge -y curl \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# checkov 2.5.20: 3.3.8 se cuelga en repos grandes (10+ min sin output)
RUN pip install --no-cache-dir checkov==2.5.20 semgrep click==8.1.8

WORKDIR /app
COPY pyproject.toml README.md ./
COPY vibeaudit/ ./vibeaudit/
RUN pip install --no-cache-dir .

ENTRYPOINT ["vibeaudit"]
CMD ["--help"]
