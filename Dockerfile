# ── Base image ────────────────────────────────────────────────────────────────
FROM python:3.12-slim

# ── Step 1: System essentials ─────────────────────────────────────────────────
RUN apt-get update && apt-get install -y \
    nmap \
    curl \
    unzip \
    git \
    && rm -rf /var/lib/apt/lists/*

# ── Step 2: ProjectDiscovery tools (pinned versions) ─────────────────────────
RUN set -e; \
    curl -L https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_linux_amd64.zip -o sub.zip \
    && unzip sub.zip subfinder && mv subfinder /usr/local/bin/ && rm sub.zip; \
    \
    curl -L https://github.com/projectdiscovery/httpx/releases/download/v1.6.0/httpx_1.6.0_linux_amd64.zip -o hx.zip \
    && unzip hx.zip httpx && mv httpx /usr/local/bin/ && rm hx.zip; \
    \
    curl -L https://github.com/projectdiscovery/nuclei/releases/download/v3.2.9/nuclei_3.2.9_linux_amd64.zip -o nuc.zip \
    && unzip nuc.zip nuclei && mv nuclei /usr/local/bin/ && rm nuc.zip

# ── Step 3: Nuclei templates (baked into image at build time) ─────────────────
# This runs during `docker build` which uses your HOST network — not the
# restricted container runtime network. Templates are stored in the image
# layer so every container starts fully scan-ready with zero extra setup.
#
# For GitHub Actions CI or air-gapped builds, see the README for the
# --build-arg SKIP_TEMPLATES=1 override.
ARG SKIP_TEMPLATES=0
RUN if [ "$SKIP_TEMPLATES" = "0" ]; then \
        echo "[+] Downloading nuclei-templates..." && \
        nuclei -update-templates -disable-update-check && \
        echo "[+] Templates ready: $(find /root/nuclei-templates -name '*.yaml' | wc -l) templates"; \
    else \
        echo "[!] Skipping template download (SKIP_TEMPLATES=1)"; \
    fi

# ── Step 4: Python app ────────────────────────────────────────────────────────
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Baked-in source — overridden by volume mount in dev via docker-compose
COPY src/ ./src/

RUN mkdir -p scans

# ── Step 5: Keep alive for docker exec / attach workflows ─────────────────────
CMD ["tail", "-f", "/dev/null"]