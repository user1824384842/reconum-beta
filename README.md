# reconum

Async, multi-stage recon engine. Subdomain discovery → DNS gating → Nmap port scan → HTTPX tech detection → Nuclei vulnerability scan. Fully self-contained — everything runs inside Docker with zero host dependencies.

## How it works

Nuclei templates are downloaded **at image build time** via `docker build`, which runs on your host's network. The templates are baked into the image layer — every container that starts from this image is immediately scan-ready with no extra setup, no volume mounts, no host dependencies.

```
docker build  →  pulls tools + templates from internet  →  baked into image
docker run    →  fully offline, self-contained, ready to scan
```

## Quick start

```bash
# 1. Build (downloads ~500MB of nuclei-templates once, cached in image layer)
docker compose build

# 2. Start
docker compose up -d

# 3. Edit targets in src/main.py
#    raw_inputs = ["192.168.1.1", "example.com", "10.0.0.0/24"]

# 4. Scan
docker exec reconum_engine python src/main.py

# 5. Results
cat scans/session_results.jsonl
```

## Rebuilding / updating templates

```bash
# Force a full rebuild to pull latest nuclei-templates
docker compose build --no-cache
```

## CI / air-gapped builds

If your build environment has no internet (GitHub Actions with restricted egress, etc.), skip the template download and mount them separately:

```bash
docker build --build-arg SKIP_TEMPLATES=1 -t flu1d/reconum .
```

Then mount templates at runtime:
```yaml
# docker-compose.yml
volumes:
  - ./nuclei-templates:/root/nuclei-templates:ro
```

## Project layout

```
reconum/
├── src/
│   ├── models.py          # Pydantic data models
│   ├── workers.py         # Async tool wrappers
│   └── main.py            # Pipeline entry point
├── scans/                 # JSONL output (gitignored)
├── Dockerfile             # Self-contained — templates baked in at build
├── docker-compose.yml
├── .dockerignore
└── requirements.txt
```

## Concurrency model

Slots are dynamically allocated based on CPU count (`cores × 4`):

| Worker  | Budget              | Reason                        |
|---------|---------------------|-------------------------------|
| general | `cores × 4`         | subfinder, httpx              |
| nmap    | `⌊total / 3⌋`       | OS-thread heavy per scan      |
| nuclei  | `⌊total / 6⌋`       | network + CPU intensive       |

## Output format

Each target is appended to `scans/session_results.jsonl` as one JSON line:

```json
{
  "address": "192.168.1.1",
  "services": [{"port": 80, "name": "http", "product": "Apache httpd", "version": "2.2.8"}],
  "vulnerabilities": [{"id": "CVE-2011-2523", "severity": "critical", "name": "vsftpd backdoor"}],
  "technologies": ["Apache"],
  "tags": ["http", "ftp", "cve"],
  "error_log": [],
  "is_dead": false
}
```