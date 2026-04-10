# ZaphScore Engine

[![Tests](https://github.com/Zaphenath103/zaphscore-engine/actions/workflows/test-gate.yml/badge.svg)](https://github.com/Zaphenath103/zaphscore-engine/actions/workflows/test-gate.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-green.svg)](https://fastapi.tiangolo.com)

**ZaphScore** — the trust score for AI agents. One number every CTO understands.

```
ZaphScore = Σ (category_weight × normalized_score × diminishing_factor)
```

Scans your AI agent repo across 7 dimensions in under 60 seconds. Outputs a score from 0–100 with severity-ranked findings, attack paths, and breach probabilities.

---

## Scoring Dimensions

| Category | Weight | What it measures |
|---|---|---|
| Secret Detection | 25% | Leaked credentials, API keys, tokens |
| Dependency Safety | 20% | CVEs, outdated packages, supply chain |
| SAST | 20% | Code injection, eval(), unsafe exec |
| IaC Hardening | 15% | Dockerfile, k8s, Terraform misconfig |
| License Compliance | 10% | GPL contamination, missing SPDX |
| SBOM Completeness | 5% | CycloneDX component inventory |
| Container Security | 5% | Base image CVEs, privilege escalation |

---

## Quick Start

```bash
# Run locally
pip install -r requirements.txt
uvicorn app.main:app --reload

# Submit a scan
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT" \
  -d '{"repo_url": "https://github.com/your-org/your-agent"}'
```

---

## Architecture

```
POST /api/scans → ScanWorker → 7-phase pipeline → SQLite/PostgreSQL
                                    ↓
                         Fernet-encrypted findings
                                    ↓
                         GET /api/scans/{id}/report.pdf
```

- **Auth**: Supabase JWT (RS256)
- **Encryption**: Fernet AES-128-CBC on all findings at rest
- **Queue**: `FOR UPDATE SKIP LOCKED` — no Redis needed
- **PDF**: ReportLab — executive summary + findings table

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `SUPABASE_URL` | Yes | Supabase project URL |
| `SUPABASE_KEY` | Yes | Supabase anon key |
| `SUPABASE_JWT_SECRET` | Yes | JWT signing secret |
| `STRIPE_SECRET_KEY` | Yes | Stripe live/test key |
| `STRIPE_WEBHOOK_SECRET` | Yes | Stripe webhook signing secret |
| `FINDINGS_ENCRYPTION_KEY` | Recommended | Fernet key for findings encryption |

---

## Running Tests

```bash
pytest tests/ -v --cov=app --cov-report=term-missing
```

Test gate runs automatically on every push via GitHub Actions.

---

## Deployment

**Vercel** (serverless):
```bash
vercel deploy
```

**Railway** (persistent workers):
```bash
railway up
```

**Docker**:
```bash
docker build -t zaphscore-engine .
docker run -p 8000:8000 --env-file .env zaphscore-engine
```

---

Built by [Zaphenath](https://zaphenath.app) — agent infrastructure for the next generation.
