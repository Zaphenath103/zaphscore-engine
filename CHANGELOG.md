# ZaphScore Engine — Changelog

All notable changes are documented here. Format: [version] — date — what changed and why.

---

## [0.4.0] — 2026-04-10

### Added
- GitHub Actions CI test gate — every push now runs pytest + ruff, blocks bad commits
- Agent self-debug workflow — auto-creates GitHub issue on test failure with failure log
- CEO Slack notifier (`scripts/notify_ceo.py`) — shift summary posted on completion
- README.md with test badge, architecture diagram, quick start, deploy guide

### Security
- Fernet AES-128-CBC encryption on all scan findings at rest (D-013)
- Security headers middleware — X-Frame-Options, CSP, X-Content-Type-Options (D-014)
- Supabase JWT auth gate on all scan submission endpoints (D-003)
- GDPR DELETE /api/user/me with cascade delete (D-012)

---

## [0.3.0] — 2026-04-09

### Added
- PDF report export (`GET /api/scans/{id}/report.pdf`) with ReportLab — executive summary + findings table
- Real NIST CVSS 3.1 formula — exploitability + impact subscores, scope-conditional
- NVD enrichment for CVE data — severity, description, publish date
- Diminishing returns scoring — prevents gaming by stacking low-severity findings
- Docker HEALTHCHECK on /ping endpoint (30s interval)
- Vercel config migration from legacy `builds` to `functions` + `rewrites`

### Fixed
- Scorer weight sum assertion (must equal 1.0)
- SBOM component type classifier — library/framework/container with 18 known frameworks
- Maven purl namespace/artifact splitting

---

## [0.2.0] — 2026-04-08

### Added
- 7-phase scan pipeline: secrets → SAST → dependencies → IaC → licenses → SBOM → containers
- SQLite fallback for zero-config local development
- SSE streaming for real-time scan progress
- Rate limiting middleware (global + per-IP)
- CycloneDX SBOM generation with NOASSERTION license fallback
- 40 unit tests across scorer and dependency resolver

### Architecture
- FastAPI async throughout — no blocking I/O
- `FOR UPDATE SKIP LOCKED` job queue — no Redis required
- Graceful env var validation — P0 vars checked on startup

---

## [0.1.0] — 2026-04-06

### Initial build
- ZaphScore Engine launched — FastAPI backend, 12-phase scan pipeline
- SQLite persistence, scan submission, async worker
- First external scan: crewAI/crewAI scored 78.6 (C) with eval() finding
- FearScore 35.6 across 20 repos (58% F-grade across 50 repos at scale)
