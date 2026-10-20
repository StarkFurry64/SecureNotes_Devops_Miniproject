# SecureNotes — DevSecOps CI/CD Pipeline with AI-Powered Remediation

A small Flask notes app wrapped in a secure delivery pipeline:

```
 git push ─▶ Stage 1: lint + tests + coverage + SonarCloud + secret scan ──fail──┐
                │ pass                                                     │
                ▼                                                          ▼
            Stage 2: docker build + Trivy scan + smoke test ──fail──▶ Stage 4: AI remediation agent
                │ pass                                                (NVIDIA NIM → pull request)
                ▼                                                          │
            Stage 3: push to Docker Hub (latest + SHA)                     │ developer reviews & merges
                ▼                                                          ▼
            Deploy & verify /health ◀──────────────── new pipeline run ◀───┘
                ▼
            Scheduled health monitor (every 15 min) ─▶ incident issue + webhook alert
```

## DevOps practices covered

| Lab requirement | Where it is in this repo |
|---|---|
| Version control | Git + GitHub, branch protection, PR-based fixes |
| Build | `requirements.txt`, `Dockerfile`, `docker buildx` in Stage 2 |
| Automated testing | `tests/` – 68 pytest cases, 97% coverage uploaded to SonarCloud |
| Linting / SAST | ruff lint, SonarCloud scan + quality gate, `scripts/secret_scan.py` |
| Application security | CSRF tokens on every form, security headers (CSP, X-Frame-Options, nosniff) |
| Containerisation | `Dockerfile` (slim base, non-root user, HEALTHCHECK), `docker-compose.yml` |
| Container security | Trivy gate on fixable HIGH/CRITICAL CVEs |
| CI/CD | `.github/workflows/pipeline.yml` (4 gated stages + deploy) |
| Continuous delivery | Docker Hub publish tagged `latest` and commit SHA |
| Deployment | `deploy` job: cloud deploy hook (e.g. Render) or staging container, verified by health check |
| Monitoring & alerting | `monitor/health_check.py`, `.github/workflows/health-monitor.yml`, GitHub issues + Discord/Slack webhook |
| Automation / AIOps | `scripts/remediate_agent.py` opens fix PRs for failed gates |

## Repository layout

```
app.py                         Flask application
Dockerfile                     hardened image (python:3.12-slim, non-root)
docker-compose.yml             local deployment: app + live monitor
requirements.txt, pytest.ini, .coveragerc, ruff.toml, sonar-project.properties
run.bat / run.sh               one-click local launchers
reset-demo.bat                 Windows wrapper for the reset script
.github/workflows/
  pipeline.yml                 Stage 1-4 + deploy
  health-monitor.yml           scheduled health checks + incident issues
scripts/
  remediate_agent.py           AI remediation agent (NVIDIA NIM, Nemotron 70B)
  secret_scan.py               hardcoded-secret scanner (backstop for SonarCloud)
  reset-demo.sh / .ps1         copy a demo profile into the working tree
monitor/health_check.py        4-check API health monitor with history & alerts
tests/                         app, monitor and security-tooling tests
templates/, static/            UI
demo-states/                   vulnerable, fixed, agent-secret-only, agent-image-only
docs/PROJECT_REPORT.md         report sections for the agent, tests, monitoring, threat model
```

## Run locally

```bash
./run.sh                       # macOS / Linux  (Windows: run.bat)
# or
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python app.py                  # http://127.0.0.1:5000
pytest                         # run the test suite
ruff check .                   # lint (pip install ruff)
```

With Docker:

```bash
docker build -t securenotes:local .
docker run -d -p 5000:5000 --name securenotes-container securenotes:local
curl http://localhost:5000/health
docker stop securenotes-container && docker rm securenotes-container
```

> **macOS:** port 5000 is taken by AirPlay Receiver (it answers with HTTP 403). Use another host port,
> e.g. `docker run -p 5001:5000 ...` and `FLASK_PORT=5001 docker compose up`, or turn off
> *System Settings → General → AirDrop & Handoff → AirPlay Receiver*.

With Docker Compose (app + monitor that checks every 10 s):

```bash
docker compose up --build -d
docker compose logs -f monitor
```

## One-time GitHub setup

1. **Create the repo and push**
   ```bash
   git init -b main && git add . && git commit -m "Initial commit"
   git remote add origin https://github.com/<you>/SecureNotes_Devops_Miniproject.git
   git push -u origin main
   ```
2. **Repository secrets** (*Settings → Secrets and variables → Actions*):

   | Secret | Needed for |
   |---|---|
   | `SONAR_TOKEN` | SonarCloud (Stage 1). Without it only the local secret scan gates Stage 1. |
   | `SONAR_PROJECT_KEY`, `SONAR_ORG` | optional; default to the values in `sonar-project.properties` |
   | `DOCKERHUB_USERNAME`, `DOCKERHUB_TOKEN` | Stage 3 publish (token: Docker Hub → Account settings → Personal access tokens, read/write) |
   | `NVIDIA_API_KEY` | Stage 4 model calls (free key at build.nvidia.com). Without it the agent uses its rule-based fallback. |
   | `NVIDIA_MODEL` | optional, default `nvidia/llama-3.1-nemotron-70b-instruct` |
   | `DEPLOY_HOOK_URL` | optional cloud deployment hook (e.g. Render "Deploy Hook") |
   | `ALERT_WEBHOOK_URL` | optional Discord/Slack incoming webhook for health alerts |

   **Repository variable** (same page, *Variables* tab): `MONITOR_URL` = public `/health` URL of your deployment (optional).
3. **SonarCloud**: import the repo at sonarcloud.io, then *Administration → Analysis Method → turn off Automatic Analysis* (CI analysis and automatic analysis cannot both run).
4. **Let the agent open PRs**: *Settings → Actions → General → Workflow permissions →* tick **Allow GitHub Actions to create and approve pull requests**.
5. **Protect `main`**: *Settings → Branches → Add rule* for `main`: require a pull request with 1 approval, and require the status checks *Stage 1* and *Stage 2*. This is what enforces the human-in-the-loop boundary.

### Optional: real cloud deployment on Render (free tier)
New → Web Service → *Deploy an existing image* → `docker.io/<you>/securenotes:latest`, port 5000, env `APP_SECRET_KEY`. Copy the service's **Deploy Hook** into the `DEPLOY_HOOK_URL` secret and set `MONITOR_URL` to `https://<service>.onrender.com/health`. The deploy job then redeploys after every publish and waits for `/health`; the scheduled monitor watches the live URL.

## Demo script (≈10 minutes)

| Step | Action | What the audience sees |
|---|---|---|
| 1 | Show the repo, `pipeline.yml`, the app at `/` and `/health` | the system under test |
| 2 | `./scripts/reset-demo.sh vulnerable`, commit, push | Stage 1 ❌ (hardcoded `SECRET_KEY`, `DB_PASSWORD`; SonarCloud issues) → Stage 4 runs |
| 3 | Open the PR created by the agent | patch, explanation, findings table, reviewer checklist |
| 4 | Review + merge the PR | new run: Stage 1 ✅, Stage 2 ❌ (python:3.8 CVEs) → Stage 4 opens an image PR |
| 5 | Merge the image PR | all stages ✅, image on Docker Hub, deploy job verifies `/health` |
| 6 | `docker compose up -d`, `docker compose logs -f monitor` | HEALTHY checks every 10 s |
| 7 | `docker compose stop securenotes` | UNHEALTHY + alert; `start` → RECOVERED |
| 8 | Actions → *Scheduled Health Monitor* → Run with **simulate_outage** | failed run + 🚨 issue; run again normally → issue auto-closed |

Shorter variants: `agent-secret-only` (only the secret fix) or `agent-image-only` (only the base-image fix). To start over: `./scripts/reset-demo.sh vulnerable` (or `fixed`).

Run the agent locally without opening a PR:

```bash
python scripts/remediate_agent.py --mode auto --dry-run              # uses NVIDIA_API_KEY from .env if set
python scripts/remediate_agent.py --mode secret --provider rules --dry-run
```

## Health monitor

```bash
python monitor/health_check.py --url http://localhost:5000/health              # one check
python monitor/health_check.py --url http://localhost:5000/health --interval 10 # continuous
python monitor/health_check.py --report                                        # availability from history
```

Checks: connectivity, HTTP 200, response time (≤500 ms healthy, ≤1000 ms warning, above = unhealthy; tunable with `--warn-ms/--fail-ms`), and JSON body `status == "healthy"`. Results go to `monitor/history.csv`. Exit code 1 means unhealthy, so the script works directly as a CI gate.

## Notes and limitations

- Notes are in memory; Gunicorn runs one worker (with threads) so every request sees the same list.
- SonarCloud may raise a security hotspot (S5725) for the Google Fonts stylesheet, because CSS served by Google cannot carry an integrity hash. Review it in SonarCloud and mark it *Safe*; the CSP limits styles and fonts to Google's two font hosts.
- SonarCloud's default gate needs ≥80% coverage on new code; the suite is at 97%, so keep adding tests with new code.
- PRs created with `GITHUB_TOKEN` do not trigger workflows themselves; the pipeline re-runs when the PR is merged to `main`. To run checks on the PR itself, use a GitHub App or fine-grained PAT for the agent.
- SonarCloud's default quality gate judges *new code*; the local secret scan makes sure a committed secret always fails Stage 1.
- Trivy runs from `aquasec/trivy:0.69.3` instead of `aquasecurity/trivy-action`, whose tags were hijacked in March 2026 (CVE-2026-33634). Pinning actions and images by digest is the next hardening step.
- GitHub may delay or skip `schedule` runs and disables them after 60 days without repository activity.
