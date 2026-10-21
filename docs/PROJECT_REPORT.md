# SecureNotes — report sections for the implementation

These sections fill the gap in `Devops_Mini_Project_Report.docx`. In that file, Section 6.4 ends with the
fragment *"…un time and is not fixed in this report."* and the text goes straight to Section 7.
That cut removed Stage 4, the agent, the tests and the threat model. Paste the sections below after
Table 7 (Section 6.4) and renumber the figures and tables. The section numbers continue the report's
numbering.

---

## 6.5 Stage 4: AI remediation

The remediate job runs when Stage 1 or Stage 2 fails, or when the workflow is started by hand with
`force_remediate` set. It does not run for pull-request events, so a failing contribution from a
developer is not answered with a second, competing pull request. The job is given only
`contents: write` and `pull-requests: write`. That is enough to push a new branch and open a pull
request. Branch protection on `main` (a required review and required status checks) stops the
agent from merging its own change.

The job downloads the two artifacts the earlier stages left behind: `secret-findings`
(Stage 1) and `trivy-scan-results` (Stage 2). It then picks a mode from the gate that failed and
runs `scripts/remediate_agent.py` (Figure 7).

**Figure 7: Remediation agent workflow**

```
failed gate ─▶ collect findings ─▶ choose mode ─▶ build prompt ─▶ NVIDIA NIM (Nemotron 70B)
  (SonarCloud API, secret scan, Trivy JSON)                         │ JSON: explanation + files
                                                                    ▼
                              rule-based fallback ◀── rejected ── validate patch
                                       │                            │ accepted
                                       └────────────▶ new branch ─▶ commit ─▶ pull request ─▶ human review
```

**Table 8: Agent modes**

| Mode | Selected when | Findings used | Files the agent may change |
|---|---|---|---|
| `secret` | Stage 1 failed | SonarCloud issues and hotspots, local secret scan | `app.py` |
| `image` | Stage 2 failed | Trivy JSON report | `Dockerfile` |
| `all` | `auto` finds both kinds | all of the above | `app.py`, `Dockerfile` |
| `auto` | manual `force_remediate` run | whatever is present; resolves to one of the above, or exits with "nothing to do" | — |

The model is asked for a single JSON object holding a plain-language explanation and the full new
content of each file it changes. Full files are easier to validate than diffs, and a model cannot
make a malformed hunk. The agent does not trust the reply. It applies the following checks:

1. Only allow-listed files (`app.py`, `Dockerfile`, `requirements.txt`) may change. The workflow,
   the scripts and the tests are not on the list, so a model reply cannot weaken the pipeline.
2. Python files must compile, keep the `/health` endpoint and pass the secret scan.
3. The Dockerfile must keep a `FROM` line and must not use an outdated `python:3.0`–`3.8` base image.
4. The patch must actually change something.

If the model is unreachable, or if its patch fails any check, a small rule-based fixer is used
instead. The fixer replaces hardcoded secrets with environment lookups, moves the base image to
`python:3.12-slim` and adds `apt-get upgrade`. The pull request states which of the two produced
it. Its body contains the explanation, a table of the findings addressed, the changed files and
a checklist for the reviewer. The agent does not open a second pull request for a mode while an
earlier one is still open.

## 6.6 Cloud deployment on Microsoft Azure

The application runs on **Azure Container Apps** in the Central India region. Every Azure resource
is described in Terraform (`infra/`), so the environment can be created with `terraform apply`
and removed with `terraform destroy`; nothing is configured by hand in the portal (Table 14).

**Table 14: Azure resources (resource group `rg-securenotes`)**

| Resource | Role |
|---|---|
| Container Apps environment and Container App | runs the published Docker image behind an HTTPS URL, one replica, liveness and readiness probes on `/health` |
| Log Analytics workspace | stores container and application logs, capped at 1 GB per day |
| Application Insights | receives request, failure, response-time and custom-metric telemetry, and Live Metrics |
| Azure Monitor workbook | the operations dashboard, defined as code |
| Standard availability test | requests `/health` from Singapore and Hong Kong every five minutes |
| Action group and two metric alerts | email both team members when the app is unavailable or returns more than 20 failed requests in five minutes |
| Consumption budget | sends cost warnings at 80% and 100% of USD 10 per month |
| User-assigned managed identity, federated credential, role assignment | lets the pipeline deploy without a stored password |

**Keyless deployment.** The deploy job runs in the GitHub `production` environment and requests an
OpenID Connect token from GitHub. Azure accepts the token only for the subject
`repo:StarkFurry64/SecureNotes_Devops_Miniproject:environment:production` and exchanges it for a
short-lived credential of the managed identity. That identity holds the Contributor role on this one
resource group and nothing else. No Azure password or key is stored in GitHub.

**Release flow.** After Stage 3 publishes `tanish15/securenotes:<commit SHA>`, the deploy job runs
`az containerapp update` with that image. Container Apps starts a new revision, named after the
pipeline run, and moves all traffic to it once the readiness probe passes. The job then calls the
public `/health` endpoint with the project's health monitor and accepts the release only when it
reports healthy. The environment URL is linked from the GitHub run.

**Images.** The Container App pulls from Docker Hub with a read-only token, because anonymous pulls
from shared cloud addresses are rate limited. Terraform creates the app once; later image changes come
only from the pipeline, which is why Terraform ignores the image field.

## 6.7 Monitoring and alerting

The application sends OpenTelemetry data to Application Insights through the Azure Monitor
distribution. Telemetry is switched on only when the connection string is present, so local runs and
tests send nothing, and the vulnerable demonstration image (Python 3.8) runs without it. Requests to
`/health` are excluded so that probe traffic does not hide real usage. Every request is recorded
(sampling is set to 100%), and the application counts created notes as a business metric.

The operations dashboard shows requests per minute, average and 95th-percentile response time,
failed requests by status code, availability per test location, notes created, and a one-hour
summary. Live Metrics shows the same signals with about one second of delay and is the view used in
the demonstration, together with `scripts/load_test.py`, which mixes page views, note creation and
deliberate 404 responses.

Monitoring works at three levels:

- **Inside the platform.** Container Apps restarts the container when the liveness probe fails.
- **From outside, by Azure.** The availability test fails when `/health` does not return
  `"healthy"`, which fires the "app down" alert and emails the team. The alert resolves itself when
  the test passes again.
- **From outside, by the project.** `monitor/health_check.py` checks connectivity, status code,
  response time and body content. It runs in the pipeline after every deployment, in
  `docker-compose.yml` for local demonstrations, and on a 15-minute schedule in GitHub Actions,
  where an outage opens an issue and recovery closes it.

## 6.8 Testing

Stage 1 lints the code with ruff, then runs 77 test cases in four files under `coverage`. The coverage
report is uploaded to SonarCloud. Line coverage is 98% (app 100%, monitor 97%, agent 98%, scanner 97%),
which is above the 80% that SonarCloud's default quality gate requires for new code.

**Table 9: Test cases**

| File | Test | Verifies |
|---|---|---|
| `test_app.py` | `test_index_renders` | index page renders, empty state shown |
| | `test_add_note_creates_note_and_redirects` | 302 redirect, text stripped, 8-character id, newest first |
| | `test_add_note_rejects_invalid_input` (5 cases) | empty, whitespace, over-length and control-character input rejected |
| | `test_delete_note_removes_it` | delete by id |
| | `test_delete_rejects_invalid_or_unknown_id` (4 cases) | malformed and unknown ids leave the store untouched |
| | `test_health_endpoint` | JSON with `status`, `service`, ISO `timestamp` |
| | `test_post_without_valid_csrf_token_is_rejected` (2 cases) | POST without a token, or with a forged one, returns 400 |
| | `test_security_headers_are_set` | CSP, X-Frame-Options, nosniff; forms carry the CSRF token |
| `test_health_check.py` | live-server test | monitor reports HEALTHY against the real app |
| | failure tests | connection refused, timeout, HTTP 500, wrong body, non-JSON |
| | thresholds | WARNING and UNHEALTHY response-time bands |
| | history, alerts, CLI | availability maths, Discord/Slack payload, exit codes |
| `test_security_tooling.py` | secret scan | repository clean, vulnerable profile flagged, placeholders ignored |
| | agent | Trivy parsing, mode selection, JSON extraction, fallback fixes for every demo profile |
| | agent safety | disallowed paths, broken Python and retained secrets rejected; dry run leaves files untouched |
| `test_agent_integrations.py` | SonarCloud / NIM | API responses parsed, outages handled, prompt built and reply parsed |
| | pull request | against a real local git remote: fix pushed to a new branch, `main` untouched, PR body requests human review; duplicate PRs skipped; missing Actions permission explained |
| | CLIs | secret-scan report and exit codes; monitor alerts once on outage and once on recovery |

## 6.9 Threat model

| Threat | Mitigation in this project |
|---|---|
| Credential committed to the repository | SonarCloud rules S2068/S6779 plus the local secret scan fail Stage 1 before an image is built |
| Vulnerable OS packages or libraries in the image | Trivy gate on fixable HIGH/CRITICAL; slim base image; `apt-get upgrade` at build time |
| Compromised CI dependency | Trivy run from a verified-safe pinned image; least-privilege `permissions` per job (digest pinning is future work) |
| Faulty or manipulated model output | file allow-list, compile and secret re-scan, fallback fixer, mandatory human review |
| Agent acting beyond its role | token limited to branch push and PR creation; branch protection blocks merge without approval |
| Container breakout impact | image runs as unprivileged `appuser` (uid 10001); only the app's files are copied in |
| Cross-site request forgery, clickjacking | per-session CSRF token checked on every POST; `SameSite=Lax` cookie; CSP and `X-Frame-Options: DENY` |
| Broken release reaching users | Stage 2 smoke test; deploy job accepts a release only after `/health` passes |
| Unnoticed outage | Azure availability test and email alerts, probes that restart the container, scheduled GitHub monitor |
| Leaked cloud credentials | OIDC federation: no Azure secret in GitHub; deploy identity limited to one resource group |

## 6.10 Limitations

- Notes are stored in memory, so the app runs one Gunicorn worker (with threads). There is no authentication.
- A pull request opened with `GITHUB_TOKEN` does not trigger workflows. The fix is re-checked when it is merged, not while it waits for review.
- The rule-based fallback removes secrets and outdated base images. It does not refactor the duplicated validation; only the model does that.
- SonarCloud's default quality gate judges new code only, so the first analysis of an older defect may pass. The local secret scan covers this case for credentials.
- GitHub may delay scheduled workflows, so the monitor's 15-minute interval is approximate.
- The agent has been evaluated only on the seeded defects in `demo-states/`.
