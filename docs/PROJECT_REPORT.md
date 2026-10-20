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

## 6.6 Deployment and verification

When Stage 3 has pushed `username/securenotes:<sha>`, the deploy job delivers it. If a
`DEPLOY_HOOK_URL` secret and a `MONITOR_URL` variable are set, the job calls the hook of a cloud
host (for example Render, which runs the Docker Hub image) and polls the public `/health` URL until
the new version answers. Without them, the job pulls the published image onto the runner and starts
it as a staging container. Either way the release is accepted only after `monitor/health_check.py`
reports it healthy, so a broken image fails the run instead of failing in production. Stage 2 also
runs the same health check against the locally built image before the image is published.

## 6.7 Continuous health monitoring

`monitor/health_check.py` probes `/health` and applies four checks:

| Check | Pass | Warning | Fail |
|---|---|---|---|
| Connectivity | response received | — | connection refused, DNS error, timeout |
| HTTP status | 200 | — | anything else |
| Response time | ≤ 500 ms | ≤ 1000 ms | > 1000 ms |
| Response body | `{"status": "healthy"}` | — | other value or non-JSON |

A failure is retried twice before the service is declared down. Every result is appended to a CSV
history file, and availability (the share of checks that were not unhealthy) and the average
response time are calculated from that file. Alerts are sent to a Discord or Slack webhook when the
service goes down and again when it recovers, not on every check.

The monitor runs in three places:

- **Locally:** the `monitor` service in `docker-compose.yml` checks the app container every 10 seconds.
  Stopping the app container shows failure detection, and starting it again shows recovery.
- **In the pipeline:** the smoke test in Stage 2 and the verification in the deploy job.
- **On a schedule:** `.github/workflows/health-monitor.yml` runs every 15 minutes against `MONITOR_URL`,
  or against a staging container when no public deployment exists. The history is kept between runs
  in the Actions cache. An unhealthy result opens a GitHub issue labelled `health-alert`, or comments
  on the open one. The next healthy result closes the issue, so the issues form an incident log.
  The `simulate_outage` input stops the container before the check, for demonstrations.

## 6.8 Testing

Stage 1 lints the code with ruff, then runs 68 test cases in four files under `coverage`. The coverage
report is uploaded to SonarCloud. Line coverage is 97% (app 97%, monitor 96%, agent 98%, scanner 95%),
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
| Unnoticed outage | scheduled monitor, incident issues, webhook alerts |

## 6.10 Limitations

- Notes are stored in memory, so the app runs one Gunicorn worker (with threads). There is no authentication.
- A pull request opened with `GITHUB_TOKEN` does not trigger workflows. The fix is re-checked when it is merged, not while it waits for review.
- The rule-based fallback removes secrets and outdated base images. It does not refactor the duplicated validation; only the model does that.
- SonarCloud's default quality gate judges new code only, so the first analysis of an older defect may pass. The local secret scan covers this case for credentials.
- GitHub may delay scheduled workflows, so the monitor's 15-minute interval is approximate.
- The agent has been evaluated only on the seeded defects in `demo-states/`.
