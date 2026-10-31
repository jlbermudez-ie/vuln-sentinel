# vuln-sentinel

CVE feed → techstack match → AI-assisted remediation, as a GitHub Actions workflow.

```
NVD 2.0 / CISA KEV / manual / repository_dispatch
        │
        ▼
 techstack.md (orders-api, orders-infra)
        │   deterministic CPE + version match  ──(no CPE data yet)──► LLM triage (OpenRouter)
        ▼
 code fix?  .remediation.yml auto_fix=false ──► BLOCKED (tracking issue opened)
        │
        ▼
 LLM proposes 2-4 infra mitigations (type, impact, effort, surface, structured changes)
        │
        ▼
 Deterministic gate (code, not model): surface allowlist → JSON schema → own cost model
        → impact/effort/type policy
        │
        ▼
 PR to orders-infra (security/waf-rules.json only) ──► terraform plan comment ──► human review ──► apply
```

## Run locally

```bash
pip install -r requirements.txt
python -m pytest -q                                    # offline, no secrets
# offline demo against the vendored fixture repos:
python -m sentinel --root tests/fixtures --cve CVE-2026-109618,CVE-2026-109619 \
  --dry-run --offline tests/fixtures --mock-llm tests/fixtures/mock_llm
# real model, real NVD, still no PRs:
OPENROUTER_API_KEY=... python -m sentinel --root <dir-with-repos/> --cve CVE-2026-109618 --dry-run
```

## Triggers
| Mode | How |
|---|---|
| Scheduled | `cron` in `.github/workflows/sentinel.yml` (default every 6h) |
| Manual | Actions → sentinel → Run workflow (optional `cve_id`, `dry_run`) |
| CVE-triggered | `scripts/trigger-cve.sh <org> <CVE>` or any system calling `repository_dispatch` `cve-alert` |

## Secrets / variables
| Name | Kind | Purpose |
|---|---|---|
| `OPENROUTER_API_KEY` | secret | LLM calls |
| `SENTINEL_APP_ID` | variable | GitHub App id |
| `SENTINEL_APP_PRIVATE_KEY` | secret | GitHub App private key (.pem contents) |
| `NVD_API_KEY` | secret (optional) | Higher NVD rate limits |

## Safety design
- CVE text and repo files are fenced as untrusted; the model output is never written directly.
- Bot can only change `security/waf-rules.json`; the infra repo's CI enforces this again.
- Costs come from `sentinel.yml`, not the model. Over-budget / high-impact / manual options become a report, not a PR.
- Branch names are deterministic (`sentinel/<cve>-<surface>`), so reruns don't duplicate PRs.
