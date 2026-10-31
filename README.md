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

## Decision matrix (how much autonomy the bot gets)

| Severity (CVSS, or CISA KEV) | worst(impact, cost) | Tier | What happens |
|---|---|---|---|
| High / Critical | low | **auto** | PR → required checks → bot squash-merges `[sentinel-auto]` → apply in env `auto`; new groups start in **COUNT** and `promote.yml` flips them to **BLOCK** |
| High / Critical | medium | **approve** | PR + Slack; a human approves (env `production`) |
| High / Critical | high | **report** | No PR; Slack escalation + tracking issue |
| Medium / Low | low–medium | approve | Never auto |

Impact and cost are **computed by code**: only allow-listed AWS managed groups count as low impact;
custom rules and rate limits are medium; manual changes are high. Cost tiers come from `sentinel.yml`.
The model's own labels are displayed but never used (it once called a never-firing rule "low impact").

**Observe, then block** (`python -m sentinel.promote`, every 30 min): after `observe_minutes` in COUNT, a group is
promoted only if ≤ `max_count_ratio` of requests matched; during `watch_minutes` it is rolled back to COUNT if it
blocks more than `max_block_ratio`. Every decision is posted to Slack and shipped as an auto-merged PR.

**Idempotency:** if a rule in `waf-rules.json` already cites the CVE, the scanner reports "already mitigated" and stops.

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
| `SLACK_WEBHOOK_URL` | secret | Slack Incoming Webhook for notifications |
| `SENTINEL_METRICS_ROLE_ARN` | variable | Read-only CloudWatch role (bootstrap output `metrics_role_arn`) |

## Safety design
- CVE text and repo files are fenced as untrusted; the model output is never written directly.
- Bot can only change `security/waf-rules.json`; the infra repo's CI enforces this again.
- Costs come from `sentinel.yml`, not the model. Over-budget / high-impact / manual options become a report, not a PR.
- Branch names are deterministic (`sentinel/<cve>-<surface>`), so reruns don't duplicate PRs.
