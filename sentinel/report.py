"""Markdown rendering for the job summary and PR bodies."""
from __future__ import annotations


def _opt_table(options: list[dict]) -> str:
    rows = ["| Option | Type | Impact | Effort | Cost/mo (computed) | Gate |",
            "|---|---|---|---|---|---|"]
    for o in options:
        cost = "n/a" if o.get("computed_cost_usd_month") is None else f"${o['computed_cost_usd_month']:.2f}"
        gate = "✅ pass" if o["gate"]["passed"] else "❌ " + "; ".join(o["gate"]["reasons"])
        rows.append(f"| **{o['id']}** — {o['title']} | {o['type']} | {o['impact']} | {o['effort']} | {cost} | {gate} |")
    return "\n".join(rows)


def render(findings: list[dict]) -> str:
    if not findings:
        return "## vuln-sentinel\n\nNo CVEs affecting the declared tech stacks.\n"
    out = ["## vuln-sentinel report", ""]
    for f in findings:
        out += [f"### {f['cve']} → `{f['service']}` (CVSS {f['cvss']} {f['severity']})",
                f"- Component: `{f['component']} {f['version']}` (matched via **{f['method']}**, confidence {f['confidence']})",
                f"- Code fix: **{f['code_fix']['status']}** — {f['code_fix'].get('reason', f['code_fix'].get('url', ''))}"]
        for m in f["mitigations"]:
            out += [f"- Infra `{m['infra_repo']}`: **{m.get('action')}** {m.get('url', '')}", ""]
            if m.get("options"):
                out += [_opt_table(m["options"]), ""]
            if m.get("permanent_fix"):
                out += [f"> Permanent fix still required: {m['permanent_fix']}", ""]
        out.append("")
    return "\n".join(out)


def pr_body(cve: dict, service: str, finding: dict, result: dict, chosen: dict) -> str:
    changes = "\n".join(f"- {s}" for s in chosen["change_summary"])
    return f"""## 🛡️ {chosen['type'].title()} mitigation for {cve['id']}

**Service:** `{service}` · **Component:** `{finding['component']} {finding['version']}` · **CVSS:** {finding['cvss']}
**Why not a code fix?** {finding['code_fix'].get('reason', finding['code_fix']['status'])}

### Change (`security/waf-rules.json` only)
{changes}

| | |
|---|---|
| Type | **{chosen['type']}** |
| Impact on legit traffic | **{chosen['impact']}** |
| Effort | {chosen['effort']} |
| Added cost (computed) | **${chosen['computed_cost_usd_month']:.2f}/month** (model guessed ${chosen.get('llm_cost_estimate_usd_month', '?')}) |

**Rationale:** {chosen['rationale']}

**Residual risk:** {chosen['residual_risk']}

**Rollback:** {chosen['rollback']}

**Permanent fix (tracked separately):** {result.get('permanent_fix', '')}

### All options considered
{_opt_table(result['options'])}

---
<sub>Opened by vuln-sentinel. The model proposed this; schema, allowlist, cost and impact gates were enforced in code.
Review the `terraform plan` comment below before approving. Suggested rollout: merge, watch WAF sampled requests / CloudWatch metrics for false positives.</sub>
"""
