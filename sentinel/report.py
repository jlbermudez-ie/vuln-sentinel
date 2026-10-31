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
                f"- Fixed upstream in: **{f.get('fixed_in') or 'unknown'}** (from NVD)",
                f"- Code fix: **{f['code_fix']['status']}** — {f['code_fix'].get('reason', f['code_fix'].get('url', ''))}"]
        for m in f["mitigations"]:
            d = m.get("decision")
            if d:
                out.append(f"- Decision: severity **{d['severity']}**{' (KEV)' if d.get('kev') else ''} · "
                           f"impact **{d['impact']}** · cost **{d['cost_tier']}** → tier **{d['tier']}**"
                           + (f" — {d['note']}" if d.get('note') else ""))
            out += [f"- Infra `{m['infra_repo']}`: **{m.get('action')}** {m.get('url', '')}", ""]
            if m.get("options"):
                out += [_opt_table(m["options"]), ""]
            if m.get("permanent_fix"):
                out += [f"> Permanent fix still required: {m['permanent_fix']}", ""]
        out.append("")
    return "\n".join(out)


def _decision_block(d: dict | None) -> str:
    if not d:
        return ""
    why = "; ".join(d.get("impact_why", []))
    action = {"auto": "auto-merge after required checks; rules staged in COUNT, promoted to BLOCK by the promotion job",
              "approve": "a human reviews and approves", "report": "no PR"}[d["tier"]]
    return (f"### Decision matrix → tier `{d['tier']}`\n"
            f"| Severity | Impact (computed) | Cost tier | Action |\n|---|---|---|---|\n"
            f"| {d['severity']}{' (KEV)' if d.get('kev') else ''} | {d['impact']} — {why} | {d['cost_tier']} | {action} |")


def pr_body(cve: dict, service: str, finding: dict, result: dict, chosen: dict) -> str:
    changes = "\n".join(f"- {s}" for s in chosen["change_summary"])
    return f"""## 🛡️ {chosen['type'].title()} mitigation for {cve['id']}

**Service:** `{service}` · **Component:** `{finding['component']} {finding['version']}` · **CVSS:** {finding['cvss']}
**Fixed upstream in:** `{finding.get('fixed_in') or 'unknown'}` (NVD) · **Why not a code fix?** {finding['code_fix'].get('reason', finding['code_fix']['status'])}

{_decision_block(result.get("decision"))}

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
