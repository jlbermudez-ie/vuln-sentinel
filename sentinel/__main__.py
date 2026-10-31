"""vuln-sentinel pipeline.

  python -m sentinel --cve CVE-2026-109618          # targeted (manual / CVE-triggered)
  python -m sentinel                                # scheduled sweep (NVD window + CISA KEV)
  python -m sentinel --cve ... --dry-run            # report only, no PRs/issues
  python -m sentinel --cve ... --offline tests/fixtures --mock-llm tests/fixtures/mock_llm
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import yaml

from . import cve_sources, decision, matcher, notify, prompts, remediation, ship
from .llm import LLMError, make_llm
from .report import render
from .techstack import load_repos


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def gather_cves(args, cfg, repos) -> list[dict]:
    fixtures = Path(args.offline) if args.offline else None
    if args.cve:
        out = []
        for cid in [c.strip().upper() for c in args.cve.split(",") if c.strip()]:
            cve = cve_sources.fetch_cve(cid, fixtures)
            if cve:
                out.append(cve)
            else:
                log(f"! {cid} not found in NVD (yet)")
        return out
    src = cfg["cve_sources"]
    products = [c.get("product") or c["name"] for r in repos for c in r.components if c.get("version")]
    cves = cve_sources.fetch_recent(products, src["nvd"]["lookback_hours"]) if src["nvd"]["enabled"] else []
    if src["kev"]["enabled"]:
        known = {c["id"] for c in cves}
        for cid in cve_sources.fetch_kev_ids(src["kev"]["lookback_days"]) - known:
            cve = cve_sources.fetch_cve(cid)
            if cve:
                cves.append(cve)
    return cves


def triage(cve: dict, repo, llm, cfg) -> dict | None:
    """Deterministic CPE match first; LLM only if NVD has no CPE data yet."""
    desc = cve_sources.description(cve)
    if matcher.has_cpe_data(cve):
        for comp in repo.components:
            hit = matcher.cpe_match(cve, comp)
            if hit:
                return {"component": comp["name"], "version": comp.get("version"), "method": "nvd-cpe",
                        "confidence": 1.0, "evidence": hit}
        return None
    relevant = [c for c in repo.components if matcher.mentions(desc, c)]
    if not relevant:
        return None
    v = llm.json("triage", prompts.TRIAGE_SYSTEM, prompts.triage_user(cve["id"], desc, relevant))
    if v.get("affected") and float(v.get("confidence", 0)) >= cfg["llm"]["min_confidence"]:
        comp = next((c for c in relevant if c["name"] == v.get("component")), relevant[0])
        return {"component": comp["name"], "version": comp.get("version"), "method": "llm",
                "confidence": v["confidence"], "evidence": {"rationale": v.get("rationale"),
                                                             "fixed_versions": v.get("fixed_versions")}}
    return None


def try_code_fix(cve, repo, finding, llm, gh, dry_run) -> dict:
    pol = repo.remediation_policy()
    if not pol.get("auto_fix", False):
        return {"status": "blocked", "reason": (pol.get("reason") or "auto_fix disabled").strip()}
    allowed = pol.get("allowed_paths", [])
    files = {p: (repo.path / p).read_text() for p in allowed if (repo.path / p).exists()}
    out = llm.json("codefix", prompts.CODEFIX_SYSTEM,
                   f"CVE {cve['id']} affects {finding['component']} {finding['version']}.\n"
                   f"Allowed files:\n<untrusted>\n{json.dumps(files)}\n</untrusted>")
    patch = {f["path"]: f["content"] for f in out.get("files", []) if f["path"] in allowed}
    if not patch:
        return {"status": "no-fix", "reason": "model proposed no change inside allowed_paths"}
    if dry_run:
        return {"status": "proposed", "files": list(patch)}
    pr = gh.create_pr(repo.full_name, f"sentinel/{cve['id'].lower()}-codefix", patch,
                      f"fix: remediate {cve['id']}", out.get("summary", ""), ["vuln-sentinel", "security"])
    return {"status": "pr-opened", "url": pr["html_url"]}


def mitigate(cve, service, finding, infra, llm, gh, cfg, dry_run) -> dict:
    waf = json.loads((infra.path / remediation.WAF_FILE).read_text())
    cited = [r["name"] for r in waf.get("managed_rule_groups", []) + waf.get("custom_rules", [])
             if cve["id"] in (r.get("reason") or "")]
    if cited:
        # Idempotency: an earlier run already mitigated this CVE. Re-runs must not keep
        # stacking controls (seen in the lab: a third PR piling on a rate limit).
        return {"infra_repo": infra.full_name, "options": [], "chosen": None,
                "action": f"already mitigated by {', '.join(cited)} (no new PR)"}
    ans = llm.json("mitigation", prompts.MITIGATION_SYSTEM,
                   prompts.mitigation_user(cve, service, finding, infra.stack, waf))
    for o in ans.get("options", []):     # tag every proposed rule with the CVE (code, not the model)
        ch = o.get("changes") or {}
        for r in (ch.get("add_managed_rule_groups") or []) + (ch.get("add_custom_rules") or []):
            if cve["id"] not in (r.get("reason") or ""):
                r["reason"] = f"{cve['id']}: {r.get('reason') or 'mitigation'}"
    evaluated = [remediation.evaluate_option(o, infra.path, cfg["policy"]) for o in ans.get("options", [])]
    chosen = remediation.choose(evaluated, ans.get("recommended"))
    result = {"infra_repo": infra.full_name, "options": evaluated, "recommended": ans.get("recommended"),
              "permanent_fix": ans.get("permanent_fix"), "chosen": chosen["id"] if chosen else None}
    if not chosen:
        result["action"] = "report-only (no option passed the policy gate)"
        return result

    lab = cfg.get("lab") or {}
    if lab.get("canary_header"):
        # Deterministic lab instrumentation, added by code (not by the model) so the
        # smoke test can prove the WAF sits in front of the app after merge.
        canary = {"name": "lab-canary", "action": "block", "header": lab["canary_header"],
                  "contains": lab["canary_value"], "reason": "Lab verification signal for the smoke test"}
        new, extra, added = remediation.apply_waf_changes(chosen["new_waf_rules"], {"add_custom_rules": [canary]})
        schema = json.loads((infra.path / remediation.WAF_SCHEMA).read_text())
        if not remediation.validate_waf(new, schema):
            chosen["new_waf_rules"] = new
            chosen["change_summary"] = chosen["change_summary"] + [s + " — lab instrumentation" for s in extra]
            chosen["computed_cost_usd_month"] += added * cfg["policy"]["cost_usd_month"].get("waf_rule", 1.0)

    # ---- decision matrix: how much autonomy this change gets (all inputs computed by code)
    dm = cfg["decision_matrix"]
    dec = decision.decide(finding["cvss"], chosen, waf, dm, in_kev=finding.get("kev", False))
    result["decision"] = dec
    tier = dec["tier"]
    rules = chosen["new_waf_rules"]
    if tier == "auto":
        rules, notes = decision.stage_for_auto(rules, waf, dm)
        chosen["change_summary"] = chosen["change_summary"] + notes
    content = json.dumps(rules, indent=2) + "\n"
    branch = f"sentinel/{cve['id'].lower()}-waf"
    head = f"{cve['id']} → {service} · {dec['severity']} · impact {dec['impact']} · cost {dec['cost_tier']} → *{tier}*"
    lines = [head, f"Change: {'; '.join(chosen['change_summary'])}",
             f"Fixed upstream in: {finding.get('fixed_in') or 'unknown'}", dec.get("note")]

    if tier == "report":
        result["action"] = "escalated: no PR (risk too high for automation)"
        notify.slack("report", f"Human decision needed: {cve['id']}", lines + [
            "Best option exceeds the automation limits; see the run summary for all options."], dry_run=dry_run)
        return result
    if dry_run:
        result["action"] = f"dry-run: tier {tier} — would open PR on {infra.full_name} branch {branch}"
        result["proposed_file"] = content
        notify.slack(tier, f"[dry-run] {cve['id']} mitigation ({tier})", lines, dry_run=True)
        return result
    if gh.open_pr_for(infra.full_name, branch):
        result["action"] = "skipped: PR already open"
        return result

    from .report import pr_body
    title = f"security: {chosen['type']} WAF mitigation for {cve['id']} ({service})"
    if tier == "auto":
        title += f" {ship.AUTO_MARKER}"
    pr = ship.open_pr(gh, infra.full_name, branch, remediation.WAF_FILE, content, title,
                      pr_body(cve, service, finding, result, chosen),
                      ["vuln-sentinel", "security", chosen["type"], f"tier:{tier}"])
    result["url"] = pr["html_url"]
    if tier == "auto":
        res = ship.auto_merge(gh, infra.full_name, pr, dm)
        result["auto_merge"] = res
        if res["merged"]:
            result["action"] = "auto-merged (staged in COUNT, promotion pending)"
            notify.slack("auto", f"Auto-mitigated {cve['id']} on {service}", lines + [
                "Merged by the bot; apply runs in the `auto` environment.",
                "Rules start in COUNT and are promoted to BLOCK by the promotion job."], url=pr["html_url"])
            return result
        tier = "approve"
        result["decision"]["tier"] = "approve"
        result["decision"]["note"] = f"auto-merge cancelled: checks {res['status']}"
        lines.append(f"Auto-merge cancelled: required checks {res['status']}")
    result["action"] = "pr-opened (awaiting human approval)"
    notify.slack("approve", f"Approval needed: {cve['id']} mitigation PR", lines, url=pr["html_url"])
    return result


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="sentinel")
    ap.add_argument("--config", default="sentinel.yml")
    ap.add_argument("--root", default=".", help="where repos/ checkouts live")
    ap.add_argument("--cve", help="comma-separated CVE ids (targeted mode)")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--offline", help="read CVEs from this fixtures dir instead of NVD")
    ap.add_argument("--mock-llm", help="read LLM answers from this dir instead of OpenRouter")
    ap.add_argument("--out", default="out")
    args = ap.parse_args(argv)

    cfg = yaml.safe_load(Path(args.config).read_text())
    repos = load_repos(cfg, Path(args.root))
    llm = make_llm(cfg["llm"], Path(args.mock_llm) if args.mock_llm else None)
    gh = None
    if not args.dry_run:
        from .github import GitHub
        gh = GitHub()

    findings = []
    for cve in gather_cves(args, cfg, repos):
        score, sev = cve_sources.cvss(cve)
        if score < cfg["policy"]["min_cvss"] and not args.cve:
            continue
        for repo in [r for r in repos if r.kind == "code"]:
            try:
                hit = triage(cve, repo, llm, cfg)
            except LLMError as e:
                log(f"! triage failed for {cve['id']}: {e}")
                continue
            if not hit:
                continue
            log(f"* {cve['id']} affects {repo.name} ({hit['component']} {hit['version']}) via {hit['method']}")
            f = {"cve": cve["id"], "cvss": score, "severity": sev, "service": repo.name,
                 "kev": bool(cve.get("cisaExploitAdd")),
                 "description": cve_sources.description(cve), **hit}
            ev = hit.get("evidence") or {}
            f["fixed_in"] = ev.get("versionEndExcluding") or ", ".join(ev.get("fixed_versions") or []) or None
            f["code_fix"] = try_code_fix(cve, repo, f, llm, gh, args.dry_run)
            f["mitigations"] = []
            if f["code_fix"]["status"] != "pr-opened":
                for infra in [r for r in repos if r.kind == "infra" and repo.name in r.serves]:
                    try:
                        f["mitigations"].append(mitigate(cve, repo.name, f, infra, llm, gh, cfg, args.dry_run))
                    except LLMError as e:
                        f["mitigations"].append({"infra_repo": infra.full_name, "action": f"error: {e}"})
            if (cfg["policy"].get("open_tracking_issue") and f["code_fix"]["status"] == "blocked"
                    and not args.dry_run):
                title = f"[{cve['id']}] permanent fix needed for {hit['component']} {hit['version']}"
                if not gh.find_issue(repo.full_name, title):
                    pf = next((m.get("permanent_fix") for m in f["mitigations"] if m.get("permanent_fix")), "")
                    if f.get("fixed_in"):
                        pf = f"Upgrade {hit['component']} to {f['fixed_in']} or later (per NVD). {pf}"
                    links = "\n".join(f"- Mitigation: {m['url']}" for m in f["mitigations"] if m.get("url"))
                    gh.create_issue(repo.full_name, title,
                                    f"{f['description']}\n\n**Automatic fix blocked:** {f['code_fix']['reason']}\n\n"
                                    f"**Permanent fix:** {pf}\n\n{links}", ["vuln-sentinel", "security"])
            findings.append(f)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.json").write_text(json.dumps(findings, indent=2, default=str))
    md = render(findings)
    (out / "report.md").write_text(md)
    if os.getenv("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as fh:
            fh.write(md)
    print(md)
    return 0


if __name__ == "__main__":
    sys.exit(main())
