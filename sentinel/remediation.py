"""Turns LLM proposals into validated, policy-gated changes.

The LLM proposes; this module decides. Nothing reaches a PR unless it:
  1. touches only an allowed mitigation surface (security/waf-rules.json),
  2. validates against the infra repo's own JSON schema + semantic checks,
  3. passes the cost / impact / effort / type policy using OUR cost model.
"""
from __future__ import annotations

import copy
import json
import re
from pathlib import Path

import jsonschema

LEVEL = {"low": 0, "medium": 1, "high": 2}
WAF_FILE = "security/waf-rules.json"
WAF_SCHEMA = "security/waf-rules.schema.json"


# ---------------------------------------------------------------- WAF changes
def _free_priority(used: set[int], start: int, step: int = 1) -> int:
    p = start
    while p in used:
        p += step
    used.add(p)
    return p


def apply_waf_changes(current: dict, changes: dict) -> tuple[dict, list[str], int]:
    """Return (new_rules, human_summary, number_of_new_billable_rules)."""
    new = copy.deepcopy(current)
    used = {g["priority"] for g in new["managed_rule_groups"]} | {r["priority"] for r in new["custom_rules"]}
    if new.get("rate_limit"):
        used.add(new["rate_limit"]["priority"])
    summary, added = [], 0

    for r in changes.get("add_custom_rules") or []:
        name = re.sub(r"[^a-z0-9-]", "-", r["name"].lower())[:64]
        if any(x["name"] == name for x in new["custom_rules"]):
            continue
        new["custom_rules"].append({
            "name": name, "priority": _free_priority(used, 1), "action": r["action"],
            "header": r["header"].lower(), "contains": r["contains"].lower(), "reason": r["reason"][:300],
        })
        summary.append(f"custom rule `{name}` ({r['action']}) on header `{r['header'].lower()}`")
        added += 1

    for g in changes.get("add_managed_rule_groups") or []:
        existing = next((x for x in new["managed_rule_groups"] if x["name"] == g["name"]), None)
        if existing:
            if existing["mode"] != g["mode"]:
                existing["mode"] = g["mode"]
                summary.append(f"managed group `{g['name']}` mode {existing['mode']} → {g['mode']}")
            continue
        new["managed_rule_groups"].append({
            "name": g["name"], "priority": _free_priority(used, 30, 10), "mode": g["mode"],
            "version": None, "rule_overrides_to_count": [], "reason": g["reason"][:300],
        })
        summary.append(f"managed group `{g['name']}` ({g['mode']})")
        added += 1

    rl = changes.get("set_rate_limit")
    if rl:
        if not new.get("rate_limit"):
            added += 1
        new["rate_limit"] = {"limit": int(rl["limit"]), "action": rl["action"],
                             "priority": (new.get("rate_limit") or {}).get("priority") or _free_priority(used, 10)}
        summary.append(f"rate limit {rl['limit']}/5min per IP ({rl['action']})")

    return new, summary, added


def validate_waf(rules: dict, schema: dict) -> list[str]:
    errs = [e.message for e in jsonschema.Draft202012Validator(schema).iter_errors(rules)]
    if errs:
        return errs
    prios = [g["priority"] for g in rules["managed_rule_groups"]] + [r["priority"] for r in rules["custom_rules"]]
    if rules.get("rate_limit"):
        prios.append(rules["rate_limit"]["priority"])
    if len(prios) != len(set(prios)):
        errs.append("duplicate priorities")
    if "AWSManagedRulesCommonRuleSet" not in [g["name"] for g in rules["managed_rule_groups"]]:
        errs.append("baseline rule set removed")
    return errs


# ---------------------------------------------------------------- policy gate
def _adds_blocking(changes: dict) -> bool:
    return any(g.get("mode") == "block" for g in changes.get("add_managed_rule_groups") or []) or \
        any(r.get("action") == "block" for r in changes.get("add_custom_rules") or [])


def evaluate_option(opt: dict, infra_path: Path, policy: dict) -> dict:
    """Attach cost, diff, validation and gate verdict to one LLM option."""
    res = {**opt, "gate": {"passed": False, "reasons": []}}
    surfaces = {"waf-managed-rule-group", "waf-custom-header-rule", "waf-rate-limit"}
    if opt.get("surface") not in surfaces:
        res["gate"]["reasons"].append("needs manual work (not an automatable surface)")
        res["computed_cost_usd_month"] = None
        return res

    current = json.loads((infra_path / WAF_FILE).read_text())
    schema = json.loads((infra_path / WAF_SCHEMA).read_text())
    new, summary, added = apply_waf_changes(current, opt.get("changes") or {})
    costs = policy.get("cost_usd_month", {})
    cost = added * costs.get("waf_rule", 1.0)
    res.update(computed_cost_usd_month=round(cost, 2), change_summary=summary, new_waf_rules=new)

    ap = policy["auto_pr"]
    reasons = res["gate"]["reasons"]
    if not summary:
        reasons.append("no effective change (already in place?)")
    reasons += [f"schema: {e}" for e in validate_waf(new, schema)]
    if cost > ap["max_monthly_cost_usd"]:
        reasons.append(f"cost ${cost} > ${ap['max_monthly_cost_usd']}")
    if LEVEL.get(opt.get("impact"), 9) > LEVEL[ap["max_impact"]]:
        reasons.append(f"impact {opt.get('impact')} > {ap['max_impact']}")
    if LEVEL.get(opt.get("effort"), 9) > LEVEL[ap["max_effort"]]:
        reasons.append(f"effort {opt.get('effort')} > {ap['max_effort']}")
    if opt.get("type") not in ap["allowed_types"]:
        reasons.append(f"type {opt.get('type')} not allowed")
    if ap.get("require_blocking_control", True) and not _adds_blocking(opt.get("changes") or {}):
        # count mode only logs, and rate limits can't stop a single-request exploit
        reasons.append("no blocking control (count-mode / rate-limit only)")
    res["gate"]["passed"] = not reasons
    return res


def choose(evaluated: list[dict], recommended_id: str | None) -> dict | None:
    passing = [o for o in evaluated if o["gate"]["passed"]]
    if not passing:
        return None
    rec = next((o for o in passing if o["id"] == recommended_id), None)
    if rec:
        return rec
    return sorted(passing, key=lambda o: (LEVEL[o["impact"]], o["computed_cost_usd_month"]))[0]
