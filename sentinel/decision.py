"""Decision matrix: how much autonomy the bot gets for one mitigation.

Every input is computed by code. The model's own "impact" and cost guesses are
shown to humans but never used here (in the first real run the model rated an
ineffective rule "low impact").

    severity x worst(impact, cost)  ->  tier
      auto     PR, wait for checks, auto-merge, apply in the `auto` environment,
               rules staged in COUNT mode and promoted to BLOCK by sentinel.promote
      approve  PR + notify, a human approves and applies (production environment)
      report   no PR: tracking issue + notify (a human decides)
"""
from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone

LEVEL = {"low": 0, "medium": 1, "high": 2}
NAMES = {v: k for k, v in LEVEL.items()}
TIERS = ("auto", "approve", "report")


def severity_of(cvss: float, cfg: dict) -> str:
    s = cfg["severity"]
    if cvss >= s["critical"]:
        return "critical"
    if cvss >= s["high"]:
        return "high"
    if cvss >= s["medium"]:
        return "medium"
    return "low"


def impact_of(option: dict, current: dict, cfg: dict) -> tuple[str, list[str]]:
    """Deterministic blast-radius estimate from WHAT the change does, not the model's label."""
    ch = option.get("changes") or {}
    low_groups = set(cfg["impact"]["low_risk_managed_groups"])
    why, level = [], 0
    if option.get("surface") not in {"waf-managed-rule-group", "waf-custom-header-rule", "waf-rate-limit"}:
        return "high", ["manual / non-automatable change"]
    existing = {g["name"]: g for g in current.get("managed_rule_groups", [])}
    for g in ch.get("add_managed_rule_groups") or []:
        if g["name"] in existing and existing[g["name"]]["mode"] == g.get("mode"):
            continue
        if g["name"] in low_groups:
            why.append(f"{g['name']}: allow-listed low-risk managed group")
        else:
            level = max(level, 1)
            why.append(f"{g['name']}: managed group not on the low-risk list")
    for r in ch.get("add_custom_rules") or []:
        level = max(level, 1)
        why.append(f"custom rule '{r.get('name')}': hand-written match, needs review")
    if ch.get("set_rate_limit"):
        level = max(level, 1)
        why.append("rate limit: can throttle legitimate bursts")
    return NAMES[level], why or ["no effective change"]


def cost_tier(cost: float | None, cfg: dict) -> str:
    if cost is None:
        return "high"
    c = cfg["cost_usd_month"]
    return "low" if cost <= c["low_max"] else "medium" if cost <= c["medium_max"] else "high"


def decide(cvss: float, option: dict, current: dict, cfg: dict, in_kev: bool = False) -> dict:
    """cfg = sentinel.yml `decision_matrix`."""
    sev = severity_of(cvss, cfg)
    impact, impact_why = impact_of(option, current, cfg)
    cost = cost_tier(option.get("computed_cost_usd_month"), cfg)
    risk = NAMES[max(LEVEL[impact], LEVEL[cost])]           # the worse of the two decides
    urgent = sev in ("high", "critical") or (in_kev and cfg.get("kev_counts_as_high", True))
    if not urgent:
        tier = "approve" if risk != "high" else "report"
    else:
        tier = {"low": "auto", "medium": "approve", "high": "report"}[risk]
    if tier == "auto" and not cfg.get("auto_merge_enabled", False):
        tier, note = "approve", "auto tier disabled in config (auto_merge_enabled: false)"
    else:
        note = None
    return {"tier": tier, "severity": sev, "impact": impact, "impact_why": impact_why,
            "cost_tier": cost, "risk": risk, "kev": in_kev, "note": note}


def stage_for_auto(new_rules: dict, current: dict, cfg: dict, now: datetime | None = None) -> tuple[dict, list[str]]:
    """Auto tier: every managed group that would start BLOCKING is deployed in COUNT
    first, with a promotion time. sentinel.promote flips it to BLOCK only if it would
    not have blocked too much legitimate traffic during the observation window."""
    now = now or datetime.now(timezone.utc)
    p = cfg["promotion"]
    staged_rules = copy.deepcopy(new_rules)
    before = {g["name"]: g["mode"] for g in current.get("managed_rule_groups", [])}
    notes = []
    for g in staged_rules["managed_rule_groups"]:
        if g["mode"] == "block" and before.get(g["name"]) != "block":
            g["mode"] = "count"
            g["staged"] = {"since": _iso(now),
                           "promote_at": _iso(now + timedelta(minutes=p["observe_minutes"])),
                           "max_count_ratio": p["max_count_ratio"]}
            notes.append(f"{g['name']} staged in COUNT; promotion to BLOCK after "
                         f"{p['observe_minutes']} min if ≤{p['max_count_ratio']:.2%} of traffic matches")
    return staged_rules, notes


def _iso(d: datetime) -> str:
    return d.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
