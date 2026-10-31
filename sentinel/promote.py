"""Observe-then-block for the auto tier.

    python -m sentinel.promote --infra repos/orders-infra [--dry-run]

For each managed rule group in security/waf-rules.json:
  staged (COUNT) and promote_at passed:
      counted share <= max_count_ratio (and enough traffic) -> promote to BLOCK + start a watch window
      otherwise                                               -> stay in COUNT, hold for a human
  watch (BLOCK) still open:
      blocked share > max_block_ratio -> roll back to COUNT, hold for a human
      window over                     -> watch cleared (promotion confirmed)

Every change goes through the same path as the scanner's auto tier: a PR touching
only waf-rules.json, required checks, squash-merge with [sentinel-auto], apply in
the `auto` environment. Every decision is posted to Slack.
"""
from __future__ import annotations

import argparse
import copy
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

import yaml

from . import notify, ship
from .decision import _iso

WAF_FILE = "security/waf-rules.json"

# metrics(rule_metric_name, metric, start, end) -> request count.
# metric is "CountedRequests" | "BlockedRequests" | "AllowedRequests"; rule "ALL" = the whole web ACL.
Metrics = Callable[[str, str, datetime, datetime], float]


def _ts(s: str) -> datetime:
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def cloudwatch_metrics(web_acl: str, region: str) -> Metrics:
    import boto3
    cw = boto3.client("cloudwatch", region_name=region)

    def get(rule: str, metric: str, start: datetime, end: datetime) -> float:
        r = cw.get_metric_statistics(
            Namespace="AWS/WAFV2", MetricName=metric, StartTime=start, EndTime=end, Period=300,
            Statistics=["Sum"],
            Dimensions=[{"Name": "WebACL", "Value": web_acl}, {"Name": "Region", "Value": region},
                        {"Name": "Rule", "Value": rule}])
        return float(sum(p["Sum"] for p in r.get("Datapoints", [])))
    return get


def evaluate(rules: dict, p: dict, metrics: Metrics, now: datetime) -> tuple[dict, list[dict]]:
    """Pure decision step: returns (new_rules, events). Unit-tested with fake metrics."""
    new = copy.deepcopy(rules)
    events = []
    for g in new["managed_rule_groups"]:
        name = g["name"]
        st, w = g.get("staged"), g.get("watch")
        if st and now >= _ts(st["promote_at"]):
            since = _ts(st["since"])
            total = metrics("ALL", "AllowedRequests", since, now) + metrics("ALL", "BlockedRequests", since, now)
            counted = metrics(name, "CountedRequests", since, now)
            ratio = counted / total if total else 0.0
            facts = f"{int(counted)} of {int(total)} requests matched while counting ({ratio:.2%})"
            if total < p["min_requests"]:
                events.append({"kind": "info", "group": name,
                               "msg": f"not enough traffic yet ({int(total)} < {p['min_requests']}); staying in COUNT"})
                continue
            if ratio <= st["max_count_ratio"]:
                g["mode"], g["staged"], g["hold_reason"] = "block", None, None
                g["watch"] = {"since": _iso(now), "until": _iso(now + timedelta(minutes=p["watch_minutes"])),
                              "max_block_ratio": p["max_block_ratio"]}
                events.append({"kind": "promoted", "group": name, "msg": f"COUNT → BLOCK. {facts}"})
            else:
                g["staged"] = None
                g["hold_reason"] = f"promotion refused: {facts} > {st['max_count_ratio']:.2%}"
                events.append({"kind": "held", "group": name,
                               "msg": f"kept in COUNT, human decision needed. {facts}"})
        elif w:
            since = _ts(w["since"])
            end = min(now, _ts(w["until"]))
            total = metrics("ALL", "AllowedRequests", since, end) + metrics("ALL", "BlockedRequests", since, end)
            blocked = metrics(name, "BlockedRequests", since, end)
            ratio = blocked / total if total else 0.0
            facts = f"{int(blocked)} of {int(total)} requests blocked by this group ({ratio:.2%})"
            if total >= p["min_requests"] and ratio > w["max_block_ratio"]:
                g["mode"], g["watch"] = "count", None
                g["hold_reason"] = f"rolled back: {facts} > {w['max_block_ratio']:.2%}"
                events.append({"kind": "rolled-back", "group": name, "msg": f"BLOCK → COUNT. {facts}"})
            elif now >= _ts(w["until"]):
                g["watch"] = None
                events.append({"kind": "promoted", "group": name, "msg": f"watch window passed, BLOCK confirmed. {facts}"})
    return new, events


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="sentinel.promote")
    ap.add_argument("--config", default="sentinel.yml")
    ap.add_argument("--infra", default="repos/orders-infra")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--metrics-json", help="offline: {rule: {metric: count}} instead of CloudWatch")
    args = ap.parse_args(argv)

    cfg = yaml.safe_load(Path(args.config).read_text())
    dm = cfg["decision_matrix"]
    p = dm["promotion"]
    infra_cfg = next(r for r in cfg["repos"] if r["kind"] == "infra")
    path = Path(args.infra) / WAF_FILE
    rules = json.loads(path.read_text())

    if args.metrics_json:
        fixed = json.loads(Path(args.metrics_json).read_text())
        metrics: Metrics = lambda rule, m, s, e: float(fixed.get(rule, {}).get(m, 0))
    else:
        metrics = cloudwatch_metrics(p["web_acl_name"], p["region"])

    now = datetime.now(timezone.utc)
    new, events = evaluate(rules, p, metrics, now)
    for e in events:
        print(f"[{e['kind']}] {e['group']}: {e['msg']}", file=sys.stderr)
    changed = new != rules
    if not changed:
        print("nothing to promote or roll back")   # no Slack: this runs every 30 min
        return 0

    content = json.dumps(new, indent=2) + "\n"
    if args.dry_run:
        print(content)
        for e in events:
            notify.slack(e["kind"], f"[dry-run] WAF {e['kind']}: {e['group']}", [e["msg"]], dry_run=True)
        return 0

    from .github import GitHub
    gh = GitHub()
    repo = infra_cfg["full_name"]
    kinds = sorted({e["kind"] for e in events if e["kind"] != "info"})
    branch = f"sentinel/promote-{now.strftime('%Y%m%d%H%M')}"
    title = f"waf: {', '.join(kinds)} ({', '.join(e['group'] for e in events if e['kind'] != 'info')}) {ship.AUTO_MARKER}"
    body = "## vuln-sentinel promotion job\n\n" + "\n".join(f"- **{e['kind']}** `{e['group']}`: {e['msg']}" for e in events) + \
           "\n\nAutomatic per the decision matrix (auto tier). Only `security/waf-rules.json` changes."
    pr = ship.open_pr(gh, repo, branch, WAF_FILE, content, title, body, ["vuln-sentinel", "tier:auto", "promotion"])
    res = ship.auto_merge(gh, repo, pr, dm)
    for e in events:
        if e["kind"] == "info":
            continue
        status = "merged" if res["merged"] else f"NOT merged (checks {res['status']}), needs a human"
        notify.slack(e["kind"] if res["merged"] else "error", f"WAF {e['kind']}: {e['group']}",
                     [e["msg"], f"PR {status}"], url=pr["html_url"])
    return 0 if res["merged"] else 1


if __name__ == "__main__":
    sys.exit(main())
