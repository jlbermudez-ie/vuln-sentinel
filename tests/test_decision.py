import copy
import json
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

from sentinel import decision, promote
from sentinel.__main__ import main

HERE = Path(__file__).parent
FIX = HERE / "fixtures"
CFG = yaml.safe_load((HERE.parent / "sentinel.yml").read_text())
DM = CFG["decision_matrix"]
BASE = json.loads((FIX / "repos/orders-infra/security/waf-rules.json").read_text())


def opt(changes, cost, surface="waf-managed-rule-group", impact_label="low"):
    return {"id": "x", "surface": surface, "impact": impact_label, "changes": changes,
            "computed_cost_usd_month": cost}


PHP_ONLY = {"add_managed_rule_groups": [{"name": "AWSManagedRulesPHPRuleSet", "mode": "block", "reason": "r"},
                                        {"name": "AWSManagedRulesKnownBadInputsRuleSet", "mode": "block", "reason": "r"}]}


# ---------------------------------------------------------------- matrix
def test_critical_low_impact_low_cost_is_auto():
    d = decision.decide(9.2, opt(PHP_ONLY, 3.0), BASE, DM)
    assert (d["severity"], d["impact"], d["cost_tier"], d["tier"]) == ("critical", "low", "low", "auto")


def test_model_label_is_ignored_custom_rule_is_medium():
    """Lab regression: the model called the never-firing size rule 'low impact'."""
    ch = {"add_custom_rules": [{"name": "blocklargepayloads", "action": "block", "header": "x-size",
                                "contains": "big", "reason": "r"}]}
    d = decision.decide(9.2, opt(ch, 1.0, surface="waf-custom-header-rule", impact_label="low"), BASE, DM)
    assert d["impact"] == "medium" and d["tier"] == "approve"


def test_pr3_rate_limit_plus_ip_reputation_needs_approval():
    """Real PR #3: IP reputation (low) + 100/5min rate limit (medium) -> worst wins -> approve."""
    ch = {"add_managed_rule_groups": [{"name": "AWSManagedRulesAmazonIpReputationList", "mode": "block", "reason": "r"}],
          "set_rate_limit": {"limit": 100, "action": "block"}}
    assert decision.decide(9.2, opt(ch, 2.0), BASE, DM)["tier"] == "approve"


def test_high_cost_is_report_only():
    d = decision.decide(9.8, opt(PHP_ONLY, 30.0), BASE, DM)
    assert d["cost_tier"] == "high" and d["tier"] == "report"


def test_mid_cost_low_impact_worst_wins():
    assert decision.decide(8.0, opt(PHP_ONLY, 10.0), BASE, DM)["tier"] == "approve"


def test_medium_severity_never_auto():
    assert decision.decide(5.0, opt(PHP_ONLY, 1.0), BASE, DM)["tier"] == "approve"


def test_kev_makes_medium_cvss_urgent():
    assert decision.decide(6.0, opt(PHP_ONLY, 1.0), BASE, DM, in_kev=True)["tier"] == "auto"


def test_kill_switch():
    dm = copy.deepcopy(DM); dm["auto_merge_enabled"] = False
    d = decision.decide(9.8, opt(PHP_ONLY, 1.0), BASE, dm)
    assert d["tier"] == "approve" and "disabled" in d["note"]


def test_manual_option_is_high_impact():
    d = decision.decide(9.8, opt({}, 0.0, surface="manual"), BASE, DM)
    assert d["impact"] == "high" and d["tier"] == "report"


def test_stage_for_auto_counts_first():
    new = copy.deepcopy(BASE)
    new["managed_rule_groups"].append({"name": "AWSManagedRulesPHPRuleSet", "priority": 30, "mode": "block",
                                       "version": None, "rule_overrides_to_count": [], "reason": "r"})
    now = datetime(2026, 10, 31, 21, 0, tzinfo=timezone.utc)
    staged, notes = decision.stage_for_auto(new, BASE, DM, now)
    php = next(g for g in staged["managed_rule_groups"] if g["name"] == "AWSManagedRulesPHPRuleSet")
    common = next(g for g in staged["managed_rule_groups"] if g["name"] == "AWSManagedRulesCommonRuleSet")
    assert php["mode"] == "count" and php["staged"]["promote_at"] == "2026-10-31T21:30:00Z"
    assert common["mode"] == "block" and "staged" not in common      # already blocking: untouched
    assert notes


# ---------------------------------------------------------------- promotion
P = DM["promotion"]
NOW = datetime(2026, 10, 31, 22, 0, tzinfo=timezone.utc)


def staged_rules(promote_at):
    r = copy.deepcopy(BASE)
    r["managed_rule_groups"].append({"name": "AWSManagedRulesPHPRuleSet", "priority": 30, "mode": "count",
                                     "reason": "CVE-2026-109618: test", "staged": {"since": "2026-10-31T21:00:00Z",
                                                               "promote_at": promote_at, "max_count_ratio": 0.01}})
    return r


def fake(counts):
    return lambda rule, metric, s, e: float(counts.get((rule, metric), 0))


def php(rules):
    return next(g for g in rules["managed_rule_groups"] if g["name"] == "AWSManagedRulesPHPRuleSet")


def test_promotes_when_quiet():
    new, ev = promote.evaluate(staged_rules("2026-10-31T21:30:00Z"), P, fake(
        {("ALL", "AllowedRequests"): 1000, ("AWSManagedRulesPHPRuleSet", "CountedRequests"): 5}), NOW)
    g = php(new)
    assert g["mode"] == "block" and g["staged"] is None and g["watch"]["max_block_ratio"] == P["max_block_ratio"]
    assert ev[0]["kind"] == "promoted"


def test_holds_when_it_would_block_too_much():
    new, ev = promote.evaluate(staged_rules("2026-10-31T21:30:00Z"), P, fake(
        {("ALL", "AllowedRequests"): 1000, ("AWSManagedRulesPHPRuleSet", "CountedRequests"): 50}), NOW)
    g = php(new)
    assert g["mode"] == "count" and g["staged"] is None and "refused" in g["hold_reason"]
    assert ev[0]["kind"] == "held"


def test_waits_until_promote_at():
    rules = staged_rules("2026-10-31T23:00:00Z")
    new, ev = promote.evaluate(rules, P, fake({}), NOW)
    assert new == rules and ev == []


def test_needs_minimum_traffic():
    p = dict(P, min_requests=1000)
    rules = staged_rules("2026-10-31T21:30:00Z")
    new, ev = promote.evaluate(rules, p, fake({("ALL", "AllowedRequests"): 10}), NOW)
    assert new == rules and ev[0]["kind"] == "info"


def watched_rules(until):
    r = copy.deepcopy(BASE)
    r["managed_rule_groups"].append({"name": "AWSManagedRulesPHPRuleSet", "priority": 30, "mode": "block",
                                     "reason": "CVE-2026-109618: test", "watch": {"since": "2026-10-31T21:30:00Z", "until": until,
                                                              "max_block_ratio": 0.02}})
    return r


def test_rolls_back_on_block_spike():
    new, ev = promote.evaluate(watched_rules("2026-10-31T22:30:00Z"), P, fake(
        {("ALL", "AllowedRequests"): 900, ("ALL", "BlockedRequests"): 100,
         ("AWSManagedRulesPHPRuleSet", "BlockedRequests"): 100}), NOW)
    g = php(new)
    assert g["mode"] == "count" and g["watch"] is None and "rolled back" in g["hold_reason"]
    assert ev[0]["kind"] == "rolled-back"


def test_confirms_after_quiet_watch():
    new, ev = promote.evaluate(watched_rules("2026-10-31T21:45:00Z"), P, fake(
        {("ALL", "AllowedRequests"): 1000, ("AWSManagedRulesPHPRuleSet", "BlockedRequests"): 2}), NOW)
    g = php(new)
    assert g["mode"] == "block" and g["watch"] is None


def test_promoted_file_passes_infra_schema():
    from sentinel import remediation
    schema = json.loads((FIX / "repos/orders-infra/security/waf-rules.schema.json").read_text())
    for rules in (staged_rules("2026-10-31T21:30:00Z"), watched_rules("2026-10-31T22:30:00Z")):
        new, _ = promote.evaluate(rules, P, fake({("ALL", "AllowedRequests"): 1000}), NOW)
        assert remediation.validate_waf(new, schema) == []


# ---------------------------------------------------------------- pipeline
def _setup(tmp_path, rules=None):
    shutil.copytree(FIX / "repos", tmp_path / "repos")
    if rules is not None:
        (tmp_path / "repos/orders-infra/security/waf-rules.json").write_text(json.dumps(rules))
    (tmp_path / "sentinel.yml").write_text(yaml.safe_dump(CFG))
    return tmp_path


def _run(root, cve="CVE-2026-109618"):
    out = root / "out"
    main(["--config", str(root / "sentinel.yml"), "--root", str(root), "--cve", cve, "--dry-run",
          "--offline", str(FIX), "--mock-llm", str(FIX / "mock_llm"), "--out", str(out)])
    return json.loads((out / "report.json").read_text())[0]["mitigations"][0]


def test_pipeline_auto_tier_stages_in_count(tmp_path):
    m = _run(_setup(tmp_path))
    assert m["decision"]["tier"] == "auto" and "tier auto" in m["action"]
    new = json.loads(m["proposed_file"])
    g = next(x for x in new["managed_rule_groups"] if x["name"] == "AWSManagedRulesPHPRuleSet")
    assert g["mode"] == "count" and g["staged"] and g["reason"].startswith("CVE-2026-109618")


def test_pipeline_already_mitigated_is_idempotent(tmp_path):
    rules = copy.deepcopy(BASE)
    rules["managed_rule_groups"].append({"name": "AWSManagedRulesPHPRuleSet", "priority": 30, "mode": "block",
                                         "version": None, "rule_overrides_to_count": [],
                                         "reason": "CVE-2026-109618: PHP2Shell signatures"})
    m = _run(_setup(tmp_path, rules))
    assert m["action"].startswith("already mitigated") and m["chosen"] is None
