import json
import shutil
from pathlib import Path

import yaml

from sentinel import cve_sources, matcher, remediation
from sentinel.__main__ import main
from sentinel.techstack import parse_techstack

HERE = Path(__file__).parent
FIX = HERE / "fixtures"
CFG = yaml.safe_load((HERE.parent / "sentinel.yml").read_text())


def _setup(tmp_path: Path) -> Path:
    shutil.copytree(FIX / "repos", tmp_path / "repos")
    cfg = dict(CFG)
    (tmp_path / "sentinel.yml").write_text(yaml.safe_dump(cfg))
    return tmp_path


def test_techstack_parse():
    stack = parse_techstack((FIX / "repos/orders-api/techstack.md").read_text())
    php = next(c for c in stack["components"] if c["name"] == "php")
    assert php["version"] == "8.3.30"


def test_cpe_range_match():
    cve = cve_sources.fetch_cve("CVE-2026-109618", FIX)
    assert matcher.cpe_match(cve, {"name": "php", "vendor": "php", "product": "php", "version": "8.3.30"})
    assert not matcher.cpe_match(cve, {"name": "php", "vendor": "php", "product": "php", "version": "8.3.36"})
    assert matcher.cpe_match(cve, {"name": "php", "vendor": "php", "product": "php", "version": "7.4.33"})
    assert not matcher.cpe_match(cve, {"name": "bref", "vendor": "bref", "product": "bref", "version": "2.3.0"})


def test_gate_rejects_unapproved_rule_group():
    infra = FIX / "repos/orders-infra"
    opt = json.loads((FIX / "mock_llm/mitigation.json").read_text())["options"][3]
    res = remediation.evaluate_option(opt, infra, CFG["policy"])
    assert not res["gate"]["passed"]
    assert any(r.startswith("schema") for r in res["gate"]["reasons"])


def test_gate_rejects_manual_and_high_impact():
    infra = FIX / "repos/orders-infra"
    opt = json.loads((FIX / "mock_llm/mitigation.json").read_text())["options"][2]
    assert not remediation.evaluate_option(opt, infra, CFG["policy"])["gate"]["passed"]


def test_end_to_end_dry_run(tmp_path):
    root = _setup(tmp_path)
    out = tmp_path / "out"
    rc = main(["--config", str(root / "sentinel.yml"), "--root", str(root),
               "--cve", "CVE-2026-109618,CVE-2026-109619", "--dry-run",
               "--offline", str(FIX), "--mock-llm", str(FIX / "mock_llm"), "--out", str(out)])
    assert rc == 0
    report = json.loads((out / "report.json").read_text())
    assert [f["cve"] for f in report] == ["CVE-2026-109618", "CVE-2026-109619"]
    assert report[0]["method"] == "nvd-cpe" and report[1]["method"] == "llm"
    for f in report:
        assert f["code_fix"]["status"] == "blocked"
        m = f["mitigations"][0]
        assert m["chosen"] == "waf-php-ruleset"
        new = json.loads(m["proposed_file"])
        names = [g["name"] for g in new["managed_rule_groups"]]
        assert "AWSManagedRulesPHPRuleSet" in names and "AWSManagedRulesCommonRuleSet" in names
        assert any(r["header"] == "x-lab-canary" for r in new["custom_rules"])
        schema = json.loads((root / "repos/orders-infra/security/waf-rules.schema.json").read_text())
        assert remediation.validate_waf(new, schema) == []
    assert "waf-php-ruleset" in (out / "report.md").read_text()


def test_gate_rejects_count_mode_and_rate_limit_only():
    """Real-model regression: 'rate limiting + PHP rule set (count mode)' must not pass."""
    infra = FIX / "repos/orders-infra"
    weak = {"id": "opt-1", "title": "rate limit + PHP count", "type": "temporary", "impact": "low",
            "effort": "low", "surface": "waf-rate-limit",
            "changes": {"add_managed_rule_groups": [{"name": "AWSManagedRulesPHPRuleSet", "mode": "count",
                                                     "reason": "observe first"}],
                        "set_rate_limit": {"limit": 1000, "action": "block"}}}
    res = remediation.evaluate_option(weak, infra, CFG["policy"])
    assert not res["gate"]["passed"]
    assert any("no blocking control" in r for r in res["gate"]["reasons"])


def test_fixed_version_comes_from_nvd(tmp_path):
    root = _setup(tmp_path)
    out = tmp_path / "out"
    main(["--config", str(root / "sentinel.yml"), "--root", str(root), "--cve", "CVE-2026-109618",
          "--dry-run", "--offline", str(FIX), "--mock-llm", str(FIX / "mock_llm"), "--out", str(out)])
    f = json.loads((out / "report.json").read_text())[0]
    assert f["fixed_in"] == "8.3.36"
    assert "8.3.36" in (out / "report.md").read_text()
    assert f["mitigations"][0]["action"].endswith("sentinel/cve-2026-109618-waf")
