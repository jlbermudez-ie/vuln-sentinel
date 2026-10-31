"""Deterministic CPE/version matching. The LLM is only used when NVD has no
CPE configuration yet (common in the first days after disclosure)."""
from __future__ import annotations

from packaging.version import InvalidVersion, Version


def _v(s: str | None) -> Version | None:
    try:
        return Version(s) if s else None
    except InvalidVersion:
        return None


def _cpe_parts(criteria: str) -> tuple[str, str, str]:
    # cpe:2.3:a:vendor:product:version:...
    p = criteria.split(":")
    return (p[3], p[4], p[5]) if len(p) > 5 else ("", "", "")


def cpe_match(cve: dict, component: dict) -> dict | None:
    """Return the matching range dict if the component version is in a vulnerable range."""
    ver = _v(component.get("version"))
    vendor = (component.get("vendor") or "").lower()
    product = (component.get("product") or component.get("name") or "").lower()
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if not m.get("vulnerable"):
                    continue
                c_vendor, c_product, c_version = _cpe_parts(m.get("criteria", ""))
                if c_product != product or (vendor and c_vendor != vendor):
                    continue
                if ver is None:
                    return {"criteria": m["criteria"], "note": "component version unknown"}
                if c_version not in ("*", "-", ""):
                    if _v(c_version) == ver:
                        return {"criteria": m["criteria"]}
                    continue
                lo_i, lo_e = _v(m.get("versionStartIncluding")), _v(m.get("versionStartExcluding"))
                hi_i, hi_e = _v(m.get("versionEndIncluding")), _v(m.get("versionEndExcluding"))
                if lo_i and ver < lo_i: continue
                if lo_e and ver <= lo_e: continue
                if hi_i and ver > hi_i: continue
                if hi_e and ver >= hi_e: continue
                return {k: m.get(k) for k in ("criteria", "versionStartIncluding", "versionStartExcluding",
                                              "versionEndIncluding", "versionEndExcluding") if m.get(k)}
    return None


def has_cpe_data(cve: dict) -> bool:
    return any(n.get("cpeMatch") for c in cve.get("configurations", []) for n in c.get("nodes", []))


def mentions(cve_text: str, component: dict) -> bool:
    t = cve_text.lower()
    names = {component.get("name", ""), component.get("product", "")}
    return any(n and len(n) > 2 and n.lower() in t for n in names)
