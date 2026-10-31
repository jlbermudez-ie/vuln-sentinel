"""CVE feeds: NVD API 2.0 + CISA KEV. Offline fixtures for tests / dry labs."""
from __future__ import annotations

import json
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def _nvd_get(params: dict) -> list[dict]:
    headers = {}
    if os.getenv("NVD_API_KEY"):
        headers["apiKey"] = os.environ["NVD_API_KEY"]   # NVD 2.0 wants the key in a header
    out, start, retries = [], 0, 0
    while True:
        r = requests.get(NVD_URL, params={**params, "startIndex": start, "resultsPerPage": 200},
                         headers=headers, timeout=60)
        if r.status_code in (403, 429, 503) and retries < 4:   # NVD rate limiting: back off
            retries += 1
            time.sleep(8 * retries)
            continue
        r.raise_for_status()
        body = r.json()
        out += [v["cve"] for v in body.get("vulnerabilities", [])]
        start += body.get("resultsPerPage", 0)
        if start >= body.get("totalResults", 0) or body.get("resultsPerPage", 0) == 0:
            return out
        time.sleep(0.7 if headers else 6.5)


def fetch_cve(cve_id: str, fixtures: Path | None = None) -> dict | None:
    if fixtures:
        f = fixtures / f"{cve_id}.json"
        return json.loads(f.read_text()) if f.exists() else None
    res = _nvd_get({"cveId": cve_id})
    return res[0] if res else None


def fetch_recent(products: list[str], lookback_hours: int) -> list[dict]:
    """CVEs modified in the window whose text mentions one of our products."""
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=lookback_hours)
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    seen: dict[str, dict] = {}
    for p in sorted(set(products)):
        for cve in _nvd_get({"keywordSearch": p, "lastModStartDate": start.strftime(fmt),
                             "lastModEndDate": end.strftime(fmt)}):
            seen[cve["id"]] = cve
    return list(seen.values())


def fetch_kev_ids(lookback_days: int) -> set[str]:
    cutoff = (datetime.now(timezone.utc) - timedelta(days=lookback_days)).date().isoformat()
    data = requests.get(KEV_URL, timeout=60).json()
    return {v["cveID"] for v in data.get("vulnerabilities", []) if v.get("dateAdded", "") >= cutoff}


def cvss(cve: dict) -> tuple[float, str]:
    m = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
        if m.get(key):
            d = m[key][0]["cvssData"]
            return float(d["baseScore"]), d.get("baseSeverity", "")
    return 0.0, "UNKNOWN"


def description(cve: dict) -> str:
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d["value"]
    return ""
