#!/usr/bin/env bash
# Fire a CVE-triggered scan (what a feed/webhook integration would do).
#   ./scripts/trigger-cve.sh YOUR_ORG CVE-2026-109618
set -euo pipefail
ORG="${1:?org}"; CVE="${2:?cve id}"
gh api "repos/${ORG}/vuln-sentinel/dispatches" \
  -f event_type=cve-alert \
  -f "client_payload[cve_id]=${CVE}"
echo "dispatched cve-alert for ${CVE}"
