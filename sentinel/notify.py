"""Slack notifications through an Incoming Webhook (secret SLACK_WEBHOOK_URL).
No webhook configured, or a dry run: the message is printed instead. A failed
notification never fails the run."""
from __future__ import annotations

import os
import sys

import requests

ICON = {"auto": ":robot_face:", "approve": ":eyes:", "report": ":rotating_light:",
        "promoted": ":shield:", "rolled-back": ":leftwards_arrow_with_hook:", "held": ":double_vertical_bar:",
        "error": ":x:", "info": ":information_source:"}


def slack(kind: str, title: str, lines: list[str], url: str | None = None, dry_run: bool = False) -> bool:
    text = f"{ICON.get(kind, '')} *{title}*\n" + "\n".join(f"• {l}" for l in lines if l)
    if url:
        text += f"\n<{url}|Open in GitHub>"
    hook = os.getenv("SLACK_WEBHOOK_URL")
    if dry_run or not hook:
        print(f"[slack{' dry-run' if dry_run else ' (no webhook)'}] {text}", file=sys.stderr)
        return False
    try:
        r = requests.post(hook, json={"text": text, "unfurl_links": False}, timeout=15)
        return r.status_code < 300
    except requests.RequestException as e:
        print(f"! slack notification failed: {e}", file=sys.stderr)
        return False
