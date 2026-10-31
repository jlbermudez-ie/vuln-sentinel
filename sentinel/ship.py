"""Open a PR and, for the auto tier, merge it once the target repo's own checks pass.
If checks fail or time out, the PR stays open for a human (downgrade to `approve`)."""
from __future__ import annotations

AUTO_MARKER = "[sentinel-auto]"


def open_pr(gh, repo: str, branch: str, path: str, content: str, title: str, body: str,
            labels: list[str]) -> dict:
    return gh.create_pr(repo, branch, {path: content}, title, body, labels)


def auto_merge(gh, repo: str, pr: dict, dm: dict) -> dict:
    """Returns {"merged": bool, "status": str, "checks": {...}}."""
    try:
        status, checks = gh.wait_for_checks(repo, pr["head"]["sha"], dm["required_checks"],
                                            timeout_s=int(dm.get("checks_timeout_minutes", 15)) * 60)
    except RuntimeError as e:
        # Typically 403: the GitHub App lacks the "Checks: Read" permission.
        status, checks = "unreadable (does the GitHub App have Checks: Read?)", {"error": str(e)[:200]}
    if status != "success":
        gh.comment(repo, pr["number"],
                   f"vuln-sentinel: auto-merge **cancelled** — required checks {status}: `{checks}`.\n"
                   "Downgraded to the *approve* tier: a human needs to review this PR.")
        return {"merged": False, "status": status, "checks": checks}
    title = pr["title"] if AUTO_MARKER in pr["title"] else f"{pr['title']} {AUTO_MARKER}"
    gh.merge_pr(repo, pr["number"], f"{title} (#{pr['number']})")
    return {"merged": True, "status": "merged", "checks": checks}
