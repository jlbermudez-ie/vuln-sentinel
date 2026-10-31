"""Minimal GitHub REST client for branches, file commits, PRs and issues.
Uses a GitHub App installation token (GH_TOKEN) so PRs trigger the target repo's workflows."""
from __future__ import annotations

import base64
import os

import requests

API = os.getenv("GITHUB_API_URL", "https://api.github.com")


class GitHub:
    def __init__(self, token: str | None = None):
        self.s = requests.Session()
        self.s.headers.update({
            "Authorization": f"Bearer {token or os.environ['GH_TOKEN']}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        })

    def _r(self, method: str, path: str, **kw):
        r = self.s.request(method, f"{API}{path}", timeout=60, **kw)
        if r.status_code >= 400:
            raise RuntimeError(f"GitHub {method} {path} -> {r.status_code}: {r.text[:400]}")
        return r.json() if r.text else {}

    def open_pr_for(self, repo: str, branch: str) -> dict | None:
        owner = repo.split("/")[0]
        prs = self._r("GET", f"/repos/{repo}/pulls", params={"head": f"{owner}:{branch}", "state": "open"})
        return prs[0] if prs else None

    def find_issue(self, repo: str, title: str) -> dict | None:
        for i in self._r("GET", f"/repos/{repo}/issues", params={"state": "open", "labels": "vuln-sentinel", "per_page": 100}):
            if i["title"] == title:
                return i
        return None

    def create_pr(self, repo: str, branch: str, files: dict[str, str], title: str, body: str,
                  labels: list[str] | None = None) -> dict:
        info = self._r("GET", f"/repos/{repo}")
        base = info["default_branch"]
        sha = self._r("GET", f"/repos/{repo}/git/ref/heads/{base}")["object"]["sha"]
        try:
            self._r("POST", f"/repos/{repo}/git/refs", json={"ref": f"refs/heads/{branch}", "sha": sha})
        except RuntimeError as e:
            if "Reference already exists" not in str(e):
                raise
            # Callers check there is no OPEN PR for this branch first, so a leftover branch
            # belongs to a merged/closed PR: reset it to the base branch, never build on it.
            self._r("PATCH", f"/repos/{repo}/git/refs/heads/{branch}", json={"sha": sha, "force": True})
        for path, content in files.items():
            cur = self.s.get(f"{API}/repos/{repo}/contents/{path}", params={"ref": branch}, timeout=60)
            payload = {"message": f"{title}\n\n[vuln-sentinel]", "branch": branch,
                       "content": base64.b64encode(content.encode()).decode()}
            if cur.status_code == 200:
                payload["sha"] = cur.json()["sha"]
            self._r("PUT", f"/repos/{repo}/contents/{path}", json=payload)
        pr = self._r("POST", f"/repos/{repo}/pulls", json={"title": title, "head": branch, "base": base, "body": body})
        if labels:
            self._r("POST", f"/repos/{repo}/issues/{pr['number']}/labels", json={"labels": labels})
        return pr

    def wait_for_checks(self, repo: str, sha: str, required: list[str], timeout_s: int = 900,
                        poll_s: int = 20) -> tuple[str, dict]:
        """Wait until every required check run on `sha` completes.
        Returns ("success" | "failure" | "timeout", {check name: conclusion})."""
        import time
        deadline = time.time() + timeout_s
        seen: dict = {}
        while time.time() < deadline:
            runs = self._r("GET", f"/repos/{repo}/commits/{sha}/check-runs", params={"per_page": 100})
            seen = {r["name"]: (r["status"], r.get("conclusion")) for r in runs.get("check_runs", [])}
            if all(n in seen and seen[n][0] == "completed" for n in required):
                ok = all(seen[n][1] == "success" for n in required)
                return ("success" if ok else "failure"), {n: seen[n][1] for n in required}
            time.sleep(poll_s)
        return "timeout", {n: (seen.get(n) or ("missing",))[0] for n in required}

    def merge_pr(self, repo: str, number: int, title: str) -> dict:
        # Squash so the commit on main carries the [sentinel-auto] marker the apply workflow checks.
        return self._r("PUT", f"/repos/{repo}/pulls/{number}/merge",
                       json={"merge_method": "squash", "commit_title": title})

    def comment(self, repo: str, number: int, body: str) -> dict:
        return self._r("POST", f"/repos/{repo}/issues/{number}/comments", json={"body": body})

    def create_issue(self, repo: str, title: str, body: str, labels: list[str]) -> dict:
        return self._r("POST", f"/repos/{repo}/issues", json={"title": title, "body": body, "labels": labels})
