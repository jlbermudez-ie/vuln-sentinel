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

    def create_issue(self, repo: str, title: str, body: str, labels: list[str]) -> dict:
        return self._r("POST", f"/repos/{repo}/issues", json={"title": title, "body": body, "labels": labels})
