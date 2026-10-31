"""Parse the machine-readable ```techstack block out of techstack.md."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

_BLOCK = re.compile(r"```techstack\s*\n(.*?)```", re.S)


@dataclass
class Repo:
    name: str
    full_name: str
    path: Path
    kind: str                       # "code" | "infra"
    stack: dict = field(default_factory=dict)
    serves: list[str] = field(default_factory=list)

    @property
    def components(self) -> list[dict]:
        return self.stack.get("components", [])

    def remediation_policy(self) -> dict:
        p = self.path / ".remediation.yml"
        return yaml.safe_load(p.read_text()) if p.exists() else {"auto_fix": False, "reason": "no .remediation.yml"}


def parse_techstack(md: str) -> dict:
    m = _BLOCK.search(md)
    if not m:
        raise ValueError("techstack.md has no ```techstack block")
    data = yaml.safe_load(m.group(1)) or {}
    for c in data.get("components", []):
        if "version" in c and c["version"] is not None:
            c["version"] = str(c["version"])
    return data


def load_repos(cfg: dict, root: Path) -> list[Repo]:
    repos = []
    for r in cfg["repos"]:
        path = (root / r["path"]).resolve()
        stack = parse_techstack((path / "techstack.md").read_text())
        repos.append(Repo(
            name=r["name"], full_name=r["full_name"], path=path, kind=r["kind"],
            stack=stack, serves=r.get("serves", stack.get("serves", [])),
        ))
    return repos
