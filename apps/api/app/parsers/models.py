from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

Provider = str  # "github_actions" | "gitlab_ci" | "jenkins"


@dataclass
class Step:
    index: int
    name: str | None = None
    uses: str | None = None
    run: str | None = None
    shell: str | None = None
    env: dict[str, Any] = field(default_factory=dict)
    with_args: dict[str, Any] = field(default_factory=dict)
    raw: Any = None
    line: int | None = None

    @property
    def label(self) -> str:
        return self.name or self.uses or (self.run.splitlines()[0][:48] if self.run else f"step {self.index + 1}")

    @property
    def text(self) -> str:
        parts = [self.name or "", self.uses or "", self.run or ""]
        return "\n".join(part for part in parts if part)


@dataclass
class Job:
    name: str
    stage: str | None = None
    runner: str | None = None
    steps: list[Step] = field(default_factory=list)
    env: dict[str, Any] = field(default_factory=dict)
    permissions: Any = None
    environment: Any = None
    when: str | None = None
    needs: list[str] = field(default_factory=list)
    timeout: Any = None
    raw: Any = None
    line: int | None = None

    @property
    def uses_secrets(self) -> bool:
        from app.analysis.patterns import SECRET_NAME_RE

        return bool(SECRET_NAME_RE.search(_stringify(self.raw)))


@dataclass
class ParsedPipeline:
    provider: Provider
    name: str | None
    raw: Any
    jobs: list[Job]
    lines: list[str]
    text: str
    triggers: list[str] = field(default_factory=list)
    permissions: Any = None
    stages: list[str] = field(default_factory=list)
    variables: dict[str, Any] = field(default_factory=dict)
    notes: dict[str, Any] = field(default_factory=dict)

    @property
    def permission_summary(self) -> dict[str, str]:
        permissions = self.permissions
        if permissions == "write-all":
            return {"*": "write"}
        if permissions == "read-all":
            return {"*": "read"}
        if isinstance(permissions, dict):
            return {str(key): str(value) for key, value in permissions.items()}
        return {}


def _stringify(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return "\n".join(f"{key}: {_stringify(val)}" for key, val in value.items())
    if isinstance(value, list):
        return "\n".join(_stringify(item) for item in value)
    return str(value) if value is not None else ""
