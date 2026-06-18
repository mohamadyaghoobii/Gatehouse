from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable

from app.analysis.context import AnalysisContext
from app.schemas import Finding

RuleFn = Callable[[AnalysisContext], Iterable[Finding]]

ALL_PROVIDERS = ("github_actions", "gitlab_ci", "jenkins")


@dataclass(frozen=True)
class RuleMeta:
    id: str
    title: str
    category: str
    severity: str
    description: str
    providers: tuple[str, ...]
    func: RuleFn


REGISTRY: list[RuleMeta] = []


def rule(
    *,
    id: str,
    title: str,
    category: str,
    severity: str,
    description: str,
    providers: Iterable[str] = ALL_PROVIDERS,
) -> Callable[[RuleFn], RuleFn]:
    def decorator(func: RuleFn) -> RuleFn:
        REGISTRY.append(
            RuleMeta(
                id=id,
                title=title,
                category=category,
                severity=severity,
                description=description,
                providers=tuple(providers),
                func=func,
            )
        )
        return func

    return decorator


def rules_for(provider: str) -> list[RuleMeta]:
    return [meta for meta in REGISTRY if provider in meta.providers]


def catalog() -> list[dict]:
    seen: dict[str, dict] = {}
    for meta in REGISTRY:
        seen[meta.id] = {
            "id": meta.id,
            "title": meta.title,
            "category": meta.category,
            "severity": meta.severity,
            "providers": list(meta.providers),
            "description": meta.description,
        }
    return list(seen.values())
