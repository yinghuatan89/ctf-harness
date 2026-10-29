"""Recipe model + runner (L1 stage of the speed pipeline).

A recipe is a scripted, deterministic attack/probe for a known challenge
archetype. Recipes are cheap (seconds), never spend LLM tokens, and both
deliver flag findings *and* push recon notes onto the blackboard so the L2
lanes start from an informed position.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from ..flagextract import extract_candidates
from ..heuristics import Finding


@dataclass
class RecipeContext:
    """Everything a recipe may use. ``current`` is the running recipe id."""

    challenge: object
    guard: object
    registry: object
    tool_ctx: object
    flag_re: str
    current: str = ""

    def dispatch(self, tool: str, **args):
        return self.registry.dispatch({"tool": tool, "args": args}, self.tool_ctx)

    def note(self, text: str, tag: str = "recipe") -> None:
        self.tool_ctx.blackboard.add(f"[{self.current}] {text}", tag)

    def scan(self, *texts: str) -> list[Finding]:
        out: list[Finding] = []
        for text in texts:
            for cand in extract_candidates(text or "", self.flag_re):
                out.append(Finding(cand, f"L1:{self.current}", (text or "")[:160]))
        return out


@dataclass
class Recipe:
    id: str
    title: str
    categories: tuple[str, ...] = ()
    description: str = ""

    def match(self, challenge) -> bool:
        """Category gate is the default; override for file/target sniffing."""
        if self.categories and challenge.category and challenge.category not in self.categories:
            return False
        return True

    def run(self, rc: RecipeContext) -> list[Finding]:  # noqa: ARG002
        return []


def run_recipes(rc: RecipeContext, recipes: list[Recipe] | None = None,
                budget_s: float = 90.0) -> tuple[list[Finding], list[str]]:
    """Run applicable recipes inside a time budget.

    Returns ``(findings, executed_ids)``. Recipes are cooperative: they rely
    on tool timeouts plus a deadline check between recipes.
    """
    if recipes is None:
        from . import all_recipes  # lazy to avoid a circular import
        recipes = all_recipes()
    executed: list[str] = []
    findings: list[Finding] = []
    applicable = [r for r in recipes if _safe_match(r, rc.challenge)]
    deadline = time.monotonic() + budget_s
    for recipe in applicable:
        if time.monotonic() > deadline:
            break
        rc.current = recipe.id
        try:
            found = recipe.run(rc) or []
        except Exception as exc:  # noqa: BLE001 - recipes must never kill the solve
            rc.note(f"recipe crashed: {type(exc).__name__}: {exc}", tag="warn")
            continue
        executed.append(recipe.id)
        if found:
            findings.extend(found)
            break  # first hit wins - do not burn the remaining budget
    return findings, executed


def _safe_match(recipe: Recipe, challenge) -> bool:
    try:
        return bool(recipe.match(challenge))
    except Exception:  # noqa: BLE001
        return False
