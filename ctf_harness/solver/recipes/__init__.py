"""Built-in recipe library (L1) + entry point for user recipes.

Custom user recipes come in two flavours:

* **Declarative JSON packs** (``recipes.d/*.json``) - no Python required,
  see :mod:`ctf_harness.solver.declarative`.
* **Python plugin recipes** (``plugins/*.py``) - full power, see
  :mod:`ctf_harness.plugins`.
"""

from __future__ import annotations

from .base import Recipe, RecipeContext, run_recipes
from .crypto import crypto_recipes
from .forensics import forensics_recipes
from .misc import misc_recipes
from .pwn_rev import pwn_rev_recipes
from .web import web_recipes


def all_recipes(extra: list[Recipe] | None = None) -> list[Recipe]:
    """Built-in recipes; ``extra`` typically holds user/plugin recipes."""
    recipes: list[Recipe] = []
    for factory in (web_recipes, crypto_recipes, misc_recipes,
                    forensics_recipes, pwn_rev_recipes):
        recipes.extend(factory())
    recipes.extend(extra or [])
    return recipes


__all__ = ["Recipe", "RecipeContext", "run_recipes", "all_recipes"]
