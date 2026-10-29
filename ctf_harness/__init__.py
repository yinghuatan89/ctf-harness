"""ctf-harness: a speed-first, category-aware, multi-model AI harness for CTF.

Pipeline per challenge:
    L0  zero-thought deterministic heuristics  (sub-second, no LLM tokens)
    L1  known-pattern recipes                 (seconds, scripted attacks)
    L2  parallel hypothesis race lanes        (LLM + tools, first flag wins)
    L3  deep reflection & replan              (strong model, only if stuck)

The harness is authorized-use only: run it against CTF platforms and
deliberately vulnerable training environments, never against systems you
do not own or are not explicitly allowed to test.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
