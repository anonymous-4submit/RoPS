"""RoPS Stage 3 -- behavior classifier.

Modules
-------
canon.py      callable-name canonicalization (compat remapping + alias folding)
typerole.py   per-argument type recovery (T1..T4) and role assignment (R1..R3)
analyzer.py   IoC matching, YARA labeling, verdict, and report finalization

Data
----
ioc_registry.yaml   indicator vocabulary with measured base rates
rules.yar           YARA behavior-labeling rules
"""

from .analyzer import (analyze_one_hit, iter_hits, protocol_of, finalize_report,
                       VERDICT_C, VERDICT_U, RANK_HIGH, RANK_LOW)

__all__ = ["analyze_one_hit", "iter_hits", "protocol_of", "finalize_report",
           "VERDICT_C", "VERDICT_U", "RANK_HIGH", "RANK_LOW"]
