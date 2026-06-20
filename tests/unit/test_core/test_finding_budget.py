"""Tests for finding budget truncation ordering (Phase 18/P7-C7).

Truncation must keep the highest-value findings, not arbitrary first-N —
otherwise high-confidence/high-severity findings can be dropped purely
because of input ordering.
"""

from types import SimpleNamespace

from src.core.finding_budget import FindingBudget


def _f(rule_id="r1", file="a.py", confidence=0.5, severity="medium", final_score=None):
    return SimpleNamespace(
        rule_id=rule_id,
        file=file,
        confidence=confidence,
        severity=severity,
        final_score=final_score,
    )


class TestBudgetTruncationKeepsHighScore:
    def test_per_rule_keeps_highest_confidence(self):
        budget = FindingBudget(max_per_rule=2, max_per_file=100, max_total=100)
        result = budget.apply([_f(confidence=0.3), _f(confidence=0.9), _f(confidence=0.8)])
        kept = sorted(f.confidence for f in result.filtered_findings)
        assert kept == [0.8, 0.9]  # 0.3 dropped, two highest kept

    def test_per_rule_prefers_final_score_over_confidence(self):
        budget = FindingBudget(max_per_rule=1, max_per_file=100, max_total=100)
        result = budget.apply([
            _f(confidence=0.95, final_score=0.2),
            _f(confidence=0.1, final_score=0.9),
        ])
        assert len(result.filtered_findings) == 1
        # final_score outranks confidence when set.
        assert result.filtered_findings[0].final_score == 0.9

    def test_per_file_keeps_highest(self):
        budget = FindingBudget(max_per_rule=100, max_per_file=2, max_total=100)
        result = budget.apply([
            _f(file="same.py", confidence=0.2),
            _f(file="same.py", confidence=0.9),
            _f(file="same.py", confidence=0.8),
        ])
        kept = sorted(f.confidence for f in result.filtered_findings)
        assert kept == [0.8, 0.9]

    def test_total_limit_keeps_highest(self):
        budget = FindingBudget(max_per_rule=100, max_per_file=100, max_total=2)
        result = budget.apply([
            _f(rule_id="r1", file="a.py", confidence=0.3),
            _f(rule_id="r2", file="b.py", confidence=0.9),
            _f(rule_id="r3", file="c.py", confidence=0.8),
        ])
        kept = sorted(f.confidence for f in result.filtered_findings)
        assert kept == [0.8, 0.9]
