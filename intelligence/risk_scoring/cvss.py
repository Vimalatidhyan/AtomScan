"""CVSS v3.1 vector parser and scorer."""
from typing import Dict, Optional

METRIC_VALUES = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {
        "U": {"N": 0.85, "L": 0.62, "H": 0.27},  # Scope Unchanged
        "C": {"N": 0.85, "L": 0.68, "H": 0.50},  # Scope Changed
    },
    "UI": {"N": 0.85, "R": 0.62},
    "S":  {"U": 0.0, "C": 1.0},
    "C":  {"N": 0.0, "L": 0.22, "H": 0.56},
    "I":  {"N": 0.0, "L": 0.22, "H": 0.56},
    "A":  {"N": 0.0, "L": 0.22, "H": 0.56},
}

class CVSSv31Calculator:
    """Parse and score CVSS v3.1 vectors."""

    def __init__(self, vector_string: str) -> None:
        self.vector_string = vector_string
        self._metrics: Dict[str, str] = {}
        self._parse()

    def _parse(self) -> None:
        parts = self.vector_string.lstrip("CVSS:3.1/").split("/")
        for part in parts:
            if ":" in part:
                k, v = part.split(":", 1)
                self._metrics[k] = v

    def parse_vector(self) -> Dict[str, str]:
        """Return dict of metric abbreviation -> value."""
        return dict(self._metrics)

    def get_base_score(self) -> float:
        """Calculate CVSS v3.1 base score (0.0-10.0)."""
        m = self._metrics
        try:
            AV = METRIC_VALUES["AV"].get(m.get("AV", "N"), 0.85)
            AC = METRIC_VALUES["AC"].get(m.get("AC", "L"), 0.77)
            
            # Fix: Use scope-dependent PR values
            scope = m.get("S", "U")
            scope_changed = (scope == "C")
            scope_key = "C" if scope_changed else "U"
            pr_value = m.get("PR", "N")
            PR = METRIC_VALUES["PR"][scope_key].get(pr_value, 0.85)
            
            UI = METRIC_VALUES["UI"].get(m.get("UI", "N"), 0.85)
            C = METRIC_VALUES["C"].get(m.get("C", "N"), 0.0)
            I = METRIC_VALUES["I"].get(m.get("I", "N"), 0.0)
            A = METRIC_VALUES["A"].get(m.get("A", "N"), 0.0)
            ISCBase = 1 - (1 - C) * (1 - I) * (1 - A)
            if scope_changed:
                ISC = 7.52 * (ISCBase - 0.029) - 3.25 * pow(ISCBase - 0.02, 15)
            else:
                ISC = 6.42 * ISCBase
            exploitability = 8.22 * AV * AC * PR * UI
            if ISC <= 0:
                return 0.0
            if scope_changed:
                base = min(1.08 * (ISC + exploitability), 10)
            else:
                base = min(ISC + exploitability, 10)
            return round(base, 1)
        except Exception:
            return 0.0

    def get_temporal_score(self, rp: float = 1.0, rl: float = 1.0) -> float:
        """Calculate temporal score."""
        return round(self.get_base_score() * rp * rl, 1)


def parse_cvss_vector(vector: str) -> Dict[str, str]:
    """Parse a CVSS vector string into a dict."""
    return CVSSv31Calculator(vector).parse_vector()
