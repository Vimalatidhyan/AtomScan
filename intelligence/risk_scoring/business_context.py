"""Business context scorer for asset criticality."""
from typing import Dict

DEFAULT_WEIGHTS = {
    "data_types": {"pii": 50, "phi": 50, "financial": 40, "trade_secrets": 35, "confidential": 20},
    "functions": {"revenue_generation": 40, "customer_facing": 35, "internal_operations": 20, "legacy": 10},
    "exposure": {"internet_facing": 25, "public_cloud": 20, "private_network": 10},
    "compliance": {"pci_dss": 20, "hipaa": 20, "gdpr": 15, "sox": 10},
}

class BusinessContextScorer:
    """Score asset criticality based on business context."""

    def __init__(self, asset_metadata: Dict, weights: Dict = DEFAULT_WEIGHTS) -> None:
        self.metadata = asset_metadata
        self.weights = weights

    def calculate_criticality(self) -> int:
        """Score in range 0-100 representing asset criticality."""
        score = 0
        for data_type in self.metadata.get("data_types", []):
            score += self.weights["data_types"].get(data_type, 0)
        for func in self.metadata.get("functions", []):
            score += self.weights["functions"].get(func, 0)
        for exposure in self.metadata.get("exposure", []):
            score += self.weights["exposure"].get(exposure, 0)
        for compliance in self.metadata.get("compliance", []):
            score += self.weights["compliance"].get(compliance, 0)
        return min(100, score)

    def get_criticality_level(self) -> str:
        """Map score to text level."""
        score = self.calculate_criticality()
        if score >= 80: return "CRITICAL"  # noqa: E701
        if score >= 60: return "HIGH"  # noqa: E701
        if score >= 40: return "MEDIUM"  # noqa: E701
        if score >= 20: return "LOW"  # noqa: E701
        return "MINIMAL"
