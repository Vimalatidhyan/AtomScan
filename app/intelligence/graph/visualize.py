"""Graph visualization utilities."""
from typing import Any
import json
import logging

logger = logging.getLogger(__name__)


def visualize_graph(graph: Any, output_file: str, fmt: str = "json") -> str:
    """Export graph to file. Supports json (always available) and png/svg (requires matplotlib/graphviz)."""
    if fmt == "json":
        try:
            import networkx as nx
            data = nx.node_link_data(graph)
            with open(output_file, "w") as f:
                json.dump(data, f, indent=2)
            logger.info(f"Graph exported to {output_file}")
            return output_file
        except Exception as e:
            logger.error(f"Graph export failed: {e}")
            return ""
    elif fmt in ("png", "svg"):
        try:
            import networkx as nx
            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt
            plt.figure(figsize=(12, 8))
            pos = nx.spring_layout(graph, k=0.5)
            nx.draw(graph, pos, with_labels=True, node_size=300, font_size=8, arrows=True)
            plt.savefig(output_file, format=fmt, dpi=150, bbox_inches="tight")
            plt.close()
            return output_file
        except Exception as e:
            logger.warning(f"Visualization requires matplotlib: {e}")
            return ""
    return ""
