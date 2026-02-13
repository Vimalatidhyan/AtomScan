"""Risk propagation — spread vulnerability risk scores across the asset graph."""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Union

import logging

logger = logging.getLogger(__name__)

try:
    import networkx as nx
    _NX_AVAILABLE = True
except ImportError:
    _NX_AVAILABLE = False

# ── constants ────────────────────────────────────────────────────────────────

SEVERITY_WEIGHTS: Dict[str, float] = {
    "critical": 1.0,
    "high": 0.8,
    "medium": 0.5,
    "low": 0.2,
    "info": 0.05,
}

PROPAGATION_DECAY = 0.5  # each hop reduces propagated risk by 50 %


# ── public API ───────────────────────────────────────────────────────────────

def propagate_risk(
    graph: Union[Dict[str, Any], "nx.DiGraph"],  # type: ignore[name-defined]
    max_depth: int = 3,
) -> Dict[str, Any]:
    """Propagate vulnerability risk scores through the graph.

    For each vulnerability node the base risk is spread to connected
    asset nodes, decaying by *PROPAGATION_DECAY* per hop up to *max_depth*.

    Args:
        graph: Either a dict with nodes/edges structure or a NetworkX DiGraph
        max_depth: Maximum propagation depth (hops)

    Returns:
        Dict with nodes (with added risk_score field) and edges
    """
    # Convert NetworkX graph to dict if necessary
    if _NX_AVAILABLE and isinstance(graph, nx.DiGraph):
        graph = nx.node_link_data(graph)
    
    nodes: List[Dict[str, Any]] = graph.get("nodes", [])
    edges: List[Dict[str, Any]] = graph.get("edges", graph.get("links", graph.get("relationships", [])))

    # Index nodes by id for O(1) lookup
    node_by_id: Dict[Any, Dict[str, Any]] = {n["id"]: n for n in nodes}

    # Build adjacency list (undirected)
    adjacency: Dict[Any, List[Any]] = {n["id"]: [] for n in nodes}
    for edge in edges:
        src = edge.get("source")
        tgt = edge.get("target")
        if src in adjacency:
            adjacency[src].append(tgt)
        if tgt in adjacency:
            adjacency[tgt].append(src)

    # Initialise risk scores
    for node in nodes:
        node["risk_score"] = SEVERITY_WEIGHTS.get(
            str(node.get("severity", "")).lower(), 0.0
        ) * 10  # scale 0–10

    # BFS propagation from each vulnerability node
    for node in nodes:
        if node.get("type") != "vulnerability":
            continue
        base_risk = node["risk_score"]
        if base_risk == 0:
            continue

        visited = {node["id"]}
        frontier = [(node["id"], base_risk)]

        for _depth in range(max_depth):
            next_frontier = []
            for current_id, current_risk in frontier:
                propagated = current_risk * PROPAGATION_DECAY
                if propagated < 0.01:
                    continue
                for neighbour_id in adjacency.get(current_id, []):
                    if neighbour_id in visited:
                        continue
                    visited.add(neighbour_id)
                    nb = node_by_id.get(neighbour_id)
                    if nb is not None:
                        nb["risk_score"] = min(10.0, nb.get("risk_score", 0) + propagated)
                    next_frontier.append((neighbour_id, propagated))
            frontier = next_frontier
            if not frontier:
                break

    # Classify each node by its final risk score
    for node in nodes:
        score = node.get("risk_score", 0)
        if score >= 8:
            node["risk_level"] = "critical"
        elif score >= 6:
            node["risk_level"] = "high"
        elif score >= 3:
            node["risk_level"] = "medium"
        else:
            node["risk_level"] = "low"

    graph["nodes"] = nodes
    logger.info("Risk propagation complete: %d nodes scored", len(nodes))
    return graph


def summarise_risk(graph: Dict[str, Any]) -> Dict[str, Any]:
    """Return a summary of risk distribution across the graph."""
    nodes: List[Dict[str, Any]] = graph.get("nodes", [])
    summary: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    total_score = 0.0

    for node in nodes:
        level = node.get("risk_level", "low")
        summary[level] = summary.get(level, 0) + 1
        total_score += node.get("risk_score", 0)

    return {
        "total_nodes": len(nodes),
        "by_risk_level": summary,
        "average_risk_score": round(total_score / len(nodes), 2) if nodes else 0,
        "max_risk_score": round(max((n.get("risk_score", 0) for n in nodes), default=0), 2),
    }
