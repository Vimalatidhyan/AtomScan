"""Attack path analysis on the asset graph."""
from typing import Dict, List, Any, Union

try:
    import networkx as nx
    _NX_AVAILABLE = True
except ImportError:
    _NX_AVAILABLE = False


def analyze_critical_paths(
    graph: Union["nx.DiGraph", Dict[str, Any]],  # type: ignore[name-defined]
    entry_points: List[str] = None,
    critical_targets: List[str] = None,
    max_paths: int = 10,
) -> List[Dict[str, Any]]:
    """Find critical paths from entry points to critical assets.

    Args:
        graph: Either a NetworkX DiGraph or a dict with nodes/edges
        entry_points: List of externally exposed nodes (if None, auto-detect
                      nodes with ``exposed=True``)
        critical_targets: List of critical asset nodes (if None, auto-detect
                          nodes with ``is_critical=True``)
        max_paths: Maximum number of paths to return (sorted by risk_score desc)

    Returns:
        List of dicts: ``{'path': [...], 'risk_score': float, 'length': int}``
    """
    if not _NX_AVAILABLE:
        return []

    # Convert dict to NetworkX if needed
    if isinstance(graph, dict):
        graph = nx.node_link_graph(graph, directed=True)

    if graph.number_of_nodes() == 0:
        return []

    # Auto-detect entry points: nodes marked exposed=True
    if entry_points is None:
        entry_points = [
            n for n, d in graph.nodes(data=True) if d.get("exposed", False)
        ]

    # Auto-detect critical targets: nodes marked is_critical=True
    if critical_targets is None:
        critical_targets = [
            n for n, d in graph.nodes(data=True) if d.get("is_critical", False)
        ]

    if not entry_points or not critical_targets:
        return []

    paths_found: List[Dict[str, Any]] = []

    for entry in entry_points:
        for target in critical_targets:
            if entry == target:
                continue
            try:
                for path in nx.all_simple_paths(graph, entry, target, cutoff=6):
                    # Accumulate risk by multiplying normalised CVSS scores
                    risk_score = 1.0
                    for node in path:
                        cvss = graph.nodes[node].get("cvss_score", 5.0)
                        risk_score *= cvss / 10.0  # normalise to [0, 1]

                    paths_found.append(
                        {
                            "path": list(path),
                            "risk_score": round(risk_score, 6),
                            "length": len(path),
                        }
                    )
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue

    # Sort by risk_score descending and return top N
    paths_found.sort(key=lambda x: x["risk_score"], reverse=True)
    return paths_found[:max_paths]
