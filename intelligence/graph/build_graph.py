"""Build NetworkX attack surface graph from relationships."""
from typing import Dict, List, Any, Union

try:
    import networkx as nx
    _NX_AVAILABLE = True
except ImportError:
    _NX_AVAILABLE = False


def build_graph(relationships: List[Dict], return_format: str = "networkx") -> Union["nx.DiGraph", Dict[str, Any]]:  # type: ignore[name-defined]
    """Build directed attack surface graph.
    
    Args:
        relationships: List of edge dictionaries with source, target, etc.
        return_format: "networkx" (default) or "dict" for serializable format
        
    Returns:
        NetworkX DiGraph or dict with nodes/edges structure
    """
    if not _NX_AVAILABLE:
        raise ImportError("networkx is required: pip install networkx")

    G = nx.DiGraph()
    for edge in relationships:
        src, tgt = edge["source"], edge["target"]
        if not G.has_node(src):
            G.add_node(src, type=edge.get("source_type", "unknown"))
        if not G.has_node(tgt):
            G.add_node(tgt, type=edge.get("target_type", "unknown"))
        G.add_edge(src, tgt, relationship=edge.get("relationship"), weight=edge.get("weight", 1.0))

    if return_format == "dict":
        return nx.node_link_data(G)
    
    return G
