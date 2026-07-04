"""
Turns K-Guard causal provenance graph (networkx.DiGraph, loaded from system_behavior_graph.gexf) into a numeric feature matrix, one row per process node
"""
# walks each node once so O(nodes × avg_edges_per_node)
import math
from typing import List, Tuple

import networkx as nx
import numpy as np

from . import config

FEATURE_NAMES = [
    "out_degree",
    "connections",
    "max_len",
    "max_entropy",
    "contains_sensitive",
    "total_bytes_sent_log",
    "send_recv_ratio",
    "num_distinct_destinations",
    "connected_uncommon_port",
    "sensitive_read_then_connect",
]


def calculate_entropy(s: str) -> float:
    """Shannon entropy over the characters of a string."""
    if not s:
        return 0.0
    entropy = 0.0
    for x in set(s):
        p_x = float(s.count(x)) / len(s)
        entropy -= p_x * math.log(p_x, 2)
    return entropy


def _contains_sensitive_keyword(name: str) -> bool:
    return any(kw in name for kw in config.SENSITIVE_KEYWORDS)


def _edge_timestamp(data: dict):
    ts = data.get("timestamp")
    try:
        return float(ts)
    except (TypeError, ValueError):
        return None


def _network_edge_stats(G: nx.DiGraph, node) -> dict:
    """Aggregate every CONNECTED_TO edge out of node into summary stats"""
    total_sent = 0.0
    total_recv = 0.0
    destinations = set()
    uncommon_port_hit = 0

    for _, target, data in G.out_edges(node, data=True):
        if data.get("relation") != "CONNECTED_TO":
            continue
        destinations.add(target)
        total_sent += float(data.get("bytes_sent") or 0)
        total_recv += float(data.get("bytes_recv") or 0)

        port = data.get("dest_port") or G.nodes.get(target, {}).get("port")
        try:
            port = int(port)
        except (TypeError, ValueError):
            port = None
        if port is not None and port not in config.WELL_KNOWN_PORTS:
            uncommon_port_hit = 1

    return {
        "total_sent": total_sent,
        "total_recv": total_recv,
        "num_destinations": len(destinations),
        "uncommon_port": uncommon_port_hit,
    }


def _sensitive_read_then_connect(G: nx.DiGraph, node) -> int:
    """
    returns 1 if node has an OPENS edge to a sensitive file followed by a CONNECTED_TO edge within the configured time window, else 0
    """
    open_ts_list = []
    connect_ts_list = []

    for _, target, data in G.out_edges(node, data=True):
        relation = data.get("relation")
        if relation == "OPENS" and _contains_sensitive_keyword(str(target)):
            open_ts_list.append(_edge_timestamp(data))
        elif relation == "CONNECTED_TO":
            connect_ts_list.append(_edge_timestamp(data))

    if not open_ts_list or not connect_ts_list:
        return 0

    for open_ts in open_ts_list:
        for connect_ts in connect_ts_list:
            if open_ts is None or connect_ts is None:
                return 1  # can't time-order them, but both happened
            if 0 <= (connect_ts - open_ts) <= config.READ_THEN_CONNECT_WINDOW_NS:
                return 1

    return 0


def extract_features(G: nx.DiGraph) -> Tuple[np.ndarray, List, List[str]]:
    """
    Build the feature matrix for every process node in G.
    Returns (X, node_list, FEATURE_NAMES) where X.shape == (len(node_list), len(FEATURE_NAMES)).
    """
    features = []
    node_list = []

    for node, data in G.nodes(data=True):
        if data.get("type") != "process":
            continue

        out_degree = G.out_degree(node)
        in_degree = G.in_degree(node)
        connections = out_degree + in_degree

        associated_files = [
            edge[1] for edge in G.out_edges(node)
            if G.edges[edge].get("relation") in ("OPENS", "EXECUTES")
        ]

        max_len = 0
        max_entropy = 0.0
        contains_sensitive = 0
        for f in associated_files:
            f = str(f)
            max_len = max(max_len, len(f))
            max_entropy = max(max_entropy, calculate_entropy(f))
            if _contains_sensitive_keyword(f):
                contains_sensitive = 1

        net_stats = _network_edge_stats(G, node)
        total_sent_log = (
            math.log1p(net_stats["total_sent"])
            if config.LOG_SCALE_BYTES
            else net_stats["total_sent"]
        )
        send_recv_ratio = (
            net_stats["total_sent"] / net_stats["total_recv"]
            if net_stats["total_recv"] > 0
            else (999.0 if net_stats["total_sent"] > 0 else 0.0)
        )

        sensitive_correlated = _sensitive_read_then_connect(G, node)

        features.append([
            out_degree,
            connections,
            max_len,
            max_entropy,
            contains_sensitive,
            total_sent_log,
            send_recv_ratio,
            net_stats["num_destinations"],
            net_stats["uncommon_port"],
            sensitive_correlated,
        ])
        node_list.append(node)

    X = np.array(features) if features else np.empty((0, len(FEATURE_NAMES)))
    return X, node_list, FEATURE_NAMES
