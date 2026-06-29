"""
provenance.py — Root-cause attribution for the K-Guard Causal Provenance Graph.

Implements Section 3.4.3 of the methodology: given an alert raised on some
process node, walk backward through the causal graph to find the root cause
— the earliest ancestor process with zero incoming edges, i.e. the first
process in the chain that K-Guard did not see anything else spawn or cause.

Used today by ml_detector.py against the saved system_behavior_graph.gexf
(offline, batch). graphengine.py can import find_root_cause() directly for
live alerting once an online anomaly check is wired into the streaming
event loop — the function only needs a networkx.DiGraph and a node, so it
works identically in both contexts.

Note on node identity: graphengine.py keys process nodes as the tuple
(pid, start_time_ns) while building the live graph. After a round trip
through nx.write_gexf() / nx.read_gexf(), GEXF stores node ids as strings,
so by the time ml_detector.py loads the graph every node id — including
these tuples — has already become a plain string such as
"(84920, 1718000000000)". That's fine: this module never unpacks the node
id, it only uses it as an opaque key, so it works the same whether the
graph came straight from graphengine.py in-memory or from a reloaded GEXF
file.
"""

import time
import networkx as nx


def find_root_cause(G: nx.DiGraph, alert_node):
    """
    Walks backward from `alert_node` to find the root-cause process.

    Args:
        G: the causal provenance graph (process/file/socket nodes,
           FORKED/EXECUTES/OPENS/CONNECTED_TO edges).
        alert_node: the node id the anomaly detector flagged.

    Returns:
        (root_node, causal_chain, mttrc_ms)

        root_node    -> the identified root-cause node, or None if
                         alert_node isn't in the graph at all.
        causal_chain -> ordered list [root, ..., alert_node] representing
                         the attack path, in the order it actually happened.
        mttrc_ms      -> wall-clock time this computation took, in
                         milliseconds. This is the Mean Time To Root Cause
                         metric from Section 3.12.2 — report the mean and
                         std dev of this value across your validation runs.

    Note on this graph's schema: every edge K-Guard records originates
    FROM a process node (FORKED -> process, EXECUTES/OPENS/CONNECTED_TO ->
    file/socket). File, binary, and socket nodes never have outgoing
    edges. That means the ancestor set of any process node can only ever
    contain other process nodes — a file or socket can never end up
    incorrectly selected as the "root cause" of a process. If you later
    add edge types where a resource node can cause a process action
    (e.g. a written file later being executed), revisit this assumption.
    """
    t0 = time.perf_counter()

    if alert_node not in G:
        return None, [], 0.0

    # Every node with a directed path leading TO alert_node.
    ancestors = nx.ancestors(G, alert_node)

    if not ancestors:
        # No traceable ancestors — alert_node is its own root (e.g. the
        # very first process K-Guard observed in this session, or an
        # orphaned/adopted process whose original parent was never seen).
        mttrc_ms = (time.perf_counter() - t0) * 1000
        return alert_node, [alert_node], mttrc_ms

    # The root cause is an ancestor with no incoming edges of its own —
    # the earliest point in the chain that K-Guard saw nothing spawn.
    roots = [n for n in ancestors if G.in_degree(n) == 0]

    if not roots:
        # Every ancestor has a parent (e.g. a cycle, or the true root
        # aged out of the graph's TTL pruning window already). Fall back
        # to the ancestor that is furthest from the alert — still useful
        # forensically even if it isn't a "true" zero-in-degree root.
        roots = list(ancestors)

    best_root, best_chain = None, None
    for root in roots:
        try:
            path = nx.shortest_path(G, root, alert_node)
        except nx.NetworkXNoPath:
            continue
        # Prefer the longest causal chain — it's the most informative
        # and most likely to be the actual initial compromise vector
        # rather than a shorter, coincidental path through a shared
        # resource node.
        if best_chain is None or len(path) > len(best_chain):
            best_root, best_chain = root, path

    mttrc_ms = (time.perf_counter() - t0) * 1000

    if best_chain is None:
        # Disconnected in a way shortest_path couldn't bridge — shouldn't
        # happen given ancestors() found them, but stay safe.
        return alert_node, [alert_node], mttrc_ms

    return best_root, best_chain, mttrc_ms


def format_chain(chain) -> str:
    """Pretty-print a causal chain for terminal / log output."""
    return " \u2192 ".join(str(node) for node in chain)
