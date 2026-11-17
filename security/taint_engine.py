"""Pairwise taint engine primitives.

The engine models a program as a directed graph:

* ``nodes``     -- every program point that may carry a value (sources,
                   sinks and the endpoints of every edge);
* ``adjacency`` -- ``{node: [successor, ...]}`` describing data flow.

The five helpers below are deliberately small, framework-agnostic building
blocks.  Front-ends (Java/Spring/Kotlin extractors) are expected to lower
their findings to this representation:

* framework entry points (``@RequestParam``, Kotlin extension functions,
  Servlet parameters, ...) become source nodes;
* field writes/reads and container inserts/reads become edges, so taint
  flows through ``obj.field`` and ``list[i]`` instead of disappearing;
* lambdas/anonymous classes that capture a variable get an edge from the
  captured variable to the closure body;
* branch alternatives are joined with :func:`merge_branches` (set union),
  never intersected.

Keeping the data structure this generic also keeps propagation linear in
the size of the graph and the reported path minimal.
"""

from __future__ import annotations

from collections import deque
from typing import Hashable, Mapping

Node = Hashable
Graph = tuple[set, dict]


def _adjacency(graph) -> Mapping:
    """Accept either ``(nodes, adjacency)`` or a bare adjacency mapping."""
    if isinstance(graph, tuple):
        if len(graph) != 2:
            raise ValueError("graph tuple must be (nodes, adjacency)")
        return graph[1]
    if isinstance(graph, Mapping):
        return graph
    raise TypeError("graph must be (nodes, adjacency) or an adjacency mapping")


def _normalize_signature(value: str) -> str:
    """Canonical form of a call label/signature.

    Signatures deliberately include the call arguments: ``escape(x)`` and
    ``escape(y)`` are different calls, and only an exact signature match may
    be treated as a sanitizer.  Whitespace is insignificant so that
    ``escape( x )`` and ``escape(x)`` compare equal.
    """
    return "".join(str(value).split())


def build_graph(sources, sinks, edges) -> Graph:
    """Build the taint graph from entry points, sinks and data-flow edges.

    Parameters
    ----------
    sources:
        Framework/servlet/Kotlin entry points (tainted on entry).
    sinks:
        Dangerous operations to report against.
    edges:
        Iterable of ``(from_node, to_node)`` pairs.  Field assignments,
        container inserts/reads and closure-capture edges are all encoded
        here by the front-end.

    Returns
    -------
    ``(nodes, adjacency)`` where ``nodes`` is the union of sources, sinks
    and edge endpoints, and ``adjacency`` maps each node *with outgoing
    edges* to the ordered, de-duplicated list of its successors.  Leaf
    nodes therefore have no adjacency entry (callers use ``.get``).
    """
    nodes = set()
    adjacency: dict[Node, list[Node]] = {}

    for group in (sources, sinks):
        nodes.update(group or ())

    for edge in edges or ():
        try:
            src, dst = edge
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"edge must be a (from_node, to_node) pair, got {edge!r}"
            ) from exc
        nodes.add(src)
        nodes.add(dst)
        successors = adjacency.setdefault(src, [])
        # A repeated edge must not duplicate traversal work.
        if dst not in successors:
            successors.append(dst)

    return nodes, adjacency


def propagate(graph, initial, sanitized=None) -> set:
    """Forward taint propagation over ``graph``.

    ``initial`` is the set of already-tainted nodes.  A node listed in
    ``sanitized`` is a sanitizer boundary: it is never tainted and taint does
    not flow through it.  Traversal is a plain BFS with a visited set, so
    cycles terminate and each reachable node is visited once.
    """
    adjacency = _adjacency(graph)
    sanitized = set(sanitized or ())

    tainted: set = set()
    queue: deque = deque()

    for node in initial or ():
        if node in sanitized or node in tainted:
            continue
        tainted.add(node)
        queue.append(node)

    while queue:
        node = queue.popleft()
        for successor in adjacency.get(node, ()):
            if successor in sanitized or successor in tainted:
                continue
            tainted.add(successor)
            queue.append(successor)

    return tainted


def is_sanitized(path, sanitizers) -> bool:
    """Return whether ``path`` passes through a whitelisted sanitizer.

    ``path`` is the sequence of nodes/labels along a taint path (for example
    ``["source", "escape(x)"]``); ``sanitizers`` is the whitelist of
    fully-qualified call signatures such as ``"escape(x)"``.

    Matching is by *signature*, not by bare method name: a custom
    same-named helper (``escape(y)``) is not on the whitelist and therefore
    does not silence the finding.
    """
    if not path:
        return False

    known = {_normalize_signature(item) for item in sanitizers or ()}
    return any(_normalize_signature(item) in known for item in path)


def shortest_taint_path(graph, source, target):
    """Return the shortest node path from ``source`` to ``target``.

    Uses BFS, so the reported chain is minimal in hop count rather than an
    arbitrary (potentially hundreds of hops long) DFS walk.  Returns
    ``None`` when ``target`` is unreachable.  A source equal to the target
    yields ``[source]``.
    """
    if source == target:
        return [source]

    adjacency = _adjacency(graph)

    previous: dict[Node, Node] = {}
    visited = {source}
    queue: deque = deque([source])

    while queue:
        node = queue.popleft()
        for successor in adjacency.get(node, ()):
            if successor in visited:
                continue
            visited.add(successor)
            previous[successor] = node
            if successor == target:
                path = [target]
                while path[-1] != source:
                    path.append(previous[path[-1]])
                path.reverse()
                return path
            queue.append(successor)

    return None


def merge_branches(left, right) -> set:
    """Join the taint state of two branches.

    A value is tainted after a conditional if it is tainted on *either*
    branch, so this is a set union.  Intersecting here would drop findings
    that only occur inside one arm of an ``if``/``else``.
    """
    return set(left or ()) | set(right or ())
