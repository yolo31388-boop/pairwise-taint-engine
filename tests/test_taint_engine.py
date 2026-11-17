import pytest

from security.taint_engine import (
    build_graph,
    propagate,
    is_sanitized,
    shortest_taint_path,
    merge_branches
)


def test_graph_nodes():
    g = build_graph(['a'], ['b'], [('a', 'b')])
    assert len(g[0]) == 2

def test_graph_edge():
    g = build_graph(['a'], ['b'], [('a', 'b')])
    assert g[1]['a'] == ['b']

def test_graph_edge_count():
    g = build_graph(['a'], ['b'], [('a', 'b')])
    assert len(g[1]) == 1

def test_propagate_basic():
    g = ({'a', 'b'}, {'a': ['b']})
    assert propagate(g, {'a'}) == {'a', 'b'}

def test_propagate_sanitized():
    g = ({'a', 'b'}, {'a': ['b']})
    assert propagate(g, {'a'}, {'b'}) == {'a'}

def test_propagate_multi():
    g = ({'a', 'b', 'c'}, {'a': ['b'], 'b': ['c']})
    assert propagate(g, {'a', 'c'}) == {'a', 'b', 'c'}

def test_propagate_empty():
    assert propagate((set(), {}), {'a'}) == {'a'}

def test_sanitized_true():
    assert is_sanitized(['source', 'escape(x)'], {'escape(x)'}) is True

def test_sanitized_signature():
    assert is_sanitized(['source', 'escape(x)'], {'escape(y)'}) is False

def test_sanitized_empty():
    assert is_sanitized([], {'escape(x)'}) is False

def test_shortest_path():
    g = ({'a', 'b', 'c'}, {'a': ['b'], 'b': ['c']})
    assert shortest_taint_path(g, 'a', 'c') == ['a', 'b', 'c']

def test_shortest_none():
    g = ({'a', 'b'}, {'a': ['b']})
    assert shortest_taint_path(g, 'a', 'b') == ['a', 'b']

def test_merge_union():
    assert merge_branches({'a', 'b'}, {'b', 'c'}) == {'a', 'b', 'c'}

def test_merge_empty():
    assert merge_branches(set(), {'a'}) == {'a'}

def test_propagate_cycle():
    g = ({'a', 'b'}, {'a': ['b'], 'b': ['a']})
    assert propagate(g, {'a'}) == {'a', 'b'}
