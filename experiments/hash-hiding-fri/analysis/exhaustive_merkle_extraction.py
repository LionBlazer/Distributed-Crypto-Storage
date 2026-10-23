"""Exhaustive bounded extraction traces; deterministic algorithm evidence only.

Run: python -B experiments/hash-hiding-fri/analysis/exhaustive_merkle_extraction.py
The model uses supplied32-byte outputs from a TWO-value alphabet, not SHA256.
All6 oracle inputs per family are present in every function table.
"""

from dataclasses import dataclass
from itertools import product
import json
import time

from merkle_extraction import (
    DictionaryOracle, Matrix, Schema, LEAF_DOMAIN, NODE_DOMAIN,
    digest, verify_opening,
)

ALPHABET = (digest(0), digest(1))


@dataclass(frozen=True)
class Query:
    raw: bytes


@dataclass(frozen=True)
class Notify:
    schema: Schema
    root: bytes


@dataclass(frozen=True)
class LeafCase:
    raw: bytes
    rows: tuple
    salts: tuple


def raw_leaf(words):
    # Reference framing independent of model.encode_leaf/encode_rows.
    return (LEAF_DOMAIN + b"".join(x.to_bytes(8, "little") for x in words)
            + len(words).to_bytes(8, "little"))


def family_cases(alias):
    if not alias:
        layout = (Matrix(1),)
        cases = tuple(LeafCase(raw_leaf((v, 10, 20, 30, 40)),
                               ((v,),), ((10, 20, 30, 40),)) for v in (0, 1))
        return {layout: cases}
    split = (Matrix(1), Matrix(1))
    joined = (Matrix(6),)
    split_cases = []
    joined_cases = []
    for v in (0, 1):
        raw = raw_leaf((v, 10, 20, 30, 40, v + 2, 50, 60, 70, 80))
        split_cases.append(LeafCase(raw, ((v,), (v + 2,)),
                                    ((10, 20, 30, 40), (50, 60, 70, 80))))
        joined_cases.append(LeafCase(raw, ((v, 10, 20, 30, 40, v + 2),),
                                     ((50, 60, 70, 80),)))
    return {split: tuple(split_cases), joined: tuple(joined_cases)}


def query_domain(cases):
    leaves = tuple(case.raw for case in next(iter(cases.values())))
    children = {NODE_DOMAIN + a + b: (a, b)
                for a in ALPHABET for b in ALPHABET}
    return leaves + tuple(children), children


def reference_flags(actions, table, children):
    """Pairwise earlier-event definition; no model target-set/parser calls."""
    prior_inputs = {}
    prior_nodes = []
    prior_roots = []
    flags = []
    for action in actions:
        if isinstance(action, Notify):
            prior_roots.append(action.root)
            continue
        raw = action.raw
        targets = set(prior_roots)
        targets.update(child for node in prior_nodes for child in node)
        prior = len(prior_inputs)
        if raw in prior_inputs:
            flags.append((False, False, False, prior, len(targets), len(prior_roots)))
            continue
        output = table[raw]
        collision = any(output == old for old in prior_inputs.values())
        hit = (any(output == root for root in prior_roots)
               or any(output == left or output == right for left, right in prior_nodes))
        flags.append((True, collision, hit, prior, len(targets), len(prior_roots)))
        prior_inputs[raw] = output
        if raw in children:
            prior_nodes.append(children[raw])
    return tuple(flags)


def model_flags(oracle):
    return tuple((e.fresh, e.collision, e.target_hit, e.prior_distinct,
                  e.prior_targets, e.prior_notifications) for e in oracle.events)


def has_bad(flags):
    return any(collision or hit for _, collision, hit, *_ in flags)


def replay(table, actions):
    oracle = DictionaryOracle(table)
    last_snapshot = None
    for action in actions:
        if isinstance(action, Query):
            oracle.query(action.raw)
        else:
            last_snapshot = oracle.notify(action.schema, action.root)
    return oracle, last_snapshot


def assert_flags(actual, expected, context):
    if actual != expected:
        raise AssertionError(("event accounting mismatch", context, actual, expected))
    for fresh, _, _, prior, targets, cap_count in actual:
        if fresh and targets > 2 * prior + cap_count:
            raise AssertionError(("prior-target count exceeds bound", context))


def reference_openings(table, depth, cases):
    # Independent bottom-up computation. Record exact queries, including repeats.
    result = []
    for case in cases:
        for index in range(1 << depth):
            for siblings in product(ALPHABET, repeat=depth):
                raw_queries = [case.raw]
                current = table[case.raw]
                for level, sibling in enumerate(siblings):
                    left, right = ((sibling, current) if (index >> level) & 1
                                   else (current, sibling))
                    raw = NODE_DOMAIN + left + right
                    raw_queries.append(raw)
                    current = table[raw]
                result.append((current, case, index, siblings,
                               tuple(Query(raw) for raw in raw_queries)))
    return tuple(result)


def check_snapshot_invariant(stats):
    # All functions on six input points, every action prefix of length0,1,2,
    # then a typed notification and every possible later row/index/sibling proof.
    for alias in (False, True):
        family = "alias_layouts" if alias else "base"
        layouts = family_cases(alias)
        raw_inputs, children = query_domain(layouts)
        assert len(raw_inputs) == 6
        configs = tuple((Schema(depth, layout), cases)
                        for layout, cases in layouts.items() for depth in (0, 1, 2))
        for table_index, answers in enumerate(product(ALPHABET, repeat=6)):
            table = dict(zip(raw_inputs, answers))
            stats["function_tables"] += 1
            for schema, cases in configs:
                if alias:
                    other = Schema(schema.depth,
                                   next(layout for layout in layouts if layout != schema.matrices))
                else:
                    other = Schema((schema.depth + 1) % 3, schema.matrices)
                actions = (tuple(Query(raw) for raw in raw_inputs)
                           + tuple(Notify(typed, root) for typed in (schema, other)
                                   for root in ALPHABET))
                openings = reference_openings(table, schema.depth, cases)
                label = f"{family}:depth{schema.depth}:widths{tuple(m.width for m in schema.matrices)}"
                summary = stats["by_configuration"].setdefault(
                    label, {"notifications": 0, "valid_later_openings": 0,
                            "outside_bad_openings": 0})
                for length in range(3):
                    for prefix in product(actions, repeat=length):
                        for root in ALPHABET:
                            history = prefix + (Notify(schema, root),)
                            context = (family, table_index, schema, prefix, root)
                            oracle, snapshot = replay(table, history)
                            expected = reference_flags(history, table, children)
                            assert_flags(model_flags(oracle), expected, context)
                            stats["prefix_notification_traces"] += 1
                            summary["notifications"] += 1
                            for accepted_root, case, index, siblings, later in openings:
                                if accepted_root != root:
                                    continue
                                stats["valid_later_openings"] += 1
                                summary["valid_later_openings"] += 1
                                full_flags = reference_flags(history + later, table, children)
                                if has_bad(full_flags):
                                    stats["bad_traces_excluded"] += 1
                                    continue
                                # Replay EACH surviving suffix from the original cutoff.
                                # Never let another trial mutate the tested oracle.
                                receiving, frozen = replay(table, history)
                                accepted = verify_opening(receiving, schema, root, index,
                                                          case.rows, case.salts, siblings)
                                assert_flags(model_flags(receiving), full_flags, context)
                                if not accepted or frozen.row(index) != case.rows:
                                    raise AssertionError(
                                        ("outside-Bad snapshot invariant counterexample",
                                         context, index, siblings, case.rows, frozen.row(index)))
                                if frozen is not receiving.notify(schema, root):
                                    raise AssertionError(("first snapshot replaced", context))
                                stats["outside_bad_openings_replayed"] += 1
                                summary["outside_bad_openings"] += 1
    # Explicit nonvacuity for EVERY height and BOTH matrix-cut interpretations.
    assert len(stats["by_configuration"]) == 9
    for label, counts in stats["by_configuration"].items():
        if not counts["outside_bad_openings"]:
            raise AssertionError(("vacuous configuration", label))


def check_three_query_event_accounting(stats):
    # All output tables, all216 raw query sequences of length3 including
    # repeats, and no cap OR either cap at each of the four atomic boundaries.
    # This also tests the third distinct query, which must collide over2 outputs.
    for alias in (False, True):
        layouts = family_cases(alias)
        inputs, children = query_domain(layouts)
        schema = Schema(0, next(iter(layouts)))
        query_sequences = tuple(product(inputs, repeat=3))
        for table_index, answers in enumerate(product(ALPHABET, repeat=6)):
            table = dict(zip(inputs, answers))
            for sequence in query_sequences:
                queries = tuple(Query(raw) for raw in sequence)
                notifications = (None,) + tuple((position, root)
                                               for position in range(4)
                                               for root in ALPHABET)
                for notification in notifications:
                    if notification is None:
                        actions = queries
                    else:
                        position, root = notification
                        actions = queries[:position] + (Notify(schema, root),) + queries[position:]
                    oracle, _ = replay(table, actions)
                    expected = reference_flags(actions, table, children)
                    assert_flags(model_flags(oracle), expected,
                                 ("event_trace", alias, table_index, actions))
                    stats["three_query_event_traces"] += 1


def main():
    started = time.perf_counter()
    stats = {
        "function_tables": 0,
        "prefix_notification_traces": 0,
        "valid_later_openings": 0,
        "bad_traces_excluded": 0,
        "outside_bad_openings_replayed": 0,
        "three_query_event_traces": 0,
        "by_configuration": {},
    }
    check_snapshot_invariant(stats)
    check_three_query_event_accounting(stats)
    report = {
        "status": "PASS; no counterexample in the stated finite universe",
        "seconds": round(time.perf_counter() - started, 6),
        "universe": {
            "digest_alphabet_size": 2,
            "raw_input_points_per_family": 6,
            "functions_per_family": 64,
            "families": 2,
            "heights": [1, 2, 4],
            "snapshot_configurations": 9,
            "prefix_action_alphabet": "6 query inputs +4 current/other typed notifications",
            "prefix_action_lengths": [0, 1, 2],
            "later_openings": "all2 leaves, all indices and all alphabet-valued sibling paths",
            "event_check": "all length3 query sequences; optional cap at each atomic boundary",
        },
        "counts": stats,
        "limitations": [
            "Assigned two-value outputs are not SHA256 or256-bit ROM samples.",
            "Exhaustive only over the stated raw inputs, action lengths and digest alphabet.",
            "No exhaustive raw byte grammar, arbitrary larger trees or unbounded histories.",
            "Alias layouts tested with base fields; EF5 framing has the separate behavior suite.",
            "No native SDK runtime, RBR/FS/hiding proof or production admission.",
            "The probability coefficient is not inferred empirically from these traces.",
        ],
    }
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
