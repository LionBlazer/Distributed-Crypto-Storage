"""Behavior examples for the finite extraction model, never crypto acceptance."""

import unittest
from hashlib import sha256

from merkle_extraction import (
    GOLD_ORDER, LEAF_DOMAIN, NODE_DOMAIN, MAX_DEPTH, MAX_LEAF_FIELDS,
    DictionaryOracle, Matrix, Schema, decode_leaf, digest, encode_leaf,
    encode_node, encode_rows, verify_opening,
)

ONE = Schema(0, (Matrix(1),))
SALT = ((10, 20, 30, 40),)


def leaf(value: int) -> bytes:
    return encode_rows(ONE, ((value,),), SALT)


class StableExtractionTests(unittest.TestCase):
    def test_complete_two_row_tree_opens_to_exact_unsalted_base_and_ef5_rows(self):
        schema = Schema(1, (Matrix(2), Matrix(1, 5)))
        rows = (((11, 12), ((1, 2, 3, 4, 5),)),
                ((21, 22), ((6, 7, 8, 9, 10),)))
        salts = (((31, 32, 33, 34), (41, 42, 43, 44)),
                 ((51, 52, 53, 54), (61, 62, 63, 64)))
        raw_left = encode_rows(schema, rows[0], salts[0])
        raw_right = encode_rows(schema, rows[1], salts[1])
        raw_root = encode_node(digest(1), digest(2))
        oracle = DictionaryOracle({raw_left: digest(1), raw_right: digest(2),
                                   raw_root: digest(3)})
        for raw in (raw_left, raw_right, raw_root):
            oracle.query(raw)

        snapshot = oracle.notify(schema, digest(3))

        self.assertEqual((snapshot.row(0), snapshot.row(1)), rows)
        self.assertTrue(verify_opening(oracle, schema, digest(3), 0,
                                      rows[0], salts[0], (digest(2),)))
        self.assertTrue(verify_opening(oracle, schema, digest(3), 1,
                                      rows[1], salts[1], (digest(1),)))
        self.assertEqual(oracle.distinct_queries, 3)
        self.assertEqual(oracle.bad_events, ())

    def test_unknown_notified_root_later_matching_leaf_is_target_hit_without_collision(self):
        raw = leaf(7)
        oracle = DictionaryOracle({raw: digest(70)})
        snapshot = oracle.notify(ONE, digest(70))

        accepted = verify_opening(oracle, ONE, digest(70), 0, ((7,),), SALT, ())

        self.assertTrue(accepted)
        self.assertEqual(snapshot.row(0), ((0,),))
        self.assertFalse(oracle.events[-1].collision)
        self.assertTrue(oracle.events[-1].target_hit)
        self.assertEqual(oracle.events[-1].prior_distinct, 0)

    def test_unknown_child_can_change_default_in_a_collision_free_trace(self):
        schema = Schema(1, (Matrix(1),))
        root_input = encode_node(digest(80), digest(81))
        oracle = DictionaryOracle({root_input: digest(82), leaf(9): digest(80)})
        oracle.query(root_input)
        snapshot = oracle.notify(schema, digest(82))

        accepted = verify_opening(oracle, schema, digest(82), 0,
                                  ((9,),), SALT, (digest(81),))

        self.assertTrue(accepted)
        self.assertEqual(snapshot.row(0), ((0,),))
        self.assertTrue(any(e.target_hit for e in oracle.events))
        self.assertFalse(any(e.collision for e in oracle.events))
        self.assertEqual(oracle.distinct_queries, 2)

    def test_late_zero_leaf_still_charges_the_unknown_child_target(self):
        schema = Schema(1, (Matrix(1),))
        parent = encode_node(digest(90), digest(91))
        oracle = DictionaryOracle({parent: digest(92), leaf(0): digest(90)})
        oracle.query(parent)
        snapshot = oracle.notify(schema, digest(92))

        self.assertTrue(verify_opening(oracle, schema, digest(92), 0,
                                      ((0,),), SALT, (digest(91),)))

        self.assertEqual(snapshot.row(0), ((0,),))
        self.assertEqual(len(oracle.bad_events), 1)
        self.assertTrue(oracle.bad_events[0].target_hit)
        self.assertFalse(oracle.bad_events[0].collision)

    def test_late_dictionary_growth_never_changes_the_first_snapshot(self):
        oracle = DictionaryOracle({leaf(17): digest(170)})
        first = oracle.notify(ONE, digest(170))
        oracle.query(leaf(17))

        second = oracle.notify(ONE, digest(170))

        self.assertIs(second, first)
        self.assertEqual(first.cutoff, 0)
        self.assertEqual(second.row(0), ((0,),))
        self.assertEqual(oracle.notifications, 2)
        self.assertTrue(oracle.bad_events[0].target_hit)

    def test_a_previously_complete_leaf_is_not_an_inversion_on_notification(self):
        oracle = DictionaryOracle({leaf(18): digest(180)})
        oracle.query(leaf(18))

        snapshot = oracle.notify(ONE, digest(180))

        self.assertEqual(snapshot.row(0), ((18,),))
        self.assertTrue(verify_opening(oracle, ONE, digest(180), 0,
                                      ((18,),), SALT, ()))
        self.assertEqual(oracle.bad_events, ())

    def test_defaults_do_not_fabricate_a_cap_consistent_tree(self):
        root = digest(190)
        oracle = DictionaryOracle({leaf(0): digest(191)})
        snapshot = oracle.notify(ONE, root)

        self.assertFalse(verify_opening(oracle, ONE, root, 0,
                                       snapshot.row(0), SALT, ()))

        self.assertEqual(snapshot.row(0), ((0,),))
        self.assertEqual(oracle.bad_events, ())

    def test_same_digest_has_distinct_ordered_matrix_layout_interpretations(self):
        # One identical leaf stream is valid under two distinct schema cuts.
        two = Schema(0, (Matrix(1), Matrix(1)))
        one = Schema(0, (Matrix(6),))
        raw = encode_leaf((11, 1, 2, 3, 4, 22, 5, 6, 7, 8))
        oracle = DictionaryOracle({raw: digest(200)})
        oracle.query(raw)

        split = oracle.notify(two, digest(200))
        joined = oracle.notify(one, digest(200))

        self.assertEqual(split.row(0), ((11,), (22,)))
        self.assertEqual(joined.row(0), ((11, 1, 2, 3, 4, 22),))
        self.assertIsNot(split, joined)
        self.assertTrue(verify_opening(oracle, two, digest(200), 0,
                                      ((11,), (22,)),
                                      ((1, 2, 3, 4), (5, 6, 7, 8)), ()))
        self.assertTrue(verify_opening(oracle, one, digest(200), 0,
                                      ((11, 1, 2, 3, 4, 22),), ((5, 6, 7, 8),), ()))
        self.assertEqual(oracle.bad_events, ())

    def test_same_digest_under_another_depth_does_not_reuse_leaf_snapshot(self):
        oracle = DictionaryOracle({leaf(23): digest(230)})
        oracle.query(leaf(23))
        flat = oracle.notify(ONE, digest(230))

        tree = oracle.notify(Schema(1, (Matrix(1),)), digest(230))

        self.assertEqual(flat.row(0), ((23,),))
        self.assertEqual((tree.row(0), tree.row(1)), (((0,),), ((0,),)))
        self.assertIsNot(flat, tree)
        self.assertEqual(oracle.bad_events, ())

    def test_self_child_is_not_a_prior_target_but_terminates_at_typed_depth(self):
        root = digest(240)
        sibling = digest(241)
        raw_node = encode_node(root, sibling)
        oracle = DictionaryOracle({raw_node: root, leaf(24): root})

        oracle.query(raw_node)

        self.assertEqual(oracle.bad_events, ())
        snapshot = oracle.notify(Schema(2, (Matrix(1),)), root)
        before = len(oracle.events)
        self.assertEqual(tuple(snapshot.row(i) for i in range(4)),
                         (((0,),),) * 4)
        self.assertEqual(len(oracle.events), before)
        self.assertTrue(verify_opening(oracle, Schema(1, (Matrix(1),)), root, 0,
                                      ((24,),), SALT, (sibling,)))
        self.assertTrue(any(e.collision for e in oracle.events))

    def test_a_back_cycle_is_finite_and_known_nodes_are_not_leaf_preimages(self):
        a, b, sibling = digest(250), digest(251), digest(252)
        first = encode_node(b, sibling)
        second = encode_node(a, sibling)
        oracle = DictionaryOracle({first: a, second: b})
        oracle.query(first)
        oracle.query(second)

        snapshot = oracle.notify(Schema(3, (Matrix(1),)), a)

        self.assertEqual(snapshot.row(0), ((0,),))
        self.assertTrue(oracle.events[1].target_hit)
        self.assertFalse(oracle.events[1].collision)

    def test_old_known_wrong_type_can_only_be_reopened_via_output_collision(self):
        auxiliary = b"untyped auxiliary input"
        oracle = DictionaryOracle({auxiliary: digest(260), leaf(26): digest(260)})
        oracle.query(auxiliary)
        snapshot = oracle.notify(ONE, digest(260))

        self.assertTrue(verify_opening(oracle, ONE, digest(260), 0,
                                      ((26,),), SALT, ()))

        self.assertEqual(snapshot.row(0), ((0,),))
        self.assertTrue(oracle.events[-1].collision)

    def test_duplicate_raw_query_is_cached_without_a_fresh_bad_event(self):
        raw = leaf(27)
        oracle = DictionaryOracle({raw: digest(270)})
        oracle.query(raw)
        oracle.notify(ONE, digest(270))

        answer = oracle.query(raw)

        self.assertEqual(answer, digest(270))
        self.assertEqual(oracle.distinct_queries, 1)
        self.assertFalse(oracle.events[-1].fresh)
        self.assertFalse(oracle.events[-1].target_hit)
        self.assertFalse(oracle.events[-1].collision)
        self.assertEqual(oracle.bad_events, ())

    def test_supplied_answers_are_copied_and_cannot_reenter_an_atomic_query(self):
        supplied = {leaf(28): digest(280)}
        oracle = DictionaryOracle(supplied)
        supplied[leaf(28)] = digest(281)
        supplied[leaf(29)] = digest(282)

        self.assertEqual(oracle.query(leaf(28)), digest(280))
        with self.assertRaises(KeyError):
            oracle.query(leaf(29))

        self.assertEqual(oracle.distinct_queries, 1)
        self.assertEqual(len(oracle.events), 1)

    def test_children_become_targets_for_the_next_query_before_control_returns(self):
        parent = encode_node(digest(290), digest(291))
        oracle = DictionaryOracle({parent: digest(292), leaf(29): digest(290)})
        oracle.query(parent)

        oracle.query(leaf(29))

        self.assertEqual(oracle.events[0].prior_targets, 0)
        self.assertEqual(oracle.events[1].prior_targets, 2)
        self.assertTrue(oracle.events[1].target_hit)

    def test_raw_fs_notification_before_expected_reveal_freezes_the_public_word(self):
        # The future Expected is represented only by its public PP row here.
        oracle = DictionaryOracle({leaf(31): digest(310)})
        before_expected = oracle.notify(ONE, digest(310))
        oracle.query(leaf(31))

        after_expected = oracle.notify(ONE, digest(310))

        self.assertIs(after_expected, before_expected)
        self.assertEqual(after_expected.row(0), ((0,),))
        self.assertTrue(verify_opening(oracle, ONE, digest(310), 0,
                                      ((31,),), SALT, ()))
        self.assertTrue(oracle.bad_events[0].target_hit)


class FramingAndGeometryTests(unittest.TestCase):
    def test_model_bytes_match_independent_native_leaf_and_node_vectors(self):
        # The same nonsecret .NET vectors are checked by real LeafHash and
        # NodeCompress in crates/bfv-hiding-stark/src/hash/merkle/tests.rs.
        self.assertEqual(sha256(encode_leaf(())).hexdigest(),
                         'b72b9b8cdb55ce78aa5678e5a6ae64c20d162c3039c80f97f338cde6b1adbf68')
        self.assertEqual(sha256(encode_leaf((0, 1, GOLD_ORDER - 1))).hexdigest(),
                         '09cea62022f5140159078cfaf494f55a158c889c7692a30aa3818b52a8026c5b')
        payload = bytes(range(64))
        self.assertEqual(sha256(encode_node(payload[:32], payload[32:])).hexdigest(),
                         'acf6f7d33e64fbf446d353f0fad1812c8608f2d2d0e2667906e582699354efd7')

    def test_leaf_encoding_uses_literal_domains_le8_and_final_le64_count(self):
        raw = encode_leaf((1, GOLD_ORDER - 1))

        self.assertEqual(raw, LEAF_DOMAIN + b"\x01" + b"\0" * 7
                         + (GOLD_ORDER - 1).to_bytes(8, "little")
                         + b"\x02" + b"\0" * 7)
        self.assertEqual(encode_node(digest(1), digest(2)),
                         NODE_DOMAIN + digest(1) + digest(2))

    def test_leaf_decoder_rejects_noncanonical_gold_wrong_count_and_trailing_bytes(self):
        valid = leaf(32)
        count = ONE.field_count
        bad_field = (LEAF_DOMAIN + GOLD_ORDER.to_bytes(8, "little")
                     + valid[len(LEAF_DOMAIN) + 8:])

        self.assertIsNone(decode_leaf(bad_field, count))
        self.assertIsNone(decode_leaf(valid[:-8] + (count + 1).to_bytes(8, "little"), count))
        self.assertIsNone(decode_leaf(valid + b"\0", count))
        self.assertIsNone(decode_leaf(valid[:-1], count))
        self.assertEqual(decode_leaf(valid, count), (32, 10, 20, 30, 40))

    def test_malformed_known_leaf_and_wrong_width_produce_fixed_defaults(self):
        valid = leaf(33)
        malformed = (LEAF_DOMAIN + GOLD_ORDER.to_bytes(8, "little")
                     + valid[len(LEAF_DOMAIN) + 8:])
        wrong_width = encode_leaf((33, 10, 20, 30))
        for raw in (malformed, wrong_width):
            with self.subTest(raw=raw):
                oracle = DictionaryOracle({raw: digest(330)})
                oracle.query(raw)

                snapshot = oracle.notify(ONE, digest(330))

                self.assertEqual(snapshot.row(0), ((0,),))
                self.assertEqual(oracle.bad_events, ())

    def test_swapped_child_order_does_not_authenticate_the_original_root(self):
        schema = Schema(1, (Matrix(1),))
        left, right, root, wrong_root = digest(340), digest(341), digest(342), digest(343)
        oracle = DictionaryOracle({leaf(34): left, leaf(35): right,
                                   encode_node(left, right): root,
                                   encode_node(right, left): wrong_root})
        for raw in (leaf(34), leaf(35), encode_node(left, right)):
            oracle.query(raw)
        snapshot = oracle.notify(schema, root)

        accepted = verify_opening(oracle, schema, root, 1, ((34,),), SALT, (right,))

        self.assertFalse(accepted)
        self.assertEqual(snapshot.row(0), ((34,),))
        self.assertEqual(snapshot.row(1), ((35,),))
        self.assertEqual(oracle.bad_events, ())

    def test_wrong_opening_extents_are_rejected_before_any_oracle_query(self):
        oracle = DictionaryOracle({})
        invalid = (
            (((1, 2),), SALT, ()),               # row width
            (((1,),), ((1, 2, 3),), ()),         # salt width
            (((GOLD_ORDER,),), SALT, ()),        # field canonicality
            (((1,),), SALT, (digest(0),)),       # sibling depth
        )
        for rows, salts, siblings in invalid:
            with self.subTest(rows=rows, salts=salts, siblings=siblings):
                self.assertFalse(verify_opening(oracle, ONE, digest(0), 0,
                                               rows, salts, siblings))
        self.assertEqual(oracle.events, ())

    def test_closed_schema_rejects_hostile_dimensions_and_bad_ef5_width(self):
        for create in (lambda: Schema(MAX_DEPTH + 1, (Matrix(1),)),
                       lambda: Schema(-1, (Matrix(1),)),
                       lambda: Schema(0, ()),
                       lambda: Matrix(MAX_LEAF_FIELDS),
                       lambda: Matrix(0),
                       lambda: Matrix(1, 2),
                       lambda: Matrix(1, 1.0),
                       lambda: Matrix(1, True),
                       lambda: Schema(True, (Matrix(1),))):
            with self.subTest(create=create):
                with self.assertRaises(ValueError):
                    create()
        ef = Schema(0, (Matrix(1, 5),))
        with self.assertRaises(ValueError):
            encode_rows(ef, (((1, 2, 3, 4),),), SALT)
        with self.assertRaises(ValueError):
            encode_leaf((GOLD_ORDER,))

    def test_snapshot_rejects_out_of_height_index_without_hashing(self):
        oracle = DictionaryOracle({})
        snapshot = oracle.notify(ONE, digest(0))
        for index in (-1, 1, 1 << 64):
            with self.subTest(index=index):
                with self.assertRaises(ValueError):
                    snapshot.row(index)
        self.assertEqual(oracle.events, ())


if __name__ == "__main__":
    unittest.main(verbosity=2)
