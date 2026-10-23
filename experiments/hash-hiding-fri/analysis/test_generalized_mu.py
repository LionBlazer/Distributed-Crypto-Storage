"""Observable analysis behavior; all oracle outputs/fixtures are public toy data."""

from array import array
from dataclasses import FrozenInstanceError
import unittest

from generalized_mu import (
    Family, FrozenWord, DegreeRecognizer, _coset_coefficients, cap_type,
    domain_point, profile, public_shape,
)
from merkle_extraction import (
    GOLD_ORDER as P, DictionaryOracle, Matrix, Schema, Snapshot, digest,
    encode_leaf, encode_node,
)


def notify_tree(family, role="PP", *, first=7, different_first=None):
    """Actual dimensions with a shared constant subtree; optionally one bad row.

    The finite assigned-answer model permits DAG reuse. This avoids giant native
    fixtures without reducing the recognized domain or any column dimension.
    """
    typed = cap_type(family, role)
    fields = []
    for matrix in typed.matrices:
        fields.extend([first] + [0] * (matrix.base_width - 1))
        fields.extend((1, 2, 3, 4))
    leaf = encode_leaf(tuple(fields))
    table, queries = {leaf: digest(1)}, [leaf]
    root, roots = digest(1), [digest(1)]
    serial = 2
    for _ in range(typed.depth):
        raw = encode_node(root, root)
        root = digest(serial)
        serial += 1
        table[raw] = root
        queries.append(raw)
        roots.append(root)
    if different_first is not None:
        changed = list(fields)
        changed[0] = different_first
        raw = encode_leaf(tuple(changed))
        altered = digest(serial)
        serial += 1
        table[raw] = altered
        queries.append(raw)
        for level in range(typed.depth):
            raw = encode_node(altered, roots[level])
            altered = digest(serial)
            serial += 1
            table[raw] = altered
            queries.append(raw)
        root = altered
    oracle = DictionaryOracle(table)
    for raw in queries:
        oracle.query(raw)
    return typed, oracle, oracle.notify(typed.schema, root)


class ClosedGeometryTests(unittest.TestCase):
    def test_all_five_native_shapes_and_every_input_cap_cut_are_fixed(self):
        expected = {
            Family.SOURCE: (691, 1024, 13, 7170, 0, 0, 16),
            Family.ROLE3: (740, 1024, 13, 1665, 0, 0, 16),
            Family.DATA: (32, 4096, 15, 521, 672, 419, 8),
            Family.WORD: (309, 1024, 13, 577, 718, 184, 8),
            Family.QUERY: (32, 4096, 15, 425, 549, 429, 8),
        }
        counts = []
        for family, (pv, k, depth, main, pp, aux, chunks) in expected.items():
            with self.subTest(family=family):
                actual = profile(family)
                self.assertEqual((actual.public, actual.k, actual.depth), (pv, k, depth))
                self.assertEqual(cap_type(family, "MAIN").schema.field_count, main)
                quotient = cap_type(family, "quotient").schema
                self.assertEqual((len(quotient.matrices), quotient.field_count),
                                 (chunks, chunks * 14))
                self.assertEqual(cap_type(family, "random").schema.field_count, 14)
                if pp:
                    self.assertEqual(cap_type(family, "PP").schema.field_count, pp)
                    self.assertEqual(cap_type(family, "AUX").schema.field_count, aux)
                else:
                    with self.assertRaises(ValueError):
                        cap_type(family, "PP")
                rounds = k.bit_length() - 1
                self.assertEqual([cap_type(family, "FRI", r).depth for r in range(rounds)],
                                 list(range(depth - 1, 2, -1)))
                self.assertTrue(all(cap_type(family, "FRI", r).schema.field_count == 14
                                    for r in range(rounds)))
                counts.append(rounds + (5 if pp else 3))
        self.assertEqual(counts, [13, 13, 17, 15, 17])
        self.assertEqual(sum(counts), 75)
        self.assertEqual(sum(bool(profile(f).pp) for f in Family), 3)

    def test_full_public_shapes_reject_noncanonical_or_mutable_input(self):
        for family in Family:
            size = profile(family).public
            self.assertEqual(public_shape(family, (0,) * size), (0,) * size)
            for values in ([0] * size, (0,) * (size - 1), (P,) + (0,) * (size - 1),
                           (True,) + (0,) * (size - 1)):
                with self.subTest(family=family, values_type=type(values)):
                    with self.assertRaises(ValueError):
                        public_shape(family, values)
        for family in (Family.SOURCE, Family.ROLE3):
            with self.assertRaises(ValueError):
                public_shape(family, (1 << 32,) + (0,) * (profile(family).public - 1))
        with self.assertRaises(ValueError):
            public_shape("Query", (0,) * 32)

    def test_base_ef5_hidden_codewords_and_each_matrix_salt_are_separate(self):
        typed = cap_type(Family.QUERY, "AUX")
        fields = tuple(range(typed.schema.field_count))
        raw = encode_leaf(fields)
        table, query = {raw: digest(1)}, [raw]
        root = digest(1)
        for level in range(typed.depth):
            node = encode_node(root, root)
            root = digest(level + 2)
            table[node] = root
            query.append(node)
        oracle = DictionaryOracle(table)
        for value in query:
            oracle.query(value)
        word = FrozenWord.first(typed, oracle.notify(typed.schema, root))
        projection, = word.row(4)
        self.assertEqual(len(projection.values), 84)
        self.assertEqual(projection.values[0], (0, 1, 2, 3, 4))
        self.assertEqual(projection.values[-1], (415, 416, 417, 418, 419))
        self.assertEqual(projection.codewords, (420, 421, 422, 423, 424))
        self.assertEqual(projection.salts, (425, 426, 427, 428))
        wrong_cut = Schema(typed.depth, (Matrix(420), Matrix(1)))
        with self.assertRaises(ValueError):
            FrozenWord.first(typed, oracle.notify(wrong_cut, root))


class BeforeFirstCoinTests(unittest.TestCase):
    def test_bad_pp_schema_or_noncanonical_public_consumes_the_attempt(self):
        _, _, data = notify_tree(Family.DATA)
        _, _, query = notify_tree(Family.QUERY)
        for public, snapshot in (((0,) * 32, data), ((P,) + (0,) * 31, query)):
            with self.subTest(snapshot_width=snapshot.schema.field_count):
                recognizer = DegreeRecognizer()
                with self.assertRaises(ValueError):
                    recognizer.notify(Family.QUERY, public, snapshot)
                with self.assertRaises(ValueError):
                    recognizer.before_first_coin()
                with self.assertRaises(ValueError):
                    recognizer.notify(Family.QUERY, (0,) * 32, query)

    def test_actual_data_and_query_allow_nonboolean_and_minus_one_pp_fields(self):
        for family in (Family.DATA, Family.QUERY):
            with self.subTest(family=family):
                typed, oracle, snapshot = notify_tree(family, first=P - 1)
                recognizer = DegreeRecognizer()
                recognizer.notify(family, (P - 1,) * 32, snapshot)
                report = recognizer.before_first_coin()
                self.assertEqual(len(report.degrees), profile(family).pp)
                self.assertEqual(report.degrees[0], 0)
                self.assertTrue(all(d == -1 for d in report.degrees[1:]))
                self.assertEqual(report.pp.row(0)[0].values[0], P - 1)
                self.assertEqual(report.pp.row((1 << typed.depth) - 1)[0].values[0], P - 1)
                # This is an analysis description, with no mutable value getter.
                with self.assertRaises(FrozenInstanceError):
                    report.public = ()
                self.assertEqual(oracle.events[-1].prior_notifications, 0)

    def test_single_bad_row_is_rejected_at_real_query_extent_before_first_coin(self):
        _, _, snapshot = notify_tree(Family.QUERY, first=7, different_first=8)
        recognizer = DegreeRecognizer()
        recognizer.notify(Family.QUERY, (0,) * 32, snapshot)
        # A point delta has degree n-1, which exceeds k=4096 at n=32768.
        with self.assertRaisesRegex(ValueError, "degree reaches k"):
            recognizer.before_first_coin()
        with self.assertRaises(ValueError):
            recognizer.before_first_coin()
        with self.assertRaises(ValueError):
            recognizer.notify(Family.QUERY, (0,) * 32, snapshot)

    def test_first_cutoff_survives_later_dictionary_growth(self):
        typed, built, after = notify_tree(Family.QUERY, first=9)
        oracle = DictionaryOracle(built._supplied)
        first = oracle.notify(typed.schema, after.root)
        recognizer = DegreeRecognizer()
        recognizer.notify(Family.QUERY, (0,) * 32, first)
        for event in built.events:
            oracle.query(event.raw)
        same = oracle.notify(typed.schema, after.root)
        self.assertIs(first, same)
        report = recognizer.before_first_coin()
        self.assertEqual(report.pp.cutoff, 0)
        self.assertEqual(report.degrees, (-1,) * 545)
        self.assertEqual(report.pp.row(0)[0].values, (0,) * 545)
        retimed = Snapshot(typed.schema, after.root, oracle.distinct_queries, oracle)
        self.assertEqual(retimed.row(0)[0][0], 9)
        with self.assertRaisesRegex(ValueError, "first registered"):
            FrozenWord.first(typed, retimed)

    def test_second_notification_mutable_reader_and_second_coin_are_rejected(self):
        _, _, first = notify_tree(Family.DATA)
        recognizer = DegreeRecognizer()
        recognizer.notify(Family.DATA, (0,) * 32, first)
        with self.assertRaises(ValueError):
            recognizer.notify(Family.DATA, (0,) * 32, first)
        recognizer.before_first_coin()
        with self.assertRaises(ValueError):
            recognizer.before_first_coin()
        fresh = DegreeRecognizer()
        with self.assertRaises(ValueError):
            fresh.notify(Family.DATA, (0,) * 32, lambda _: (0,) * 668)
        with self.assertRaises(ValueError):
            fresh.notify(Family.DATA, (0,) * 32, first)

    def test_unimplemented_source_role3_and_fixed_word_are_fail_closed(self):
        _, _, snapshot = notify_tree(Family.DATA)
        for family in (Family.SOURCE, Family.ROLE3, Family.WORD):
            recognizer = DegreeRecognizer()
            with self.assertRaisesRegex(ValueError, "factory association not implemented"):
                recognizer.notify(family, (0,) * profile(family).public, snapshot)
            with self.assertRaises(ValueError):
                recognizer.before_first_coin()

    def test_interpolation_uses_literal_bitreversed_seven_coset(self):
        # Independent naive evaluation, including a degree beyond a nominal k=4.
        coefficients = (11, P - 1, 7, 0, 0, 3, 0, 0)
        omega = pow(7, (P - 1) // 8, P)
        natural = [7 * pow(omega, i, P) % P for i in range(8)]
        order = (0, 4, 2, 6, 1, 5, 3, 7)
        self.assertEqual([domain_point(3, i) for i in range(8)],
                         [natural[i] for i in order])
        values = array("Q", (sum(c * pow(natural[j], i, P)
                                  for i, c in enumerate(coefficients)) % P for j in order))
        self.assertEqual(tuple(_coset_coefficients(values)), coefficients)
        # Natural row order is not silently accepted as native physical order.
        unpermuted = array("Q", (sum(c * pow(x, i, P)
                                      for i, c in enumerate(coefficients)) % P for x in natural))
        self.assertNotEqual(tuple(_coset_coefficients(unpermuted)), coefficients)


if __name__ == "__main__":
    unittest.main(verbosity=2)
