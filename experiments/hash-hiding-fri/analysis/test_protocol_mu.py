"""Bounded encoder tests; recognition itself belongs to the owning Rust reader."""

import io
import unittest

from generalized_mu import Family, cap_type, profile
from merkle_extraction import DictionaryOracle
from protocol_mu import ProtocolRecognizer
from test_generalized_mu import notify_tree


class PrefixSink:
    def __init__(self, limit):
        self.data = bytearray()
        self.limit = limit

    def write(self, data):
        if len(self.data) + len(data) > self.limit:
            raise OSError("bounded test sink ended")
        self.data.extend(data)
        return len(data)


class ProtocolMuTests(unittest.TestCase):
    def test_uni_headers_have_no_pp_and_preserve_the_complete_public_vector(self):
        for family in (Family.SOURCE, Family.ROLE3):
            values = tuple(range(profile(family).public))
            recognizer = ProtocolRecognizer()
            recognizer.notify(family, values)
            output = io.BytesIO()
            self.assertIsNone(recognizer.write_before_first_coin(output))
            data = output.getvalue()
            self.assertEqual(data[:8], b"DCSMUB01")
            self.assertEqual(data[8], tuple(Family).index(family))
            self.assertEqual(data[9:64], bytes(55))
            self.assertEqual(data[64:], b"".join(x.to_bytes(8, "little") for x in values))
            self.assertEqual(len(data), 64 + profile(family).public * 8)
            # These arbitrary bytes are NOT claimed valid Source/Role3 claims.
            with self.assertRaises(ValueError):
                recognizer.write_before_first_coin(output)

    def test_real_query_column_order_root_cutoff_and_salt_exclusion(self):
        typed, _, first = notify_tree(Family.QUERY, first=(1 << 64) - (1 << 32))
        recognizer = ProtocolRecognizer()
        recognizer.notify(Family.QUERY, (0,) * 32, first)
        prefix = 64 + 32 * 8
        first_column_bytes = (1 << typed.depth) * 8
        output = PrefixSink(prefix + first_column_bytes + 8192)
        with self.assertRaises(OSError):
            recognizer.write_before_first_coin(output)
        data = bytes(output.data)
        self.assertEqual(data[9], 15)
        self.assertEqual(data[16:48], first.root)
        self.assertEqual(int.from_bytes(data[48:56], "little"), first.cutoff)
        minus_one = ((1 << 64) - (1 << 32)).to_bytes(8, "little")
        self.assertEqual(data[prefix:prefix + first_column_bytes], minus_one * (1 << 15))
        self.assertEqual(data[prefix + first_column_bytes:], bytes(8192))
        # The failed stream is consumed; a driver cannot repair it after a coin.
        with self.assertRaises(ValueError):
            recognizer.write_before_first_coin(io.BytesIO())

    def test_word_uses_its_real_first_snapshot_and_cannot_take_mutable_rows(self):
        _, _, snapshot = notify_tree(Family.WORD)
        recognizer = ProtocolRecognizer()
        recognizer.notify(Family.WORD, (0,) * 309, snapshot)
        output = PrefixSink(64)
        with self.assertRaises(OSError):
            recognizer.write_before_first_coin(output)
        self.assertEqual(bytes(output.data)[:10], b"DCSMUB01\x03\x0d")
        for supplied in (None, lambda _: (0,) * 714, []):
            with self.assertRaises(ValueError):
                ProtocolRecognizer().notify(Family.WORD, (0,) * 309, supplied)

    def test_missing_first_word_remains_zero_when_dictionary_later_grows(self):
        typed, built, after = notify_tree(Family.DATA)
        oracle = DictionaryOracle(built._supplied)
        first = oracle.notify(typed.schema, after.root)
        recognizer = ProtocolRecognizer()
        recognizer.notify(Family.DATA, (0,) * 32, first)
        for event in built.events:
            oracle.query(event.raw)
        self.assertIs(first, oracle.notify(typed.schema, after.root))
        output = PrefixSink(64 + 32 * 8 + 8192)
        with self.assertRaises(OSError):
            recognizer.write_before_first_coin(output)
        self.assertEqual(output.data[48:56], bytes(8))
        self.assertEqual(output.data[64 + 32 * 8:], bytes(8192))

    def test_wrong_uni_pp_and_repeated_notification_fail_closed(self):
        _, _, snapshot = notify_tree(Family.DATA)
        for family in (Family.SOURCE, Family.ROLE3):
            recognizer = ProtocolRecognizer()
            with self.assertRaises(ValueError):
                recognizer.notify(family, (0,) * profile(family).public, snapshot)
            with self.assertRaises(ValueError):
                recognizer.notify(family, (0,) * profile(family).public)
        recognizer = ProtocolRecognizer()
        recognizer.notify(Family.SOURCE, (0,) * 691)
        with self.assertRaises(ValueError):
            recognizer.notify(Family.SOURCE, (0,) * 691)
        self.assertEqual(cap_type(Family.WORD, "PP").schema.field_count, 718)


if __name__ == "__main__":
    unittest.main(verbosity=2)
