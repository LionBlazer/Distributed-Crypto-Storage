"""Hermetic observer contracts; no Sage shim or attack-cost estimate is run."""
import sys
import types
import unittest
from unittest.mock import patch

from estimate_n4096 import install_attack_progress


class AttackProgressTests(unittest.TestCase):
    def setUp(self):
        self.calls, self.events = [], []
        self.params = object()
        self.util = types.ModuleType("estimator.util")
        package = types.ModuleType("estimator")
        package.util = self.util

        def original(f, x, log_level=0, f_repr=None, catch_exceptions=True):
            self.calls.append((f, x, log_level, f_repr, catch_exceptions))
            return f(x)

        original.__name__ = "_batch_estimatef"
        original.__module__ = "estimator.util"
        self.original = self.util._batch_estimatef = original
        modules = patch.dict(sys.modules, {"estimator": package, "estimator.util": self.util})
        modules.start()
        self.addCleanup(modules.stop)

    def observe(self, attacks):
        restore, check = install_attack_progress(
            lambda event, **fields: self.events.append((event, fields)),
            attacks, "public-test-model", self.params,
        )
        self.addCleanup(restore)
        return check

    def test_all_original_arguments_and_result_objects_are_preserved(self):
        attacks = tuple("abcdefgh")
        check = self.observe(attacks)
        results = {}
        for index, attack in enumerate(attacks):
            expected = {"public_test_marker": index}
            producer = lambda _params, expected=expected: expected

            actual = self.util._batch_estimatef(producer, self.params, 7, "original name", False)

            self.assertIs(actual, expected)
            self.assertEqual(self.calls[-1], (producer, self.params, 7, "original name", False))
            results[attack] = actual
        check(results)
        self.assertEqual([event for event, _ in self.events], ["attack_start", "attack_return"] * 8)
        for index, (_, fields) in enumerate(self.events):
            self.assertEqual(fields["attack"], attacks[index // 2])
            self.assertEqual(fields["index"], index // 2)

    def test_original_failure_is_preserved_and_incomplete_attack_is_recorded(self):
        self.observe(("one",))
        failure = LookupError("original public-test failure")

        def fails(_params):
            raise failure

        with self.assertRaises(LookupError) as caught:
            self.util._batch_estimatef(fails, self.params, catch_exceptions=False)

        self.assertIs(caught.exception, failure)
        self.assertEqual([event for event, _ in self.events], ["attack_start", "attack_incomplete"])

    def test_missing_extra_and_foreign_result_maps_reject(self):
        check = self.observe(("one",))
        result = self.util._batch_estimatef(lambda _params: {}, self.params, catch_exceptions=False)

        for mapping in ({}, {"one": result, "extra": {}}, {"one": {}}):
            with self.subTest(mapping=mapping), self.assertRaises(RuntimeError):
                check(mapping)
        with self.assertRaises(RuntimeError):
            self.util._batch_estimatef(lambda _params: {}, self.params, catch_exceptions=False)

    def test_unexpected_input_or_exception_swallowing_rejects_before_original_call(self):
        self.observe(("one",))

        with self.assertRaises(RuntimeError):
            self.util._batch_estimatef(lambda _params: {}, object(), catch_exceptions=False)
        with self.assertRaises(RuntimeError):
            self.util._batch_estimatef(lambda _params: {}, self.params, catch_exceptions=True)

        self.assertEqual(self.calls, [])
        self.assertEqual(self.events, [])

    def test_absent_original_result_remains_incomplete(self):
        self.observe(("one",))

        with self.assertRaises(RuntimeError):
            self.util._batch_estimatef(lambda _params: None, self.params, catch_exceptions=False)

        self.assertEqual([event for event, _ in self.events], ["attack_start", "attack_incomplete"])

    def test_final_result_map_cannot_reorder_the_original_attacks(self):
        check = self.observe(("one", "two"))
        one = self.util._batch_estimatef(lambda _params: {}, self.params, catch_exceptions=False)
        two = self.util._batch_estimatef(lambda _params: {}, self.params, catch_exceptions=False)

        with self.assertRaises(RuntimeError):
            check({"two": two, "one": one})

    def test_restore_puts_back_the_exact_original_function(self):
        restore, _ = install_attack_progress(lambda *_args, **_kwargs: None, (), "model", self.params)

        restore()

        self.assertIs(self.util._batch_estimatef, self.original)


if __name__ == "__main__":
    unittest.main()
