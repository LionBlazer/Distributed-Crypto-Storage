"""PUBLIC algebraic examples. No Sage, DCS input, estimator sweep or network."""
import math
import random
import unittest

import exact_gb_cost as subject


def finite_binomial_series(n, factors, precision):
    """Independent original product via finite binomial coefficients/convolution."""
    numerator = [1] + [0] * (precision - 1)
    for degree, multiplicity in factors:
        factor = [(j * degree, (-1)**j * math.comb(multiplicity, j))
                  for j in range(min(multiplicity, (precision - 1) // degree) + 1)]
        result = [0] * precision
        for i, value in enumerate(numerator):
            for shift, coefficient in factor:
                if value and i + shift < precision:
                    result[i + shift] += value * coefficient
        numerator = result
    denominator = [math.comb(n + i - 1, i) for i in range(precision)]
    return [sum(numerator[j] * denominator[i - j] for j in range(i + 1))
            for i in range(precision)]


class ExactSeriesTests(unittest.TestCase):
    def test_full_coefficients_match_independent_binomial_product(self):
        cases = [(n, [(d, m)], 24) for n in range(1, 6)
                 for d in range(1, 7) for m in range(6)]
        rng = random.Random(0x5055424C4943)  # deterministic PUBLIC examples only
        cases += [(rng.randrange(1, 13),
                   [(rng.randrange(1, 21), rng.randrange(9)) for _ in range(3)],
                   rng.randrange(1, 65)) for _ in range(160)]
        cases += [(8, [(2, 3), (2, 5), (5, 0)], 64),
                  (8, [(1, 8)], 64), (8, [(1, 9)], 64),
                  (3, [], 64), (16, [(5, 2**80 + 7)], 32),
                  (12, [(9, 2), (41, 12)], 96)]
        for n, factors, precision in cases:
            with self.subTest(n=n, factors=factors, precision=precision):
                self.assertEqual(list(subject.coefficients(n, factors, precision)),
                                 finite_binomial_series(n, factors, precision))

    def test_zero_is_skipped_and_precision_excludes_its_endpoint(self):
        self.assertEqual(list(subject.coefficients(2, [(2, 3)], 8)),
                         [1, 2, 0, -2, -1, 0, 0, 0])
        self.assertIsNone(subject.first_negative(2, [(2, 3)], 3))
        self.assertEqual(subject.first_negative(2, [(2, 3)], 4), 3)
        self.assertIsNone(subject.first_negative(8, [(1, 8)], 64))

    def test_original_bounded_cbd20_baseline_first_negative_is_41(self):
        n = 4096
        actual = list(subject.coefficients(n, [(41, n**41), (41, n)], 42))
        expected = [math.comb(n + k - 1, k) for k in range(42)]
        expected[41] -= n**41 + n
        self.assertEqual(actual, expected)
        self.assertEqual([i for i, value in enumerate(actual) if value < 0], [41])

    def test_full_gaussian_like_zero_sample_prefix_has_exact_selected_coefficients(self):
        # The genuine first Gaussian-like branch has m_can=0. This series is
        # ((1-z**41)/(1-z))**4096, with all coefficients nonnegative.
        n, precision = 4096, 8192
        actual = list(subject.coefficients(n, [(9, 0), (41, n)], precision))
        self.assertEqual(len(actual), precision)
        self.assertTrue(all(value >= 0 for value in actual))
        for k in [0, 1, 40, 41, 255, 1024, 4095, 8191]:
            expected = sum((-1)**j * math.comb(n, j)
                           * math.comb(n + k - 41*j - 1, k - 41*j)
                           for j in range(k // 41 + 1))
            self.assertEqual(actual[k], expected)

    def test_repeated_zero_and_outside_precision_factors_are_exact_identities(self):
        actual = list(subject.coefficients(12, [(9, 0), (3, 2), (3, 5), (41, 99)], 32))
        self.assertEqual(actual, finite_binomial_series(12, [(3, 7)], 32))

    def test_invalid_domains_reject_without_consuming_iterators(self):
        def forbidden():
            raise AssertionError("unsupported iterator was consumed")
            yield (2, 3)
        for n, factors, precision in [(0, [], 2), (True, [], 2), (2.0, [], 2),
                                      (2, [(0, 3)], 2), (2, [(2, -1)], 2),
                                      (2, [(2, True)], 2), (2, [(2, 1.0)], 2),
                                      (2, [], 0), (2, [], True), (2, forbidden(), 2)]:
            with self.subTest(n=n, precision=precision):
                with self.assertRaises(ValueError):
                    list(subject.coefficients(n, factors, precision))

    def test_certified_positive_prefixes_match_independent_full_products(self):
        cases = [(n, [(s, n), (d, m)], 128)
                 for n in [32, 64, 128] for s in [17, 41]
                 for d in [57, 79, 80, 81, 127] for m in [1, 2**16, 2**31]]
        certified = 0
        for n, factors, precision in cases:
            if subject._proved_nonnegative_prefix(n, factors, precision):
                certified += 1
                with self.subTest(n=n, factors=factors):
                    expected = finite_binomial_series(n, factors, precision)
                    self.assertTrue(all(value >= 0 for value in expected))
                    self.assertIsNone(subject.first_negative(n, factors, precision))
        self.assertGreater(certified, 50)

    def test_actual_negative_bounded_profile_is_not_certified_positive(self):
        n, multiplicity = 4096, 2**31 + 4096
        self.assertEqual(subject.first_negative(n, [(41, multiplicity)], 8192), 6615)
        for k, negative in [(6614, False), (6615, True)]:
            expected = sum((-1)**j * math.comb(multiplicity, j)
                           * math.comb(n + k - 41*j - 1, k - 41*j)
                           for j in range(k // 41 + 1))
            self.assertEqual(expected < 0, negative)
        self.assertEqual(subject.first_negative(1, [(41, 1), (81, 2**31)], 128), 81)

    def test_general_nonnegative_certificate_keeps_zeros_and_unbounded_denominator(self):
        for n, factors in [(8, [(1, 8)]), (12, [(2, 3), (3, 4)]), (4, [])]:
            self.assertIsNone(subject.first_negative(n, factors, 64))
            self.assertTrue(all(value >= 0 for value in finite_binomial_series(n, factors, 64)))


if __name__ == "__main__":
    unittest.main()
