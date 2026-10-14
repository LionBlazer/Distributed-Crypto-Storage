"""Observable CLI input profiles; no Sage, estimator import or attack execution."""
import json
from pathlib import Path
import subprocess
import sys
import unittest

SCRIPT = Path(__file__).with_name("estimate_bfv.py")


class ManifestProfiles(unittest.TestCase):
    def invoke(self, *arguments):
        return subprocess.run([sys.executable, str(SCRIPT), *arguments],
                              text=True, capture_output=True, check=False)

    def manifest(self, *arguments):
        result = self.invoke(*arguments)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertEqual(len(result.stdout.splitlines()), 1)
        return json.loads(result.stdout)

    def test_default_keeps_original_n16384_parameters_and_exposure(self):
        actual = self.manifest()
        self.assertEqual(actual, self.manifest("--profile", "n16384-plain25"))
        self.assertEqual(actual["generic_lwe_dimension"], 16384)
        self.assertEqual(actual["plaintext_modulus"], 33292289)
        self.assertEqual(actual["q_decimal"],
                         "709803428473824464899716522243808726188912609449487857793115029420083157504007498781933901411951056604199361914151348163758737883137")
        self.assertEqual(actual["coefficient_prime_bit_lengths"], [48,48,48,49,49,49,49,49,49])
        self.assertEqual([row["rns_key_switch_ciphertext_pairs"]
                          for row in actual["switching_key_exposure"]], [72,108])
        self.assertEqual(actual["plaintext_component_bound"], 16776960)

    def test_byte17_selects_8192_product_limbs_and_five_prime_exposure(self):
        actual = self.manifest("--profile", "n8192-byte17")
        self.assertEqual(actual["profile"], "n8192-byte17")
        self.assertEqual(actual["generic_lwe_dimension"], 8192)
        self.assertEqual(actual["plaintext_modulus"], 114689)
        self.assertEqual(actual["q_decimal"],
                         "421249101157150430150591791601812858371395928330411389778873040897")
        self.assertEqual(actual["coefficient_prime_bit_lengths"], [43,43,44,44,44])
        self.assertEqual(actual["output_packing"], "byte-limb-low-high-count")
        self.assertEqual(actual["plaintext_component_bound"], 65280)
        self.assertEqual([row["rns_key_switch_ciphertext_pairs"]
                          for row in actual["switching_key_exposure"]], [40,60])
        self.assertEqual([row["scalar_coefficient_relations_inventory_only"]
                          for row in actual["switching_key_exposure"]], [327680,491520])

    def test_both_profiles_keep_exact_cbd_and_unlimited_lwe_caveat(self):
        for profile in ("n16384-plain25", "n8192-byte17"):
            with self.subTest(profile=profile):
                actual = self.manifest("--profile", profile)
                for field in ("secret_distribution", "error_distribution"):
                    self.assertEqual(actual[field]["estimator_distribution"], "ND.CenteredBinomial(20)")
                    self.assertEqual(actual[field]["variance_exact"], "10")
                    self.assertEqual(actual[field]["support"], [-20,20])
                self.assertEqual(actual["sample_count_model"], "unlimited")
                self.assertTrue(actual["ring_correlations_and_kdm_not_modeled_by_lwe_estimator"])
                self.assertFalse(actual["security_bits_estimated"])
                self.assertEqual(actual["estimator_revision"], "53da5982597709ba0fdf94ea37a84d822310fd84")

    def test_finite_samples_use_selected_dimension_before_any_estimator_import(self):
        actual = self.manifest("--profile", "n8192-byte17", "--samples", "8192")
        self.assertEqual(actual["sample_count_model"], "8192")
        rejected = self.invoke("--samples", "8192")
        self.assertEqual(rejected.returncode, 2)
        self.assertEqual(rejected.stdout, "")
        self.assertIn("at least one N-coefficient polynomial", rejected.stderr)

    def test_unknown_profile_rejects_instead_of_falling_back(self):
        rejected = self.invoke("--profile", "n8192-typo")
        self.assertEqual(rejected.returncode, 2)
        self.assertEqual(rejected.stdout, "")
        self.assertIn("invalid choice", rejected.stderr)


if __name__ == "__main__":
    unittest.main()
