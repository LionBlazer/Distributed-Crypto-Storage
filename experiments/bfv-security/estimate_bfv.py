#!/usr/bin/env python3
"""Exact BFV input manifest; optional official Sage estimator, never a reimplementation."""
from __future__ import annotations

import argparse
from fractions import Fraction
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import subprocess
import sys

ESTIMATOR_REVISION = "53da5982597709ba0fdf94ea37a84d822310fd84"
FHE_REVISION = "fe47bac2e2abf0077c0e8d95f5c2ce7ce8a40b2a"
N = 16384
T = 33292289
MODULI = (
    0xFFFFFFFD8001,
    0xFFFFFFFA0001,
    0xFFFFFFF00001,
    0x1FFFFFFF68001,
    0x1FFFFFFF50001,
    0x1FFFFFFEE8001,
    0x1FFFFFFEA0001,
    0x1FFFFFFE88001,
    0x1FFFFFFE48001,
)
Q = math.prod(MODULI)
ETA = 20
ATTACKS = (
    "arora-gb", "bkw", "usvp", "bdd", "bdd_hybrid",
    "bdd_mitm_hybrid", "dual", "dual_hybrid",
)


def emit(record: dict) -> None:
    print(json.dumps(record, sort_keys=True, allow_nan=False), flush=True)


def exact_distribution_check() -> dict:
    # Input-mapping check only: exact distribution of popcount20-popcount20.
    pmf = {k: Fraction(math.comb(2 * ETA, ETA + k), 2 ** (2 * ETA))
           for k in range(-ETA, ETA + 1)}
    mass = sum(pmf.values())
    mean = sum(k * p for k, p in pmf.items())
    variance = sum((k - mean) ** 2 * p for k, p in pmf.items())
    assert mass == 1 and mean == 0 and variance == 10
    return {"estimator_distribution": "ND.CenteredBinomial(20)",
            "source_sampler": "popcount20 - popcount20 from40 independent bits",
            "mean_exact": str(mean), "variance_exact": str(variance),
            "support": [-20, 20], "standard_deviation": math.sqrt(10),
            "pmf_mass_exact": str(mass)}


def verify_estimator(repo: Path, git: str) -> None:
    revision = subprocess.check_output(
        [git, "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
    if revision != ESTIMATOR_REVISION:
        raise SystemExit(f"Estimator revision mismatch: {revision}")
    changed = subprocess.check_output(
        [git, "-C", str(repo), "status", "--porcelain", "--untracked-files=normal"],
        text=True).strip()
    if changed:
        raise SystemExit("Estimator checkout must be clean, including untracked source")


def manifest(samples: str) -> dict:
    assert N == 16384 and T > 256 * 65535 and T % (2 * N) == 1
    assert all(q % (2 * N) == 1 for q in MODULI)
    return {
        "event": "exact_inputs_no_security_result",
        "fhe_package": "fhe=0.1.1", "fhe_revision": FHE_REVISION,
        "estimator_revision": ESTIMATOR_REVISION,
        "ring": "Z_Q[x]/(x^16384+1), cyclotomic index32768",
        "generic_lwe_dimension": N, "q_decimal": str(Q),
        "q_hex": hex(Q), "q_log2": math.log2(Q), "q_bit_length": Q.bit_length(),
        "coefficient_moduli": list(MODULI),
        "coefficient_prime_bit_lengths": [q.bit_length() for q in MODULI],
        "plaintext_modulus": T, "ciphertext_level": 0,
        "secret_distribution": exact_distribution_check(),
        "error_distribution": exact_distribution_check(),
        "sample_count_model": samples,
        "unlimited_model_is_independent_lwe_heuristic": True,
        "ring_correlations_and_kdm_not_modeled_by_lwe_estimator": True,
        "switching_key_exposure": [
            {"selected_rows": k, "rotation_keys": rotations,
             "relinearization_keys": 1,
             "rns_key_switch_ciphertext_pairs": 9 * (rotations + 1),
             "scalar_coefficient_relations_inventory_only": N * 9 * (rotations + 1)}
            for k, rotations in ((16, 7), (256, 11))
        ],
        "new_query_ciphertext_pairs": {"equal_or_ge": 3, "range": 4},
        "security_bits_estimated": False,
        "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--estimate", action="store_true",
                        help="Run official Sage estimator; obtain exclusive CPU lease first")
    parser.add_argument("--estimator-root", type=Path)
    parser.add_argument("--git", default="git")
    parser.add_argument("--model", choices=("matzov", "adps16", "both"), default="both")
    parser.add_argument("--samples", default="unlimited",
                        help="unlimited (primary sensitivity model), or integer scalar sample count")
    args = parser.parse_args()
    if args.samples != "unlimited" and int(args.samples) < N:
        parser.error("Finite sample sensitivity must contain at least one N-coefficient polynomial")
    emit(manifest(args.samples))
    if args.estimator_root is not None:
        verify_estimator(args.estimator_root.resolve(), args.git)
    if not args.estimate:
        return
    if args.estimator_root is None:
        parser.error("--estimate requires a clean pinned --estimator-root")
    for variable in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS"):
        os.environ[variable] = "1"  # Only this child process, no global settings.
    try:
        from sage.all import ZZ, log, oo
        from sage.env import SAGE_VERSION
    except ModuleNotFoundError as error:
        raise SystemExit("Missing Sage runtime: use an existing 'sage -python' environment; "
                         "this script installs nothing and no security estimate ran") from error
    repo = args.estimator_root.resolve()
    sys.path.insert(0, str(repo))
    import estimator
    from estimator import LWE, ND, RC, Simulator
    if Path(estimator.__file__).resolve() != repo / "estimator" / "__init__.py":
        raise SystemExit("Imported estimator is not the pinned checkout")
    sample_count = oo if args.samples == "unlimited" else int(args.samples)
    secret, error = ND.CenteredBinomial(ETA), ND.CenteredBinomial(ETA)
    assert secret.bounds == (-20, 20) and abs(float(secret.stddev**2) - 10) < 1e-12
    params = LWE.Parameters(n=N, q=ZZ(Q), Xs=secret, Xe=error, m=sample_count,
                            tag="fhe0.1.1-N16384-CBD20-generic-LWE-only")
    models = {"matzov": RC.MATZOV, "adps16": RC.ADPS16}
    chosen = models if args.model == "both" else {args.model: models[args.model]}
    for name, model in chosen.items():
        emit({"event": "estimator_start", "sage_version": SAGE_VERSION,
              "python": platform.python_version(), "model": name,
              "model_state": vars(model), "shape": "GSA", "jobs": 1,
              "configured_attacks": ATTACKS, "catch_exceptions": False,
              "ring_and_kdm_security_claim": False})
        results = LWE.estimate(params, red_cost_model=model, red_shape_model=Simulator.GSA,
                               deny_list=(), add_list=(), jobs=1,
                               catch_exceptions=False, quiet=True)
        finite = []
        for attack, cost in sorted(results.items()):
            bits = None if cost["rop"] == oo else float(log(cost["rop"], 2))
            if bits is not None:
                finite.append(bits)
            emit({"event": "attack_estimate", "model": name, "attack": attack,
                  "rop_log2": bits, "cost_fields": {str(k): str(v) for k, v in cost.items()}})
        emit({"event": "conditional_lwe_result", "model": name,
              "minimum_finite_rop_log2": min(finite) if finite else None,
              "returned_attack_names": sorted(results),
              "full_api_prunes_dominated_hybrids": True,
              "independently_audited_bfv_security_claim": False})


if __name__ == "__main__":
    main()
