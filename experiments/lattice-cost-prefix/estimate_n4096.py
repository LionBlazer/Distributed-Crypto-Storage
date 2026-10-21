#!/usr/bin/env python3
"""Public fixed-profile input for the unmodified official Sage lattice estimator.

SOURCE ONLY: Root must review the script and runtime before executing it.
This file contains no DCS imports, fixture data, keys, query or participant data.
It never installs packages, starts a VM/service, or accepts online-service terms.
"""
from __future__ import annotations

import argparse
from fractions import Fraction
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import time

sys.dont_write_bytecode = True
for _name in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS",
              "NUMEXPR_NUM_THREADS", "VECLIB_MAXIMUM_THREADS", "SAGE_NUM_THREADS"):
    os.environ[_name] = "1"

ESTIMATOR_REVISION = "53da5982597709ba0fdf94ea37a84d822310fd84"
SAGE_VERSION = "10.10"
N, T, ETA = 4096, 65537, 20
Q_BASES = (1073692673, 1073668097)
Q = 1152789568982753281
ATTACKS = ("arora-gb", "bkw", "usvp", "bdd", "bdd_hybrid",
           "bdd_mitm_hybrid", "dual", "dual_hybrid")
SOURCE_PINS = {
    "estimator/lwe.py": "9ff2ac14f6480863d741eac1c2a9c935adf87a8954d2344024a22b581133e230",
    "estimator/nd.py": "d87fca7bb191a0fb29b24507897e00c8beba784da552b6b90a982c718fc1c459",
    "estimator/conf.py": "b8270fcc702ef72e00308fc691112f374da4d0d0395665b7c244c9b99b77f7dd",
    "estimator/lwe_parameters.py": "72bde0ae3bdd89a4de02b249a1da144256b8d84d009b28b59bde6364b0bc8ecc",
    "estimator/reduction.py": "b1354702c88a8309f78d373ae7f4b0b4347799abfd1a13c07e0fa75bf87bd59a",
    "requirements.txt": "451f79772de6e219c198ae79c8123ab4931cbc416e0145b9b5a310e454bfd444",
}


def emit(event: str, **fields) -> None:
    print("DCS_ESTIMATOR_JSON " + json.dumps(
        {"event": event, **fields}, sort_keys=True, allow_nan=False), flush=True)


SOURCE_ARCHIVE_MANIFEST_JSON = r'''{"source_kind":"full_byte_pinned_official_archive","revision":"53da5982597709ba0fdf94ea37a84d822310fd84","revision_url":"https://github.com/malb/lattice-estimator/tree/53da5982597709ba0fdf94ea37a84d822310fd84","archive_url":"https://codeload.github.com/malb/lattice-estimator/tar.gz/53da5982597709ba0fdf94ea37a84d822310fd84","archive_bytes":101555,"archive_sha256":"4236adc38031c139c8a2721804d8962d6cacd015fae37f6f5215d2ac7f011060","uncompressed_tar_bytes":450560,"regular_file_count":63,"regular_file_bytes":387400,"directories":["",".github",".github/ISSUE_TEMPLATE",".github/workflows","docker","docs","docs/_templates","docs/_templates/autosummary","docs/algorithms","docs/schemes","estimator"],"archive_metadata":[{"kind":"global_pax_comment","comment":"53da5982597709ba0fdf94ea37a84d822310fd84"}],"files":{".flake8":{"bytes":173,"sha256":"863a7e55be3e36f1036e78824046fd1bff95119a19e94bec4fb1e5e8450a77b5"},".github/ISSUE_TEMPLATE/bug_report.md":{"bytes":508,"sha256":"58632f6f25c89e1e0603378744489171308d698cead098663f4eff437787a863"},".github/ISSUE_TEMPLATE/feature-request-to-add-a-new-attack-from-the-literature.md":{"bytes":344,"sha256":"c52f4cb0d0aba925bd68ce0ce208779c7fe90d2f81febb3bde2ed7291df15a9a"},".github/workflows/jupyter.yml":{"bytes":1927,"sha256":"89cabc8465d0ec7f1beeba6dc9bba2e61a5685a10d596b157076eeb0689c4e38"},".github/workflows/pep8.yml":{"bytes":345,"sha256":"39b2686b854873fe3885b6e44ce237f6711b55ed261f752d18a62ea69eef0705"},".github/workflows/tests.yml":{"bytes":1105,"sha256":"49cb845b7386bab8588aedd769b7b5853247740e7b85292434ef850274227f63"},".gitignore":{"bytes":47,"sha256":"183daab5d889ab12781584ecee87fa6f9faf90945e3960ef979d9a30994fdd32"},"Makefile":{"bytes":671,"sha256":"5c72767f4dc0c8707c69f712e2daf1b9133bbcc5c3c270aec34749c6e9bbaaa2"},"README.rst":{"bytes":9727,"sha256":"a91ed8597f90f0baab66f27dcdf5c897e2473571676ce9ca522f736f2d6e9b00"},"docker/Dockerfile":{"bytes":553,"sha256":"e851d3d1e8ceaf711fd2c9ad3cdf5a947b992bf9bf2ab4ee96db28b3b328ca0c"},"docker/Dockerfile.dev":{"bytes":343,"sha256":"ec69ff92a80fc35f7cb51b96c2a369c84b11ef88f0a8cad62f4185f1afe2d0f7"},"docker/README.md":{"bytes":707,"sha256":"13c34c4a66c1bb471c46210232a17667115bfbf205756c3d7425734a8a5debb6"},"docs/Makefile":{"bytes":7646,"sha256":"66a54f1da663cdd56bbc65dc331b9185283c724b4b7075ea18f912e3d1641e0d"},"docs/_templates/autosummary/base.rst":{"bytes":101,"sha256":"cad67b3b644eb7ab6f5b09330980248d5f65dc714c10516590be741e99ed20a9"},"docs/_templates/autosummary/class.rst":{"bytes":613,"sha256":"d1e5c7a1958ec38a8ab60a0b89e4d3b9061b0204d211adf26569fac84b148e7a"},"docs/_templates/autosummary/module.rst":{"bytes":504,"sha256":"4c4344e30999a809b7741a5dc00cde90886200a1442a9fec932507dc1d9974ec"},"docs/algorithms/gb.rst":{"bytes":983,"sha256":"079092d759aab59ffa9037278ca942b23c29db2d91fc9e25ed292c410051b690"},"docs/algorithms/lwe-bkw.rst":{"bytes":588,"sha256":"163fe025cdce7a6103292323b9237a9b44c835652621135b8c06911e6acb2125"},"docs/algorithms/lwe-dual.rst":{"bytes":775,"sha256":"3375058ace3d1d1202e6f705debb19799385593b429f06cba8146a953b063a87"},"docs/algorithms/lwe-primal.rst":{"bytes":1657,"sha256":"f9764915b7a7125f9724f88fe9048359900727955e226b1b57c07e840bab9bbd"},"docs/algorithms/ntru.rst":{"bytes":2458,"sha256":"ee799135df0471a12d56136393f918afdcad520cadad0e4667b98484f8427a5d"},"docs/algorithms/sis-lattice.rst":{"bytes":4489,"sha256":"b424e6b013133d7d44069831b560eba02e90dfd51c141b025911191e81b2a7d4"},"docs/api_doc.rst":{"bytes":551,"sha256":"02ead5f850913ddc305fe50110d8f766581b67beb229fb258327b962363a452a"},"docs/conf.py":{"bytes":11213,"sha256":"b87491c1cecc59998a26dd16ae98a3cd61772349ce8167f9201bb1564478b8ab"},"docs/contributing.rst":{"bytes":5427,"sha256":"76324f792b0f63962d5fd8460100f1b3be7a8c1f6bbfab3ff184d8d4e3211be3"},"docs/genindex.rst":{"bytes":63,"sha256":"b474c9755108d0ec634da4454d33b2a60893ea0edebab80080b88d38c292bb4e"},"docs/index.rst":{"bytes":754,"sha256":"d67d147946aff19e3149eff9e5d0658a661281a60716523d12b629ec77e2a988"},"docs/prompt.rst":{"bytes":775,"sha256":"b82dee7d35b6a2fb7ff9d6ac9ea03b82bbba0e805b7f08886e36a1fe1f16589c"},"docs/readme_link.rst":{"bytes":165,"sha256":"63d46b446cc7316da233e597bc55b4df17de7de282c2758c6ef34ddeb00e5584"},"docs/references.rst":{"bytes":8806,"sha256":"7f3b5e1cd3f71da5224029f60cca2fd6bd8f601142c01e2a4392aac42b4cebc9"},"docs/schemes/hes.rst":{"bytes":1409,"sha256":"400afaf97d11ebb496efe71809b9fed436367cd59c04dcda59b061dd0cd841e3"},"docs/schemes/nist-pqc-round-3.rst":{"bytes":3340,"sha256":"2fd6bad1363e77bb0e1f6bc57e71be25a2291e5d40c63c4f756427275aa8904b"},"doctest.sh":{"bytes":665,"sha256":"af23ae031509418694fdcd22d225f12db8635d26f7a1594dba343b287f1bf0f1"},"estimator/__init__.py":{"bytes":315,"sha256":"e002e825d7245ce39c9a388456b9ffb2a3ec326d39c14c4efb8f964843907cdd"},"estimator/conf.py":{"bytes":613,"sha256":"b8270fcc702ef72e00308fc691112f374da4d0d0395665b7c244c9b99b77f7dd"},"estimator/cost.py":{"bytes":6957,"sha256":"f1424722796fcdda2dd65957e317ae610af9c04cc2473c29b35ffc7ae0939f60"},"estimator/errors.py":{"bytes":277,"sha256":"6ffd53eb82f27233c0dd3612b3b6139da28b48e5c128885cf1211e16154086f5"},"estimator/gb.py":{"bytes":8646,"sha256":"d785ee73ad40a470422d1ddc21d76e9f32b8ab1d85d88ae2539590b32bbd7edc"},"estimator/io.py":{"bytes":2500,"sha256":"316d7ec3c0371ebf4f83d301030a935e7b89774cf7366bc7d5237348124a057e"},"estimator/lwe.py":{"bytes":7264,"sha256":"9ff2ac14f6480863d741eac1c2a9c935adf87a8954d2344024a22b581133e230"},"estimator/lwe_bkw.py":{"bytes":10614,"sha256":"6caf4a9a1301a173a3c28863c39535d13c4927d7e870f37d68ad4b09e894a9f2"},"estimator/lwe_dual.py":{"bytes":29728,"sha256":"8f6a077589393f907fbcc87b9ef812beafc73bf5cc78abc4f857924b80a21a8b"},"estimator/lwe_guess.py":{"bytes":17563,"sha256":"33020dcf5a4783a6d90f489a44314ed2bc3b594862262c99f19bf7c2493ee8fb"},"estimator/lwe_parameters.py":{"bytes":5952,"sha256":"72bde0ae3bdd89a4de02b249a1da144256b8d84d009b28b59bde6364b0bc8ecc"},"estimator/lwe_primal.py":{"bytes":34102,"sha256":"f46e682a3eb0b7e3b175c326f96244caee5df6f07df78974cdb834e1d6f006d1"},"estimator/nd.py":{"bytes":21177,"sha256":"d87fca7bb191a0fb29b24507897e00c8beba784da552b6b90a982c718fc1c459"},"estimator/ntru.py":{"bytes":7754,"sha256":"f0cfb95048f2ecac32922e61f05ae3c9c7bbbbff4d7acbd8572b318168405769"},"estimator/ntru_parameters.py":{"bytes":3481,"sha256":"4d4964ccaad895e5387606f8e7d6d069347736a39b432ffd88bdbee503764011"},"estimator/ntru_primal.py":{"bytes":15693,"sha256":"fdceaf65d4e4717ac15af6628a84659c9c760f7cede5a4ba1f405b733c641eaa"},"estimator/prob.py":{"bytes":9842,"sha256":"264693353e4ee439f43775351ffd94697468eeda84392d1b4226ec9adf5e7693"},"estimator/reduction.py":{"bytes":37592,"sha256":"b1354702c88a8309f78d373ae7f4b0b4347799abfd1a13c07e0fa75bf87bd59a"},"estimator/schemes.py":{"bytes":12142,"sha256":"1381414eb6c3fb8d13e90f655a6db4c4a0e70293c89d297b90d8fb99a8b7d673"},"estimator/simulator.py":{"bytes":11080,"sha256":"5fc05d91665b4bf149aa27d87191c69ac617296b04b6f682a3a0ab3f0547633a"},"estimator/sis.py":{"bytes":5807,"sha256":"3e32a433f88f4df2203384d74ff04556da700f1317b88c6e2ed9a56d4d4834ba"},"estimator/sis_large_norm.py":{"bytes":15021,"sha256":"3f8ac06c7965d745f8991e8294f0c1eedda723af496c6c73cef4add9f79554cf"},"estimator/sis_lattice.py":{"bytes":14783,"sha256":"243dc77e57b160925876f526beef9dd4d19157ece215bf5fe5cda9c2799498a9"},"estimator/sis_parameters.py":{"bytes":1926,"sha256":"726ae10ed711cf8f9a42efa07b6d7ed00c67dbb28f0f4f97bbac3bb7c8d59b4c"},"estimator/util.py":{"bytes":15252,"sha256":"0da1e981bc56db2a008e46709d50b9b326673e04aecf406cb180fe18b437af01"},"fix-doctest.sh":{"bytes":710,"sha256":"001933ce33eae420375fa90c3f38d94f051b96400c7e0b8f7a9838b05d0631d3"},"param_sweep.py":{"bytes":19719,"sha256":"9d083300e18820ad274b87b7733bfe4b22c43243b3fb9d44f796da7f7cbaa9bf"},"pyproject.toml":{"bytes":656,"sha256":"f8547ef88975269c1888d9a52871eb80a565a222d7dd4c1ac7d72cad8ef112ec"},"readthedocs.yml":{"bytes":705,"sha256":"27ded57dc09a095f43e94d6f1e2c3c6989890876d2641d33a57df06a31582a44"},"requirements.txt":{"bytes":97,"sha256":"451f79772de6e219c198ae79c8123ab4931cbc416e0145b9b5a310e454bfd444"}},"all_six_existing_raw_pins_match":true,"special_files_links_duplicates_traversal_rejected":true,"security_assessed":false}'''


def verify_source(repo: Path) -> dict:
    import stat
    manifest = json.loads(SOURCE_ARCHIVE_MANIFEST_JSON)
    expected = manifest["files"]
    if repo.is_symlink() or not repo.is_dir():
        raise RuntimeError("The source root must be a real directory")
    actual, directories = {}, set()
    for current, children, filenames in os.walk(repo, followlinks=False):
        directory = Path(current)
        relative = directory.relative_to(repo).as_posix()
        relative = "" if relative == "." else relative
        if relative not in manifest["directories"]:
            raise RuntimeError("Unexpected source directory")
        directories.add(relative)
        for name in children:
            path = directory / name
            if not stat.S_ISDIR(path.lstat().st_mode) or path.is_symlink():
                raise RuntimeError("Source directory links/special entries are forbidden")
        for name in filenames:
            path = directory / name
            relative_file = path.relative_to(repo).as_posix()
            info = path.lstat()
            if relative_file not in expected or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise RuntimeError("Unexpected, linked or special source file")
            pin = expected[relative_file]
            if info.st_size != pin["bytes"]:
                raise RuntimeError("Source byte length changed")
            data = path.read_bytes()
            item = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
            if item != pin:
                raise RuntimeError("Complete official source byte pin mismatch")
            actual[relative_file] = item
    if actual != expected or directories != set(manifest["directories"]):
        raise RuntimeError("The complete source tree must match without extras or omissions")
    raw = {name: actual[name]["sha256"] for name in SOURCE_PINS}
    if raw != SOURCE_PINS:
        raise RuntimeError("An original RAW source pin changed")
    return {"source_kind": "full_byte_pinned_official_archive",
            "revision": ESTIMATOR_REVISION, "revision_url": manifest["revision_url"],
            "archive_url": manifest["archive_url"], "archive_sha256": manifest["archive_sha256"],
            "archive_bytes": manifest["archive_bytes"], "git_clean": None,
            "raw_source_sha256": raw, "full_source_files": actual,
            "full_source_directories": sorted(directories)}


def public_inputs() -> dict:
    assert math.prod(Q_BASES) == Q
    assert all(q % (2 * N) == 1 for q in Q_BASES)
    assert T % (2 * N) == 1
    # Input mapping only, not an attack estimate or entropy proof.
    mass = {k: Fraction(math.comb(2 * ETA, ETA + k), 2 ** (2 * ETA))
            for k in range(-ETA, ETA + 1)}
    assert sum(mass.values()) == 1
    assert sum(k * p for k, p in mass.items()) == 0
    assert sum(k * k * p for k, p in mass.items()) == 10
    return {
        "n": N, "ring": "Z_Q[X]/(X^4096+1)", "q": str(Q),
        "ordered_q_bases": list(Q_BASES), "plaintext_modulus": T,
        "xs": "ND.CenteredBinomial(20)", "xe": "ND.CenteredBinomial(20)",
        "variance_exact": "10", "support": [-20, 20],
        "scalar_sample_count": "infinity", "jobs": 1,
        "independent_lwe_heuristic": True,
        "ring_rotations_are_not_independent_random_rows": True,
        "p_extension_primes_are_not_ciphertext_modulus": True,
        "no_relinearization_or_rotation_keys_in_this_product_profile": True,
        "prng_entropy_side_channels_and_ring_attacks_not_audited": True,
        "does_not_assess_whole_system_security_or_sql": True,
    }


def limit_alarm(_number, _frame) -> None:
    raise TimeoutError("Reviewed per-model wall deadline exceeded; estimate incomplete")


def install_attack_progress(emit_record, attacks, model, normalized_params):
    """Observe the original sequential batch; never select or replace an attack."""
    import estimator.util as util
    original = util._batch_estimatef
    if (original.__module__ != "estimator.util" or
            original.__name__ != "_batch_estimatef"):
        raise RuntimeError("Unexpected upstream batch implementation")
    returned = []
    active = False

    def observed(f, x, log_level=0, f_repr=None, catch_exceptions=True):
        nonlocal active
        index = len(returned)
        if active or index >= len(attacks) or x != normalized_params or catch_exceptions:
            raise RuntimeError("Unexpected sequential upstream attack invocation")
        active = True
        attack = attacks[index]
        started, cpu_started = time.perf_counter(), time.process_time()
        emit_record("attack_start", model=model, attack=attack, index=index)
        try:
            result = original(f, x, log_level, f_repr, catch_exceptions)
            if result is None:
                raise RuntimeError("No original attack result")
            emit_record("attack_return", model=model, attack=attack, index=index,
                        fields={str(k): str(v) for k, v in result.items()},
                        wall_seconds=time.perf_counter() - started,
                        cpu_seconds=time.process_time() - cpu_started)
            returned.append((attack, result))
            return result
        except Exception as error:
            emit_record("attack_incomplete", model=model, attack=attack, index=index,
                        error_type=type(error).__name__,
                        wall_seconds=time.perf_counter() - started)
            raise
        finally:
            active = False

    util._batch_estimatef = observed

    def restore():
        if util._batch_estimatef is not observed:
            raise RuntimeError("Upstream observation hook changed unexpectedly")
        util._batch_estimatef = original

    def check_results(results):
        if len(returned) != len(attacks) or tuple(results) != tuple(attacks):
            raise RuntimeError("Incomplete original attack order")
        if any(results[attack] is not result for attack, result in returned):
            raise RuntimeError("Returned map differs from original attack objects")

    return restore, check_results


def install_exact_dual_rounding(params):
    """Preserve the correctly rounded30-bit scalar on a proved bounded domain."""
    import ast
    import inspect
    import textwrap
    from sage.all import RealField, RealIntervalField, RR
    import estimator.lwe_dual as dual
    from estimator.reduction import ADPS16, RC

    path = Path(dual.__file__).resolve(strict=True)
    original = dual.MATZOV.cost.__func__
    source_sha = "8f6a077589393f907fbcc87b9ef812beafc73bf5cc78abc4f857924b80a21a8b"
    if (hashlib.sha256(path.read_bytes()).hexdigest() != source_sha or
            original.__module__ != "estimator.lwe_dual" or
            Path(original.__code__.co_filename).resolve(strict=True) != path):
        raise RuntimeError("Unexpected official dual cost implementation")
    nearest = RealField(30)
    real_type = type(RR(1))

    def stable(sigma, fallback):
        # For3<=sigma<=4,81<alpha=pi^2*sigma^2<160 and0<tanh(alpha)<1.
        # Thus0<delta=8*alpha*exp(-2*alpha)*tanh(alpha)<2^-151,
        # and0<exp(delta)-1<2^-150<half-ulp(1)=2^-30 at precision30.
        if type(sigma) is real_type and sigma.parent() is RR and RR(3) <= sigma <= RR(4):
            return nearest(1)
        return fallback()

    tree = ast.parse(textwrap.dedent(inspect.getsource(original)))
    function = tree.body[0]
    assignments = [node for node in ast.walk(function) if isinstance(node, ast.Assign)
                   and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                   and node.targets[0].id == "tmp_a"]
    expected = ast.parse("exp(8 * tmp_alpha * exp(-2 * tmp_alpha) * tanh(tmp_alpha)).n(30)", mode="eval").body
    if len(assignments) != 1 or ast.dump(assignments[0].value) != ast.dump(expected):
        raise RuntimeError("Unexpected official dual rounding expression")
    old_expression = assignments[0].value
    assignments[0].value = ast.Call(
        func=ast.Name(id="_dcs_exact_tmp_a", ctx=ast.Load()),
        args=[ast.parse("params.Xs.stddev", mode="eval").body,
              ast.Lambda(args=ast.arguments(posonlyargs=[], args=[], kwonlyargs=[],
                                          kw_defaults=[], defaults=[]), body=old_expression)],
        keywords=[])
    namespace = dict(original.__globals__, _dcs_exact_tmp_a=stable)
    exec(compile(ast.fix_missing_locations(tree), "<exact-dual-scalar-rounding>", "exec"), namespace)
    descriptor = namespace[function.name]
    if not isinstance(descriptor, classmethod):
        raise RuntimeError("Unexpected dual method descriptor")
    candidate = descriptor.__func__
    candidate.__qualname__ = original.__qualname__

    # Directed interval arithmetic independently encloses every gate scalar.
    interval = RealIntervalField(256)
    for i in range(17):
        sigma = RR(3) + RR(i) / 16
        alpha = interval.pi()**2 * interval(sigma.exact_rational())**2
        value = (8 * alpha * (-2 * alpha).exp() * alpha.tanh()).exp()
        if nearest(value.lower()) != nearest(1) or nearest(value.upper()) != nearest(1):
            raise RuntimeError("Dual scalar interval did not certify unique rounding")
        original_value = eval(compile(ast.Expression(expected), "<original-dual-scalar>", "eval"),
                              dict(original.__globals__, tmp_alpha=dual.pi**2 * sigma**2))
        if type(original_value) is not type(nearest(1)) or original_value != stable(sigma, lambda: None):
            raise RuntimeError("Original dual scalar equivalence mismatch")
    for sigma in (RR(2), RR(5)):
        marker = object()
        if stable(sigma, lambda: marker) is not marker:
            raise RuntimeError("Unsupported dual scalar bypassed original expression")
    count = 0
    for model in (RC.MATZOV, ADPS16(mode="classical")):
        for beta, guessed in ((776, 0), (781, 0), (776, 20), (781, 20)):
            arguments = dict(p=3, k_enum=guessed, red_cost_model=model)
            expected_cost = original(dual.MATZOV, beta, params, **arguments)
            metadata = dict(dual.Cost.impermanents)
            actual = candidate(dual.MATZOV, beta, params, **arguments)
            if (type(actual) is not type(expected_cost) or list(actual.items()) != list(expected_cost.items())
                    or dict(dual.Cost.impermanents) != metadata):
                raise RuntimeError("Dual full Cost/type/order/metadata mismatch")
            count += 1
    if hashlib.sha256(path.read_bytes()).hexdigest() != source_sha or dual.MATZOV.cost.__func__ is not original:
        raise RuntimeError("Dual source/function changed during the gate")
    dual.MATZOV.cost = descriptor
    return dict(implementation="exact_dual_tmp_a_round30_v1", official_dual_sha256=source_sha,
                scalar_interval_and_original_cases=17, original_fallback_cases=2,
                full_cost_type_order_metadata_cases=count, equivalence_gate_complete=True,
                official_source_files_unchanged=True, vanilla_official_execution=False,
                security_assessed=False, sql_accepted=False, full_query_500ms_established=False)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--estimator-root", type=Path, required=True)
    parser.add_argument("--model", choices=("both-classical", "matzov-classical",
                        "adps16-classical", "adps16-quantum-sensitivity"),
                        default="both-classical")
    parser.add_argument("--max-seconds-per-model", type=int, default=600)
    args = parser.parse_args()
    if not 1 <= args.max_seconds_per_model <= 600:
        parser.error("The reviewed per-model wall bound must be 1..600 seconds")
    if platform.system() != "Linux" or not hasattr(signal, "setitimer"):
        raise RuntimeError("The reviewed bounded runtime is Linux Sage, not a host shim")

    repo = args.estimator_root.resolve(strict=True)
    source_before = verify_source(repo)
    emit("public_inputs_only", **public_inputs(), estimator=source_before,
         script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())

    # These are real Sage imports. A CPython package or compatibility shim is not Sage.
    from sage.env import SAGE_VERSION as actual_sage_version
    from sage.all import RealField, ZZ, oo
    if str(actual_sage_version) != SAGE_VERSION:
        raise RuntimeError(f"Sage runtime mismatch: expected {SAGE_VERSION}, got {actual_sage_version}")
    sys.path.insert(0, str(repo))
    from estimator import LWE, ND
    from estimator.reduction import ADPS16, RC
    from estimator.simulator import GSA

    import resource
    real = RealField(256)
    params = LWE.Parameters(
        n=N, q=ZZ(Q), Xs=ND.CenteredBinomial(ETA), Xe=ND.CenteredBinomial(ETA),
        m=oo, tag="DCS-N4096-Q2-CBD20-unlimited-independent-LWE-heuristic")
    models = []
    if args.model in ("both-classical", "matzov-classical"):
        models.append(("matzov-classical", RC.MATZOV, False))
    if args.model in ("both-classical", "adps16-classical"):
        models.append(("adps16-classical", ADPS16(mode="classical"), False))
    if args.model == "adps16-quantum-sensitivity":
        models.append((args.model, ADPS16(mode="quantum"), True))
    emit("runtime", sage=str(actual_sage_version), python=sys.version,
         platform=platform.platform(), configured_attacks=list(ATTACKS),
         deny_list=[], add_list=[], shape="GSA", catch_exceptions=False,
         jobs=1, model_deadline_seconds=args.max_seconds_per_model,
         ordinary_estimator_not_rough=True, runtime_not_installed_by_script=True,
         asynchronous_stack_sampling=False)

    # BEGIN explicit reviewed exact-coefficient implementation override.
    import importlib.util
    exact_path = Path(__file__).with_name("exact_gb_cost.py").resolve(strict=True)
    if hashlib.sha256(exact_path.read_bytes()).hexdigest() != "188a1e011c9841bda5aa8b894d2cdfdb6a616fc9e2d7874332d703786372141a":
        raise RuntimeError("Exact GB optimization module source mismatch")
    exact_spec = importlib.util.spec_from_file_location("dcs_public_exact_gb_cost", exact_path)
    if exact_spec is None or exact_spec.loader is None:
        raise RuntimeError("Exact GB optimization module loader unavailable")
    exact_module = importlib.util.module_from_spec(exact_spec)
    exact_spec.loader.exec_module(exact_module)
    emit("implementation_provenance", **exact_module.install())
    # END explicit reviewed exact-coefficient implementation override.
    emit("dual_rounding_provenance", **install_exact_dual_rounding(params))

    all_finite = []
    signal.signal(signal.SIGALRM, limit_alarm)
    for name, cost_model, quantum_sensitivity in models:
        start = time.perf_counter()
        cpu_start = time.process_time()
        emit("model_start", model=name, model_type=type(cost_model).__name__,
             model_state={k: str(v) for k, v in vars(cost_model).items()},
             quantum_reduction_sensitivity_only=quantum_sensitivity,
             complete_quantum_attack_model=False)
        signal.setitimer(signal.ITIMER_REAL, args.max_seconds_per_model)
        try:
            restore_progress, check_progress = install_attack_progress(
                emit, ATTACKS, name, params.normalize())
            try:
                results = LWE.estimate(
                    params, red_cost_model=cost_model, red_shape_model=GSA,
                    deny_list=tuple(), add_list=tuple(), jobs=1,
                    catch_exceptions=False, quiet=False)
            finally:
                restore_progress()
            check_progress(results)
            # Preserve EVERY configured result, including infinity and dominated ones.
            # The upstream pretty printer may omit dominated hybrids; its returned map matters.
            for attack in ATTACKS:
                if attack not in results:
                    emit("missing_attack", model=name, attack=attack)
                    continue
                result = results[attack]
                cost = result.get("rop", oo)
                finite = cost != oo and cost > 0
                log2_cost = str(real(cost).log(2)) if finite else None
                emit("attack_result", model=name, attack=attack,
                     fields={str(k): str(v) for k, v in result.items()},
                     finite_positive_rop=bool(finite), rop_log2=log2_cost,
                     quantum_reduction_sensitivity_only=quantum_sensitivity)
                if finite:
                    all_finite.append((real(cost), name, attack))
            missing = sorted(set(ATTACKS) - set(results))
            if missing:
                raise RuntimeError(f"Incomplete attack sweep: {missing}")
            if not any(r.get("rop", oo) != oo and r.get("rop", oo) > 0
                       for r in results.values()):
                raise RuntimeError("No finite positive operation cost; no minimum estimate")
        except Exception as error:
            emit("model_incomplete", model=name, error_type=type(error).__name__,
                 error=str(error), wall_seconds=time.perf_counter() - start,
                 cpu_seconds=time.process_time() - cpu_start,
                 peak_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                 security_assessed=False)
            raise
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
        emit("model_complete", model=name, wall_seconds=time.perf_counter() - start,
             cpu_seconds=time.process_time() - cpu_start,
             peak_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
             security_assessed=False)

    if verify_source(repo) != source_before:
        raise RuntimeError("Estimator source changed during evaluation")
    minimum, model, attack = min(all_finite, key=lambda item: item[0])
    emit("attack_cost_estimates_only", model=model, attack=attack,
         minimum_rop_log2=str(minimum.log(2)), security_assessed=False,
         quantum_security_assessed=False, arithmetic_proof_security_assessed=False,
         sql_accepted=False, full_query_500ms_established=False)


if __name__ == "__main__":
    main()
