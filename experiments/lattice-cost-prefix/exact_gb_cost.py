"""Exact sparse differential coefficients for a pinned public research estimator.

Pure integer coefficient generation needs only Python. The explicit install()
adapter additionally requires Sage and the byte-pinned official estimator; it
changes one in-memory function only after an independent Sage equivalence gate.
Neither interface establishes attack costs or cryptographic security by itself.
"""
from hashlib import sha256
from pathlib import Path

OFFICIAL_GB_SHA256 = "d785ee73ad40a470422d1ddc21d76e9f32b8ab1d85d88ae2539590b32bbd7edc"
IMPLEMENTATION = "exact_integer_sparse_differential_prefix_v2"
_installed = False


def _positive_integer(value, Integer):
    return type(value) is not bool and (type(value) is int or isinstance(value, Integer)) and value > 0


def _nonnegative_integer(value, Integer):
    return type(value) is not bool and (type(value) is int or isinstance(value, Integer)) and value >= 0


def _domain(n, factors, prec, Integer):
    """Reject unsupported types without consuming iterators or coercing floats."""
    if not _positive_integer(n, Integer) or type(factors) not in (list, tuple):
        return None
    precision = 2 * n if prec is None else prec
    if not _positive_integer(precision, Integer):
        return None
    normalized = []
    for pair in factors:
        if type(pair) not in (list, tuple) or len(pair) != 2:
            return None
        d, multiplicity = pair
        if not (_positive_integer(d, Integer)
                and _nonnegative_integer(multiplicity, Integer)):
            return None
        normalized.append((Integer(d), Integer(multiplicity)))
    return Integer(n), tuple(normalized), int(precision)


def _times_factor(polynomial, degree, precision):
    """Exact truncated multiplication by (1-z**degree), as sparse integer terms."""
    result = dict(polynomial)
    for power, value in polynomial.items():
        at = power + degree
        if at < precision:
            result[at] = result.get(at, 0) - value
    return {power: value for power, value in result.items() if value != 0}


def _differential(n, factors, precision, Integer):
    """P*H'=R*H, P=(1-z)*prod_distinct(1-z**d), P(0)=1.

    Zero multiplicities and degrees >= precision are exact identities at this
    truncation. Equal degrees combine by addition; huge exponents are NEVER
    expanded into dense polynomial powers. P and R need only coefficients below
    precision. This is an algebraic rewrite, not early attack-cost pruning.
    """
    combined = {}
    for degree, multiplicity in factors:
        if multiplicity and degree < precision:
            degree = int(degree)
            combined[degree] = combined.get(degree, Integer(0)) + multiplicity
    degrees = sorted(combined)
    quotient = {0: Integer(1)}
    for degree in degrees:
        quotient = _times_factor(quotient, degree, precision)
    p = _times_factor(quotient, 1, precision)
    r = {power: n * value for power, value in quotient.items()}
    for degree in degrees:
        without = {0: Integer(1)}
        for other in degrees:
            if other != degree:
                without = _times_factor(without, other, precision)
        scale = combined[degree] * degree
        for power, value in without.items():
            # -(1-z)*m*d*z**(d-1)*prod_other(1-z**other)
            for at, sign in [(power + degree - 1, -1), (power + degree, 1)]:
                if at < precision:
                    r[at] = r.get(at, Integer(0)) + sign * scale * value
    shifts = sorted(set(p).union(power + 1 for power in r))
    return [(shift, p.get(shift, Integer(0)), r.get(shift - 1, Integer(0)))
            for shift in shifts if 0 < shift < precision
            and (p.get(shift, 0) != 0 or r.get(shift - 1, 0) != 0)]


def _coefficients(n, factors, precision, Integer):
    """Yield A[0..precision-1] exactly; caller may stop at first negative.

    From P*H'=R*H:
      k*A[k] = sum((R[i-1]-(k-i)*P[i])*A[k-i], i=1..k).
    Only nonzero P/R shifts are visited. Division MUST have zero remainder.
    Both ordinary Python integers and Sage integers use the same exact code.
    """
    shifts = _differential(n, factors, precision, Integer)
    values = [Integer(1)]
    yield values[0]
    for degree in range(1, precision):
        numerator = Integer(0)
        for shift, p, r in shifts:
            if shift > degree:
                break
            numerator += (r - (degree - shift) * p) * values[degree - shift]
        coefficient, remainder = divmod(numerator, degree)
        if remainder != 0:
            raise ArithmeticError("Exact GB differential recurrence was not integral")
        values.append(coefficient)
        yield coefficient


def coefficients(n, factors, precision):
    """Public exact-integer series API; no Sage, network, installation or cost claim."""
    normalized = _domain(n, factors, precision, int)
    if normalized is None:
        raise ValueError("positive integer n/precision and nonnegative integer factors required")
    yield from _coefficients(*normalized, int)


def first_negative(n, factors, precision):
    """First STRICTLY negative coefficient below precision, or None after all pass."""
    return next((i for i, value in enumerate(coefficients(n, factors, precision)) if value < 0), None)


def _cost(gb, original_n, normalized, omega, Integer):
    n, factors, precision = normalized
    retval = gb.Cost(rop=gb.oo, dreg=gb.oo)
    retval.register_impermanent({"rop": True, "dreg": False, "mem": False})
    for degree, coefficient in enumerate(_coefficients(n, factors, precision, Integer)):
        if coefficient < 0:
            retval["dreg"] = degree
            retval["rop"] = gb.binomial(original_n + degree, degree) ** omega
            retval["mem"] = gb.binomial(original_n + degree, degree) ** 2
            break
    return retval


def _wrapper(gb, original, Integer):
    def exact_gb_cost(n, D, omega=2, prec=None):
        normalized = _domain(n, D, prec, Integer)
        if normalized is None:
            return original(n, D, omega=omega, prec=prec)
        return _cost(gb, n, normalized, omega, Integer)
    return exact_gb_cost


def _equivalence_gate(gb, original, candidate, Integer):
    """Independent QQ PowerSeries oracle; every checked coefficient and Cost is exact."""
    cases = [(n, [(d, m)], 12, 2)
             for n in range(1, 5) for d in range(1, 5) for m in range(1, 4)]
    cases += [
        (2, [(1, 2), (2, 1)], 2, 2),  # zero before first negative, outside precision
        (2, [(1, 2), (2, 1)], 3, 2),  # zero before first negative, included
        (7, [(2, 3), (3, 8)], 24, 2),
        (9, [(3, 2), (3, 4), (5, 1)], 28, 2),  # repeated degrees
        (4, [(9, 2)], 8, 2),  # factor outside truncation
        (16, [(5, Integer(2) ** 80 + 7)], 32, 2),
        (3, [], 14, 2),
        (8, [(2, 7), (7, 2)], 16, gb.QQ(3) / 2),
        (Integer(4), [(Integer(2), Integer(6))], None, 2),
        (4, [(2, 0)], 16, 2),
        (8, [(3, 0), (5, 4)], 24, 2),
        (8, [(1, 0), (3, 0)], 24, 2),
        (8, [(3, 0), (3, 4)], 24, 2),
        (8, [(3, 4), (3, 0)], 24, 2),
        (8, [(1, 8)], 24, 2),
        (8, [(1, 9)], 24, 2),
        (8, [(2, 3), (2, 5), (5, 0)], 24, 2),
        (12, [(9, 2), (41, 12)], 96, 2),
        (32, [(9, 0), (41, 32)], 96, 2),
        (16, [(9, 1), (41, 16)], 96, 2),
    ]
    checked_coefficients = 0
    for n, factors, prec, omega in cases:
        normalized = _domain(n, factors, prec, Integer)
        if normalized is None:
            raise RuntimeError("GB oracle case unexpectedly outside exact domain")
        precision = normalized[2]
        # This is the upstream expression, not the recurrence under test.
        ring = gb.PowerSeriesRing(gb.QQ, "z", precision)
        z = ring.gen().add_bigoh(precision)
        one = ring(1).add_bigoh(precision)
        reference = gb.prod(((1 - z**d)**m for d, m in factors), one) / (1 - z) ** n
        actual = list(_coefficients(*normalized, Integer))
        if len(actual) != precision or any(actual[k] != reference[k] for k in range(precision)):
            raise RuntimeError("Exact GB coefficient/Sage oracle mismatch")
        checked_coefficients += precision
        expected = original(n, factors, omega=omega, prec=prec)
        expected_metadata = dict(gb.Cost.impermanents)
        observed = candidate(n, factors, omega=omega, prec=prec)
        if (type(observed) is not type(expected)
                or list(observed.items()) != list(expected.items())
                or dict(gb.Cost.impermanents) != expected_metadata):
            raise RuntimeError("Exact GB Cost/metadata oracle mismatch")
    # Exercise actual official fallback with valid upstream inputs outside our domain.
    fallback_cases = [(3, [(2, -1)], 12), (gb.QQ(3), [(2, 4)], 12)]
    for n, factors, prec in fallback_cases:
        if _domain(n, factors, prec, Integer) is not None:
            raise RuntimeError("GB fallback oracle case unexpectedly optimized")
        expected = original(n, factors, prec=prec)
        expected_metadata = dict(gb.Cost.impermanents)
        observed = candidate(n, factors, prec=prec)
        if (type(observed) is not type(expected)
                or list(observed.items()) != list(expected.items())
                or dict(gb.Cost.impermanents) != expected_metadata):
            raise RuntimeError("Exact GB official fallback oracle mismatch")
    # Independent exact binomial identity for the observed public bounded baseline.
    # This is a coefficient check, not a complete attack cost or security estimate.
    n, d = Integer(4096), Integer(41)
    factors = [(d, n**d), (d, n)]
    normalized = _domain(n, factors, 42, Integer)
    prefix = list(_coefficients(*normalized, Integer))
    for k, actual in enumerate(prefix):
        expected = gb.binomial(n + k - 1, k)
        if k == d:
            expected -= n**d + n
        if actual != expected:
            raise RuntimeError("Exact public GB prefix/binomial oracle mismatch")
    negatives = [k for k, value in enumerate(prefix) if value < 0]
    if negatives != [41]:
        raise RuntimeError("Public GB first-negative prefix check failed")
    return {"full_sage_coefficient_cases": len(cases),
            "full_sage_coefficients_checked": checked_coefficients,
            "full_cost_and_metadata_cases": len(cases),
            "official_fallback_cases": len(fallback_cases),
            "public_bounded_prefix_coefficients_checked": len(prefix),
            "public_bounded_prefix_first_negative": negatives[0]}


def install():
    """Fail closed before patching on any source/oracle error; no file modification."""
    global _installed
    if _installed:
        raise RuntimeError("Exact GB implementation already installed")
    from sage.all import Integer
    import estimator.gb as gb
    original = gb.gb_cost
    source = Path(gb.__file__).resolve(strict=True)
    if (source.name != "gb.py" or sha256(source.read_bytes()).hexdigest() != OFFICIAL_GB_SHA256
            or original.__module__ != "estimator.gb" or original.__name__ != "gb_cost"
            or Path(original.__code__.co_filename).resolve(strict=True) != source):
        raise RuntimeError("Exact GB original source/function identity mismatch")
    candidate = _wrapper(gb, original, Integer)
    gate = _equivalence_gate(gb, original, candidate, Integer)
    if sha256(source.read_bytes()).hexdigest() != OFFICIAL_GB_SHA256 or gb.gb_cost is not original:
        raise RuntimeError("Exact GB source/global changed during equivalence gate")
    gb.gb_cost = candidate
    _installed = True
    return {"implementation_kind": "official_archive_with_explicit_in_memory_gb_override",
            "implementation": IMPLEMENTATION,
            "optimization_module_sha256": sha256(Path(__file__).read_bytes()).hexdigest(),
            "official_gb_sha256": OFFICIAL_GB_SHA256,
            "official_source_files_unchanged": True,
            "vanilla_official_execution": False,
            "equivalence_gate_complete": True,
            "coefficient_ring": "exact integers embedded in QQ",
            "first_negative_test": "strictly_less_than_zero",
            "unsupported_domain": "unchanged_official_gb_cost",
            "gate": gate,
            "security_assessed": False,
            "quantum_security_assessed": False,
            "arithmetic_proof_security_assessed": False,
            "sql_accepted": False,
            "full_query_500ms_established": False}
