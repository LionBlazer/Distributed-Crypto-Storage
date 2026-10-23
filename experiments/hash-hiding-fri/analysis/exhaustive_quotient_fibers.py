"""Exhaustive F17 quotient-mask fibers; research arithmetic, no crypto grant."""
from collections import Counter
from itertools import product
from pathlib import Path
import hashlib
import json
import sys
import time

P, N = 17, 4
START = time.monotonic()


def canonical(a):
    a = [x % P for x in a]
    while len(a) > 1 and a[-1] == 0:
        a.pop()
    return tuple(a or [0])


def add(a, b):
    out = [0] * max(len(a), len(b))
    for i, x in enumerate(a):
        out[i] += x
    for i, x in enumerate(b):
        out[i] += x
    return canonical(out)


def scale(a, c):
    return canonical([x * c for x in a])


def multiply(a, b):
    out = [0] * (len(a) + len(b) - 1)
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            out[i + j] += x * y
    return canonical(out)


def remainder(a, modulus):
    out = list(canonical(a))
    inverse = pow(modulus[-1], -1, P)
    while len(out) >= len(modulus):
        factor, offset = out[-1] * inverse % P, len(out) - len(modulus)
        for j, x in enumerate(modulus):
            out[offset + j] = (out[offset + j] - factor * x) % P
        while len(out) > 1 and out[-1] == 0:
            out.pop()
    return canonical(out)


def evaluate(a, point):
    value = 0
    for x in reversed(a):
        value = (value * point + x) % P
    return value


def residue(a, modulus):
    out = remainder(a, modulus)
    return out + (0,) * (len(modulus) - 1 - len(out))


def affine_target(selectors, qbar, modulus):
    """Independent target: solve the residue equation by ordinary F17 RREF."""
    m = len(modulus) - 1
    columns = [residue(multiply(lam, (0,) * j + (1,)), modulus)
               for lam in selectors for j in range(m)]
    rows = [[columns[j][i] for j in range(2 * m)] + [qbar[i]]
            for i in range(m)]
    pivots = []
    for column in range(2 * m):
        pivot = next((r for r in range(len(pivots), m) if rows[r][column]), None)
        if pivot is None:
            continue
        r = len(pivots)
        rows[r], rows[pivot] = rows[pivot], rows[r]
        inv = pow(rows[r][column], -1, P)
        rows[r] = [x * inv % P for x in rows[r]]
        for other in range(m):
            if other != r:
                factor = rows[other][column]
                rows[other] = [(a - factor * b) % P
                               for a, b in zip(rows[other], rows[r])]
        pivots.append(column)
        if len(pivots) == m:
            break
    assert len(pivots) == m, "selector equation must have full residue rank"
    free = [j for j in range(2 * m) if j not in pivots]
    solutions = set()
    for choices in product(range(P), repeat=len(free)):
        y = [0] * (2 * m)
        for j, x in zip(free, choices):
            y[j] = x
        for r, pivot in enumerate(pivots):
            y[pivot] = (rows[r][-1] - sum(rows[r][j] * y[j] for j in free)) % P
        solutions.add(tuple(y))
    return solutions


def check_case(name, modulus, shifts, vanish, constants, selectors):
    m = len(modulus) - 1
    original = ((2, 3, 4, 1), (7, 0, 2, 5))
    # Change both residue slots without using the native mask parameterization.
    alternative = (add(original[0], remainder(selectors[1], modulus)),
                   add(original[1], scale(remainder(selectors[0], modulus), -1)))
    assert original != alternative and all(len(q) <= N for q in alternative)

    def recomposed(q):
        return add(multiply(selectors[0], q[0]), multiply(selectors[1], q[1]))

    qbar = residue(recomposed(original), modulus)
    assert residue(recomposed(alternative), modulus) == qbar
    target = affine_target(selectors, qbar, modulus)
    observed, changed = Counter(), Counter()
    ratio = -constants[0] * pow(constants[1], -1, P) % P

    # Act: every literal native coefficient mask, before any quotient-ring reduction.
    for index, first in enumerate(product(range(P), repeat=N)):
        if index % 1024 == 0 and time.monotonic() - START > 90:
            raise TimeoutError("bounded arithmetic run exceeded 90 seconds")
        second = scale(first, ratio)
        noise = (multiply(vanish[0], first), multiply(vanish[1], second))
        for q, counts in ((original, observed), (alternative, changed)):
            disclosed = tuple(x for i in range(2)
                              for x in residue(add(q[i], noise[i]), modulus))
            counts[disclosed] += 1

    # Assert: a different algorithm defines the whole target, not just its cardinality.
    assert set(observed) == target
    assert changed == observed
    assert len(target) == P ** m
    assert set(observed.values()) == {P ** (N - m)}
    assert sum(observed.values()) == P ** N
    vanishing_at = [i for i, shift in enumerate(shifts)
                    if evaluate(modulus, shift) == 0]
    for i in vanishing_at:
        assert evaluate(vanish[i], shifts[i]) == 0
        for y in observed:
            assert evaluate(y[i * m:(i + 1) * m], shifts[i]) == evaluate(original[i], shifts[i])
    return {"name": name, "modulus": modulus, "residue_degree": m,
            "literal_masks": P ** N, "support": len(target),
            "equal_fiber_size": P ** (N - m),
            "same_Q_different_originals": True, "vanishing_chunk_cases": vanishing_at}


def main():
    # Arrange exact native-normalized domains, independently checking the selectors.
    assert pow(3, 8, P) == P - 1 and pow(3, 16, P) == 1
    shifts = (3, 3 * pow(3, 2, P) % P)
    domains = [{s * pow(3, 4 * j, P) % P for j in range(N)} for s in shifts]
    whole = {3 * pow(3, 2 * j, P) % P for j in range(2 * N)}
    assert not domains[0] & domains[1] and domains[0] | domains[1] == whole
    vanish = [canonical((-1, 0, 0, 0, pow(s, -N, P))) for s in shifts]
    constants = [pow(evaluate(vanish[1 - i], shifts[i]), -1, P) for i in range(2)]
    selectors = [scale(vanish[1 - i], constants[i]) for i in range(2)]
    assert add(*selectors) == (1,)
    for i in range(2):
        for j, domain in enumerate(domains):
            assert all(evaluate(selectors[i], x) == int(i == j) for x in domain)
            assert all(evaluate(vanish[i], x) == 0 for x in domains[i])
    inside, outside, quadratic = (-3 % P, 1), (-1 % P, 1), (-3 % P, 0, 1)
    assert all(evaluate(quadratic, x) != 0 for x in range(P))
    assert 3 in whole and 1 not in whole
    cases = [("linear_inside_U", inside), ("linear_outside_U", outside),
             ("irreducible_quadratic", quadratic),
             ("linear_times_quadratic", multiply(inside, quadratic))]
    results = [check_case(name, modulus, shifts, vanish, constants, selectors)
               for name, modulus in cases]
    report = {"status": "passed", "scope": "finite_F17_arithmetic_only",
              "python": sys.version.split()[0], "elapsed_seconds": time.monotonic() - START,
              "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "shifts": shifts, "constants": constants, "cases": results,
              "native_proofs": False, "cryptographic_admission": False}
    output = json.dumps(report, indent=2)
    if len(sys.argv) == 2:
        with open(sys.argv[1], "x", encoding="utf-8") as receipt:
            receipt.write(output + "\n")
    print(output)


if __name__ == "__main__":
    main()
