"""Analysis-only B primitive over first-notified typed Merkle words.

This module draws no coin, evaluates no AIR, and grants no native acceptance.
DATA/Query permit generalized field-valued PP. The other factories fail closed
at the final association step; a shape check is not their public factory parse.
"""

from array import array
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType

from merkle_extraction import (
    GOLD_ORDER as P, LEAF_DOMAIN, DictionaryOracle, Matrix, Schema, Snapshot, node_children,
)


class Family(Enum):
    SOURCE = "Source"
    ROLE3 = "Role3"
    DATA = "DATA"
    WORD = "Word"
    QUERY = "Query"


@dataclass(frozen=True, slots=True)
class Profile:
    public: int
    original: int
    main: int
    pp: int
    aux: int
    chunks: int

    @property
    def k(self) -> int:
        return 2 * self.original

    @property
    def depth(self) -> int:
        return self.k.bit_length() - 1 + 3


# Actual five native families, not reduced examples or caller-selected shapes.
PROFILES = MappingProxyType({
    Family.SOURCE: Profile(691, 512, 7161, 0, 0, 16),
    Family.ROLE3: Profile(740, 512, 1656, 0, 0, 16),
    Family.DATA: Profile(32, 2048, 512, 668, 82, 8),
    Family.WORD: Profile(309, 512, 568, 714, 35, 8),
    Family.QUERY: Profile(32, 2048, 416, 545, 84, 8),
})


def profile(family: Family) -> Profile:
    if type(family) is not Family:
        raise ValueError("one exact closed family required")
    return PROFILES[family]


def public_shape(family: Family, values: tuple[int, ...]) -> tuple[int, ...]:
    """Canonical complete PV shape; not Source/Role3 factory validity."""
    geometry = profile(family)
    if type(values) is not tuple or len(values) != geometry.public:
        raise ValueError("immutable complete public tuple required")
    if any(type(x) is not int or not 0 <= x < P for x in values):
        raise ValueError("noncanonical Gold public value")
    byte_words: tuple[int, ...] = ()
    if family is Family.SOURCE:
        byte_words = values[:683]
    elif family is Family.ROLE3:
        byte_words = values[:691] + values[699:724] + values[728:736]
    if any(x >= (1 << 32) for x in byte_words):
        raise ValueError("noncanonical public byte packing")
    return values


@dataclass(frozen=True, slots=True)
class Columns:
    width: int
    extension: int = 1
    hiding: int = 0

    @property
    def base_width(self) -> int:
        return self.width * self.extension + self.hiding


@dataclass(frozen=True, slots=True)
class TypedCap:
    family: Family
    role: str
    depth: int
    matrices: tuple[Columns, ...]

    @property
    def schema(self) -> Schema:
        # One equal-height partition. Each matrix has its own trailing salt4.
        # Flattening EF coordinates changes no byte or matrix boundary.
        return Schema(self.depth, tuple(Matrix(m.base_width) for m in self.matrices))


def cap_type(family: Family, role: str, round_index: int | None = None) -> TypedCap:
    geometry = profile(family)
    if type(role) is not str:
        raise ValueError("exact commitment role required")
    if role == "FRI":
        rounds = geometry.k.bit_length() - 1
        if type(round_index) is not int or not 0 <= round_index < rounds:
            raise ValueError("fixed FRI round required")
        return TypedCap(family, role, geometry.depth - round_index - 1,
                        (Columns(2, 5),))
    if round_index is not None:
        raise ValueError("round only belongs to FRI")
    if role == "MAIN":
        matrices = (Columns(geometry.main, hiding=5),)
    elif role == "PP" and geometry.pp:
        matrices = (Columns(geometry.pp),)
    elif role == "AUX" and geometry.aux:
        matrices = (Columns(geometry.aux, 5, 5),)
    elif role == "quotient":
        matrices = (Columns(1, 5, 5),) * geometry.chunks
    elif role == "random":
        matrices = (Columns(1, 5, 5),)
    else:
        raise ValueError("role absent from this closed family")
    return TypedCap(family, role, geometry.depth, matrices)


def domain_point(depth: int, physical_row: int) -> int:
    """Native physical order x=7*omega^bitreverse(row), never a caller coset."""
    if type(depth) is not int or not 0 <= depth <= 15:
        raise ValueError("closed domain depth")
    n = 1 << depth
    if type(physical_row) is not int or not 0 <= physical_row < n:
        raise ValueError("physical row outside domain")
    exponent = 0
    for bit in range(depth):
        exponent = (exponent << 1) | ((physical_row >> bit) & 1)
    return 7 * pow(pow(7, (P - 1) // n, P), exponent, P) % P


def _canonical_leaf(raw: bytes | None, count: int) -> bytes | None:
    if (type(raw) is not bytes or len(raw) != len(LEAF_DOMAIN) + count * 8 + 8
            or not raw.startswith(LEAF_DOMAIN)
            or int.from_bytes(raw[-8:], "little") != count):
        return None
    start = len(LEAF_DOMAIN)
    if any(int.from_bytes(raw[start + i * 8:start + (i + 1) * 8], "little") >= P
           for i in range(count)):
        return None
    return raw


@dataclass(frozen=True, slots=True)
class Projection:
    values: tuple[int | tuple[int, ...], ...]
    codewords: tuple[int, ...]
    salts: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class FrozenWord:
    typed: TypedCap
    root: bytes
    cutoff: int
    _leaves: tuple[bytes | None, ...]

    @classmethod
    def first(cls, typed: TypedCap, snapshot: Snapshot) -> "FrozenWord":
        # Reject forged/re-timed Snapshot objects, mutable row callbacks, and a
        # different cut of the same total leaf width. No later query is issued.
        if type(typed) is not TypedCap or typed != cap_type(
                typed.family, typed.role):
            raise ValueError("exact input commitment type required")
        if type(snapshot) is not Snapshot or snapshot.schema != typed.schema:
            raise ValueError("first snapshot has wrong typed schema")
        oracle = snapshot._oracle
        if (type(oracle) is not DictionaryOracle
                or oracle._snapshots.get((snapshot.schema, snapshot.root)) is not snapshot):
            raise ValueError("not the first registered notification")
        count = typed.schema.field_count
        memo: dict[tuple[bytes, int], tuple[bytes | None, ...]] = {}

        def walk(root: bytes, depth: int) -> tuple[bytes | None, ...]:
            key = (root, depth)
            if key not in memo:
                raw = oracle.preimage_at(root, snapshot.cutoff)
                if depth == 0:
                    result = (_canonical_leaf(raw, count),)
                else:
                    children = node_children(raw) if raw is not None else None
                    result = ((None,) * (1 << depth) if children is None else
                              walk(children[0], depth - 1) + walk(children[1], depth - 1))
                memo[key] = result
            return memo[key]

        leaves = walk(snapshot.root, snapshot.schema.depth)
        return cls(typed, snapshot.root, snapshot.cutoff, leaves)

    def _field(self, raw: bytes | None, column: int) -> int:
        if raw is None:
            return 0
        offset = len(LEAF_DOMAIN) + column * 8
        return int.from_bytes(raw[offset:offset + 8], "little")

    def row(self, index: int) -> tuple[Projection, ...]:
        if type(index) is not int or not 0 <= index < len(self._leaves):
            raise ValueError("frozen row outside domain")
        raw, offset, result = self._leaves[index], 0, []
        for matrix in self.typed.matrices:
            fields = tuple(self._field(raw, offset + j) for j in range(matrix.base_width + 4))
            data_end = matrix.width * matrix.extension
            data = fields[:data_end]
            values = data if matrix.extension == 1 else tuple(
                tuple(data[j:j + 5]) for j in range(0, data_end, 5))
            result.append(Projection(values, fields[data_end:matrix.base_width], fields[-4:]))
            offset += matrix.base_width + 4
        return tuple(result)

    def pp_degree(self, column: int) -> int:
        if (self.typed.role != "PP" or type(column) is not int
                or not 0 <= column < profile(self.typed.family).pp):
            raise ValueError("fixed PP column required")
        # A shared constant leaf (including default completion) needs no FFT.
        # Salt fields never enter any PP column polynomial.
        first = self._leaves[0]
        if all(raw is first for raw in self._leaves):
            return 0 if self._field(first, column) else -1
        values = array("Q", (self._field(raw, column) for raw in self._leaves))
        coefficients = _coset_coefficients(values)
        return next((i for i in range(len(coefficients) - 1, -1, -1)
                     if coefficients[i]), -1)


def _coset_coefficients(bit_reversed_values: array) -> array:
    """One-column inverse FFT for x=7*K, using O(n) bounded packed workspace."""
    n = len(bit_reversed_values)
    if n < 1 or n > (1 << 15) or n & (n - 1):
        raise ValueError("closed radix-two column extent")
    # Native bit-reversed samples already are the input permutation for DIT.
    a = array("Q", bit_reversed_values)
    width = 2
    while width <= n:
        step = pow(7, (P - 1) // width, P)
        step = pow(step, P - 2, P)
        for start in range(0, n, width):
            twiddle = 1
            for j in range(width // 2):
                left, right = start + j, start + j + width // 2
                u, v = a[left], a[right] * twiddle % P
                a[left], a[right] = (u + v) % P, (u - v) % P
                twiddle = twiddle * step % P
        width *= 2
    scale, shift = pow(n, P - 2, P), 1
    inverse_coset = pow(7, P - 2, P)
    for i in range(n):
        a[i] = a[i] * scale % P * shift % P
        shift = shift * inverse_coset % P
    return a


@dataclass(frozen=True, slots=True)
class MuAnalysis:
    family: Family
    public: tuple[int, ...]
    pp: FrozenWord
    degrees: tuple[int, ...]


class DegreeRecognizer:
    """Single notification followed by B validation BEFORE the first coin.

    This state machine does not parse raw SHA512 prefixes or sample a coin.
    That caller must invoke notify at its first potential typed notification.
    """

    def __init__(self) -> None:
        self._pending: tuple[Family, tuple[int, ...], FrozenWord] | None = None
        self._closed = False

    def notify(self, family: Family, public: tuple[int, ...], pp: Snapshot) -> None:
        if self._pending is not None or self._closed:
            raise ValueError("only the first notification may select the instance")
        # Consume even malformed attempts; a failed prefix is not repaired in place.
        self._closed = True
        values = public_shape(family, public)
        if family not in (Family.DATA, Family.QUERY):
            raise ValueError("exact Source/Role3/Word factory association not implemented")
        frozen = FrozenWord.first(cap_type(family, "PP"), pp)
        self._pending = (family, values, frozen)
        self._closed = False

    def before_first_coin(self) -> MuAnalysis:
        if self._closed or self._pending is None:
            raise ValueError("missing first notification or already consumed")
        self._closed = True
        family, public, word = self._pending
        geometry = profile(family)
        degrees = []
        for column in range(geometry.pp):
            degree = word.pp_degree(column)
            if degree >= geometry.k:
                raise ValueError("frozen PP degree reaches k before the first coin")
            degrees.append(degree)
        return MuAnalysis(family, public, word, tuple(degrees))
