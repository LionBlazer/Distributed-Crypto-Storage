"""Finite online-extraction model; supplied outputs are NOT SHA256 or a ROM proof.

All leaf/node byte encodings match the closed suite. No production verifier,
key material, arbitrary AIR, crypto-security estimate or admission token exists.
The oracle step is single-threaded and atomic: it has no user callback between
drawing an assigned output and recording the completed query's child targets.
"""

from dataclasses import dataclass
from typing import Mapping

GOLD_ORDER = 18446744069414584321
LEAF_DOMAIN = b"DCS/research/hash-hiding-FRI/SHA256/leaf/ValLE8/countLE64/v1\0"
NODE_DOMAIN = b"DCS/research/hash-hiding-FRI/SHA256/node/binary32/v1\0"
SALT_FIELDS = 4
MAX_DEPTH = 15
MAX_LEAF_FIELDS = 65536

LogicalValue = int | tuple[int, ...]
MatrixRow = tuple[LogicalValue, ...]
OpenedRows = tuple[MatrixRow, ...]


def digest(value: int) -> bytes:
    """Readable deterministic toy answer, never a cryptographic hash."""
    if type(value) is not int or not 0 <= value < (1 << 256):
        raise ValueError("toy digest outside256 bits")
    return value.to_bytes(32, "big")


def _digest(value: bytes) -> bytes:
    if type(value) is not bytes or len(value) != 32:
        raise ValueError("digest must be32 raw bytes")
    return value


def _field(value: int) -> int:
    if type(value) is not int or not 0 <= value < GOLD_ORDER:
        raise ValueError("noncanonical Gold word")
    return value


def encode_leaf(fields: tuple[int, ...]) -> bytes:
    if len(fields) > MAX_LEAF_FIELDS:
        raise ValueError("leaf field limit")
    words = b"".join(_field(x).to_bytes(8, "little") for x in fields)
    return LEAF_DOMAIN + words + len(fields).to_bytes(8, "little")


def encode_node(left: bytes, right: bytes) -> bytes:
    return NODE_DOMAIN + _digest(left) + _digest(right)


def node_children(raw: bytes) -> tuple[bytes, bytes] | None:
    if len(raw) != len(NODE_DOMAIN) + 64 or not raw.startswith(NODE_DOMAIN):
        return None
    start = len(NODE_DOMAIN)
    return raw[start:start + 32], raw[start + 32:start + 64]


def decode_leaf(raw: bytes, expected_count: int) -> tuple[int, ...] | None:
    if type(expected_count) is not int or not 0 <= expected_count <= MAX_LEAF_FIELDS:
        raise ValueError("closed leaf count limit")
    # Check the exact bounded extent before constructing a result.
    if len(raw) != len(LEAF_DOMAIN) + expected_count * 8 + 8:
        return None
    if not raw.startswith(LEAF_DOMAIN):
        return None
    if int.from_bytes(raw[-8:], "little") != expected_count:
        return None
    start = len(LEAF_DOMAIN)
    words = tuple(int.from_bytes(raw[start + i * 8:start + (i + 1) * 8], "little")
                  for i in range(expected_count))
    return words if all(x < GOLD_ORDER for x in words) else None


@dataclass(frozen=True)
class Matrix:
    width: int
    extension: int = 1

    def __post_init__(self) -> None:
        if type(self.width) is not int or self.width <= 0:
            raise ValueError("positive logical width required")
        if type(self.extension) is not int or self.extension not in (1, 5):
            raise ValueError("only native base/EF5 widths are modeled")
        if self.base_width > MAX_LEAF_FIELDS - SALT_FIELDS:
            raise ValueError("matrix width limit")

    @property
    def base_width(self) -> int:
        return self.width * self.extension


@dataclass(frozen=True)
class Schema:
    depth: int
    matrices: tuple[Matrix, ...]

    def __post_init__(self) -> None:
        if type(self.depth) is not int or not 0 <= self.depth <= MAX_DEPTH:
            raise ValueError("closed depth limit")
        if type(self.matrices) is not tuple or not self.matrices:
            raise ValueError("fixed ordered tuple of matrices required")
        if any(not isinstance(m, Matrix) for m in self.matrices):
            raise ValueError("invalid matrix")
        if self.field_count > MAX_LEAF_FIELDS:
            raise ValueError("aggregate leaf field limit")

    @property
    def height(self) -> int:
        return 1 << self.depth

    @property
    def field_count(self) -> int:
        return sum(m.base_width + SALT_FIELDS for m in self.matrices)

    def zero_row(self) -> OpenedRows:
        return tuple(tuple(0 if m.extension == 1 else (0,) * 5
                           for _ in range(m.width)) for m in self.matrices)

    def split(self, fields: tuple[int, ...]) -> OpenedRows:
        if len(fields) != self.field_count:
            raise ValueError("wrong canonical leaf width")
        result = []
        offset = 0
        for matrix in self.matrices:
            data = fields[offset:offset + matrix.base_width]
            if matrix.extension == 1:
                result.append(tuple(data))
            else:
                result.append(tuple(tuple(data[j:j + 5])
                                    for j in range(0, len(data), 5)))
            offset += matrix.base_width + SALT_FIELDS
        return tuple(result)


def encode_rows(schema: Schema, rows: OpenedRows,
                salts: tuple[tuple[int, ...], ...]) -> bytes:
    if len(rows) != len(schema.matrices) or len(salts) != len(schema.matrices):
        raise ValueError("matrix/salt count mismatch")
    fields = []
    for matrix, row, salt in zip(schema.matrices, rows, salts):
        if type(row) is not tuple or len(row) != matrix.width:
            raise ValueError("wrong logical row width")
        for value in row:
            if matrix.extension == 1:
                fields.append(_field(value))
            else:
                if type(value) is not tuple or len(value) != 5:
                    raise ValueError("wrong EF5 coefficient width")
                fields.extend(_field(x) for x in value)
        if type(salt) is not tuple or len(salt) != SALT_FIELDS:
            raise ValueError("four salt fields per matrix required")
        fields.extend(_field(x) for x in salt)
    return encode_leaf(tuple(fields))


@dataclass(frozen=True)
class Entry:
    serial: int
    raw: bytes
    output: bytes


@dataclass(frozen=True)
class QueryEvent:
    serial: int
    raw: bytes
    output: bytes
    fresh: bool
    collision: bool
    target_hit: bool
    prior_distinct: int
    prior_targets: int
    prior_notifications: int


class DictionaryOracle:
    """Assigned-answer oracle. All mutable steps finish before query returns."""

    def __init__(self, supplied: Mapping[bytes, bytes]) -> None:
        self._supplied = dict(supplied)
        if any(type(raw) is not bytes for raw in self._supplied):
            raise ValueError("raw inputs must be bytes")
        for answer in self._supplied.values():
            _digest(answer)
        self._by_input: dict[bytes, Entry] = {}
        self._by_output: dict[bytes, Entry] = {}
        self._targets: set[bytes] = set()
        self._events: list[QueryEvent] = []
        self._snapshots: dict[tuple[Schema, bytes], Snapshot] = {}
        self._notifications = 0

    @property
    def distinct_queries(self) -> int:
        return len(self._by_input)

    @property
    def notifications(self) -> int:
        return self._notifications

    @property
    def events(self) -> tuple[QueryEvent, ...]:
        return tuple(self._events)

    @property
    def bad_events(self) -> tuple[QueryEvent, ...]:
        return tuple(e for e in self._events if e.collision or e.target_hit)

    def query(self, raw: bytes) -> bytes:
        if type(raw) is not bytes:
            raise ValueError("raw input must be bytes")
        prior = self.distinct_queries
        if raw in self._by_input:
            entry = self._by_input[raw]
            self._events.append(QueryEvent(
                entry.serial, raw, entry.output, False, False, False,
                prior, len(self._targets), self._notifications))
            return entry.output
        # This is a table lookup, not a callback that can reenter the oracle.
        answer = self._supplied[raw]
        entry = Entry(prior + 1, raw, answer)
        event = QueryEvent(entry.serial, raw, answer, True,
                           answer in self._by_output, answer in self._targets,
                           prior, len(self._targets), self._notifications)
        self._by_input[raw] = entry
        self._by_output.setdefault(answer, entry)
        children = node_children(raw)
        if children is not None:
            self._targets.update(children)
        self._events.append(event)
        return answer

    def notify(self, schema: Schema, root: bytes) -> "Snapshot":
        _digest(root)
        if not isinstance(schema, Schema):
            raise ValueError("fixed schema required")
        self._notifications += 1
        self._targets.add(root)
        key = (schema, root)
        if key not in self._snapshots:
            self._snapshots[key] = Snapshot(schema, root, self.distinct_queries, self)
        return self._snapshots[key]

    def preimage_at(self, output: bytes, cutoff: int) -> bytes | None:
        entry = self._by_output.get(output)
        return entry.raw if entry is not None and entry.serial <= cutoff else None


@dataclass(frozen=True)
class Snapshot:
    schema: Schema
    root: bytes
    cutoff: int
    _oracle: DictionaryOracle

    def row(self, index: int) -> OpenedRows:
        if type(index) is not int or not 0 <= index < self.schema.height:
            raise ValueError("row index outside fixed height")
        current = self.root
        # Each iteration consumes one typed level, even for cyclic digests.
        for remaining in range(self.schema.depth, 0, -1):
            raw = self._oracle.preimage_at(current, self.cutoff)
            children = node_children(raw) if raw is not None else None
            if children is None:
                return self.schema.zero_row()
            current = children[(index >> (remaining - 1)) & 1]
        raw = self._oracle.preimage_at(current, self.cutoff)
        fields = decode_leaf(raw, self.schema.field_count) if raw is not None else None
        return self.schema.split(fields) if fields is not None else self.schema.zero_row()


def verify_opening(oracle: DictionaryOracle, schema: Schema, root: bytes, index: int,
                   rows: OpenedRows, salts: tuple[tuple[int, ...], ...],
                   siblings: tuple[bytes, ...]) -> bool:
    """Independent bottom-up typed row check; does not consult Snapshot."""
    try:
        _digest(root)
        if type(index) is not int or not 0 <= index < schema.height:
            return False
        if type(siblings) is not tuple or len(siblings) != schema.depth:
            return False
        for sibling in siblings:
            _digest(sibling)
        raw_leaf = encode_rows(schema, rows, salts)
    except (ValueError, TypeError):
        return False
    current = oracle.query(raw_leaf)
    for level, sibling in enumerate(siblings):
        current = oracle.query(encode_node(
            sibling, current) if ((index >> level) & 1) else encode_node(current, sibling))
    return current == root
