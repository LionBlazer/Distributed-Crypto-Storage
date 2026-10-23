"""Frozen-snapshot encoder for the cfg(test) all-five public-factory reader.

Encoding is not successful recognition. The owning Rust read_before_first_coin
must finish synchronously before the driver samples any challenge. No mutable
Expected, configurable verifier, result callback or subprocess is accepted here.
"""

from generalized_mu import Family, FrozenWord, cap_type, profile, public_shape
from merkle_extraction import Snapshot

MAGIC = b"DCSMUB01"
FAMILIES = tuple(Family)


def _write(writer, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        count = writer.write(data[offset:])
        if type(count) is not int or not 0 < count <= len(data) - offset:
            raise ValueError("output did not consume its bounded bytes")
        offset += count


class ProtocolRecognizer:
    """One first notification, then canonical full u/P stream for all five."""

    def __init__(self) -> None:
        self._pending = None
        self._closed = False

    def notify(self, family: Family, public: tuple[int, ...],
               pp: Snapshot | None = None) -> None:
        if self._closed or self._pending is not None:
            raise ValueError("one first notification only")
        self._closed = True
        public = public_shape(family, public)
        if profile(family).pp:
            word = FrozenWord.first(cap_type(family, "PP"), pp)
        else:
            if pp is not None:
                raise ValueError("Source/Role3 have no PP notification")
            word = None
        self._pending = (family, public, word)
        self._closed = False

    def write_before_first_coin(self, writer) -> None:
        if self._closed or self._pending is None:
            raise ValueError("missing first notification or already consumed")
        self._closed = True
        family, public, word = self._pending
        header = bytearray(64)
        header[:8] = MAGIC
        header[8] = FAMILIES.index(family)
        if word is not None:
            if not 0 <= word.cutoff < (1 << 64):
                raise ValueError("first notification cutoff outside protocol")
            header[9] = word.typed.depth
            header[16:48] = word.root
            header[48:56] = word.cutoff.to_bytes(8, "little")
        _write(writer, bytes(header))
        _write(writer, b"".join(x.to_bytes(8, "little") for x in public))
        if word is not None:
            # Stream one bounded byte block at a time: no width*n transpose,
            # default repair, salt bytes, codewords or mutable row provider.
            block = bytearray()
            for column in range(profile(family).pp):
                for raw in word._leaves:
                    block.extend(word._field(raw, column).to_bytes(8, "little"))
                    if len(block) == 8192:
                        _write(writer, bytes(block))
                        block.clear()
            if block:
                _write(writer, bytes(block))
