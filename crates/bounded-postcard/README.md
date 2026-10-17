# Bounded Postcard decoding

Reusable Serde sequence/map budgets around the original Postcard representation.
The library owns per-call accounting; consumers own frame caps, accepted types,
canonical-encoding checks, trailing-byte policy and application errors. It has no
project dependencies. Direct external dependencies are Serde and Postcard.

`take_from_bytes::<T>(bytes, Limits)` returns one decoded value and the untouched
trailing slice. Every sequence, tuple, fixed array and map shares one slot budget;
a map charges both keys and values. Declared lengths are checked before invoking
the allocating consumer. Unknown lengths, multiplication overflow and nested
budget exhaustion reject with `Error::ResourceLimit`; malformed encoding returns
`Error::Encoding`. Each decode starts a fresh budget.

The limits count container slots. They do not bound input bytes, strings, custom
consumer allocations, type recursion, total RAM or processing time. A protocol
consumer must independently cap its input frame and validate its decoded value.

[BFV query proofs](../bfv-query-proof/README.md) retain their existing proof frame,
sequence and shared-slot limits while using this decoder. The RNS proof experiment
can choose its own explicit frame without duplicating generic decoding code.

```sh
cargo test --release --locked --offline -p bounded-postcard
```
