# Registry200 encoding evidence

Validated experimental encoding evidence. All 19 new tests, 98 prior controls
and two actual contracts passed; see the [validation record](../../../../PRIVATE-REGISTRY-LIFECYCLE-ENCODING-VALIDATION.md).
This module proves a new encoding commitment; it does not yet form a BFV ciphertext
or admit encrypted SQL answers.

The client compiles exact SQL bytes plus a separate nonce and pins the existing
Journal/lifecycle query identity independently. They are deliberately different
identities: Journal creates its pre-proof intent before C_open and C_cmd. A private
`CommandOpening` uses full u64 transaction, revision and sequence values and the
controller/salt solely to match canonical Command160 against the independently
expected C_cmd. The sealed `Expected` retains the full parent identity and packets,
complete PV116, SQL/nonce identity and projection. It retains no private opening,
controller or salt and cannot be deserialized from a response. This is client-side
compiler provenance, not controller authorization or a public SQL parser proof.

`prove_with_trace` and `verify` require the original actual canonical Source and
Registry200 Lifecycle proof pair. Both original proofs verify before the encoding
Backend or trace factory. No Boolean, cached receipt, plaintext state evaluator or
old Return168 producer is accepted. A successful Acquire with LIMIT 0 is valid;
Savepoint, WAIT/NOWAIT failure and EndAbort are not empty successful Acquires.

The new AIR has 4028 columns, 297 periodic columns and PV136: new profile8,
complete parent PV116, exact SQL/nonce identity8, C_enc4. The C_enc context includes
both full parent PV116 and SQL identity. It opens the original Source680 at rows
1..85 and Result144 at 86..103 with a zero-capacity reset, comparing C_open at row 85
and C_result at row 103. Source's six original pad fields and Result's seven pad fields
remain fixed zero. Persistent 96 data bits and canonical streamed u32 source words
link the original age/amount and all eight RowId words.

Sixteen Boolean routing cells bind original-position returned flags to four compact
slots in original order. Each slot preserves presence, source ordinal, full age,
full amount and all eight RowId words, even if projected SQL asks only for age or
amount. Visited, skipped and held rows are not returned rows. Equal values with
different RowIds do not make interchangeable answers. All absent tuples are zero
and present tuples form a prefix. The shared inverse-SIMD matrix and exact bounded
integer equations prove every one of the 8192 m/W coefficients and all zero SIMD
padding. Three Poseidon2 gadgets retain the existing 8208-field encoded stream and
final row 511 check. Existing Selected88/Return168 profiles and producer whitelists
remain distinct.

The distinct DCSLFE01 **encoding evidence** frame contains exactly three canonical
SDK proofs and C_next/C_result/C_enc. Independent Expected is never on wire.
The 212-byte header pins all three profile IDs and bounded lengths. The new
profile also fingerprints the exact frame/slot limits and magic. Limits are
20 MiB Source, 12,578,091-byte Lifecycle, 12 MiB encoding and 48 MiB aggregate.
Sequence limits are 16384, with separate 24/16/16 Mi element-slot budgets charged
before nested vector reservation. Fixed trusted topology checks, canonical scalar
and full re-encoding checks precede SDK verification. Limits are finite allocation
policies, not peak-RAM guarantees. The 48 MiB cap is below an existing 64 MiB
transport capacity; this frame is not registered as a live transport response.
It is deliberately outside the unchanged 32 MiB Journal Body cap.

Direct dependencies are the [parent lifecycle relation](../README.md), its
[canonical Source](../../README.md), the [coefficient kernel](../../selection/encoding/README.md),
[fixed bounded SDK codec](../../proof_wire/README.md), existing SQL parser and the
same hiding-FRI backend. Public-nonsecret fixtures are isolated from verification.
The accepted-history owning test is a test-only Journal consumer: actual signed
Bootstrap→Begin→Acquire, original stored-frame decode, exact client compiler bind,
new encoding proof and fresh three-proof frame verification. It establishes no
confirmed agreed head. Other owning tests cover conditional cryptographic statements,
full native SDK SIMD parity, complete-source/parent/compiler binding, coherent
integer/routing/identity attacks and malformed or excessive nested wire values.

```sh
cargo run --release --locked --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml -- security registry-lifecycle-encoding
cargo run --release --locked --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml -- prove registry-lifecycle-encoding
```

Security mode is analytical only and emits Source, Lifecycle and encoding reports.
Prove mode emits actual three-component/frame byte counts, generation time and
fresh canonical decode plus original proof verification time after original proof
objects and witnesses are dropped. These are whole-stage scopes, not SQL latency.
Individual profile floors do not establish composed 128-bit security. Remaining
work includes Registry200 BFV formation and key authority, peer-only encrypted
selection, complete FHE program proofs, fresh agreed-head admission, controller
authorization and bounded safe Journal history compaction. Production storage-client
acceptance remains fail-closed.
