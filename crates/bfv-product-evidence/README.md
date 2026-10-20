# Retained BFV product evidence

This Core library retains the PUBLIC bytes of the existing ordinary private-WHERE
input16 and full134 product. It owns no FHE/AEAD secret, proof producer, SQL
compiler, fixture, transport, application vote or consensus policy. A content
catalog identifies bytes; it never replaces a cryptographic check.

| Direct project dependency | Responsibility |
| --- | --- |
| [protocol-storage](../protocol-storage/README.md) | Typed participant depot, immutable bounded CAS, actual shared persistent file accounting |
| [bfv-mul-relin-proof](../bfv-mul-relin-proof/README.md) | Independently pinned Provenance/Expected and actual input16/output118 verification |
| [bfv-query-core](../bfv-query-core/README.md) | Original public setup, complete private-predicate request/response association |
| [bfv-relinearization-key-source](../bfv-relinearization-key-source/README.md) | Fresh actual preparation of the independently pinned original public key |
| [registry200-proof](../registry200-proof/README.md) | Unchanged bounded Source/Encoding pair parser and untrusted canonical assembler |
| sha2 | Public content identities and full independent-context binding |

`ProductStore::open(DepotBudget)` is the only store constructor. It uses the
existing CAS implementation and cannot receive a legacy/control budget. The
participant owns the independent namespace/capacity and whole-root inventory.
Depot handles share its ONE logical-file ledger and exclusive root ownership;
cloning a budget creates no allowance. No GC, overwrite fallback, cached verified
flag or persisted application receipt is introduced.

## Recording lifecycle

`RecordingVerifier::new` takes a store, independent `Expected` and `PreparedKey`,
object ID, complete original request and original encrypted response. It checks
their full setup/request/query/head/operand association. It retains public metadata
and the original setup in one or two fixed chunks, each at most 32 MiB. It invokes
the existing actual verifier for claims, all mandatory input proofs, and each
ordered output record. Each proof buffer is written only after its actual check
succeeds; input verification precedes input proof retention. The two encoding
pairs must contain identical original Source proof bytes. Storage retains that
Source once, both child proofs, the original Key, ten ordered Basis frames and
two Formation frames. It retains no private opening or decoded proof.

`finish(empty_end, stream)` requires the transport owner to have parsed the actual
bound END/ordinal, reads actual EOF, and consumes the actual verifier's `finish`.
It returns an opaque `CompletedRecording`. The transport owner checks its live
cancellation/deadline once more, then consumes `publish` to write the catalog
LAST. A failure, cancellation or Drop before publication returns no completed
catalog. Already published public blobs remain accounted; there is no rollback
or eviction. Quota or ambiguous I/O errors remain explicit storage errors.
Cancellation racing a completed publication does not undo durable public bytes.

The actual client entry is
[`RemotePeer::prove_private_product_recorded`](../peer-runtime/src/client/private_product.rs).
It shares the original TLS/client verification loop with `prove_private_product`.
Both paths enforce all proof, object, session, role, ordinal, END/EOF and live
budget checks. The new return contains the checked mathematical ciphertext and
an UNTRUSTED catalog identity; no accepting SQL flag or alternative verifier
callback exists. The peer still owns no durable product spool in this change.

## Catalog and fresh replay

`DCSFPE01` has a fixed 256-byte header and 44-byte references: role u16, ordinal
u16, exact length u64 and SHA25632. Its storage profile, unchanged full graph
profile, graph identity64 and independent-pin binding64 are explicit. The latter
binds the original object, full setup ID/digest, complete local Provenance claim
and complete request with lengths. Full Source691/packets/heads, both Key33,
queries, encoding roots and both original ciphertexts remain in those pins.

There are exactly 138 non-setup references: Provenance, request, response, Key,
one Source, two Encoding children, ten Basis, two Formation, graph claims and
118 ordered output records. Exactly one or two setup references precede them,
depending only on the complete setup length (at most 64 MiB). A two-chunk setup
has a full first 32-MiB chunk and its exact nonempty remainder. The maximum
catalog is 6,416 bytes. Every fixed role has its original independent byte cap;
counts/lengths/profiles/reserved bytes/order/canonical EOF reject before blob
allocation. Anyone can construct `CatalogId`; it proves nothing.

`ProductStore::catalog_claim(id)` reads/hash-checks that catalog and uses this
same canonical parser to return a `CatalogClaim` with private fields. Its
read-only getters expose `setup_parts`, `setup_bytes`, `provenance`, `request`,
`response`, `source`, `query_child` and `graph_identity`. The query child is the
PrivateMask child, not the SourceAllOriginal child. These are UNVERIFIED content
references: this call neither opens their blobs nor checks a proof. No public
catalog constructor, mutable field, verification flag or receipt is exposed.

`CatalogClaim::references()` is a zero-allocation, exact-size, fused iterator
over all 139/140 references in the same canonical order. Each readonly
`CatalogReference` exposes `role()`, `ordinal()`, `blob_id()` and `byte_cap()`.
The existing role codes and counts are:

| Role | Code | Count |
| --- | --- | --- |
| Original setup chunk | 1 | 1 or 2 |
| Provenance | 2 | 1 |
| Request | 3 | 1 |
| Response | 4 | 1 |
| Key | 5 | 1 |
| Shared Source | 6 | 1 |
| Encoding child | 7 | 2 |
| Basis | 8 | 10 |
| Formation | 9 | 2 |
| Graph claims | 10 | 1 |
| Output record | 11 | 118 |

Ordinals start at zero within each role; Basis uses
Input0/Q0..4 then Input1/Q0..4 and output records use0..117. Caps come from the
original parser's SAME fixed role table, with no new allowance or wire change.
This lets a Joint follower prefetch every public premise through the same depot
ingress before taking a Journal lock, without copying or replacing the catalog
parser. Enumeration performs no I/O, custody check or cryptographic verification.
The resulting identities never substitute for actual input16/output118 and
Lifecycle/Kind/Link replay under independent pins at admission and reopen.

`read_public_blob(id, cap)` requires a caller cap in `1..=32 MiB`, checks the
declared extent before allocation, then reads the exact bytes with SHA256/EOF
validation. `retain_public_blob(bytes)` rejects empty or oversized input before
hashing or staging and retains at most 32 MiB of PUBLIC bytes through the same
actual CAS and typed depot ledger. It verifies no proof. These narrow operations
let a consumer retain additional bounded Lifecycle/Kind/Link bytes without
opening another store or multiplying an allowance. Such bytes are not added to
this fixed product catalog. A future JointApp must genuinely replay all input16
and output118 proofs and its actual Lifecycle/Kind/Link evidence on each
admission/reopen; metadata or a prior QC supplies no shortcut.

`ProductStore::replay(id, object, provenance, request)` requires independent local
pins, not labels promoted from the catalog or a prior QC. It freshly opens and
hashes every referenced blob to exact EOF, checks original setup SHA256/SHA512,
compares complete stored provenance/request to the local pins, and validates the
original response association. It reconstructs the two unchanged DCSCEP01 pairs
with the bounded untrusted `wire::join`, then calls the actual existing verifier
again. That verifier checks Key, both Source-first Encoding pairs, ten Basis and
both Formation prerequisites. Only after those bytes drop does replay read and
verify each output record. `finish` and the full graph identity must both match
before `ReplayedProduct` exists. Missing, corrupt, reordered, omitted, foreign or
trailing bytes are errors after any prior successful read or application QC.

No aggregate proof blob is created. Blob32-MiB, transport64-MiB and combined
control/WAL/Journal256-MiB policies remain unchanged. The new participant depot
can hold the separate bounded collection under its actual global/class quota;
the complete collection is not one Journal Body or transport message. The input
verifier currently requires a bounded collection of fifteen borrowed frames, so
replay materializes those original input frames (up to 348,130,800 bytes) and
temporary pair assembly buffers, then drops them before output replay. Setup,
graph claims, prepared public key, SDK scratch and filesystem buffers also exist.
There is no output graph proof Vec. These structural bounds establish no
whole-process 1–2-GiB measurement or filesystem-allocation/power-loss guarantee.
File sync and immutable publication retain the existing protocol-storage
guarantee; a missing directory entry after a crash fails fresh verification.

Input relations retain their original individual128 policies; the output
verifier computes its own actual SDK union floor. This supplies no whole128,
end-to-end144, public same-secret RK proof, Source authorization, fresh agreed
head, SQL completeness, writer right, FOR UPDATE/SKIP LOCKED or finality grant.
Lifecycle/PredicateAcquireLink and a future closed JointApp require separate
actual evidence and admission composition; they are not part of this catalog.

## Shared store ownership

`ProductStore::into_shared()` moves the existing exclusive store into one
`SharedProductStore`. Cloning this owner opens no directory and creates no new
budget, allowance or verification result. `RecordingVerifier::new_shared` and
`SharedProductStore::replay` use the same private fixed verifier and replay engine
as the existing exclusive APIs. The exclusive borrow remains a valid standalone
ownership model.

The shared owner exposes bounded owned-byte `read_public_blob`,
`retain_public_blob` and `catalog_claim` operations. No mutex guard, reader,
verification callback or unchecked acceptance flag is public. Each blob's
read/hash/EOF or staged write/publication holds the private store lock; SDK
decoding, native proof verification, network I/O, cancellation checks and stream
END/EOF run outside it. Setup identity is still checked with streaming SHA256 and
SHA512 before SDK use, without serializing another complete setup during replay.
Filesystem I/O and sync may block; a short critical section is a lifetime boundary,
not a wall-clock deadline or a performance measurement.

The host must separately own and share one actual native resource gate across
producer, recorder, replay and application services. Store sharing supplies no
native-work admission, current head or proof-validity cache. Keeping another
setup/History owner alive can increase process memory; this change establishes
no measured RAM bound.

The added owning cases cover clone/root-lock lifetime, one-charge deduplication,
concurrent same-store ingress, quota/reopen behavior and invalid public bounds
returning while the private store is locked. They use explicit public byte
fixtures and confer no cryptographic success. The additive opt-in OS case
`private_product_success::shared_retained_product_replays_after_private_owners_drop_and_rejects_repaired_splices`
uses the real shared RPC and all existing genuine proof/decryption, END/EOF,
fresh reopen/replay and repaired-splice assertions. The twelve evidence-store
tests, eight Joint tests and this actual OS-peer case passed native validation.
The unchanged four-validator/FHE Acquire regression also passed with the shared
Joint verifier. See the [executed record](../../docs/shared-evidence-owner-restart.md).
These cases do not measure concurrent ingress during a live RPC or
mid-filesystem-publication cancellation. The original exclusive pre-cancel case
is retained; no additional shared mid-stream cancellation result is claimed.

The executed record includes the exact serial owning commands, source and peer
image identities, resource observations and remaining integration boundaries.

## Earlier executed validation

The library's nine owning tests use public nonsecret bytes and actual owned files
for fixed grammar/caps, quotas, immutable reopen, missing/corrupt references and
terminal I/O. The public-boundary cases also check exact metadata roles without
referenced proofs, cap failures without file/ledger changes, and public-byte
deduplication/reopen in the same depot. The complete-reference test checks both
setup counts, every role/ordinal/id/cap, iterator cardinality/order and exhaustion.
They grant no crypto success. The new opt-in actual OS-peer test
retains the existing complete genuine fixture and assertions, then drops private
owners/producers/input frames, stops the peer, reopens the depot and genuinely
replays all proofs. It additionally repairs catalog references to swap genuine
Encoding children and duplicate a genuine record, tests independent foreign pins,
omitted/trailing/missing/corrupt bytes, and pre-cancelled recording with no I/O or
new catalog. Expected plaintext rows are only the test oracle.

The nine storage/catalog cases and 98 peer-runtime cases passed, together with
four compile-fail ownership contracts. The opt-in genuine OS-peer scenario also
passed: all 16 input proofs and 118 output records were freshly checked after
private owners/producers dropped and the peer stopped. All-target checking,
strict Clippy, Core default checking and workspace formatting passed. Executed
commands and the measured scope are recorded in the
[native evidence record](../../docs/retained-product-evidence.md).

```sh
cargo test --release --locked --offline -p bfv-product-evidence -p peer-runtime -- --test-threads=1
cargo clippy --release --locked --offline -p bfv-product-evidence -p peer-runtime -p dcs-peer --all-targets -- -D warnings
cargo test --release --locked --offline -p dcs-peer --test private_product private_product_success::retained_stored_product_replays_after_private_owners_drop_and_rejects_repaired_splices -- --ignored --exact --nocapture --test-threads=1
```

The genuine retained scenario has a finite 1800-second test-process allowance;
its product connection retains the unchanged absolute 1800-second deadline.
The full OS command took 680.345s, including compilation. Initial preparation and
FHE stream verification took 535.465s; fresh retained replay took 55.103s. These
N4 fixture observations establish neither interactive speed nor full SQL admission.
