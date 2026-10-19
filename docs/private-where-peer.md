# Private WHERE on an independent peer

## Implemented boundary

The opt-in `storage-client::private_predicate` producer and
`RemotePeer::prove_private_product` now connect actual canonical encrypted storage,
private input proofs, real peer FHE multiplication and the complete fixed
mathematical proof graph. The owning OS-process success test passed on 2026-10-19.

This is a fixed N4 building block, **not SQL admission**. `Session`, scripts and
typed SQL still reject query/mutation execution. There is no fresh finalized head,
transaction ownership, writer fence or `FOR UPDATE`/`SKIP LOCKED` grant. The
[PostgreSQL contract](postgresql-contract.md) records that remaining composition.

| Participant | Actual work |
| --- | --- |
| Owner application | Seal all four originals, retain independent TableId/object/heads, store and fetch through TLS, reopen the complete authenticated images, encrypt every original and the hidden age-domain predicate, produce Source/Encoding/Key/Basis/Formation evidence |
| Independent `dcs-peer` process | Authenticate the application, audit the actual physical stored object and both heads, verify all input evidence, perform CT-by-CT FHE multiplication, produce every output proof record |
| Client verifier | Keep its local original provenance, verify exact output/request association, input evidence, all ordered output records and terminal EOF; only then expose the checked encrypted product |
| Owner completion | Decrypt that completed encrypted response and check its row/range/padding format |

The compiler reads SQL only; its encrypted 256-age truth table does not depend on
stored rows. The peer receives neither plaintext SQL, its private blind, the
predicate truth table, AEAD/BFV secret keys nor an owner-selected answer. The owner
opens and encrypts **all** four source rows. Source private state and proof-epoch
state are dropped before peer computation in the success test. The retained BFV
owner is used for final client decryption.

Supported input shape is `SELECT age, amount FROM records` with the existing
age-only boolean predicate and default window. Locking plans, mutations,
aggregates, other projections and nondefault windows reject. N4, `age:u8` and
`amount:u16` remain explicit limitations; this is not general PostgreSQL execution
or an index-accelerated hidden-predicate plan.

## Stream and verification

RPC v2 appends one private-product start variant. The connection-scoped stream
binds each frame to the request ID, full job digest, unpredictable server nonce,
role and ordinal. Its fixed order is Ready; fifteen input frames; output; claims;
118 proof records; End; authenticated TLS EOF. The client requests each next
record only after verifying the preceding stage. Input16 comprises one Key,
one shared Source, two Encodings, ten Basis and two Formation roles. Source occurs
inside both Encoding frames, giving fifteen wire frames. The output graph has
134 logical nodes: 115 NTT, seventeen arithmetic and two relinearization nodes.
The seventeen arithmetic nodes share one atomic proof block, giving 118 output
records. Input16 is a separate mandatory prerequisite, not part of that node count.

No prefix returns a checked product. Public claims decoded by the prover are not
independent authority: the client constructs its verifier from its own local
provenance and owner anchor. The server checks actual custody and verifies inputs
before FHE work, then drops uploaded input buffers before output proving. One
shared proof permit bounds concurrent expensive server jobs. Proof records are
produced and checked one at a time; there is no retained remote job or proof spool.

The existing individual proof caps are unchanged. The fifteen-frame worst-case
collection is 348,130,800 bytes and is never encoded as one transport or journal
body. The public provenance claim cap is 1,051,948 bytes. Start fields have bounded
decoders before variable allocation. Transport still caps each application frame
at 64 MiB. Inactivity is 180 seconds and the private stream's absolute I/O budget
is 1,800 seconds; initial request decoding has a 180-second absolute budget.
TLS handshakes retain their separate 15-second absolute/inactivity budget.

Absolute socket deadlines interrupt progressing partial reads. Cancellation and
expiry are checked before subsequent native phases and output delivery. An
already running synchronous native proof is not preempted. Cancellation changes
no database state and does not roll back a published mutation.

## Actual successful operation

The public test originals are `(7,0), (42,65535), (128,17), (255,1)`; the query is
`SELECT age, amount FROM records WHERE age >= 42 AND age < 200`. Keys, RowIds and
TableId are freshly generated. The client decrypted complete rows 1 and 2 and
zeroed absent rows 0 and 3 only after full verification. These expected rows are a
test oracle; peer execution does not read an owner fixture or filter plaintext.

| Observation | Actual value |
| --- | ---: |
| Owner / independent peer PID | 543716 / 531260 |
| `SourceOwner::produce` with an already-Ready Key epoch | 91,915.0672 ms |
| Peer stream and full client verification | 447,775.6268 ms |
| Whole test operation before clean shutdown | 543,256.5148 ms |
| Native command including compilation/shutdown | 559.5911 seconds |
| Input proof frames, including both Source copies | 264,178,143 bytes |
| Output BFV ciphertext | 446,494 bytes |
| Sent / received application frame bytes | 265,087,829 / 254,078,312 |
| Sent / received observed application frames | 134 / 122 |

Application byte counters exclude the transport's outer framing, TLS overhead and
kernel traffic. The `produce` row excludes owner/setup generation, Key proof,
ingest, setup installation, Fetch and compilation, all of which are included in
the whole-test timer. Times are one successful warm-cache sample, not throughput,
tail latency, speedup or a practical interactive-query claim. Owner preparation,
peer proving and client verification are all real; no stage is replaced by dummy
cryptographic work. The printed `logical_output_nodes:134` field counts logical
output nodes, separately from the sixteen input roles and 118 output records.

Windows per-process memory observations covered Cargo and its actual descendant
owner/test and peer processes. The observer sampled at 100 ms nominal cadence;
the largest measured gap was 720.3334 ms. It obtained 2,180 owner and 2,180 peer
samples and retained OS peak-working-set counters.

| Process | Maximum sampled working set | Maximum sampled private bytes | OS peak working set |
| --- | ---: | ---: | ---: |
| Owner/test | 1,444,892,672 | 1,473,662,976 | 1,444,892,672 |
| Peer | 1,233,358,848 | 1,227,808,768 | 1,233,358,848 |

There was no 1,792-MiB-per-PID sampled soft-fuse or 1,200-second runner-budget
abort. Sampling and OS working-set counters are not a hard memory bound, a sum
over both computers, SDK erasure proof or evidence for larger SQL workloads.
The environment was Windows x86_64, 32 logical processors, processor identifier
`AMD64 Family 26 Model 68 Stepping 0, AuthenticAMD`; the actual proof backend
reported `avx512`. Rust was 1.99.0 MSVC, `-C target-cpu=native`, two Cargo jobs and
two Rayon threads, with an isolated copied target and offline pinned dependencies.

## Reproduction and retained evidence

```powershell
$env:RUSTFLAGS = '-C target-cpu=native'
$env:CARGO_BUILD_JOBS = '2'
$env:RAYON_NUM_THREADS = '2'
cargo test --release --offline --locked -p dcs-peer --test private_product private_product_success::stored_originals_and_hidden_where_complete_real_peer_fhe_after_private_source_drop -- --ignored --exact --nocapture --test-threads=1
cargo test --release --offline --locked -p dcs-peer --test private_product -- --test-threads=1 --nocapture
```

The positive receipt is retained in ignored
`.local/private-peer-native-r1/peer-full-r1/`. Its stdout SHA-256 is
`055A965A47B2732CEA3E5B4D2389CA1C120E7F1759BDB2829EC2A86E877F2C4F`;
stderr is `9DE8B317B53DAF87DA0E80F94760512CF0FD9961CF96449E73D2712D1F3286AF`.
The source manifest is
`.local/private-peer-full-r1/source.json`, SHA-256
`15A6D9C55B0EAA783F99C9418F7EBBF4AC1131DEFCF5A8F88E8E25CFFF586843`.
All 1,381 recorded source hashes matched after the command finished. The manifest
predates only the follow-up cancellation/deadline guard placement, source-ignore
exception and validation documentation; the owning follow-up checks cover those
changes separately. The public compact storage API tests were initially ignored
by the general `storage/` directory pattern; the explicit source exception makes
them part of the published tree. No generated receipts, local encrypted images
or secret credentials are committed.

Four actual OS-peer negative tests reject a foreign TLS identity, an unknown object
or foreign physical heads, all fifteen deliberately dummy proof frames, and an
interrupted upload. The latter two verify that the shared permit is released and
a fresh independent scope can start; stored object/journal state is preserved.
Dummy frames are negative inputs only and cannot produce output. The first
four-test receipt is `peer-negative-r1`, stdout SHA-256
`F2F41741536127C747F6446F34E2DCBE1A302C5E562D372F1DA3FB0640526127`.

After moving cancellation checks ahead of expensive public work and checking
server deadlines again after received input/demand, the owning follow-up gate
passed 42 tests:

| Native receipt | Observable scope | Passed |
| --- | --- | ---: |
| `compact-keys-r1` | Same caller-owned key reopens every page; wrong key/database/domain reject | 3 |
| `compact-api-r1` | Every canonical original reopens; independent heads/key/domain and complete tail checks | 4 |
| `provenance-codec-r1` | Complete public identity, foreign claims, canonical fields/caps and all fifteen frame roles | 4 |
| `anchor-codec-r2` | Public setup association without owner authority; canonical roots/length/setup rejection | 2 |
| `public-request-r1` | Borrowed complete original inputs and response/request binding | 1 |
| `private-inputs-r1` | Query-only compilation, unsupported plans, independent Source pins and producer preflight | 6 |
| `runtime-stream-r1` | Session/role/order/caps/reserved fields, malformed starts, complete-read observation and typed Busy | 4 |
| `transport-r3` | Absolute deadline despite progressing reads, disarm, actual TLS identity/handshake/cancellation | 14 |
| `peer-negative-r2` | All four actual OS-peer negative cases after cancellation guard changes | 4 |

`anchor-codec-r1` without the required feature discovered zero tests and is not
counted. The explicit `formation-proofs` rerun discovered and passed both tests.
`peer-negative-r2` stdout SHA-256 is
`C3D8FB0596DAB2445B76EEBAA71D34C818D8E26BE20057DB7DAA7934B82B7ED5`.
All receipts remain in the ignored directory above; old failed/intermediate
receipts were preserved. This is focused coverage, not a passing full SQL suite.

The pre-existing experimental compiler contract also passed after the compiler
implementation moved to `storage-client`. The experiment's actual security CLI
produced three complete Source/Encoding JSON reports exactly equal to the retained
preceding reports, field for field. Both lock files preserve every third-party
version/source/checksum; only local package dependency edges changed.

Strict `clippy --all-targets -- -D warnings` passed for the nine affected packages
with `storage-client/private-input-proofs` enabled and for the standalone
experiment. Root/experiment formatting checks, the default core build, the actual
`requirements_sync` test and all 33 Core proof-feature doctests passed. The local
Markdown-link check resolved 123 links. Receipts are `experiment-compiler-r2`,
`experiment-numeric-r1`, `clippy-r1`, `experiment-clippy-r1`, `fmt-final-r1`,
`experiment-fmt-final-r1`, `default-check-r1`, `requirements-sync-r2` and
`core-docs-r1`. The initial experiment `--lib` invocation was invalid because this
package has only a binary target; it ran no test and is not counted.

## Remaining requirements

The proof profiles, arithmetic constraints and numerical security reports are
unchanged. The output SDK estimate is at least 144 bits for this actual graph; it
does not establish a composed theorem for Source, inputs, output and protocol.
Independently trusted owner setup association still does not prove that every
public evaluation key shares the same BFV secret.

No result is bound to an independently fresh finalized database/control head.
Private predicate commitments and Registry lifecycle commitments have not yet
been joined by one relation. Durable weighted consensus, safe roster activation,
transaction ownership, held RowIds, writer fencing and recovery remain necessary
before SQL admission or real locking. The selected less-than-one-third malicious
computational-weight contract and quorum waiting remain mandatory. These missing
guarantees are not supplied by TLS, decryption, hashes or signatures alone.
