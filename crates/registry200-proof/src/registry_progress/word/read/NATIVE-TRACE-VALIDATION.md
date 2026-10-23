# Actual five-verifier SHA transcript capture

## Implemented boundary

The genuine five-AIR/original-product owning test now scopes the optional engine
`transcript-audit` recorder around actual `hash::Verifier::new` and its cold
`verify_and_retain` call. Proof production precedes capture. The original closed
Source/Role3/DATA/Word/Query native receiving stacks run normally, followed by
protected completion, the complete 4096-coefficient oracle and every existing
hostile-proof, foreign-endpoint, replay and fresh retained-query assertion.

This captures SDK calls, rather than driving transcript helpers or expanding an
interaction manifest. The engine hook records the same absorbed byte slices
and full SHA512 digest of every actual draw, including any rejection attempt.
The feature is disabled by default; registry200-proof enables it only through
a dev dependency. No caller can select coins, inject events or replace a verifier.

The test-only [runtime checker](hash_tests/README.md) selects exactly one of the
five prefix-free actual STARK seed vectors, checks independently retained public
endpoints (including all 309 Word values), then checks every FIELD/CAP/SAMPLE
extent, canonical field value, degree/terminal constant, PCS opening count,
nested seed, FRI round and complete final 192-sample group. It independently
recomputes every DRAW digest from the recorded prefix, global counter and retry,
checking the first accepted Gold value. Incremental hashing shares prefix work.

All 78 mutations reject: changed seeds/PVs with unchanged manifests, noncanonical
fields, omitted/inserted/reordered observations, skipped SAMPLE counters, false
sample histories, cap counts 0/2/u64MAX, changed cap/PP cap/opening without fresh
draws, truncation and trailing events. The native verifier still checks proofs;
this diagnostic parser creates no mathematical or admission capability.

PP caps are opaque bytes from real receiver reconstruction. No inverse of the
complete Expected or independently authenticated PP root is supplied by the
metadata checker. This finite complete-stream test is not an implementation of
the generalized adaptive raw-oracle recognizer, online Merkle extraction,
state-restoration reduction or composed RBR/FS/hiding theorem. Those obligations,
BFV/product assessment, original external binding, freshness/finality and final
SQL/lock admission remain separate. Predicate admission stays closed.

## Executed checks, 2026-10-23

The actual owning fixture passed at r667 after build r666. It captured five
complete verifier traces and eight DOMAIN-only constructor/fork traces:

| Family | Challenge groups | Accepted base samples |
| --- | ---: | ---: |
| Source | 14 | 257 |
| Role3 | 14 | 257 |
| DATA | 17 | 277 |
| Word | 15 | 267 |
| Query | 17 | 277 |
| Total | 77 | 1335 |

There were 1335 actual attempts, so this honest run observed no rejection retry.
The checker handles each retry actually present; it does not claim adversarial
reverse-retry or guessed-history model coverage. Existing deterministic sampler
tests separately exercise rejected modulus/u64MAX candidates.

The full owning test passed in 9.35s; its held process lived 9365.8514ms. It includes
cold setup, production of real proofs, recording/parser overhead and hostile
cases. It is neither a performance comparison with a feature-disabled image nor
a full network SQL timing. The complete 500ms SQL/FOR UPDATE target is unmet.

Windows/MSVC Rust 1.99.0, release opt-level 3/native CPU, locked/offline dependencies,
Cargo jobs 2 and Rayon 8 were retained, with no simultaneous heavy build/test.
The observer pinned source/image hashes, held the exact directly launched
handle/image/creation identity, and retained 120s/1792MiB whole-process fuses with
20ms sampling. OS peak working set was 585,424,896 bytes; sampled private-byte
peak 572,043,264. The process exited 0 with no faults or forced cleanup.

The native image is 14,410,752 bytes, SHA256
`A4402AAB507D5EF57FD8527D231C69082CC614FF870098421288AD3558F5B4D0`.
Generated receipt
`.local/word-cmd-native-r667-registry200-proof-observe-tests/result.json` has SHA256
`037803D9D730B63DC92C08CB6423D775726D45502976DF854D45E274DFAE1E0C`.
Proofs, traces, binaries and local logs remain outside Git.

All 21 audit-enabled hash/lifecycle tests passed, including clone forks,
cross-thread capture isolation, moved enrolled workers, escaped handles,
unwinding, nesting and observation limits. All 17 feature-disabled hash vectors
also passed. Limit errors finish the observed operation without changing its
challenges, then fail the audit. Stored payload is bounded to 8MiB/64 traces;
that does not establish a complete peer memory bound. Strict all-target release
Clippy passed for the audit engine and owning registry crate, as did formatting
and the dependency-free requirements mirror guard.

Reproduce with the stated environment:

```powershell
cargo test --release --locked -p bfv-hiding-stark --features transcript-audit --lib hash:: -- --test-threads=1
cargo test --release --locked -p bfv-hiding-stark --lib hash:: -- --test-threads=1
cargo test --release --locked -p registry200-proof --features owner-read --lib registry_progress::word::read::hash::tests:: -- --nocapture --test-threads=1
cargo clippy --release --locked -p bfv-hiding-stark --features transcript-audit --all-targets -- -D warnings
cargo clippy --release --locked -p registry200-proof --features owner-read --all-targets -- -D warnings
cargo test --release --locked -p repository-contracts --test requirements_sync
```
