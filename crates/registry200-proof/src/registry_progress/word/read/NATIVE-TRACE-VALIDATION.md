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

## Typed CAP and actual input-opening association

The follow-up owning check labels each actual CAP with its fixed receiving role,
ordered matrix layout, base/EF5 width, per-matrix salts and depth. Roles are not
inferred from a digest or incoming dimensions. STARK order is MAIN, optional
PP/AUX, quotient, random, then FRI rounds; PCS order is random, MAIN, quotient,
optional PP/AUX. The helper explicitly maps these orders.

| Family | MAIN base width | PP base width | AUX EF5 width | Quotient chunks | Input depth | Total CAPs |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Source | 7161 | 0 | 0 | 16 | 13 | 13 |
| Role3 | 1656 | 0 | 0 | 16 | 13 | 13 |
| DATA | 512 | 668 | 82 | 8 | 15 | 17 |
| Word | 568 | 714 | 35 | 8 | 13 | 15 |
| Query | 416 | 545 | 84 | 8 | 15 | 17 |

Private matrices append five base hiding codewords; PP does not. Each quotient
chunk and random matrix begins with one EF5 column. Every matrix appends its own
four base salts. A binary FRI row has two EF5 values and four salts, hence 14 base
fields; its depth is input_depth-1-round. All matrices inside one input commit
have the same height. The check also rejects a deliberately mixed-height schema.

After the real native receive, each already accepted fixture proof is decoded
once. Its MAIN/AUX/quotient/random/FRI roots match the captured CAPs byte-for-byte.
All 21 actual input commitments, including all three PP commitments, are
authenticated by the fixed SHA256 MMCS against their captured roots, actual rows,
per-matrix salts and the 192 low-bit indices derived from the actual final Gold
samples. This adds only Merkle authentication; it invokes no second AIR, PCS or
FHE evaluation. The original genuine and hostile native assertions remain.
Five altered genuine DATA PP inputs reject: root, row, salt, width and depth.

All 54 FRI caps match too. Their carried sibling EF5 values, salt rows and fixed
depth frontier bounds are checked. The other coordinate in each two-EF5 row is
computed inside the original native folding verifier, which authenticates the
whole row. This helper does not independently capture that computed coordinate.
Full PP extraction is not inferred from authenticating its sampled rows.

For every CAP, its exact byte extent precedes its first actual draw. MAIN and PP
precede the first coin. These are honest runtime byte positions, not timestamps
of an arbitrary oracle experiment. A generalized raw-query recognizer must
notify the typed root at FIRST examination of any potentially canonical prefix,
before later hash-table growth or Expected reveal changes its interpretation.
At most 17 notifications per canonical raw prefix plus 75 final roots gives the
conditional ceiling `C <= 17*Q512 + 75`. Q512 includes all auxiliary/offline and
public-setup calls. The separate shared-dictionary [extraction argument](../../../../../../experiments/hash-hiding-fri/analysis/EXTRACTION.md)
also counts every verifier/setup/auxiliary SHA256 query in T. Neither this count
nor the finite native test alone proves that complete adaptive composition.

The exact owning fixture passed at r678 with 75 roots, PP3, 21 authenticated input
commitments and five rejected opening corruptions; all previous 77 groups, 1335
draws and 78 stream mutations passed too. Test time was 8.37s and process lifetime
8404.0975ms, including all cold setup, proofs, diagnostics and hostile examples.
This is not a feature-disabled performance comparison or a full SQL query.
The same native 8-worker/source/image/120s/1792MiB/20ms capture policy was retained.
OS peak working set was 585,654,272 bytes; sampled private peak 570,949,632. It
exited 0 without faults or cleanup. The r677 image is 14,453,760 bytes, SHA256
`875541019B438F41FFA157C17F227E2D57C063C735186C20D9F7CE305565D298`.
The ignored r678 receipt SHA256 is
`E10E87078744A4AAF8463B3F0AD77DFE53E5307B20906237186400B8179A392C`.
