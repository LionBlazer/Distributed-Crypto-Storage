# Owner-side private locking inputs

The [joint locking producer](../crates/storage-client/src/private_predicate/source/locking/README.md)
connects a hidden PostgreSQL locking predicate to actual fetched Source, encrypted
BFV operands, Lifecycle Acquire and PredicateAcquire Link evidence. This is an
owner-side preparation boundary. Session SQL execution, a finalized lock grant,
accepted query results and durable owner recovery remain unavailable.

The fixed profile has four original rows and an age-domain predicate with SQL
three-valued logic. All four originals are encrypted regardless of OFFSET, LIMIT
or returned flags. The independently encrypted mask is the other operand. The
private SQL identity, complete historical parent, actor intent and original setup
bind the query before Source Copen, without putting fresh proof fields into a
cyclic query identifier. All downstream input proofs retain the complete Key33.
The existing original Registry application does not admit this larger composite.

Success retains the actual next Registry opening in an opaque staged object.
Its private constructor rechecks the real next commitment and the exact request,
parent, Link and input association. Holding it never promotes authoritative state.
WAIT/NOWAIT produces only non-admitted Source/Lifecycle evidence; it cannot create
a success Link or grant. An empty successful SKIP or LIMIT 0 still requires the
actual proofs. No owner fixtures supply a completed BFV answer.

## Native verification

The actual consumer command was:

```sh
cargo test --release --offline --locked -p storage-client --features private-input-proofs -- --test-threads=1
```

All 43 unit tests passed in 735.57s, including eight new cases covering:

- Compiler bounds, SQL NULL semantics, lock strengths and private-blind guards.
- Exact actual historical parent, actor and Registry opening preflight.
- Genuine SKIP/window, LIMIT 0, empty TRUE set and all-locked input production.
- Genuine WAIT/NOWAIT rejection without success evidence.
- Acyclic stable query binding with independently verified different full Key33.
- Individually valid foreign mask, parent and control pairs rejected by the Link.
- The actual staged next opening constructing a conditional End witness while
  wrong salts/controllers are rejected. This does not prove or finalize that End.

The command as a whole **failed**: the separate `tests/relational.rs` executable
passed four tests and failed seven. Those older tests expect generic relational
SELECT/write execution and cancellation after submission. The existing
`require_select_capability` and mutation guards reject that unavailable execution
before those events. The capability implementation, relational implementation and
integration-test source are unchanged from parent commit
`5829678efa1d800404d8ed3a06322da09c89e223`; no passing full SQL suite is claimed.
These failures remain work for the complete SQL implementation.

All-target feature checking, strict Clippy, default-feature checking and workspace
format checking passed. The requirements mirror matched. The only Cargo change
adds the already locked `registry200-journal` as an optional direct dependency of
`storage-client` and enables it in `private-input-proofs`; no package/version changed.

## Measurement and attribution

The complete command took 765.585s, including 23.70s compilation and the failing
integration executable. The Windows observer collected 6237 samples across Cargo
and both test executables, with maximum gap 788.402ms. Maximum sampled/OS-peak
working set was 1,741,701,120 bytes and maximum sampled private bytes
1,771,356,160. Neither the 1792MiB per-process soft fuse nor 1800s runner budget
triggered. This is a serial owner-side proof suite, not query latency, whole-peer
RAM, concurrent-operation capacity or a composed security theorem.

The frozen 1454-file source manifest SHA256 is
`6569DD471AB28242C5389078BEE9B94BFB18F64416718BC6A11ADB17EBBDACEF`.
All raw file hashes matched after the run, before this documentation update.
Ignored receipts are in
`.local/private-peer-native-r1/locking-source-tests-r1/`. Stdout SHA256 is
`50EB6450F0DC47E1F3AC3BAA129A164B85999621FDE1B16D06CE466FBF93B325`;
stderr SHA256 is
`79D59E1152BEFA02EFB1E5B7971A9469E47F86BFE83ABFB7FE7FB8215EBA4A45`.
`locking-source-check-r1` checked the old module after an import preflight refusal
and is excluded from candidate validation. The actual imported candidate was
checked by `locking-source-check-r2` and `locking-source-clippy-r1`.

## Remaining integration

The complete input16 and FHE output graph must be verified, retained and replayed
under a new closed application. The exact joint Acquire must be finalized at the
required fresh parent, with writer fencing and no conflicting grant without a
quorum. Owner pending state and exact signed bytes must survive a restart before
submission can safely promote the staged opening. Only that verified outcome may
authorize client decryption/projection from the actual FHE fields. General SQL,
arbitrary tables and public evaluation-key same-secret proof remain separate work.
