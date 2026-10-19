# Closed Registry200 checkpoint finality

`registry200-finality` now owns an actual Registry200 Journal, a weighted
multi-slot signer and a durable certificate floor log. It always invokes the
concrete existing Source-first/Lifecycle verifier. Network callers cannot provide
a proof callback, mutable Journal, signing key getter or supplied successor
context. This is a local protocol owner, not a deployed peer actor or live SQL
lock grant.

## What changed

`Rules::multi_slot` explicitly selects a separate complete rules/work domain.
The original single-slot rules identity, ticket/vote/QC formats and all original
mathematical profiles remain unchanged. Only the owned signer's no-argument
`advance()` can persist a slot change, using its own durable decision and a
separate DCSWFW02 header. It rechecks application/certificate evidence, syncs the
Advance record and then resets the next-slot round state. Recovery replays every
actual decision and Advance from independently pinned slot one.

Semantic DecisionId binds the exact ContextId and length-delimited value, while
excluding QC signature bytes, signer subset and commit round. Two genuine
certificates for the same value therefore derive one successor context. Those
certificates are still independently verified and retained in the floor log.

`Journal::reverify_block` repeats full Header/work/time/body/owner/application
verification, even for a cached candidate. Its mechanical monotonic ancestry
filter cannot authorize a floor: the closed adapter must first verify a genuine
certificate and actual application. Candidate import, fork reconsideration and
confirmed resolution respect that filter; the default Genesis floor preserves
the preceding cumulative-work behavior. Historical rechecks remain possible for
actual certificate/WAL recovery.

The closed adapter checks independent Binding/Genesis/application/RulesId pins,
resolves the exact retained body and enforces the actual preceding certified
parent for every slot. Publication follows durable signer decision → actual
application/QC recheck → floor append/sync → mechanical floor installation →
durable next-slot Advance. A failed uncertain write suppresses actions and
poisons the owner. Lost acknowledgments recover the same decision and signer;
torn tails fail without truncation, recreation or reset.

Journal/floor/WAL bytes share the actual `protocol-storage::ByteBudget`. Initial
Journal writes have a real reservation, transferred continuously to a persistent
file charge; ambiguous initialization retains the conservative charge. The old
256 MiB aggregate, Body32MiB, input2MiB, record8MiB and individual proof limits
remain unchanged. This original application cannot admit the larger detached
private-predicate/FHE composite by replacing its proof with metadata.

## Executed owning tests

The native run passed 62 runtime tests and eight ownership compile-fail examples:

| Boundary | Runtime cases | Scope |
| --- | --- | --- |
| Closed Registry200 adapter | 6 | Actual checkpoints, alternative QCs, same shared quota, real Source/Lifecycle history, missing/wrong/invalid candidates, floor I/O failures and terminal header bound |
| Journal floor/reverification unit boundary | 2 new | Actual Empty work branches and reject-only proof hooks; never a substitute for the closed proof verifier |
| Existing Journal contracts | 18 | Work/owner/proof rejection, canonical codecs, forks, freshness, durable namespaces/corruption and exclusive ownership |
| Work election/quorum/consensus/WAL | 36, including 3 new | Genuine distinct quorum subsets/rounds with one lineage, two-slot replay, lost Advance acknowledgment and strict torn-tail recovery |

The six adapter cases include an owner-signed four-body
Bootstrap → Begin → Acquire → End history. Each body contains a genuinely produced
canonical Source and Lifecycle child proof. The private witness and owner inputs
are dropped before `open_existing` repeats actual Journal/floor/WAL verification.
This is four actual proof pairs, not an FHE output computation or hidden WHERE
test. No cached-success flag, native answer comparison or fake Source verifier is
used by that closed boundary. Empty-only controls are labelled separately.

The `max_headers = 2` boundary test commits the last admissible floor, rejects a
third header and reopens into slot three while retaining the second floor. The
history has Genesis context plus two successor contexts: the existing `>` bound
is deliberate. Replacing it with `>=` would reject the final valid floor after
its record was synced.

The first all-targets check found that new tests were sibling modules trying to
access private adapter state. Root moved them to `adapter::tests` and updated
their fixture-relative path. No production visibility was widened and no private
getter was added. An enrollment64 fixture uses the original Source commitment
digest; the lifecycle digest's fixed 144/160/200-field guard is unchanged.

## Native attribution and reproduction

Windows/MSVC Rust 1.99.0, release/offline/locked, native CPU flags, Cargo jobs 2,
Rayon threads 2. Commands:

```text
cargo test --release --offline --locked -p registry200-finality -p work-finality -p version-journal -- --test-threads=1
cargo clippy --release --offline --locked -p registry200-finality -p work-finality -p version-journal --all-targets -- -D warnings
cargo check --release --offline --locked
cargo fmt --all -- --check
```

Adapter tests took 97.38 s; Journal groups took 0.00/0.05 s; work-finality took
0.63 s; compile-fail groups took 0.82/2.01 s. The whole test command took 149.709 s,
including compilation. This is not SQL latency. Strict Clippy, the Core default
build and format checks passed; the requirements mirror and changed local
documentation links remain synchronized.

The nominal 100 ms process observer captured Cargo, the adapter and work-finality
test processes, with 744 samples and maximum sample gap 837.790 ms. Maximum
sampled/OS-reported peak WS was 1,037,017,088 B and sampled private bytes
1,035,898,880 B. Short Journal/doctest processes were not all observed; this is
not a whole-peer RAM bound. No sampled1792MiB soft fuse or runner-budget abort
occurred. No full FHE graph or network measurement was repeated in this stage.

The frozen 1433-file source manifest `.local/registry-finality-native-r1/source.json`
has SHA256 `B97069B2D7EF90A2129D911702C6E29C117537BFD866CBB2FD0C96C723CE6426`.
Every listed raw file matched after tests and the default build check, before
these documentation updates. The ignored native receipt
`.local/private-peer-native-r1/registry-finality-tests-r1/` has stdout SHA256
`04174BEB9CE6F9D53FC6D47C37F3FAEBC5998982FE2412E558164720D357F004`
and stderr SHA256
`CE3EAE03B7B718F672F122D1A96EE9219EAC87FBE8A43CC6AC3ABF7558CBF283`.
The donor20 aggregate was
`3C4210125CA8255F59D7AAE0447F24E1F4432BDE36E87EDDDC9C1C27815C7015`.
Root preserved the already validated storage integration through four checked
three-way merges; import manifest SHA256 is
`AB472DFD6C0CCCC0A1957FE9567BC15C81DED2812E1075EF11CFF31E2F0BC149`.
Formatting preceded the final frozen manifest; independent source review matched
all 1433 files and checked those integration seams. Native execution belongs to
the Root run above, not to that source review.

Cargo metadata adds only the local `registry200-finality` package. Every
preceding locked package and dependency entry is unchanged. Generated files,
test databases, binaries and private materials are not committed.

## Remaining distributed obligations

The safety premise is less than one third Byzantine confirmed work in the
activated roster, with honest durable signing protected from rollback. Checked
work does not establish fair inclusion, that Byzantine fraction or availability
after a high-weight peer disappears. Only the bootstrap roster is activated.

Transport/gossip and actual independent-peer partition/restart gates, a
permissionless system lane and safe epoch handoff, globally fresh barriers, and
the new joint hidden-predicate/FHE/lock application remain required. Immutable
`FinalizedHead` metadata records a checked floor; it cannot establish the newest
global head during an unseen partition. [Full proof retention](protocol-storage.md),
[private peer execution](private-where-peer.md), [predicate/Acquire linkage](private-predicate-acquire.md),
owner key/pending-state restoration, full SQL coverage and composed cryptographic
security remain separately unresolved. No live SQL acceptance guard is opened.
