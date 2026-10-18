# Non-admitting Registry200 WriteImage consumer

This private experiment produces a separate AddAmount eligibility and complete
logical afterimage proof. It is a required mathematical dependency toward a
future lock-aware mutation, not an accepting encrypted SQL update. No production
storage/client/peer verifier admits this output or changes its Source/control CAS.

| Owned file or direct dependency | Responsibility |
| --- | --- |
| [Shared WriteImage AIR](../../../../../../crates/registry200-proof/src/write/README.md) | One canonical mathematical statement/layout/AIR/profile |
| compiler.rs | Existing sql-plan AddAmount parsing, exact SQL+nonce identity, intent q and private command binding |
| trace.rs | Owner-local current-root opening match and genuine shared-arithmetic trace writer |
| statement.rs | Local PublicStatement/Kind adapter; no duplicate AIR/profile |
| mod.rs | Mandatory actual Source verification before the private child factory |
| frame.rs | Distinct bounded canonical Source+WriteImage evidence |
| tests.rs | Owning genuine proof, arithmetic, replay, resource and rebuilt malicious-trace cases |
| [Journal owner consumer](../journal/write_input.rs) | Actual validated parent and genuine signed Bootstrap/Begin/Acquire provenance |
| [Existing backend](../../../backend.rs) | One actual hiding SDK/configuration/analysis/proving/verification engine |

The client parser derives the entire 256-age mask and u16 delta from the exact
supported UPDATE text. The source-independent intent q includes original
application/G/parent, nonce and exact SQL identity before C_open or C_command.
The compiled object retains that nonce privately and recomputes q during command
binding; a foreign SQL/nonce/parent cannot bind an existing Source request.
The new command commits Source/context/current registry plus full u64 transaction,
revision, sequence, principal/controller, mask, delta and salt. Neither q nor the
command includes its own digest or C_image. AIR checks the committed semantics;
it does not prove that arbitrary peer text was parsed or grant controller rights.

The operational producer reads the actual Journal parent, Source/control heads
and sticky enrollment. Before computing C_command it matches the externally
retained registry opening and enrollment to that parent. It then creates a genuine
canonical Source proof and verifies it before child Backend/trace allocation.
The normal CLI first appends three actually owner-signed and genuinely verified
Bootstrap/Begin/Acquire bodies. No fixture-derived root substitutes for the
accepted parent. The public pair itself carries no historical lineage proof;
independent Journal validation remains necessary.

DCSRWI01 has a distinct role0xA1 and 120-byte header: magic8, role1/reserved7,
Source profile32, WriteImage profile32, two u32 component lengths and output32.
The hard aggregate ceiling is 32 MiB; Source <=20 MiB and child <=12,578,091 B.
Sequence length is at most16384; decoded-element budgets are24 Mi/16 Mi.
Component sizes and topology come from fixed independently selected statements.
Cheap borrowed header/cap/canonical-root checks precede decoding. Source is
canonically decoded and genuinely verified first, then dropped before child
decoding. Each actual SDK instance owns its immutable AIR/public values and
assessment. No header, native image or receipt replaces a proof. These limits are
not a signed-Body fit or data-CAS/transport registration claim, and are not RSS.

From the repository root:

~~~powershell
cargo run --release --locked --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml -- security registry200-write-image
cargo run --release --locked --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml -- prove registry200-write-image
~~~

Security mode prints two analytical individual reports (canonical Source and the
new relation), without a trace, proof or append. Prove mode uses the genuine signed
history, encodes the new pair, drops all private preparation and proof objects,
and runs a fresh verifier with public inputs only. Registry/head/accounting must
remain unchanged. generation_ms includes fixture/history generation through
private-drop/frame generation; write_generation_ms is the new Source/child/frame
phase; fresh_verification_ms covers the bounded fresh decode/verify. full_cli_ms
also includes the surrounding producer call. Printed proof/frame/body sizes are
actual values only once the command has genuinely executed.

All fixtures are PUBLIC NONSECRET. High-u64 and rebuilt cases are explicitly
conditional arithmetic fixtures, not fabricated reachable signed histories.
All ten new owning tests passed, together with the affected old Registry200
tests, in the [native validation](../../../../REGISTRY200-WRITE-IMAGE-VALIDATION.md).
Parent history and SQL identity are not freshness or SQL
acceptance tokens: a historical proof may remain mathematically valid while real
Journal ancestry/freshness rejects use after a same-root sibling reorganization.

This stage performs no peer FHE predicate/UPDATE execution, new AEAD/BFV formation,
atomic Source+control mutation, lock-enforced data admission, MVCC or commit/rollback.
It changes neither the old seven operations nor any existing profile/allowlist,
Body/history quota or live SQL rejection. The validation records actual emitter
fit, individual floors and process observations for this fixed experiment;
no whole-peer bound, composed128 or full goal completion is claimed. Native field/trace/SDK scratch is
not guaranteed securely erased; no operational key export API is introduced.
