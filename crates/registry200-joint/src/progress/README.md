# Closed fixed-source Registry progress application

## v3 application and closed original-stream import

The Progress APPLICATION contract domain is now v3. Its digest explicitly names
cold full native replay OR the keyless owner's original genuine input16/output118
stream plus SAME-depot full byte association within one execute. Core896 and all
individual math profiles, field/wire geometry, and 02 metadata grammar stay exact.
Contract32 in descriptor/manifest and derived App/G/operation IDs decisively
separate v2: old descriptors/manifests reject; old Request application/G fails
installed association. There is no old-QC, bank, seed or Binding migration/relabel.

`ProgressVerifier::prepare_import_recorded` is a fixed, single-use Predicate-only
adapter. It consumes `ScopedRecordedProduct`, checks its SAME actual depot and
all original byte references against independently installed full setup/anchor/
ALL33/Source/query pins, then performs the existing actual Source/query/Core896
verification. The result is ordinary mathematical `VerifiedOperation`; its public
`product()->Option<&ReplayedProduct>` still means complete actual checked math,
from original native stream plus byte association rather than a second native
pass. Boot/Control/Empty/second use reject this adapter. No flag/callback can mint
it. It supplies no owner/QC/current-head/SQL grant.

All existing cold `check/check_block/prepare_import` paths, including every
validator vote/import/floor/reopen and duplicate, still unconditionally invoke
full native replay. Fresh exact Header/current Journal/QC and owner private
completion remain separate mandatory layers. The selected v3-contract case and
actual five-product/eleven-QC Driver composition passed; see the
[v3 validation record](../../../../docs/progress-driver-scoped-completion.md).
Earlier v2 execution records remain historical.


This namespace composes actual retained FHE evidence with the NEW Core
Registry208 / Statement96 / Progress48 / Result160 relations. The Core gates and
full local FHE/application gate passed the
[native validation](../../../../docs/progress-application-validation.md). It does not activate
SQL, participant voting, durable owner progress or a current lock grant.

## Ownership and dependencies

| Module | Owns |
| --- | --- |
| `descriptor` | Independent SourceSpec, object, full original setup SHA256/SHA512, anchor and ALL33; new application/Genesis checks |
| `request` | New request, unchanged inner intent and unverified operation identity |
| `manifest` | Fixed bounded reference roles and hidden next/result commitments |
| `depot` | ONE ProductStore/typed DepotBudget, app-bound setup and public-byte ingress |
| `verifier` | Closed actual Source/Core/product proofs and fixed Journal adapters |

Direct library dependencies are [registry200-proof](../../../registry200-proof/README.md)
for Source, Bootstrap803, Control815, Predicate896 and Encoding;
[registry200-journal](../../../registry200-journal/README.md) for the immutable
inner SourceSpec/head/request grammar and unchanged `intent_query`;
[bfv-product-evidence](../../../bfv-product-evidence/README.md) for actual retained
input16/output118 replay; [bfv-mul-relin-proof](../../../bfv-mul-relin-proof/README.md),
[bfv-query-core](../../../bfv-query-core/README.md) and
[bfv-key-transform](../../../bfv-key-transform/README.md) for original public
provenance/setup/anchor/Key33; [protocol-storage](../../../protocol-storage/README.md)
for content identities/shared quota; and
[version-journal](../../../version-journal/README.md) for owner/Header/body and
fresh unpublished import. No consumer, RPC, fixture or generic accepting verifier
is a production dependency.

## Immutable contracts

`Descriptor::checked` takes independently authenticated owner pins. Its 896 bytes
use `DCSPAD02`: magic8, contract32, original SourceSpec312, object32, full setup
SHA25632/SHA51264, anchor140, Key33 canonical u64 words and reserved12. This byte
length coincides with Predicate's field count, not its proof format. The new app
ID hashes the entire descriptor under a new domain; its contract includes all
Core v2 and retained product/Key profiles.

`Application::new` requires a genuinely NEW Genesis application commitment,
network/database and exactly the SourceSpec initial shards. It never relaxes old
`SourceSpec::require_genesis`. The old SourceSpec only labels inner Source and
control-head shapes; its Registry200 verifier does not accept Registry208.
New G commits the full descriptor, including object, full setup SHA512 and role
profiles not all separately present in Core's smaller explicit statement scope.

`Request` uses `DCSPRQ02` and exactly 48+2716 bytes. Public lane is Bootstrap,
Control or Predicate; inner operation stays original Bootstrap/Transition and
inner application stays SourceSpec.id. Query is exactly unchanged
`intent_query(SourceSpec,newG,actualParent,nonce,enrollment,operation)`.
The owner chooses intent before Copen/Cmd/proofs. Opaque q does not authenticate
private SQL or a caller; original SQL/call custody belongs to a future host.

`Manifest` uses `DCSPMF02`, fixed 192 bytes on every lane: magic8, contract32,
lane1/reserved7, next208-root32, result160-root32, two `(hash32,len64)` refs.
Bootstrap requires Source+Bootstrap803 and zero result; Control requires
Source+Control815; Predicate requires full product catalog+Predicate896.
Unverified reference iteration exposes fixed role caps BEFORE I/O, each blob
at most 32 MiB. No Parked/Done/Error, holder, cursor, mask, SQL, mode, window or
projection field is added publicly. Access-pattern policy remains unresolved.

`OperationId::new` binds new app/G and full canonical Request+Manifest. This is
UNVERIFIED association metadata. Own expected ID must originate in independently
retained original work, not a received Body rehashed locally. It is not a proof,
signature, Header/QC, finality or current-head receipt.

## One public store and actual verification

`ProgressDepot::open(budget,&descriptor)` opens ONE ProductStore and its typed
ledger. `share(SharedProductStore,&descriptor)` pins the new canonical descriptor
around the SAME already-open concrete store/Arc/ledger without opening files or
creating another budget. Ingress/recording handles clone that same store; no old
JointDepot/Descriptor/SetupClaim cast, mutable store guard or Journal getter exists.
Local capacity is not a RulesID. Ingress stores arbitrary bounded PUBLIC bytes;
hash/existence never confers proof authority. Setup retention uses NEW `DCSPST02`
claims bound to this descriptor ID and exactly one/two 32 MiB chunks, at most 64 MiB.
Verifier construction reopens chunks and checks BOTH independent full hashes
before SDK decode. Host custody must independently authenticate descriptor and
small SetupClaim; RAM setup alone is not durable custody. Drop all shared store
handles before exclusive existing-only reopen; a second store is not a handoff.
ParticipantQuota namespace identifies storage ownership, not this SQL application;
the wrapper does not require namespace==AppID. Tests deliberately use a separate
public storage namespace. AppID is pinned in the wrapper and SetupClaim. Sharing
public blobs supplies no registry/profile migration or old checked receipt. The
owning host must supply the already-owned store rather than allocate another quota
per database, and share its one actual native ProofGate; this pure kernel creates
none. Source tests check shared reads, one retained charge, duplicate store-open
refusal and root-lock lifetime through the last shared handle.

`ProgressVerifier::check` validates new app/G/database, exact parent/previous
state root, both Source/control heads, one control CAS, sticky enrollment,
next state root, unchanged intent and manifest. Bootstrap calls genuine
Source-first `verify_bootstrap`; Control calls Source-first `transition::verify`
under Control815, which excludes Acquire and unrelated parked-actor operations.
Predicate pins complete descriptor provenance, ALL33, Source values/raw heads/
packets/Ckey/Copen/q, then invokes the SAME store's real full input16/output118
replay. Original request/response, setup/ciphertexts, catalog extents/hash/EOF
and graph identity remain mandatory. It assembles current Query772 with the
SAME literal stored Source and calls actual Predicate896. Old Lifecycle,
PredicateAcquire Link and Result144 are never cast, relabelled or used as fallback.

`VerifiedOperation` has a private constructor after these checks and reveals no
step status. It exposes immutable Core mathematical statements/root commitments;
`product()` is present iff Predicate, only after BOTH full product replay and
Core896 succeed. Failure drops product. An owner must privately open Result160
against this exact checked root before branching on status. TLS, hashes, QC,
signatures or successful decryption cannot replace computation proof.

`check_block` also invokes actual Journal owner/Header/body validation through a
fixed private adapter. `prepare_import` returns the actual per-call result and
exclusive PendingImport from that same fresh check. Independent expected ID is
checked before math/import. Drop publishes nothing; argument-free commit imports
that exact prepared block. Future finality must first check its own full semantics,
QC and durable accounting. Separate checks/reopens verify proofs again, including
known blocks. There is no persisted/cross-query verified marker or caller callback.

## Historical v2 owning tests and remaining integration

Owning source tests share one bounded public generated setup/anchor/Key33 fixture,
use real owner-signed bodies and Source+Bootstrap803 then Source+Control815 under
new G. They check own expected-ID rejection before import, root association,
unchanged Journal on rejection, a genuine child with hash-valid missing Source
proof, descriptor/legacy-domain/cap failures and unproved catalog rejection.
These four cases passed and supply no network or weighted-QC execution credit.
The fixture now creates ONE genuine Ready proof epoch instead of a separate Key
proof, retaining bounded encrypted Owner/Anchor/Ready records under an explicitly
PUBLIC NONSECRET test wrapping authority. No plaintext Owner is cached. Ordinary
four tests add no FHE product work. The canonical public index suffix is owned at
`tests/fixtures/index-v3-four-row-suffix.hex`, copied byte-exact from the existing
explicitly public fixture; the cryptographic relation is unchanged.

The opt-in local owning test
`progress::tests::predicate::new_genesis_predicate_records_real_fhe_and_imports_the_exact_original_operation`
restores that SAME Owner/Ready/all33, imports genuine signed Bootstrap803 and
Begin815 under NEW G, then proves actual Source and both Encodings, ten Basis and
two Formation roles. The actual SDK evaluates ALL four original ciphertext rows
against the full encrypted private mask. The original product Prover creates all
118 records; the SAME shared store's RecordingVerifier checks and records them,
requires local END/actual Cursor EOF and publishes the catalog. This is local
production-library computation, with no peer/network/weighted-QC claim. It makes
no fixture-computed product or answer. Core Predicate896 is genuinely proved and
the fixed ProgressVerifier freshly replays the whole catalog plus Core before an
exclusive argument-free Journal commit.

Only after that actual check does the test open NEW Result160, decrypt all four
actual result rows and use the proved selected flags for projection. The expected
public rows come from this application's fixture ages `[255,0,255,128]`; no Core
fixture's different row order is substituted. No second WHERE/OFFSET/LIMIT runs.
A direct corrupted Core child is rejected at its real proof boundary; an
independently wrong OperationId rejects without another complete product replay.
The test keeps no raw input proof collection during output118 production and
drops its output Prover/PreparedKey before the application's fresh full replay.
It reports preparation/input/recording/application timing observations and actual
retained quota bytes. The five-case group, including the real Predicate case,
passed in 629.02 seconds in its test body, 644.370 seconds including rebuild.
All input16/output118 checks remain mandatory.

Root owns sequential native validation, for example:

```sh
cargo test --release --offline --locked -p registry200-joint --lib progress::tests::predicate::new_genesis_predicate_records_real_fhe_and_imports_the_exact_original_operation -- --ignored --exact --nocapture --test-threads=1
```

This gate and revised fixture passed with measured resource observations in the
validation record. Old-G evidence was not relabelled to supply the positive.
Two privacy compile-fail cases and strict all-target release Clippy also passed.
New dev-only Formation/key-source edges preserve production dependency direction;
Cargo.lock records only those two already-existing workspace package edges.

WAIT/NOWAIT/SKIP share one hidden bank and v2 Predicate profile. Resume keeps exact
original Statement and ALL33 including CsHat; a new arbitrary Ready epoch cannot
resume it. Fresh q/Copen/current Encoding SQL identity/nonce are allowed under the
same retained Key33 and complete mask/options. Only Start anchors original blinded
SQL identity to its first Encoding; original invocation/SQL still are owner custody,
not caller authentication from q. End compaction carries waiters by stable ID.

The separate [Progress finality library](../../../registry200-finality/src/progress/README.md)
now provides typed Work/Rules binding, actual QC and historical parent/operation
verification with strict durable replay. The separate
[v3 Driver gate](../../../../docs/progress-driver-scoped-completion.md) covers
fixed-source owner custody, durable parked WAL and network orchestration.
General fresh-grant policy, parked cancellation/rollback, deadlocks and
mutable-tuple EPQ remain open. No rows for Parked/Error or End
permission without a real quorum follow. No SQL enable switch, ordinary read lane
or old-binding compatibility path exists. History compaction and repeated replay
cost remain unresolved within participant quota; no QC/snapshot proof shortcut
is claimed.


### Mathematical transition-step access

`VerifiedOperation::transition_step()` borrows the actual sealed Core
`VerifiedStep` for Control or Predicate, and returns None for Bootstrap. It adds
no verifier choice, dependency, cached success bit, QC, current-head/lock, SQL
status/rows or bank-installation authority. The typed Core predicate and Control
openers still reject the other lane and require independently retained private
openings. The finality owner's separate exact operation/QC association remains
mandatory before private completion.

Four ordinary application cases and two privacy compile-fail examples passed;
the genuine Bootstrap/Control case checks accessor absence/presence. The
explicitly ignored full input16/output118 Predicate896 case now uses the existing
typed Result160 opener through this accessor. Its new assertions were compiled
but not executed in this gate: full product preparation/replay is unchanged,
the getter only borrows the existing sealed Step, and the Core Predicate opener
already has genuine owning coverage. The earlier full application gate retains
its original executed scope. See the
[Control opening validation](../../../../docs/control-result160-validation.md).
