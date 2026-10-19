# Durable Joint signing and checkpoint recovery

The [closed Joint owner](../crates/registry200-finality/src/joint/README.md)
now owns the actual Journal, signer WAL and certificate floor for the fixed
Joint FHE/control application. It opens its concrete depot from the same
`ParticipantQuota`. Independent original setup, anchor, Key33, Source and Genesis
pins remain mandatory. The original application's profiles and byte formats are
unchanged; the new durable profile has no migration or accepting fallback.

Creation reserves metadata absence before opening the depot or restoring setup,
then holds that actual permit until metadata-last publication. Existing-only
recovery checks full setup and actual application proofs, all floor QCs and
historical parents, then the signer WAL. The order for a new decision is durable
signer decision, full application/QC preflight, synced floor, ancestry restriction,
and actual signer advance with its successor WAL sync. No outbound action or
historical parent escapes an incomplete synchronization.

## Executed behavior

Five new owning cases passed, alongside the ten original durable and four
keyless Joint regressions. Seven ownership compile-fail contracts passed. The
new cases use genuine signed Source/Bootstrap/Begin/ControlKind bodies, a real
four-member Work roster and three-signature QCs. Public fixture rows, keys and
openings are explicitly nonsecret.

Coverage includes fresh file/depot recovery, a re-signed wrong-q competitor,
alternate genuine QC retry without extra floor/WAL writes, metadata-last and
missing-WAL refusal, partial and lost-acknowledgment floor writes, shared-ledger
refusal at actual signer advance, a corrupt closed-WAL tail, and the last allowed
Header followed by fresh recovery. Missing proof premises fail actual replay;
corrupt bytes fail earlier during existing participant inventory. The previously
saved floor/WAL bytes remain unchanged in both cases.

The pre-advance test marks the actual shared ledger failed before the real
signer's file growth. It does not simulate a successful WAL write. Closed-WAL
corruption changes actual file bytes after releasing its exclusive Windows lock.
These cases do not establish arbitrary filesystem fault coverage, directory-entry
power-loss durability or protection against malicious disk/key rollback.

```sh
# Initial full run: 18 passed; one competing-branch fixture failed during setup.
cargo test --release --offline --locked -p registry200-finality -- --nocapture --test-threads=1
# Corrected fixture: genuine signed replay and retained-premise faults passed.
cargo test --release --offline --locked -p registry200-finality joint::adapter::tests::real_signed_bootstrap_begin_kind_and_alternate_qc_reopen_then_missing_or_corrupt_premise_fail_closed -- --exact --nocapture --test-threads=1
# All seven ownership contracts passed.
cargo test --release --offline --locked -p registry200-finality --doc -- --test-threads=1
```

The first failure came from constructing the competing Body through
`Journal::candidate` after the honest Begin was already imported. That selected
the unfinalized best candidate, whereas the competing Body named the certified
Bootstrap parent. The corrected fixture explicitly mines the competitor on that
same certified parent. Only the test fixture changed between runs; production
source and proof profiles did not change. Across the two runs, **19 distinct
runtime cases passed**. The initial failure remains recorded.

Strict all-target Clippy for `registry200-finality`, the Core default release
check, all-target `dcs-peer` checking and workspace formatting passed. No Cargo
manifest, lock file or dependency changed in this stage. Requirements copies
matched before implementation and completion.

## Measurements and evidence

The initial command took 167.522s, including 5.99s compilation and 161.29s runtime.
Its observer retained 1,304 samples, with a maximum 437.727ms gap. Maximum sampled
and OS-peak working set was 1,032,790,016 bytes; maximum private bytes was
1,031,507,968.

The corrected focused command took 58.475s, including 4.49s compilation and
53.89s runtime. Its 426 samples had a maximum 397.652ms gap. Maximum sampled and
OS-peak working set was 980,709,376 bytes; maximum private bytes was 978,436,096.
Neither command hit the 1792MiB per-process soft fuse or 1800s runner budget.
Sampling does not establish a concurrent whole-peer RAM bound. These local
control/recovery suite times are not SQL or full FHE Acquire latency.

Parent commit was `99c8d9c6b7824f51cbde6008012c46caee0bd797`. The initial
1,511-file frozen source manifest SHA256 was
`688425C2F3B64D1C684B5F96372E845E71162D642262CF46E8821965BA02ACA8`;
the corrected manifest was
`7AE28B26A90C5A26812A115A9CB566FBA09EF54F1BDAB9986D7D072D3A691F8B`.
All raw source hashes and the complete inventory matched after native and
completion checks, before this documentation update.

Ignored receipts are under `.local/private-peer-native-r1/` in
`durable-joint-tests-r1`, `durable-joint-tests-r2` and
`durable-joint-doc-tests-r1`. Initial stdout/stderr SHA256:

```text
B7BC785CEB0135CE16BDD4BF0D98A6F1D36E699E24F4E2518DB084694D9AF821
B3F0976219FAE5CE69CC4188F3E63CCB8E1E04E1DD881ADA7105DE7A94B85117
```

Corrected focused stdout/stderr SHA256:

```text
6BA8B0365692448E471B252477F7F0D23F6EBAB926ADC1D3C78DB01652379984
7007F5C1ACDCE71BB0091308A452399655D5A636D9019AEBC6032EE24B5049D7
```

The seven compile-fail cases took 1.138s including command startup. Their
stdout/stderr SHA256:

```text
7D121C38478A344E84F39645BE5410ED763FCE75ECE6134EE24CD1B4F02A98B5
EA35F7E149B4456ED29AF7CA762379C0E5C45E7965CCE91741B1805106CDD2A7
```

## Remaining integration

This gate used local native tests, not independent Joint daemons. Full new-Genesis
Acquire with all actual input16/output118 proofs has not yet run through this
durable owner. Network prefetch, participant hosting, owner Vault and exact signed
retry, operation-specific fresh completion, ordinary SELECT and general SQL
remain separate required work. A historical parent or local latest floor gives
no current SQL grant. The safety assumption remains less than one third Byzantine
activated computational weight with non-rollback honest signing. No quorum gives
no lock or release permission.

Individual proof configurations do not establish a composed 128-bit security
claim. Immutable retained history still has finite quota and no safe compaction.
SQL entry guards remain closed until the complete required evidence is present.
