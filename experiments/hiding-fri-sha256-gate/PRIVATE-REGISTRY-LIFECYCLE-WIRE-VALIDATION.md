# Registry200 bounded proof wire validation

Validated on Windows x86_64 MSVC with Rust 1.99.0, against parent
`9ed6b962e485d3609d5e92f863c48d05f6537602`. This is an experimental byte transport
for the existing Registry200 proofs. It does not enable a Journal adapter or live SQL.

## Change and invariant boundary

[The typed wire](src/opening/registry_lifecycle/wire/README.md) uses distinct
`DCSLFPW1` Bootstrap/Transition roles and the existing canonical Source and lifecycle
profiles. Independent Expected supplies the complete Source statement, genesis,
parent, enrollment and, for transitions, old/command roots. The frame supplies only
next, or next/result, plus both mandatory original SDK proofs. Fresh decoding and
the original Source-first composite verifier determine acceptance.

[The internal codec](src/opening/proof_codec.rs) shares bounded canonical Postcard
and fixed SDK topology only. Roles, allowed kinds, profiles and byte/slot policies
remain with typed callers. The legacy `DCSLKPW1` policy, checks, profiles and old
test bodies are preserved. All 29 former security commands produced exactly equal
complete ordered JSON object lists. The two new commands also matched the complete
corresponding lifecycle dictionaries after excluding only `statement_case`.
No Cargo manifest, lockfile, dependency graph, requirement or production consumer changed.

## Actual execution

Release rustfmt check, Clippy all-targets with `-D warnings`, test build and normal
binary build passed on the first frozen native candidate. Actual test discovery
listed **304** cases: 296 previous plus eight new. Executed **56 leaf tests**
(all eight new and 48 previous controls), plus the actual `requirements_sync` and
`architecture` contract tests: **58 passed**. The other **248 leaf bodies were not
rerun**. Contract sources were compiled directly with release rustc; architecture
used the actual built serde_json dependency and Cargo metadata. This was not a GUI build.

The new owning tests freshly decode both genuine roles after producer proof objects
and witnesses are dropped; check reencoding and mandatory components; mutate all
independent Expected fields, including first/last bytes of both 60/2384-byte packets,
and all output roots; verify a genuine foreign enrollment/fresh-query pair under its
own Expected before rejecting distinct mixed proofs. They reject 31 nested topology
families, canonicality/field/sequence/shared-slot faults, eight same-shape crypto
families and an invalid Source paired with a genuine child. Complete signed Body
tests use 2716/4096-byte requests, strict pinned-fixture Ed25519 verification,
actual encoded-length minus one/exact/plus one valid-profile bounds, and signature
faults in request/proof/update/parent/genesis.

Each of 31 numerical command invocations passed individual unique/list target
checks. Source remains W11521/PV691, bootstrap W1082/PV104 and transition W6741/PV116;
all use Q16. This is **not a composed 128-bit soundness claim**.

## Measured complete signed Bodies

Both normal prove commands created actual Source/child proofs, dropped the original
objects, signed the complete owner Body, encoded/decoded/reencoded it, strictly
checked its signature and freshly verified the decoded pair under independent Expected.
Request length was 2716 bytes and there was exactly one opaque test update.

| Role | Source bytes | Child bytes | Frame bytes | Body bytes | Full process ms | Signed Body roundtrip/fresh verification ms | Observed OS peak bytes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| bootstrap | 19297119 | 2430415 | 21727654 | 21730943 | 5930.8137 | 1345.2329 | 844582912 |
| transition | 19300895 | 11574655 | 30875702 | 30878991 | 14175.4557 | 1654.4680 | 846770176 |

The Body lengths are actual encode results, independently checked against
`117 + request_bytes + 456 * updates + frame_bytes`. The narrow timer covers owner
signing, Body encode/decode/canonicality, strict signature checking and fresh proof
verification. Full owned-process elapsed includes setup, numerical analysis and
proving; transition additionally establishes a genuine empty-bootstrap prerequisite.
These are local experimental operations, not network SQL latency measurements or SLAs.

The wire caps are Source 20 MiB, child 12,578,091 bytes and full frame 33,549,763 bytes.
Header sizes are 120/152 bytes. Reserving 117 +4096 +456 leaves the unchanged
32 MiB Body cap. Maximum-envelope equality is an arithmetic capacity assertion;
the genuine measured Bodies above and actual-size profile boundaries were executed.
The legacy 5 MiB child/26 MiB frame caps were not widened.

## Resource observations and reproducibility

CPU reported AMD Ryzen 9 9950X3D2 16-Core Processor, 16 cores/32 logical processors.
Build jobs and Rayon threads were both two; `RUSTFLAGS=-C target-cpu=native`.
Cargo used the pinned offline cache, `--release --locked --offline`, the standalone
leaf manifest and fresh `.local/target-private-lifecycle-wire-r1`. Its locked graph
retained all 213 packages/nodes. Old 1163 EXE/DLL artifacts and pinned SDK/tool bytes
were protected and unchanged.

Across 31 numerical, two genuine Body and 11 filtered-test processes, the owned-PID
observer retained **44 observations/5312 CSV rows**.
Largest observed OS peak/working set were **1082941440/
1082941440 bytes**, and largest sampled private usage was
**1082171392 bytes**. Sampling was nominally 100 ms; maximum
actual sample gap was **111.4442 ms**. No sampled 1792 MiB
soft fuse or 1200-second per-process fuse fired. Compiler/contract processes were
outside this observer. These observations do not guarantee whole-peer RAM, hostile
OOM recovery, distributed availability or an interactive SQL target. Source24Mi and
child16Mi decoded-container slot ceilings are structural allocation budgets, not bytes/RSS.

Normal entry points (from the standalone leaf):

```powershell
cargo run --release --locked --offline -- security registry-lifecycle-bootstrap-wire
cargo run --release --locked --offline -- security registry-lifecycle-wire
cargo run --release --locked --offline -- prove registry-lifecycle-bootstrap-wire
cargo run --release --locked --offline -- prove registry-lifecycle-wire
```

Both security aliases emit analytical Source then child reports without proving.
Focused release tests used the compiled test executable with `--test-threads=1`:
new wire tests; existing lifecycle/private-Journal/legacy-wire modules; and five
previous genuine prerequisite/locking controls. Evidence is retained locally under
`.local/private-lifecycle-wire-validation-r1`, including source snapshots, actual
artifact discovery, raw command logs and owned-PID CSVs; generated proof bytes,
operational owner keys and binaries are not committed.

Frozen source manifest SHA256:
`B39C7BFFBF0D121C0C9678CE3D44312BBF1383FAED12B00AD7A9A8AE269D888B`.
Root executed-source SHA256: `2BA759FBF5CFC912B41E4A45CB7AE371A847198AE7717E68387EC3D0FFFBD06E`.
Closed gate receipt SHA256: `009A1E090EFE79A89371F06F8D498EB7F9AC83BDBA6F7C1DAE955E70F99ADA30`.

## Remaining requirements

The signed Body example contains explicitly public nonsecret opaque request bytes
and update heads. There is no Request200-to-Expected parser or semantic update
admission, Journal import/reopen, delegated controller signature or production
lock grant. Signature validity authorizes exact bytes and does not prove their
semantics. The code does not add peer network I/O, fresh agreed heads, MVCC,
encrypted data commit/rollback, writer fences, complete SQL computation/completeness
proofs, decentralized finality or compact encrypted storage. Those requirements
remain open; the whole PostgreSQL goal is active.
