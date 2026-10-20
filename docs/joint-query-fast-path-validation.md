# Joint query prerequisite and transport checks

This revision removes repeated work within one live query or synchronous
finality command. Its affected seven-process integration gate passed on
2026-10-20 in 2593.751 seconds, compared with 3345.196 seconds previously.
The earlier [seven-process result](joint-sql-network-validation.md) measured the
preceding implementation: 3345.196 seconds for the complete recovery scenario,
including 1277.232 seconds for its first production Driver Acquire. Neither run
isolates the effect of any one change.

## Changed work

- Upload scheduling retains each peer's acknowledged blob ordinal during one
  round. A turn performs one real RPC and yields to the other peers. BUSY retries
  the current blob; cancellation, full candidate/QC verification and joins remain.
- One durable finality drive hands its actual application result to that same
  decision's floor preflight. Full metadata, context, candidate, parent, floor,
  signature and successor checks remain. No result survives another drive or
  restart; historical import and recovery still verify all actual premises.
- A fresh Idle Driver Acquire retains its original private owner and pending
  objects through that exclusive call. It consumes the actual checked recorded
  product, checks every retained reference and keeps full pre-Body and final
  application verification. Every yield or restart requires ordinary full restore.
- One `Provenance::verify_inputs` freshly verifies its own anchor Key and borrows
  that actual transform through the ten Basis and two Formation checks. The static
  call graph changes Key verification from 13 to 1 and Basis verification from
  20 to 10. Source/Encoding, output118, standalone verifiers and every native child
  proof remain. These counts establish no whole-operation speedup.

No proof language, wire profile, quorum threshold, authorization, resource cap,
production timeout or freshness condition is relaxed.

## Owning native checks

The release/offline/locked checks used Rust 1.99 MSVC and host-native codegen.
Cargo jobs remained two. Input16 and live-drop tests requested four Rayon threads;
the other checks requested two. The observer retained its 1792 MiB per-process
soft fuse and 1800-second whole-command budget. No fuse fired. Observer samples
are measurements, not a formal RAM bound.

| Boundary | Actual result | Test body | Whole command |
| --- | --- | ---: | ---: |
| Scheduler and real framed-TCP I/O | Six passed | Under 0.1 s | 0.546 s |
| Genuine nondeciding proposal, corrupted Kind, strict reopen | One passed | 36.35 s | 42.717 s |
| Scoped Basis ownership | Two compile-fail cases passed | 0.55 s | 27.618 s |
| Genuine Input16 and foreign scopes/premises | One passed | 110.52 s | 114.206 s |
| Dropped live objects and exact full Compute restore | One passed | 166.50 s | 167.097 s |

The eight-case finality attempt first produced seven passes and one failure in
the new test's fixture: its timer had no quorum and correctly returned Stale.
The corrected test installs the actually elected participant and uses its real
durable `propose` API. Only that affected case was repeated. The seven other
passes cover actual floor-sync loss, torn floor, advance refusal, quota, corrupt
WAL and strict reopen. The failed attempt remains a failure; no complete 8/8
rerun is claimed.

The genuine Input16 test generates Source, Key, both Encoding, ten Basis and two
Formation proofs. It rejects foreign CsHat, ciphertext/request/order/setup,
distinct transform instances with identical public claims, malformed proofs and
a corrupted second invocation. It does not simulate FHE output or a valid QC.
The live-drop case includes actual Source/Lifecycle/Link verification, rejects
malformed catalog metadata, stale CAS and a wrong recovery authority, and checks
unchanged cursor/WAL/quota. It supplies no output118 or positive network result.

Input16's observed OS peak working set was 1483759616 bytes; live-drop's was
1524854784 bytes. Neither number measures all production peers together or
establishes latency/resource improvement against a comparable earlier run.

The exact source receipt for the latter four checks is
`F7C8C3C951717B7D46DC84CF6DF65020913B7F31465495BAEB170C2BB7428392`;
the after receipt, including the then-failing strict Clippy result, is
`F8F0924ED32061CAB68B983768850149A7C780E6A291AC6950D8140F77AB10A0`.
Clippy identified the new internal transport enum's large optional checkpoint.
It was changed to `Option<Box<JointCheckpoint>>`, allocating only for a present
untrusted QC. The six transport cases passed again in 0.02 seconds; their whole
command including rebuild took 28.662 seconds. Strict Clippy passed all targets
of the five affected packages in 2.802 seconds. The final source receipt is
`F923162891291EBBC474588351D76C5BD5EA1672A3CF8FFBC9CD825AA8462DD0`,
and its unchanged-inventory/source/log after receipt is
`A6D741818CDD298B597980249F20968EC9B7333962A77906F449339B4468F092`.

The test's explicit public index suffix now belongs to this proof crate's own
`tests/fixtures/`. Its 6741-byte text is byte-identical to the public suffix used
in the measured Input16 run, SHA-256
`CE187A477E387691A33D6F41A2E9B6ADF7517E06A07FE72D3063987B4BAE9D2A`.
Moving its include path and updating status comments do not change the proved
fixture. No production dependency on consumer test code is introduced.

## Executed seven-process integration gate

The matching peer build passed in 11.813 seconds. The existing Host7OS case then
passed all its original assertions, deadlines and recovery steps: one selected
test passed, zero failed or ignored. Its body took 2593.16 seconds; the whole
Cargo command took 2593.751 seconds, including its already-warm 0.29-second build.
The scenario retains four real validator processes, one real FHE peer and two
sequential independent owner processes. Two genuine encrypted evaluations,
input16/output118/END/EOF, all four actual weighted certificates, held-row
SKIP-before-OFFSET behavior, exact second-call recovery, prepaid ACK, stale/foreign
rejection, COMMIT/ROLLBACK lock lifecycle and the final strict reopen all passed.
COMMIT here closes the lock registry; it does not implement SQL data mutations.

| Complete operation or phase interval | Previous | Current |
| --- | ---: | ---: |
| Whole seven-process recovery scenario | 3345.196 s | 2593.751 s |
| First production Driver `execute` | 1277.232 s | 917.562 s |
| Second genuine FHE exchange | 411.734 s | 425.346 s |
| Owner B strict Acquire-aware reopen | 233.524 s | 134.718 s |
| Both final Control operations through four QCs | 130.043 s | 260.708 s |
| Final strict G6 reopen | 218.165 s | 133.154 s |

The whole scenario was 22.46% shorter; its first complete Driver query was 28.16%
shorter. These are one comparable observation per revision, with four source
optimizations together. The outer runner requested four Rayon threads instead
of two on the same 32-logical-processor host; FHE/validator children inherit it,
while the explicit owner launcher still sets two threads. The experiment cannot
attribute savings to one optimization or to the thread setting and does not
establish a statistically repeated speedup or interactive latency.

Intervals mix computation, transport, checking and consensus waiting. In
particular, the first final Control operation returned all four submit ACKs in
about 1.68 seconds, then peer zero reported no QC for 218.899 seconds. Its later
checkpoint/Body RPCs and those of the other peers mostly took about 30 ms. A
submit ACK establishes no quorum. The configured 180-second consensus step
timers can explain such waiting after a late candidate, but the current log has
no round/step diagnostics to establish that cause. No production timer was
shortened. This slower interval is retained in the complete comparison.

The observer kept its 1792 MiB per-process fuse and the existing 10800-second
whole-scenario budget; neither fired. Owner A's observed maximum working set was
1550536704 bytes and private bytes 1593085952; the FHE peer's OS peak working set
was 1206812672, Owner B's 1154072576 and validators' peaks 641458176 to 657563648.
The largest sampling gap was 1615.438 ms. These samples establish no formal
whole-process bound or memory improvement. Last live user/kernel CPU samples
were 778.859/65.828 seconds for Owner A, 404.125/22.297 for Owner B and
1062.375/89.250 for the FHE peer; validator user CPU ranged 462.859 to 655.281
seconds. They are not exact process-exit totals or phase-specific CPU profiles.

The test source/inventory receipt covers 1619 unchanged files:
`E49F899BCF275A6347EFAE1E4F645C9B2A97BC7F331FB881BE7B27E5F05C0B12`.
The after receipt, including the matching binary and both terminal commands, is
`44653AD5905200B5E1FDC15A0A4331880BC6B1E00CF911898646DF6EB56CD571`.
The 21424640-byte peer image SHA-256 is
`F99572529904BF036BABFBD36ADD07288D8CF58DBAA2EB2AD6994BA0CC403696`.
Local uncommitted observations remain in
`.local/private-peer-native-r1/joint-fast-driver-seven-os-r1/`; stdout, stderr,
CPU CSV and memory CSV hashes are respectively:

```text
C836C89BD82F645475C3ED2AD4C73B6839E47A2E61CF36B34ED957F2D2D0ABE1
D91CE4953B2830227FEFE49D8B3D028ADA6B8DC614BF02F07CB71B4AA8BB7098
E19A92C9AA19D66FFEF4296DA3D06A5B3724C2E50FD59DCC152BD490736D152B
5BD32AC0D231B319CB0D9928497EBBC4B7F2AFCBD46891FAB4FBE5AC4D447180
```

The memory CSV hash and complete phase/process observations are pinned by local
`.local/joint-fast-driver-seven-native-r1/profile.json`, SHA-256
`85BD66068948B5E242C69A8EC09704C3A416511B96DCACAD665471EE288F6DE8`.
Generic Session/GUI SQL, complete PostgreSQL, WAIT/NOWAIT, production enrollment
and a current lease remain outside this record.
