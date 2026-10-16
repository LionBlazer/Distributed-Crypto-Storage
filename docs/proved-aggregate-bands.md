# Q2 proved COUNT/SUM capacity and measurements

This 2026-10-16 record measures the fixed, non-null `records(age:u8,amount:u16)`
prototype after extending genuine coefficient aggregation to 2560 selected rows
per shard. It establishes neither full PostgreSQL support nor a general 500 ms
latency bound. Typed aggregates, live SQL locks and general transactions remain open.
The [requirements](../REQUIREMENTS.md) are unchanged.

## Computation and acceptance boundary

The [Q2/R2 kernel](../crates/bfv-query-core/README.md) packs ten 256-row bands into
three contiguous original-value fields and uses the same public 256-term
polynomial. It produces one encrypted product and one complete 81,920-residue proof
per shard. FHE/STARK profile v3 and the trusted kernel ABI are unchanged. Application
domain v3 additionally commits the aggregate semantics ID; old application v2
anchors and Q1/R1 wires reject without migration. Row SELECT, mutations and row
references retain their independent 256-row limits.

The owner authenticates complete selected postings and data against both agreed
heads, encrypts original amounts/presence, and drops the source plaintext. Each
independent peer computes the real product and supplies a STARK. The owner verifies
the exact statement, decrypts actual per-band coefficients, checks every band count,
limb bound, cardinality envelope and zero tail, then combines with checked u64
arithmetic and checks freshness. Empty SUM is NULL; a nonempty zero SUM is zero.
No fixture-derived sum, result echo or dummy cryptographic path is used. Public
AEAD-to-FHE linkage remains open; this uses the existing owner-online boundary.

## Fixture and timing envelope

Source: `fbf335e15eea2784d097f7be85c3656c511a02de` on
`codex/feature/aggregate-bands`. The `aggregate` test filter selects three real-process
tests: old-v2 journal initialization refusal, a 5121-row capacity failure with no
published head/object change, and the asymmetric 5119/5120-row Q2 fixture. All nine
test executions and all 30 timed query assertions passed.

Each of three fresh test invocations creates a pair of independently identified
peer processes for the Q2 fixture. Round-robin shards contain 2560/2559 and 2560/2560
rows. Per-band values and amounts differ between shards. Age 18 selects only one
shard; age 7 selects the other; age 42 selects one zero-valued row; age 255 selects
nothing. The two fixture sizes run in that order and install separate setups in
the same pair of peers. Setup is outside the query timer.

`accepted_sql_ms` wraps the entire `Session::execute`: planning, journal synchronization,
complete encrypted snapshot fetch and authentication, original-input encryption,
peer product/proof, verification, final decryption and fresh-head check. Session
creation and peer startup are outside the timer. RPC, PID and memory hooks were
disabled. Other agents paused builds/proof workloads during this coordinated window.
No timing phase was moved out of the accepted query.

Host: AMD Ryzen 9 9950X3D2, 16 cores/32 logical processors, Windows x86-64 MSVC;
Rust 1.99.0 (`b940084d7`, LLVM 23.1.1), release with `-C target-cpu=native`.
Owner and each peer use eight Rayon threads. Peers selected trusted AVX-512 kernels.
All participants run on one computer: this does not establish independent failure
domains, WAN latency, throughput or a tail-latency bound. Memory was not measured
in this window; the 1–2 GB whole-process target is not established by these samples.

## Full accepted query latency

Times are milliseconds; each cell lists all three runs. COUNT-only and SUM-only
projections still use the current combined encrypted count/limb product internally.

| Source rows | SQL | Runs ms | Median ms |
| ---: | --- | --- | ---: |
| 5119 | `SELECT COUNT(*), SUM(amount) FROM records` | 206.102 / 205.505 / 198.820 | 205.505 |
| 5119 | `SELECT COUNT(*) FROM records WHERE age = 18` | 204.209 / 206.946 / 203.023 | 204.209 |
| 5119 | `SELECT SUM(amount) FROM records WHERE age = 7` | 229.072 / 245.984 / 247.065 | 245.984 |
| 5119 | `SELECT COUNT(*), SUM(amount) FROM records WHERE age = 42` | 253.975 / 242.225 / 237.239 | 242.225 |
| 5119 | `SELECT COUNT(*), SUM(amount) FROM records WHERE age = 255` | 249.430 / 230.840 / 225.100 | 230.840 |
| 5120 | `SELECT COUNT(*), SUM(amount) FROM records` | 275.321 / 258.643 / 248.188 | 258.643 |
| 5120 | `SELECT COUNT(*) FROM records WHERE age = 18` | 250.721 / 238.568 / 243.471 | 243.471 |
| 5120 | `SELECT SUM(amount) FROM records WHERE age = 7` | 279.037 / 257.417 / 247.468 | 257.417 |
| 5120 | `SELECT COUNT(*), SUM(amount) FROM records WHERE age = 42` | 284.874 / 271.844 / 272.416 | 272.416 |
| 5120 | `SELECT COUNT(*), SUM(amount) FROM records WHERE age = 255` | 274.909 / 273.562 / 266.474 | 273.562 |

All measured queries were 198.820–284.874 ms. These are small public fixtures and
three samples, not a percentile estimate or a comparison against Q1, whose source
capacity differs. Larger tables still incur full snapshot retrieval; this change
adds no sparse network fetch and does not resolve the measured million-row UPDATE
latency failure.

## Reproduction and artifacts

Build outside the timing window with an isolated `CARGO_TARGET_DIR`, Cargo jobs 2,
`RUSTFLAGS=-C target-cpu=native`, and the unchanged profile-v3 trusted SIMD kernels
beside `dcs-peer.exe` in `proof-kernels/`:

```powershell
cargo test --release --locked -p dcs-peer --test proved_sql --no-run
$env:RAYON_NUM_THREADS='8'
$env:DCS_TEST_PEER_THREADS='8'
Remove-Item Env:DCS_TEST_RPC_PROFILE -ErrorAction SilentlyContinue
Remove-Item Env:DCS_TEST_FIXED_PIDS -ErrorAction SilentlyContinue
# Use the actual test executable path printed by Cargo. Repeat three times:
& $testExecutable aggregate --nocapture --test-threads=1
```

Ignored raw logs and artifact metadata:
`.local/aggregate-bands-timings/20261016-044455-693/{run-1.log,run-2.log,run-3.log,artifacts.json}`.
SHA256 identities:

- `proved_sql-43b267abd6ab93e6.exe`: `757645990039A1B2B23C1FC46C1AB8C25A0334139C8DC86D057721387960102C`.
- `dcs-peer.exe`: `38A2A44A5E95D2136C2D664D091ED2122E2AD2B93006A2655FE82810A8DBE4BF`.
- `dcs-proof-avx2.dll`: `8E62FB81AEABF1AEE9F325591635B9B1B2E2E940F0D3C95036061C7B7B394940`.
- `dcs-proof-avx512.dll`: `BA7C5E7106629402169267D69A5BAD2D68526BC9D0EE1579D5D59125E5260A60`.
