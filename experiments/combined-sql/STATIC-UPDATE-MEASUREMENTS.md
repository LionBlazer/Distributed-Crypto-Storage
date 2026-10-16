# Static UPDATE source comparison

On 2026-10-16, the complete accepted million-row UPDATE and subsequent SELECT ran
on `edb486d68659fd24fb37798bdc71eaa602173a37` and its direct child
`1ad514844085067611cd887598b3db113d495816`. Both include randomized custody
object profile 2, RPC v2 and application v4. BFV/STARK, private index, compact image
formats, admission limits and final freshness rules are unchanged.

## Change and preserved checks

UPDATE freezes public placement and Full/Delta recipient classes before proof
preparation. If every recipient is a known Delta holder, its initial source is
the fixed ReadImage: complete data and padded index posting prefix. For this
million-row geometry it transfers 5,461,696 application bytes instead of a
37,604,580-byte full Fetch reply, excluding transport/TLS. If any Full recipient
was preplanned, UPDATE still obtains complete images. An error never changes this
class or triggers a Full fallback for a known Delta holder.

The static path stages the genuinely checked encrypted amount updates and
reissues only the authenticated index header page. It never fabricates a complete
Table from a partial index. Every recipient receives the same target nonce and
heads; ordinary Full candidates retain the complete preflighted RawBundle.
All shard proofs, overflow checks, freshness and wire/journal preflight finish
before the first Store or new authorization.

The peer still audits its complete physical base and both final roots when
applying Delta. Confirmation still fetches the complete agreed object, audits both
images and checks owner header/TableId binding. Pending recovery retains complete
holder audits and exact target identity. Prefix membership, server implementation
and storage ACKs do not become a proof of complete custody. The fixed initial
footprint does not add predicate-dependent addresses or response volumes. These
bounds do not establish sparse disk I/O, a RAM saving or WAN performance.

## Full accepted operation measurements

The same existing real-process scenario and public one-million-row fixture as the
[object-profile comparison](CUSTODY-PROFILE-MEASUREMENTS.md#operation-and-configuration)
updates the last row from amount 1 to 2 and reads exactly `[[42, 2]]`. Both owners
run `million_row_private_index_crosses_real_custody_frames_and_agreed_update_restore`.
Startup, keys and table creation remain outside the timers; real TLS I/O, FHE,
proof verification, complete mutation publication/confirmation and final agreed
restore remain inside UPDATE. The easy work target and one descendant confirmation
are prototype settings, not production attack resistance.

Three fresh alternating before/after pairs ran in
`.local/static-update-network-runs/20261016-090219-240/`. All six scenarios, exact
result/head assertions and twelve accepted-operation timers passed. No development
build, other proof test or memory monitor ran in this window. All three diagnostic
variables were removed and checked absent before launch; logs contain no RPC/PID
markers. Unrelated host background load was not controlled.

| Complete operation | Before min / median / max ms | After min / median / max ms |
| --- | ---: | ---: |
| UPDATE | 932.074 / 990.834 / 1084.675 | 868.618 / 888.723 / 934.264 |
| SELECT | 349.865 / 353.917 / 378.497 | 346.153 / 359.175 / 369.706 |

The UPDATE difference between medians is -10.3%; SELECT is +1.5%. These are not
medians of paired percentages. Both operations have overlapping sample ranges,
and SELECT's implementation is unchanged by this patch. With three samples these
values cannot isolate causation or establish a tail bound. All UPDATE samples
still exceed 500 ms. Complete PostgreSQL, live private FOR UPDATE/SKIP LOCKED,
public source-completeness proofs and production finality remain unfinished.
Do not combine this window with earlier windows to claim a cumulative speedup.

## Reproduction and verification

The Windows x64 host is AMD Ryzen 9 9950X3D2. Both builds use Rust 1.99.0/MSVC,
release, `-C target-cpu=native` and locked dependencies. Both measured owners and
peers use eight Rayon threads; peers report AVX-512. N8192/Q218 proof profile v3,
all 81,920 residues, FRI blowup 8, 192 queries, extension degree 5 and the 128-bit
floor are unchanged. Kernel identities and the exact no-hook reproduction command
are in the [preceding record](CUSTODY-PROFILE-MEASUREMENTS.md#frozen-artifacts-and-reproduction).
The floor is not a security proof of the complete storage protocol.

| Variant | Exact owner under repository root | Baked peer directory |
| --- | --- | --- |
| Before | `.local/target-salted-custody-objects/x86_64-pc-windows-msvc/release/deps/proved_sql-501f76c956e504af.exe` | `.local/target-salted-custody-objects/x86_64-pc-windows-msvc/release/` |
| After | `.local/target-static-update-network/release/deps/proved_sql-18a2eaec0e34c184.exe` | `.local/target-static-update-network/release/` |

| Artifact | SHA256 |
| --- | --- |
| Before owner | `D21873170B9D2F92ED9597F4C6EF40F42DCDDDE8282579B416B1602BD4370C36` |
| Before peer | `7EC7B4E4E7B319C96B65DFC00A597D723A5A2CB6ECF7B6CCBB938CEF734BE335` |
| After owner | `BAEE8839B0CED44CCC540302B66B470A966C7C984F575BD93FE9C15D65394160` |
| After peer | `E1B028E183ED55CC1FE45B4F6A21643E575C23D1A1E9AF66293A036A49915ADE` |

The ignored window preserves all six raw logs, twelve timers, exact owner/peer
and kernel copies, hashes, baked paths and the executed measurement script. Restore
matching peer/kernels at the baked path outside the timer before reproducing;
do not overwrite another active consumer's binaries. A copied owner alone does
not pin its peer. Generated executables, logs and ciphertext are not committed.

The exact integrated change passed 140 native behavioral tests: runtime 51,
client 32, actual transport 14, fault 4 and SQL 39. One ignored aggregate measurement
fixture was not run in that suite. Five new real-process cases cover fixed initial
ReadImage plus full final FetchVersion, interrupted source retrieval without
fallback, corrupt unrequested tail after Delta ACK with exact pending recovery,
preplanned Full/Delta classes with identical complete target envelopes, and genuine
two-shard overflow that prevents all Store/authorization. Strict affected Clippy,
formatting, requirements mirroring, module links and independent source review
passed before the artifacts were frozen. No whole-process memory measurement or
full PostgreSQL compatibility claim follows from these checks.
