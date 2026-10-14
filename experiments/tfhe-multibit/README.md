# Official TFHE multi-bit CPU comparison

Bounded real comparison completed: 89 encrypted operations passed across five
native processes. Grouping4 did not reach 500 ms for the measured multirow queries.

This isolated experiment exports current compact-query and compact-store from
commit 9c4ad836c8a581455bfb4a7a9d395a9e87507675 into ignored local workspaces.
It compares unchanged classic CPU parameters with the official grouping4 CPU
TUniform 2M128 set in TFHE 1.8.1. No main or older private-access source is edited.

| Entry point | Responsibility |
| --- | --- |
| [run-multibit.ps1](run-multibit.ps1) | Export exact project source, select one official parameter import, record provenance, build/run the isolated example and preserve ignored JSONL. |
| [probe.rs](probe.rs) | Current-main full serialized owner/peer lifecycle, 1M rows, indexed 0/1/4/16 aggregates, range, repeated point and multirow FHE updates, restart/stale output checks, overflow/zero/replay corner cases. |
| [support.rs](support.rs) | Windows native working-set/private-commit counters, sampled process-thread counts and a process-local 2 GB guard. |
| [Cargo.lock](Cargo.lock) | Exact current-main package versions/checksums, pruned to the 99-package standalone feature graph by offline Cargo metadata. |

Direct project dependencies are copied
[compact-query](../../crates/compact-query/README.md) and
[compact-store](../../crates/compact-store/README.md). They keep their existing
ownership, wire format, predicate, FHE kernel, update validation and canonical
snapshot/index lifecycle. Both copied profiles get the same workbench-only
evaluation-key decoding cap of 1 GiB, because the current 512 MiB cap rejects
the estimated 558 MB multi-bit key. The sole candidate-only core change is the
official parameter import. Dedicated OPRF remains enabled in both.

Prepare without invoking Cargo:

    ./experiments/tfhe-multibit/run-multibit.ps1 -Preset classic -PrepareOnly
    ./experiments/tfhe-multibit/run-multibit.ps1 -Preset group4 -PrepareOnly

Run only after the CPU lease is granted, first with one row initiator and two
Rayon workers; compare the control under the same budgets:

    ./experiments/tfhe-multibit/run-multibit.ps1 -Preset classic -Threads 2 -RowWorkers 1 -Offline
    ./experiments/tfhe-multibit/run-multibit.ps1 -Preset group4 -Threads 2 -RowWorkers 1 -Offline

The next bounded comparison may use four/eight Rayon workers. Eight row
initiators are optional only after the single-initiator run confirms safe memory.
Native multi-bit creates nine OS producer threads per PBS independently of
Rayon; Rayon workers are not a total process-thread limit.

The Windows sampler polls at 25 ms and adds one monitoring thread. It records
OS-maintained memory peaks but only a sampled thread maximum. Both profiles use
the same sampler. Exceeding 2,000,000,000 current working-set or private-commit
bytes exits with code 3 and preserves a partial report. This is a sampled guard,
not an allocator-enforced hard cap.

The detailed [source feasibility report](../../docs/experiment-tfhe-multibit.md)
distinguishes estimates from measurements, exact official parameters/security,
thread proliferation, larger keys, storage amortization and pending checks.
