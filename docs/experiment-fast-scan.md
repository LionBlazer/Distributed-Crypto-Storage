# Evaluator scan and update kernels

The public `Evaluator` API now uses a 12-bit encrypted COUNT internally, masks
amounts at their stored 16-bit width, and uses TFHE's specialized multiple-input
sum. Its returned COUNT and exact SUM remain 32-bit ciphertexts. The public table
limit of 1024 rows bounds COUNT to 1024 and SUM to 67,107,840; compile-time checks
prevent either accumulator width from silently becoming insufficient.

UPDATE obtains its candidate and encrypted overflow carry from `overflowing_add`,
instead of adding and then comparing the modular result with the original amount.
Every overflow remains masked by the encrypted predicate. A global encrypted
rejection condition still retains all original amounts if any matching row would
overflow. No plaintext branch, predicate, delta or secret key is added to evaluation.
Empty behavior, domain checks and public result types are unchanged.

## Reproduction and measurement boundary

```sh
cargo test --release --locked -p fhe-prototype --test relational_operations -- --test-threads=1
cargo test --release --locked -p fhe-playground --tests -- --test-threads=1
cargo run --release --locked -p fhe-prototype --example query_layout -- 2 3
cargo run --release --locked -p fhe-prototype --example query_layout -- 8 3
```

The example uses the same public four-row fixture repeated to 4 and 16 rows,
ephemeral resident keys and ciphertexts, and unchanged TFHE-rs 1.8.1
`PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128` parameters. Each round alternates
kernel order. `optimized=false` reproduces the previous serial evaluator kernels;
`optimized=true, parallel_rows=false` reproduces the current evaluator scan.
UPDATE rows report `update_and_status_decrypt_ms`; scan rows report
`query_and_decrypt_ms`. Updated amounts are checked individually outside the timed
UPDATE/status boundary. All scan answers are checked against the public fixture.
Every UPDATE trial derives a fresh result from the unchanged encrypted fixture.

The third scan variant (`parallel_rows=true`) gives each scoped initiating thread
an evaluation-key context, while TFHE's internal work shares the Rayon pool. It
adds up to `min(rows, Rayon threads)` initiating threads, so it is a different
whole-process CPU/thread budget. The new threads also use the global Rayon pool
rather than inheriting a caller-local pool. It stays experimental. Installing/restoring a
context for each high-level operation in `par_iter` risks replacing a key while a
nested TFHE operation still borrows that worker's thread-local key.

These are local scan/update microbenchmarks, including owner result/status
decryption. They exclude input encryption, storage restoration, networking,
consensus, version freshness and query proofs. The process peak includes keys and
all variants in that run; it is not an isolated operation's incremental memory.
Ranges from a few paired trials are not p95/p99 or an indexed query SLA.

## Measured results

Measured on 2026-10-14 with Rust 1.99.0 on Windows x86_64. Each cell is the minimum
and maximum of three rounds in one run per Rayon thread count. Keys and encrypted
inputs were resident before timing; no other agent benchmark ran concurrently.
All 60 emitted measurements passed their plaintext-fixture checks. Raw JSON lines
are retained locally in ignored `.local/fhe-research/fast-scan-{2,8}threads-3rounds.jsonl`.

| Rayon workers | Rows | Previous scan, ms | Current scan, ms | Paired speedup | Experimental parallel scan, ms |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 2 | 4 | 3559–3645 | 1163–1317 | 2.76–3.06x | 1202–1407 |
| 2 | 16 | 9991–14553 | 2898–4406 | 2.72–3.45x | 2843–4453 |
| 8 | 4 | 1109–1171 | 388–417 | 2.68–3.01x | 303–309 |
| 8 | 16 | 4550–5050 | 1202–1351 | 3.60–4.16x | 953–968 |

| Rayon workers | Rows | Previous UPDATE/status, ms | Current UPDATE/status, ms | Paired speedup |
| ---: | ---: | ---: | ---: | ---: |
| 2 | 4 | 2210–2745 | 1737–2187 | 1.22–1.30x |
| 2 | 16 | 6115–8864 | 4994–7582 | 1.17–1.24x |
| 8 | 4 | 803–850 | 712–746 | 1.10–1.15x |
| 8 | 16 | 3133–3405 | 2581–2877 | 1.18–1.27x |

Whole-process peak resident memory was 359.6 MiB at two Rayon workers and 362.0 MiB
at eight, including owner/evaluator keys and all tested variants. Absolute timings
varied substantially within the two-worker 16-row run; the ratios compare the same
round's previous/current operations. The parallel variant improves the eight-worker
cases but has no consistent four-row benefit at two workers. The library therefore
keeps serial row traversal and the original caller/thread-context behavior.

## Acceptance limits

Public API coverage includes encrypted equality/range boundaries, empty selection
and table, COUNT carry past 255, exact wide SUM, atomic matching-row overflow,
nonmatching overflow, zero and maximum deltas, domain rejection before mutation,
and repeated compression/reload. Playground tests cover the dependent SQL/shard
boundary and rollback of an update rejected on a later shard.

Validation passed: 17 prototype API tests (72.00 s), five playground library tests,
13 playground workflow tests (58.13 s), seven SQL/fixture tests, and prototype
`cargo clippy --release --locked -p fhe-prototype --all-targets -- -D warnings`.
The desktop playground executable was already in use, so Cargo could not replace
it while building all test targets. Its freshly built integration-test executables
were run directly with `--test-threads=1`; no GUI was started or stopped.

This change does not provide an index, compact canonical storage, query proofs or
distributed SQL. The [measured storage expansion](fhe-optimization.md) remains
about 50x at 1024 rows. Neither the active 2x storage / 500 ms indexed-query goal
nor the earlier 100 ms research target is established by a faster full scan.
