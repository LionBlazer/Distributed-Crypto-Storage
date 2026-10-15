# BFV integration source plan

Historical source assessment prepared before implementation. The owning-library
integration and finite validation are complete; see the
[measured integration report](experiment-bfv-gui-integration.md) for actual
contracts,147 full headless operations, hashes and limitations. This plan records
why the integration has two explicit backend contracts, without claiming arbitrary
SQL, private access, production security or arithmetic proofs.

## Reviewed baseline and semantic boundary

At main62de3ad, LabEngine owned one compact-query TFHE Owner, public Evaluator clones
and one canonical Table per logical peer. Creation immediately generated TFHE keys
and configured row workers. The GUI allowed128 total rows and16 peers. Its worker
serialized operations and gated staged writes on transport cancellation/commit
permission; virtual packets held references, not actual wire payloads. The
headless sql_workload example used this SAME LabEngine.

The parser consumes the entire statement and supports combined COUNT(*),SUM(amount)
and amount=amount+u16, with age equality or >=; omitted WHERE means all ages. It
rejects other projections, clauses, operators, joins, aliases, comments and multiple
statements. Empty SUM is0. Every GUI query used an exact complete age-index range
equal to the authorized predicate, including[0,255] for no WHERE.

The reusable TFHE API was broader: FullScan and strict-superset index candidates
require encrypted filtering/conditional updates. Existing multi-page, coarse-
selection and global-overflow tests established that boundary. Exact-index BFV ADD
updates EVERY active input; substituting it for generic APIs would silently change
behavior. The integration therefore retains TFHE under an optional default feature
and adds a distinct explicit BFV namespace.

## Cohesive owning extraction

| Owning boundary | Approved change |
| --- | --- |
| crates/bfv-query-core; root Cargo.toml/lock | Extract current arithmetic/wire/key roles and37 tests/2 doctests. Change crate imports only; retain private kernel/exact_index/indexed_update children, public roles, complete original keyset and profile. No library dependency on a demo, storage or frozen probe. |
| compact-query Cargo/lib/storage | Make TFHE optional under default tfhe-backend. Add optional bfv-experiment and owning-library dependency. Share Table, schema, canonical index, AEAD lifecycle and staged data/index replacement through private storage helpers. |
| compact-query::bfv | Separate exact aggregate/update prepared tokens; private complete-index capability from current two heads, authenticated postings/data, no duplicates and EVERY selected age check before encryption. No arbitrary-vector or coarse shortcut. Preserve multi-page support. |
| GUI LabEngine | Disable TFHE defaults, generate BFV only, share PUBLIC evaluator/setup through Arc. Use exact aggregate or encrypted addition followed by unverified decode/local oracle. Preserve quotas, offline/empty policy, global staging and transport commit permit. |
| Tests/docs | Retain broader TFHE tests and unchanged parser/worker/UI contracts. Add BFV storage failure-model tests, full128 GUI regression and finite full-operation measurements; report every slow result and all keys/memory. |

Exact aggregate must retain fresh low/high byte weights and COUNT ones, without
substituting an owner-computed answer. A nonempty shard with zero matches still
executes encrypted zeros; physically empty shards retain the prior skip policy.
UPDATE must perform peer ciphertext addition before the local checked-add oracle;
verify ALL slots and global overflow before publication. Preserve index page0 after
112 bytes, fresh nonces, constant live size and current data+index roots. Inspector
refresh must read actual staged ciphertexts. Local checking is not a cryptographic
malicious-computation proof; in-memory staging does not establish disk durability.

The baseline BFV crate declares Rust1.99 despite old GUI1.95/workspace1.91.1. Preserve
that truthful requirement unless separately validated on older toolchains. Keep
N8192/Q218/t114689/CBD variance10, native NTT, level0 and the full keyset unchanged.
Record resolved features: a label alone cannot detect unification. Frozen probes
remain historical files without forwarding/migration layers. Owner-key recovery
and private PIR/disk retrieval require separate ownership extraction.

Required gates include0/1/16/128/256 selections, complete budget/count/varint and
duplicate rejection, authenticated wrong ages, both stale heads, domain/keyset/
foreign owner, carry/max unsigned SUM, positive256 multi-page UPDATE with unselected
rows unchanged, actual public in-bounds forgery rejection, global overflow, index
suffix/nonce/no-growth and cancellation/late-shard rollback. The
[completed report](experiment-bfv-gui-integration.md) records the exact executed
gates and the finite visible-only timing/accounting evidence.
