# Retained public evidence and actual shared file accounting

`protocol-storage` owns the single actual retained-file byte budget formerly
inside the consensus signer, plus bounded immutable public evidence files.
`work-finality` uses that implementation directly; its old local implementation
and public compatibility reexports are removed. The storage library depends only
on `std` and the already locked SHA-256 implementation, not on consensus, SQL,
the Journal, fixtures or cryptographic proof verification.

## Observable contracts

The existing 256 MiB aggregate budget remains a hard ceiling. Actual canonical
regular-file charges survive handle Drop. Existing files must be registered
after the owning file lock; absolute growth is charged before writing. Explicit
reservation transfer preserves its charge continuously, and failed transfer
leaves the lease intact. Ambiguous I/O can retain a conservative charge until a
full new accounting owner reconstructs actual disk. No public file-charge reset,
release, truncation or repair API is introduced.

`EvidenceStore` exclusively owns an existing directory and recognizes only its
bounded file grammar. It creates stages without overwriting, reserves their full
extent before writing payload, hashes exact bytes, syncs the file and publishes
an immutable name using a no-clobber hard link. Duplicate publication verifies
actual existing contents. Cancellation removes only the owned stage; failed
cleanup keeps its charge. Committed proof bytes are never garbage-collected.

A `BlobId` is only SHA-256 plus exact length. It can be constructed by anyone and
grants no proof validity, authorization, finality or freshness. Reads require
complete bytes/EOF/hash checks. Applications must separately decode and genuinely
verify all required proofs under independently supplied expectations on every
admission and reopen. Missing required identities fail even when an earlier
application certificate was valid.

The library cannot discover external application references or a WAL outside its
directory. The runtime must reconstruct all retained protocol charges in the
same budget before resuming signing/admission. Windows `std` file sync and hard
links do not establish directory-entry persistence after power loss; absent
referenced files stop recovery. Unsupported publication filesystems return an
error without an overwrite/copy fallback.

## Recovery defect caught before native validation

Independent source review found that charging a surviving `.part` before cleanup
could reject an exact-quota reopen after a crash between hard-link and unlink.
Both names could refer to one actual committed payload. Recovery now preflights
all bounded names, file types and extents before deleting anything, removes only
recognized abandoned stages under exclusive ownership, and then registers and
rehashes retained blobs. Existing stage charges are released only after checked
physical removal. Unknown or oversized files stop opening and preserve evidence.
Failed opening is never a complete reconstructed inventory or admission grant.

The new regression creates the two surviving hard links directly, without a
`StagedBlob` destructor, and pre-registers the committed bytes at an exact quota.
The old code necessarily fails regardless of directory enumeration order. A
separate regression covers distinct abandoned copies at full quota and preserves
oversized/corrupt stage bytes. These are real file operations with bounded fault
injection, not operating-system power-failure tests.

## Executed validation

On Windows/MSVC Rust 1.99.0, release/offline/locked, native CPU flags, Cargo jobs
2 and Rayon threads 2:

```text
cargo test --release --offline --locked -p protocol-storage -p work-finality -- --test-threads=1
cargo clippy --release --offline --locked -p protocol-storage -p work-finality --all-targets -- -D warnings
cargo check --release --offline --locked
cargo fmt --all -- --check
```

All 12 storage tests, all 33 existing election/quorum/consensus/WAL tests and all
five existing ownership compile-fail examples passed. Runtime groups took
0.45 s and 0.56 s; doctests took 0.33 s. The entire test command took 10.839 s,
including compilation. Strict Clippy, Core default-member check and format check
passed. The requirements mirror and changed local documentation links match.

The nominal 100 ms Windows observer recorded only 27 samples, with a maximum
1045.632 ms gap. It captured Cargo and the work-finality test process, but missed
the short-lived storage process. Its sampled maximum WS was 65,204,224 B,
private bytes 52,789,248 B, OS-reported peak WS 67,125,248 B. These partial samples
establish no memory bound for the storage tests, full proof verification or a
whole peer. No runner-budget or sampled soft-fuse abort occurred.

The test source manifest `.local/protocol-storage-native-r1/source.json` has
SHA256 `3EE1D40F41510FF57E2702CAA47DCE30950A5DD9DC572CF30E3D552AA0B61293`.
All 1423 raw source files matched after the tests/default build check and before
these documentation updates. The ignored receipt
`.local/private-peer-native-r1/protocol-storage-tests-r1/` preserves stdout
SHA256 `6E75C4F827CF551A2AEA2AA4A7CFD8400737930635B04F105A0EE92ED97544E2`
and stderr SHA256
`B709F11C25A6EE1D4A2FC310398A5C063280B6ABADDCA65CC4E5C380824AC34F`.
The source-only donor packet aggregate was
`BB752FC6A2CF6F5143CC0E9035A5BAB082E9C2190ECAFB6084260B2266CA5901`;
the import manifest SHA256 was
`A0A589FE3BC0BF35618F64F389A124282447D9D04621AAA02277D836B1CEFC67`.
Root applied formatting before freezing the tested sources.

Cargo metadata adds only the local `protocol-storage` package and its local
`work-finality` dependency. Every other locked package and dependency entry is
unchanged. No new third-party version, generated output, binary, local database
or private material is committed.

## Remaining integration

This module has not been connected to a live SQL answer, a finalized lock or a
durable full FHE evidence graph. The [actual private-peer proof graph](private-where-peer.md)
does not fit this legacy 256 MiB aggregate budget. A new application/resource
profile with a separately explicit participant-wide quota is required; silently
excluding its proof files or accepting a cached verification result is forbidden.
The [detached linkage Body-cap blocker](private-predicate-acquire.md), composed
security obligations, complete evidence availability, fresh quorum head and
network partition/restart gates remain unresolved.
