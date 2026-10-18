# Streamed lookup research records

The reviewed SDK source, license, upstream identity and owning tests now live in
[vendor/p3-multi-stark](../../vendor/p3-multi-stark/README.md). Consumers use one
explicit SDK path identity; this archive is no longer a Cargo package.

Historical measurements retain their own sources and mode semantics:

- [Initial streamed lookup validation](VALIDATION.md).
- [Streamed round validation](STREAMED-ROUNDS-VALIDATION.md).
- [Per-AIR row cache validation](PER-AIR-ROW-CACHE-VALIDATION.md).

The current SDK selects Resident by default and Streaming only per call. Neither
mode supplies SQL admission, private source proofs or fresh agreed state.

The [proof-library extraction validation](../bfv-mul-relin-proof/LIBRARY-EXTRACTION-VALIDATION.md) records the current
relocation, owning native tests and preserved proof policy.
