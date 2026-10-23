# Actual receiving transcript tests

The parent genuine five-proof fixture scopes the optional engine transcript audit
around real closed native receiving. This test-only helper checks complete
Source/Role3/DATA/Word/Query event streams against owning public endpoints and
actual SDK manifests, then independently hashes every recorded draw preimage.
Its direct dependencies are the parent read expectations/transcript inspector,
engine audit records, field operations and SHA2; it constructs no native proof.
The [typed CAP helper](runtime_trace/README.md) additionally binds actual decoded
commitments and input Merkle openings to their captured roots and fixed schemas.

`runtime_trace::check` requires all five families, 77 challenge groups and 1335
accepted base samples, verifies retry/counter/digest agreement, and rejects 78
mutations of those actual streams. PP caps originate in real receiver
reconstruction; their actual input rows/salts are authenticated against those
captured roots, not inverted from metadata.
This finite runtime correspondence test proves neither an online extractor nor
an adaptive ROM reduction, composed security, freshness or SQL admission.
