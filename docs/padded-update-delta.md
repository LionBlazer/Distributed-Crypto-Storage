# Padded UPDATE ciphertext writeback

The fixed-schema owner/client UPDATE retains the page addresses actually replaced
after checking a genuine full-residue BFV Addition proof and decoding its output.
It sends those encrypted replacement pages with independent new-head membership
proofs rather than uploading unchanged encrypted identity pages to existing holders.
This changes transport only: complete authenticated selection, proof checking,
overflow rejection, confirmed-head freshness and signed transition validation
remain mandatory. No FHE/STARK profile, application anchor or kernel ABI changes.

## Placement and privacy contract

Before proof jobs, `session::writeback` freezes the exact old object/heads and the
current public `Shard.peers` holder class. Known holders use Delta only if its
public geometry plan is smaller than Full Store. Other existing participants
are preplanned new replicas and use Full Store. Geometry-selected Full stays Full.
No missing base, quota failure, damaged object, timeout or other response changes
a recipient's mode. Different participant IDs sharing a TLS identity or socket
address, and conflicting endpoint bindings for one ID, reject before proof work;
routing aliases cannot become new replicas or count as separate copies. A failed known-holder Delta advances to the next frozen
candidate, never Full Store at that same peer. INSERT always uses Full Store.

The Delta wire size depends only on public geometry and the fixed 257-page cap
across both images. It is identical for 1, 2, 64, 256 or 257 replacements,
regardless of their contents or last-page positions. Addresses inside the padded
payload remain visible to the recipient, which already holds the old ciphertext
and could compare it with the new image. Timing, public placement and geometry
remain visible; this is not hidden-address or ORAM/PIR SQL. Full new replicas
receive the same ordinary whole-object upload as before.

## Executable resource geometry

A membership response occupies `64 + plaintext_page_bytes + 32 * proof_height`.
Each Delta entry adds 13 bytes. The fixed header is 524 bytes and the runtime
request envelope is 22 bytes. The planner sorts at most four counted groups
(data/index full/last pages) and adds the largest `min(257, total_pages)` entries.
It never scans the actual dirty set. Zero padding fills the remainder.

For the existing one-million-row fixed schema/private index-3 geometry:

| Complete application request | Encoded bytes |
| --- | ---: |
| Padded Delta, every admissible changed-page count | 1,188,143 |
| Ordinary Full Store | 37,604,542 |

The transport prefix adds 16 bytes; TLS/TCP overhead is separate.
Independent default-limit extrema give a conservative padded-request upper bound
of 16,994,671 bytes, below the new 32-MiB **complete request** cap. These extrema
need not all be simultaneously attainable under the unchanged image cap.
The existing global frame limit is still 64 MiB. Generic Delta accepts at most
257 pages across both images; row SELECT, UPDATE, INSERT and RowReferences still
retain their separate 256-row limits.

The decoder checks the global bounded frame before allocating its frame vector,
then validates exact header-derived length, counts, canonical addresses, exact
page proof sizes and all-zero remainder. It rejects malformed or legacy bodies.
The owning client preflights all full/delta uploads and the complete unsigned
transition after all jobs pass and before the first write or signature.

## Storage and recovery

A first Delta write fully audits the old physical bundle, both old roots and its
canonical immutable hash, including overwritten or unrequested corrupt bytes.
Only verified new-head pages enter consuming same-geometry snapshot replacement.
The complete reconstructed new roots and full new Bundle hash must match.
Ordinary complete candidate validation, full-object quota, file sync and atomic
rename still apply. Failure does not modify the old file; the base remains until
normal journal GC. An already stored target is fully audited on replay, even
when normal GC has removed its base. A cached object record never grants an ACK.

The runtime enforces TLS owner upload authority, not SQL authorization. The signed
journal transition remains the authorization boundary. Cancellation can lose an
ACK after a durable upload; exact retry is idempotent and does not repeat SQL.
Existing complete `FetchVersion` and final holder `Fetch` checks remain unchanged.

Tests exercise actual encrypted packets, full roots and canonical wire bytes;
genuine FHE UPDATE carries/overflow/address retention; real-process TLS owner
checks, lost ACK/restart/corrupt replay; and quota failures with no same-holder
Full fallback followed by a preplanned new replica and fresh proved SELECT.
Performance and whole-process peak RAM must be measured for the complete operation;
the smaller upload alone does not establish a 500-ms bound.
