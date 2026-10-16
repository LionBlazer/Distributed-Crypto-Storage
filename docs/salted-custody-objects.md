# Randomized custody object profile 2

This is a selected **prototype upgrade**, not a change to the requirements or a
new SQL, consensus or cryptographic-computation guarantee. Old networks and
workspaces reject; no migration, compatibility alias or fallback is provided.
BFV/STARK parameters, kernel ABI, CSTORE01 images and private index formats stay
unchanged. The [matched operation record](../experiments/combined-sql/CUSTODY-PROFILE-MEASUREMENTS.md)
reports measured prototype latency and its limits; no process-RAM improvement is established.

## Identity and metadata boundary

ObjectProfileID is the exact 32 ASCII bytes
`DCS-SALTED-HEAD-OBJECT-PROFILE02`. The object address is SHA256 of the concatenation:

```
"dcs/peer-runtime/salted-head-object/v2" || nonce[32] || data_head[112] || index_head[112]
```

The heads are exact canonical compact-store manifests in data/index order. Fixed
field sizes make the encoding unambiguous. The owner obtains a fresh 256-bit OS
random nonce once per staged object, before the operation's first Store. All
recipients, Full/Delta representations and retries use that same nonce/ID; Copy
preserves it. Entropy failure returns no staged object. Different nonces can
represent identical image heads under different object IDs; retained head pairs
protect **all** corresponding IDs. The object count and disk quotas still apply.

The binding to every canonical ciphertext byte is transitive and CONDITIONAL on
complete validation of both images: exact manifest/layout/length, ordered leaves
binding page index, packet length and all packet bytes, complete Merkle roots and
packet-revision bounds. Raw payload with unchanged claimed heads is trivially
malleable until that audit. SHA256's classical 128-bit collision strength is not
a 128-bit proof of the whole protocol. Hiding the head-to-ID relationship from an
observer without the random nonce uses the usual random-oracle/hash-hiding
assumption; collision resistance alone does not imply hiding.

The nonce is absent from public journals, Status/ObjectInfo, Trace/Activity,
QueryContext and proof public values. Journals expose heads but no custody object
ID. Status exposes IDs and geometry but no heads. Unsalted head IDs would add
cheap offline correlation between those channels. Full Fetch/FetchVersion are
already available to authenticated readers and reveal ID/head/image mapping;
Full Store/Copy and Delta recipients already see this mapping. Adding the nonce
to their envelope creates no new such mapping. ReadImage requests already bind
ID to both heads; their responses return a fixed extra 32 bytes. This is a scoped
metadata comparison, not a proof of general access-pattern confidentiality.
RawBundle Debug omits nonce and heads. No adaptive SQL page/count policy changes.

## Ownership and validation

RawBundle carries explicit version 2, nonce and four byte vectors. Deserializing
it does NOT audit ciphertext: owner authentication remains before expensive
Store admission. TargetVersion is immutable structural binding metadata only.
CheckedObject is non-cloneable/non-deserializable and owns complete checked raw
images and decoded snapshots. Its sole raw factory audits both entire images.
Candidate consumes that checked lineage, or sealed Delta reconstruction after a
complete physical base audit, verified replacements and both complete final
roots. No validation boolean, mutable prevalidated wrapper or disk-audit cache
exists. Every Fetch/FetchVersion/PageBatch/ReadImage/Prove and retry custody read
still physically reads and audits all bytes, including unrequested identity pages.

Delta takes TargetVersion plus replacement proofs, never ignored raw target
images. Its 524-byte header replaces the old target ID slot with nonce32 and
rederives the ID from the exact heads. Existing-target retries still verify all
request pages AND audit the physical target before ACK, including after base GC.
Recovered-holder and already-copied fast paths use the complete validator; hashes,
TLS, status and decryption alone do not establish custody or SQL correctness.

## Breaking protocol and disk lifecycle

Bootstrap is strictly `{ "version": 2, "config": { ... } }`, with unknown fields
rejected at both levels. Old mandatory top-level fields are absent, so the old
flat producer/consumer cannot silently accept it. RPC v2's fixed prefix is checked
before enum decoding. PageBatch, ReadImage and Delta use explicit v2 magic/version.
JobVerifier application v4 includes ObjectProfileID. Old application anchors fail
before journal registration or creation. The FHE relation itself does not change.

An initialized root contains `custody-v2.profile` (DCSDIR02 + ObjectProfileID),
`peer.lock`, canonical hex-ID `.object2` files, hex-network-ID `.journal2` files
and optionally the sole reserved `write-v2.pending` path. Object files begin with
DCSOBJ02 + ObjectProfileID, followed by canonical RawBundle v2. Generic
DurableJournal uses DCSJL002 plus a caller-supplied opaque namespace32; the runtime
supplies ObjectProfileID. Its module has no runtime dependency or default namespace.

Read-only preflight checks exact bounded profile bytes, every filename/kind and
object/journal namespace before mkdir, lock creation or cleanup, then repeats
under the cooperative exclusive lock. Old write.pending, old/unknown/mixed files
and missing/partial profiles in nonempty roots reject without modifying their
tree. An interrupted FIRST initialization before a durable complete profile is
also ambiguous and rejects: no custody was accepted, and the code cannot safely
distinguish it from an old lock-only root. This is not automatic conversion.

For an already initialized v2 root, write-v2.pending is the known disposable
current-format staging path: it may be empty or have a truncated header after a
crash. All existing objects are fully audited and quotas checked BEFORE removing
it. Arbitrary partial-header format detection is not claimed. Corrupt existing
objects and any legacy/mixed namespace preserve the pending bytes on rejection.

The GUI preflights ALL bounded participant directories before any add/restart;
standalone restart does so before stopping the existing child. Its unique process
roots do not implement workspace reopen or persisted owner/bootstrap files.
Credentials remain in memory and bootstrap travels over a private stdin pipe.

## Executable bounds and scope

The 40-byte root profile and complete object envelope count against disk quota.
Disk and RPC objects remain within 64 MiB; Delta requests remain at most 32 MiB,
PageBatch replies 1 MiB and ReadImage replies 16 MiB. Prefix/page/connection/proof-permit
limits remain 512/64/8/1. Owner staging checks frame geometry before image encoding.
For the existing 1M fixed layout, Full Store is 37,604,576 bytes, padded Delta remains
1,188,143 bytes and static ReadImage is 5,461,696 bytes, excluding transport/TLS.
Owning tests use actual codecs, plus corruption, exact-envelope equality, nonce
retention, quota, namespace byte-preservation and real process/proof/freshness paths.

Removing the old whole-object hash removes 37,604,528 bytes of SHA input per legacy
ID computation in this geometry. Complete Merkle audits remain. The matched
whole-operation measurements do not isolate the hash change or establish a
general 500-ms bound.
