# Generalized public-instance source association

This test-only module owns the fixed all-five classifier of complete canonical
public values `u` and public preprocessing word `P` before a first challenge.
Its internal entry point is `read_before_first_coin(Read)`. The returned private
`Association` records analysis metadata, not a verified-proof capability.
It has no production import, configuration callback or private input.

Source parses both full public canonical images through `SourceVersionExpected`
and compares all 691 derived fields. Role3 reconstructs that Source, the public
key binding and the actual 740-field statement. Word constructs the fixed
Predicate graph, checks its full plan, obtains actual PP and compares every
714-by-8192 cell of the zero-interleaved public LDE. DATA/Query accept arbitrary
canonical field PP of degree below 4096, checking one column at a time; a constant
column needs no FFT. Word's literal factory equality implies degree below 1024.

Direct dependencies are the owning Source/Role3 public constructors, Word graph,
plan and AIR public preprocessing, compact-store parsing, standard `Read`, and
the pinned P3 base-field DFT/matrix interfaces. Tests reuse the owning explicitly
nonsecret Source fixture through a narrow test-only helper.

The 64-byte `DCSMUB01` header fixes family, PP depth, a root/cutoff pin and zero
reserved bytes. Complete canonical Gold values follow: public vector, then PP
columns in physical bit-reversed `7*K` order. Salts and private codewords are
excluded from PP. Extents are fixed by the family, and trailing bytes reject.
Word retains its fixed public LDE (46,792,704 bytes) plus column/DFT workspace;
DATA/Query process one 32,768-element column at a time, with DFT temporaries.
No complete wide input stream is allocated.

The stream must come from the separately first-frozen typed extraction snapshot.
This reader alone does not authenticate a caller-supplied root or cutoff. The
Python [frozen encoder](../../../../../../experiments/hash-hiding-fri/analysis/protocol_mu.py)
preserves that snapshot and streams bounded blocks. It must finish this classifier
synchronously before a raw-FS driver returns its first coin. Source association
does not prove the remaining RBR transitions, hiding, external application
bindings, freshness, consensus or live SQL admission.
The test-only [first-coin driver](first_coin/README.md) owns actual SHA256 query
registration, parses the five native initial transcript shapes and invokes this
classifier synchronously before answering SHA512. It binds its in-process stream
to registered first snapshots rather than trusting a caller header. The separate
file bridge exercises frozen encoding followed by this classifier.

Run the owning metadata/FFT gate:

```sh
cargo test --release --locked -p registry200-proof --features owner-read registry_progress::word_inventory::generalized_mu::tests:: -- --test-threads=1
```

The optional cross-language request test is explicitly ignored by default and
requires a public `DCS_MU_REQUEST` file. An ignored case is not executed evidence.
See [validation](VALIDATION.md) for the executed owning and model bridge checks.

The independent public-PCS case commits the original Word PP through the actual
native `commit_preprocessing`, obtains all native LDE cells and compares them
with the classifier's fixed word. This cross-check uses an ordinary fresh suite
for a public commitment; it does not commit private traces or create a proof.
