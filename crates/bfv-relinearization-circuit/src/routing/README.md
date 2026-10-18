# Complete relinearization vector routing

This module owns only the public-vector assembly shared by consumers of the
existing level0/0 Embed and AccumulateAndAdd relations. It uses the parent
crate's fixed geometry, role counts and canonical codecs; it adds no dependency,
arithmetic evaluator, proof configuration, factory, key parser or admission token.

| Entry point | Exact responsibility |
| --- | --- |
| `embed_request` | Preserve all five complete PowerBasis c2 rows and encode/decode the existing Embed request with independently supplied binding/keyset labels |
| `digit_row` | Borrow complete Embed row `5*i+j`; check exact 25N geometry, bounded i/j and every selected-row residue against q_j |
| `mac_request` | Assemble 85 native-NTT rows as target-j blocks `O0,O1,D0..4,K00..04,K10..14`; validate the complete request through the existing codec |
| `component_outputs` | Validate all ten target-major output rows and copy `2*j+c` into two component-major Q5 arrays (`5*c+j`) |

Each original and each key component/decomposition slice contains all five Q rows
of 8192 values. The digit array contains all 25 source-major rows. Request builders
reject incomplete dimensions before assembling vectors; canonical residues are
checked by the existing codecs. `digit_row` checks only the row it borrows, not
the other 24 rows. `component_outputs` checks all rows before allocating outputs.
No helper reduces residues, performs an NTT, evaluates an Embed/MAC equation or
converts native NTT to the SDK's PowerBasis ciphertext payload.

Inputs are untrusted public mathematical claims, never proof results. The caller
must independently pin complete original setup/query/key context, derive exact
requests from admitted parents, and cryptographically verify every required edge.
Matching labels and successful routing prove none of those obligations. No Source,
key consistency, whole MulRelin, hidden WHERE, freshness or SQL grant is established.

The [complete32 consumer](../../../../experiments/bfv-complete-relinearization/README.md)
uses these helpers without skipping its five inverse NTTs, Embed, 25 forward NTTs
or MAC verification. Its independently prepared public key remains experiment-owned.

New owning source tests cover all 8192 values in every routed row, all original,
digit and key positions, q-1/q final-coefficient boundaries, invalid dimensions,
oversized indices and the output transpose. The
[executed graph validation](../../../../experiments/bfv-mul-relin-proof/VALIDATION.md)
records default12/Plonky3 15 owning cases, strict Clippy and genuine consumer
regressions, with their exact retained-R3/final-R4 source scope.
Existing AIRs, profiles, codecs, proof caps and historical tests remain unchanged.
