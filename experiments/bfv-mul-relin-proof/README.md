# BFV full product research records

The actual graph proof implementation and owning tests now live in the Core
library [bfv-mul-relin-proof](../../crates/bfv-mul-relin-proof/README.md).
This directory retains historical research evidence; it is no longer a Cargo
package and provides no compatibility library.

- [Original full graph validation](VALIDATION.md): complete input16/output134
  proof composition and the reviewed per-call SDK materialization change.
- [Proof-library extraction validation](LIBRARY-EXTRACTION-VALIDATION.md): actual producers, bounded
  verifiers and hostile tests moved into Core, with one unchanged vendored SDK.
- [Circuit extraction validation](CORE-EXTRACTION-VALIDATION.md): exact claim
  codec/routing and original public key preprocessing moved into Core.

Those reports describe their own pinned sources, commands and measurements.
Their former standalone manifest paths refer to those historical revisions.
Current Core usage and proof boundaries are documented by the library.
