# Fixed BFV geometry

This dependency-free library owns the existing level-zero ring degree, plaintext
modulus and ordered Q5/P5 bases used by the fixed BFV arithmetic profile. Addition,
RNS scaling, NTT and owner/public-peer adapters depend on this common contract
instead of depending on another operation solely for its parameters.

`DEGREE`, `MODULI`, `AUXILIARY_MODULI`, `EXTENDED_MODULI`, `PLAINTEXT` and
`CIPHERTEXT_COMPONENTS` are public compile-time constants. The two-component count
describes input/relinearized ciphertexts; multiplication tensor intermediates
have three components. This module owns no keys, SDK context, FHE operation,
proof configuration, storage, fixtures or application policy.

Existing circuit exports retain their exact names and values. Original request,
output and proof profiles are unchanged. Upstream parameter/prime parity and
observable arithmetic tests remain with the consuming libraries and experiments.
These constants alone establish no cryptographic security or accepted SQL result.
