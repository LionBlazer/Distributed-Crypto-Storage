---
name: library-api-structure
description: Structure reusable storage, cryptographic, or networking libraries with explicit public contracts and internal implementation boundaries. Use when creating or reorganizing library APIs without selecting a language or build system.
---

# Library API structure

Adapted from SpaceTimeAutocoder2. Make reusable contracts easy to identify and keep
implementation details from becoming accidental API.

- Use the selected language's visibility and packaging mechanisms to distinguish
  public contracts from internal implementations; use api/internal namespaces where
  idiomatic. Keep implementations grouped by capability and lifecycle owner.
- Public signatures must not expose internal types, product-specific adapters, or
  implementation-only dependencies. Export dependencies only when the public contract
  actually requires them.
- Keep product composition, UI, executable packaging, peer deployment policy, and
  credential configuration outside generic library contracts.
- Specify ownership and cleanup for handles, buffers, connections, and keys. For
  cryptographic APIs, distinguish plaintext, ciphertext, proof, public parameters,
  and secret-key roles explicitly; do not invent a cryptographic primitive.

When refactoring, inspect external consumers, define their smallest stable contract,
update consumers, and place tests at the owning boundary. Add compatibility aliases
only if requested. Validate the affected library and consumers through the actual
repository build and test tools.
