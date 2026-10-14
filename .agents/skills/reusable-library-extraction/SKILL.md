---
name: reusable-library-extraction
description: Extract a cohesive reusable capability from product or peer code while preserving lifecycle ownership and dependency direction. Use for architectural refactors that risk carrying application policy into shared libraries.
---

# Reusable library extraction

Adapted from SpaceTimeAutocoder2. Extract code when it can own a coherent reusable
contract without importing the product that uses it. Follow the established layout;
do not choose a language or create a speculative module tree during extraction.

1. Identify the capability, consumers, and lifecycle owner before moving files.
2. Define the smallest public contract. Keep implementation helpers private/internal.
3. Keep generic validation, storage contracts, transport abstractions, and state
   machines with their owning library. Keep product composition, UI adapters,
   deployment policy, provider credentials, and executable resources outside it.
4. Dependencies point from product adapters to libraries. Do not add reverse product
   dependencies or extract pass-through wrappers solely to create another layer.
5. Move behavior tests with their implementation; keep adapter/composition integration
   tests with the adapter. Preserve resource and key ownership across the boundary.
6. Remove obsolete dependencies and product-specific paths or defaults. Pass policy
   from the composition root where needed. Validate the library and its consumers.

Document a public type's ownership, lifecycle, or security contract when its signature
does not explain it. Do not change protocol guarantees as an incidental refactor.
