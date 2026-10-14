---
name: document-modules
description: Create or update concise module README files describing actual responsibilities, direct module dependencies, public entry points, and usage. Use when a module is added or its boundary changes, regardless of the selected build system.
---

# Document modules

Adapted from SpaceTimeAutocoder2's document-gradle-modules skill. Keep a module
understandable from its root without imposing Gradle or a bilingual document set.

Inspect the actual module manifest, public entry points, implementation, and direct
consumers before writing. Maintain a concise English README.md beside the module
manifest unless the user requests another language or the project adopts a different
document convention. Preserve existing language variants when present.

Include the module's purpose and why it exists, direct project-module dependencies
with relative links and short roles, owned responsibilities, key public entry points,
and main usage scenarios. Describe exclusions only where they clarify neighboring
ownership. Use a dependency table when helpful; avoid catalogs of all classes or
third-party dependencies.

Describe implemented behavior separately from requirements and experiments. A storage
module's README must not promise a proof, failure tolerance, or performance target
that its code and measurements do not establish. Keep reproducible commands and
measurement assumptions alongside relevant experiments when they exist.

Check links and commands against the repository, and update documentation when the
module's boundary, API, or direct dependencies change.
