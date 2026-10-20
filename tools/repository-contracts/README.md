# Repository contracts

This workspace tool owns repository contract checks that use only the Rust standard
library. Keeping these checks independent of GUI, network and cryptographic packages
lets Cargo build the guard without those package dependencies.

The package has no project or third-party dependencies, library target or executable
target. It is a workspace member and is excluded from default-members.

tests/requirements_sync.rs is the single test entry point. It compares the marked
Russian requirements block in [AGENTS.md](../../AGENTS.md) with the canonical section
of [REQUIREMENTS.md](../../REQUIREMENTS.md), keeping the research-source appendix
separate. The test embeds both files with include_str! and normalizes CRLF before
comparison.

Run from the repository root:

    cargo test --release --locked -p repository-contracts --test requirements_sync
