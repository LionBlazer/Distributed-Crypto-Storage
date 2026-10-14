# Distributed Crypto Storage

Research and development of distributed encrypted SQL storage on participant-owned
computers. The target system combines encrypted storage and FHE query processing,
replication and recovery, and verifiable results from untrusted peers.

[REQUIREMENTS.md](REQUIREMENTS.md) contains the target requirements, open questions,
and research references. Their joint feasibility and resource costs still need to
be validated. No implementation or technology stack has been selected yet.

The integration branch is `master`. [AGENTS.md](AGENTS.md) defines task branches,
automatic commit and push after each completed change, synchronization from master,
and explicitly requested promotion back to master. Project skills live in
[.agents/skills](.agents/skills).
