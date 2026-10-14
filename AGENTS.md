# Distributed Crypto Storage

## Project context

This project aims to build distributed encrypted SQL storage on participant-owned
computers, following [REQUIREMENTS.md](REQUIREMENTS.md). Peers should store encrypted
data and process queries without access to plaintext. The requirements cover FHE,
SQL operations, bounded storage and memory, replication, recovery, malicious peers,
and verifiable query results.

The repository is at the requirements and research stage. There is no implementation
or selected language, build system, cryptographic library, consensus protocol, or
reward mechanism yet. Treat performance and resource numbers as targets to validate,
not established capabilities. Do not assume that blockchain is required.

## Working conventions

- Respond to the user in Russian. Write new project documentation, code, and commit
  messages in English unless requested otherwise. Preserve the imported Russian
  REQUIREMENTS.md and its sources; change requirements only within the requested scope.
- Work in this checkout using ordinary Git branches. Do not create worktrees unless
  the user requests one. Preserve unrelated files, staged changes, and commits.
- Before implementation, read the relevant requirements and existing code. Record
  unresolved technical choices instead of silently presenting them as settled.
- Keep module ownership and dependencies clear. Do not introduce compatibility
  layers or migrations unless requested.
- Never commit credentials, secret keys, participant data, local database contents,
  or generated outputs. Public test fixtures must be explicitly non-secret.

## Branch selection

The integration branch is `master`; the remote is `origin`:
`git@github.com:LionBlazer/Distributed-Crypto-Storage.git`.

Before a new implementation or documentation task, use
[task-branch](.agents/skills/task-branch/SKILL.md). Create a short
`codex/feature/<topic>`, `codex/fix/<topic>`, `codex/docs/<topic>`, or
`codex/chore/<topic>` branch from freshly fetched `origin/master` when on master
or on an already integrated branch. Continue related unfinished work in its branch.
Explicit user instructions about the branch override this default. Initial repository
setup is explicitly authorized to commit and push directly to master.

## Commit, push, and synchronization

**After every completed, validated logical change, commit and push automatically.**
This includes small fixes, documentation, configuration, and skill changes; do not
wait until a change is substantial or for another request to publish it. Group edits
that form one coherent change, rather than committing every intermediate file save.
Explicit read-only, no-commit, or no-push instructions take precedence.

Use [commit-and-push](.agents/skills/commit-and-push/SKILL.md). Stage explicit task
paths and inspect the staged diff before committing. Use Conventional Commits such
as `feat(storage): add shard allocation` or `docs: clarify query proof requirements`.
Commit only completed task changes. Never stash, reset, discard, or unstage unrelated
work to make publication easier.

Push normally to the same named branch with an explicit destination. Do not force
push or rewrite published history without explicit authorization. If the remote
branch advanced, fetch, inspect both histories, merge compatible changes, validate
the combined result, and retry normally. Stop after repeated concurrent updates or
when conflict intent cannot be established.

After a successful task-branch push, fetch remote master and merge `origin/master`
into that same working branch. If this changes the branch, validate and push again.
Perform one such synchronization cycle; its follow-up push does not start another.
When working directly on master by explicit request, synchronize against remote
master before its push and verify the result afterwards.

Promoting a task branch into master is a separate operation. Use
[merge-to-master](.agents/skills/merge-to-master/SKILL.md) only when the user invokes
it or requests promotion. That request authorizes review, necessary fixes, merge,
normal push to master, and returning this checkout to master without another generic
confirmation. Ordinary task completion publishes only the task branch.

## Verification and completion

Use the project's actual build and test commands once they exist. Until then, check
document links, skill frontmatter, diffs, and requirements consistency; do not invent
a build command or describe documentation checks as application tests.

For implementation changes, test the observable behavior at the owning boundary.
For distributed or cryptographic changes, cover the affected failure model,
authorization, version freshness, proof rejection, or resource limit as relevant.
Performance claims require reproducible measurements of the full operation.

Report the change, relevant verification, final branch and commit, and whether push
and master synchronization succeeded. State concrete blockers accurately.

## Project skills

Keep shared skills in `.agents/skills/`. They are adapted from SpaceTimeAutocoder2
for this repository and do not select its technology stack.

- [task-branch](.agents/skills/task-branch/SKILL.md): select or create a working branch.
- [commit-and-push](.agents/skills/commit-and-push/SKILL.md): publish each completed change and incorporate remote master.
- [merge-to-master](.agents/skills/merge-to-master/SKILL.md): review and promote an explicitly requested branch.
- [readable-test-design](.agents/skills/readable-test-design/SKILL.md): test observable behavior at the right boundary.
- [library-api-structure](.agents/skills/library-api-structure/SKILL.md): separate reusable contracts from implementation.
- [reusable-library-extraction](.agents/skills/reusable-library-extraction/SKILL.md): extract capabilities with clear ownership.
- [document-modules](.agents/skills/document-modules/SKILL.md): document actual module responsibilities and dependencies.
