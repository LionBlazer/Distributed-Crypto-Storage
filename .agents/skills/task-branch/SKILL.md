---
name: task-branch
description: Select or create a working branch for a new Distributed Crypto Storage task from fresh remote master, or continue related unfinished work. Use before repository edits; skip read-only requests and repeated checks within the same task.
---

# Task branch

Follow AGENTS.md and explicit branch instructions. Use the current checkout unless
the user requests a worktree. A new chat does not by itself make a task unrelated.

## Inspect at the task boundary

Read status, the active branch and upstream, a short recent history, and any
in-progress Git operation. Verify origin, then fetch it. Use `origin/master` as the
fresh base without switching or resetting local master. If local master has unpublished
commits, preserve them and establish whether they are inputs to this task before
starting from the remote base; do not silently omit or incorporate unrelated commits.

Check integration with `git merge-base --is-ancestor HEAD origin/master`: exit 0
proves the committed tip is included, exit 1 does not, and other exits are errors.
Squash or rebase integration needs verified evidence, not a similar branch name.
If fetch fails, preserve the current state and report the unavailable fresh base.

## Choose and start

- Read-only request: keep the checkout and create no branch.
- Explicit branch or starting-state instruction: honor it.
- On master, or on a branch already integrated into master: create a new task branch.
- Related unfinished work on an unmerged branch: continue there.
- Unrelated work on an unmerged branch: prefer a new branch from fetched master when
  the checkout is clean and existing commits can remain safely in their branch.
  Ask only when task inputs or dirty changes make that choice ambiguous or unsafe.

Use `codex/<type>/<short-kebab-topic>`; examples are
`codex/feature/shard-allocation`, `codex/fix/proof-freshness`, and
`codex/docs/storage-model`. Validate the name and check local and remote collisions.
Choose a short suffix for an automatically chosen name if needed; never reset an
existing branch. Create with `git switch --no-track -c <branch> origin/master`, then
verify the selected branch and base.

Preserve staged changes, dirty files, and local commits. Do not stash, reset, discard,
or relocate unrelated work. If switching would move unrelated dirty changes into the
task or overwrite files, stop the switch and resolve that concrete blocker.

Retain the settled branch, purpose, and base in task context. Re-evaluate on a new
objective, explicit override, external branch change, or the task after promotion.
Finish each completed change using [commit-and-push](../commit-and-push/SKILL.md).
