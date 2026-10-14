---
name: commit-and-push
description: Commit and normally push each completed validated repository change, then incorporate fetched remote master into the current task branch. Use automatically for code, documentation, configuration, and skill edits unless the user requests no commit or push.
---

# Commit and push

AGENTS.md authorizes automatic publication after every completed logical change,
including small ones. Honor explicit read-only, no-commit, or no-push instructions.
This workflow does not promote a task branch into master.

## Prepare the change

Verify the branch and origin. Direct master publication requires an explicit user
instruction; otherwise use [task-branch](../task-branch/SKILL.md) before edits.
Run checks appropriate to the change using actual repository commands. Documentation
and skill changes need their relevant checks, not an invented application test suite.

Inspect existing staged changes before staging explicit task paths. Review
`git diff --cached --stat`, the staged diff, and `git diff --cached --check`.
Exclude secrets, generated output, unrelated changes, and unfinished work. If the
index already contains unrelated work, isolate this task's commit safely or report
the blocker without changing someone else's index entries.

Commit using Conventional Commits. If nothing changed, do not create an empty commit;
publish completed, unpublished task commits when that is within the task.

## Publish safely

Fetch origin. Compare the current branch with its remote counterpart if it exists.
Inspect divergent commits and diffs before merging remote-only changes. Resolve
conflicts from both changes' intent; do not select entire files blindly with ours
or theirs. For a non-fast-forward merge use `git merge --no-commit <fetched-ref>`;
review the combined tree and staged diff, validate, then commit using a Conventional
Commit message. A fast-forward needs no merge commit, but still inspect the delta.

When explicitly working on master, incorporate `origin/master` before its push.
For a task branch, normally push with an explicit same-named destination:
`git push -u origin HEAD:refs/heads/<branch>` for the first publication, then
`git push origin HEAD:refs/heads/<branch>`. Never force push or publish unrelated refs.

If push is rejected because the destination advanced, fetch, inspect, integrate,
validate, and retry normally. Stop after two rejected publication attempts in this
cycle, or when access or unresolved conflict intent prevents progress. Preserve
local commits and report the actual blocker.

## Bring master into the task branch

After a successful task-branch push, fetch origin once more. Review incoming master
changes, then merge `origin/master` into the same branch using the reviewed merge
procedure above. Use a Conventional Commit message when a merge commit is needed,
such as `chore(git): merge master into shard-allocation`.

If integration changes HEAD, review the result, run affected checks, and normally
push the integrated branch. Do not start another master synchronization after this
follow-up push. Conflicts or rejections use the same handling and bounded retry
policy above. Do not update master as part of this incoming synchronization.

Verify the published destination contains the completed commit and record its hash.
Report the final branch, commit, checks, push outcome, and master synchronization.
Promotion belongs to [merge-to-master](../merge-to-master/SKILL.md) only when requested.
