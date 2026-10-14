---
name: merge-to-master
description: Review, validate, and promote the requested task branch into remote master, then return this checkout to synchronized master. Use only when the user invokes this skill or explicitly requests promotion; routine pushes only synchronize master into the task branch.
---

# Merge to master

Explicit invocation or a promotion request authorizes review, necessary fixes,
integration, normal push to master, and returning the checkout to master without
another generic confirmation. Creating or editing this skill is not its invocation.

## Establish and integrate the source

Record the source branch, HEAD, upstream, origin, status, and in-progress operations.
Use this checkout. Preserve unrelated dirty files, staged changes, and commits; never
stash, reset, discard, or delete them. Resolve an unclear source before promotion.

Fetch origin. Inspect both histories before integrating remote-only source commits.
Bring `origin/master` into the source branch and resolve conflicts by intent. For
non-fast-forward merges use `git merge --no-commit <fetched-ref>`, inspect the staged
diff and combined tree, validate, then commit using a Conventional Commit message.
A fast-forward needs no merge commit; inspect its delta and validate affected behavior.
Publish the source using normal explicit pushes.

## Review and fix

Review the complete source diff and commits relative to fetched master, including
consumers and relevant tests. Check the requirements affected by the change: SQL
semantics, data/version integrity, authorization, cryptographic boundaries, proof
validation, peer failures, recovery, resource ownership, and budgets as applicable.
Do not treat a textually clean merge as evidence of correct behavior.

Fix actionable findings in focused source commits. Run affected tests and available
broader repository checks appropriate to promotion. Documentation-only changes need
document validation. Report unavailable runtime or external checks. Do not make
unsupported claims about security, throughput, or resource use.

Record the exact reviewed source commit and fetched master commit. Push the validated
source normally. Reuse checks only when they cover the identical resulting tree and
relevant dependencies; new changes require the affected checks again.

## Promote and return to master

1. Fetch master again. If it advanced, inspect the delta, merge it into the source,
   review and validate the affected result, then publish the source again.
2. Verify fetched master is an ancestor of the reviewed source commit. Push that
   exact reviewed hash normally: `git push origin <reviewed-sha>:refs/heads/master`.
   A rejection requires new inspection and integration; it never authorizes force.
   Stop after two rejected master pushes or unresolved access/conflict blockers.
3. Fetch and verify `origin/master` contains the reviewed source commit. If newer
   master commits appeared, inspect them and verify the actual selected result.
4. Switch this checkout to local master and fast-forward it to verified remote
   master using `git merge --ff-only origin/master`; create a tracking master branch
   if absent. If local master diverged, another checkout owns it, or dirty files block
   switching, preserve the work and report the blocker rather than resetting it.
5. Keep the source branch. The next implementation task uses
   [task-branch](../task-branch/SKILL.md); create no empty next-task branch now.

Do not bypass branch protection or rewrite published history. Report source and
published hashes, material review fixes, checks, final branch, and synchronization.
Do not claim successful publication from a local merge or failed push alone.
