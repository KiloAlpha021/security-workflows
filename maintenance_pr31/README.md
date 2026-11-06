# Finite successor maintenance witness for security-policy PR #31

This proposal is a new finite witness. It does not alter or replace the
historical witness at
`8b35cf9f83b32c6bd8ee4fdd824bee1a57aaa94a`.

It admits only security-policy PR #31 with base
`f36ed0b258a0581903698cc2cfac923ded19bd30`, head
`852b1e80e4dc86517f6023aad9d78c87d99b95c2`, synthetic merge
`ef48261a4b1a9ca95254a5107fb91387f4a95b91`, and tree
`d690abf621fa2d844f19d5c40ddefaab5a16cf53`.

The exact two changed paths, their predecessor and successor blobs, canonical
bytes, dependency locks, historical fixture identity, repository, PR number,
branch, commit graph, clean worktrees and source provenance are fail-closed.
No candidate-controlled profile or wildcard authority exists.

## Required governance sequence

1. Independently review and qualify this exact security-workflows proposal.
2. Obtain separate owner merge approval.
3. Merge it through protected security-workflows main.
4. Record the resulting protected merge commit and verify that the workflow and
   witness blobs are unchanged.
5. Under separate organization-administration authority, atomically replace the
   workflow entry in ruleset `24643586` with the exact protected successor
   commit, path
   `.github/workflows/security-policy-maintenance-pr31.yml`, and
   `refs/heads/main`.
6. Keep enforcement active, the default-branch target unchanged, and the bypass
   list empty.
7. Trigger the new required workflow for unchanged PR #31 and require PASS.
8. If any identity differs, restore the old ruleset workflow entry immediately
   and keep PR #31 blocked.

The witness supplies assurance only. It cannot merge, alter a ruleset, modify
security-policy, grant trading authority or approve itself.
