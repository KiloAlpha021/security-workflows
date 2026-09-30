# Non-active historical records

This directory preserves evidence, not executable trusted-control profiles.
The trusted evaluator loads only `profiles/`; it does not load `archives/`.
Nothing stored here grants authority or can satisfy candidate verification,
even if an archived document contains an active-state claim or matching IDs.

Preserve original record bytes and their Git blob identities. Each archived
profile has a `provenance.json` recording its original paths, publication commit,
protected merge, and explicit non-active disposition. This metadata describes
history; it does not certify the referenced candidate or approve activation.

The Stage 3 SYNC-2 record from PR #33 is retained byte-for-byte under
`archives/profiles/stage3-sync2-consumability-record/`. Its intentional
`CANDIDATE_BOUND_LOCAL_ONLY` state remains unchanged. The owner's remediation
disposition is `LEGITIMATE_NON_ACTIVE_RECORD`, with no protected activation.
Its earlier publication inside `profiles/` caused strict profile loading to
fail; relocation preserves that fact without weakening the loader.

Active controls remain exclusively under `profiles/` and must satisfy all
existing checks, including `ACTIVE_ON_PROTECTED_MAIN`. Archival is not a path
to activation: any future active profile requires separately established
candidate evidence, authority, and a normal protected pull request. Do not
copy or promote archived records automatically.
