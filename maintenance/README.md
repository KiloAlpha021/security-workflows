# Finite security-policy maintenance witness

Status: proposed independent trust root. Local tests do not establish this source
as trusted. An owner must review the exact source commit and establish its
protection before any result is accepted as certification.

## Scope and independence

Source: `KiloAlpha021/security-workflows`, dedicated branch
`f7-policy-maintenance-certifier-v1`. Its parent is protected trust main
`619960e99a07bedf42ecf2284d430225130a8fdb`. This branch is not a change to the
existing trust main, ATIS, PR64, PR81, or frozen policy PR21.

Target: one ordinary successor of security-policy
`c047a203fc7e1e3326e044f128a7323dea60041b`, base tree
`c49bebd5d6106da224da733d30b4c2d97c430bfc`, modifying only
`test_verify_security_workflows.py` in regular-file mode. No policy workflow,
bootstrap, validator, dependency, historical binding, or assertion removal is
admitted. The independent witness derives the only accepted new bytes from the
SHA-256-pinned protected test source. This is an exact operation, not a general
maintenance permission. Changed identities or a future operation require a new
owner-established witness; no candidate-selected profiles or exceptions exist.

The fixture recipe canonicalizes two cloned repository Paths, applies
`core.autocrlf=false` to the initial clone and the S2C historical checkout,
and scopes a three-variable Git environment to the deliberate CRLF attack only.
The previous environment is restored and checked. Existing assertions remain.
The full 123-test protected suite is required with exactly its two pre-existing
input-binding skips. Bootstrap root rejection is separately attacked with
relative, missing, aliased, and junction/symlink paths. No production validator
changes. Historical CRLF workflow bytes remain exact historical bytes; the new
test artifact and witness files are UTF-8, no BOM/NUL/CR, one final LF.

## Bootstrap and protection boundary

Do not merge this source through the broken downstream policy check or treat
its own test results as independent first-landing certification. The organization
owner is the administrative root establishing the initial immutable witness.
Owner approval of the exact source commit, source-branch freeze, and organization
workflow rule are prerequisites to using it. A separate branch avoids the
policy -> security-workflows/main -> policy certification cycle. Existing
default-branch protections are left intact; no bypass is used.

Source ruleset: active, exact branch `refs/heads/f7-policy-maintenance-certifier-v1`,
no bypass actors, restrict updates, restrict deletions, non-fast-forward protection.
Required target workflow: this repository's
`.github/workflows/security-policy-maintenance.yml`, source branch above and
exact owner-approved commit SHA. Target only `security-policy`, default branch
`main`, active enforcement, empty bypass list, `do_not_enforce_on_create=false`.
Preserve classic target protection. The workflow cannot pass on unsupported
events, another repository, another base, mutable identities, or a different patch.
Do not use an ordinary same-name status check as a substitute for the required
workflow. Candidate jobs have contents-read permission and no persisted checkout
credentials. Every native command has an immediate exit guard.

## Acceptance and lifecycle

Run independent witness tests, exact candidate identity/oracle validation, the
full admitted policy suite, syntax compilation, independently pinned hash-locked
policy/audit installs, pip checks, and dependency audit. All executable stages
must complete successfully; missing/skipped/cancelled/neutral stages are not PASS.
The only permitted skips are the two enumerated input-bound policy test methods,
not whole jobs. Inspect actual logs and exact head/base/tree/source attribution.

This control emits assurance only. It cannot merge, mutate policy, grant ATIS
or trading authority, or certify itself. A successful maintenance candidate still
requires owner merge and exact post-merge verification. It does not independently
admit frozen PR21: the original PR21 policy pipeline must then be rerun against
the new protected source, retaining PR21 head bytes and inspecting the resulting
GitHub merge evaluation identity. Any incompatible main/head merge must stop.

This finite rule intentionally rejects PR21 and every other patch. After the
maintenance owner merge, an independently reviewed successor witness must bind
the then-known protected base and unchanged PR21 before that PR can satisfy this
required control. Do not disable the control to let PR21 merge, reuse the old
maintenance PASS, or let PR21 supply its own admission policy. This is a later
owner-controlled source-version change, not authority granted by this witness.

Rollback of an incorrect activation: keep all merges stopped, disable only the
new target required-workflow rule, retain the frozen witness branch and existing
rules unchanged, and re-establish the corrected rule through owner review. A
disabled rule supplies no assurance and must not be used to justify a merge.
