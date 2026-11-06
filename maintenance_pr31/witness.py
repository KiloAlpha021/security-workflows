"""Finite independent maintenance witness for security-policy PR #31.

This witness admits exactly one immutable policy successor.  It is not a
general maintenance authority and cannot select its own trusted source.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys


TARGET = "KiloAlpha021/security-policy"
SOURCE = "KiloAlpha021/security-workflows"
SOURCE_BRANCH = "main"
WORKFLOW = ".github/workflows/security-policy-maintenance-pr31.yml"
PR_NUMBER = 31

BASE = "f36ed0b258a0581903698cc2cfac923ded19bd30"
BASE_TREE = "9dd71ad7b7164db624862a3acc2b1dc9cf2be7b2"
HEAD = "852b1e80e4dc86517f6023aad9d78c87d99b95c2"
HEAD_TREE = "d690abf621fa2d844f19d5c40ddefaab5a16cf53"
MERGE = "ef48261a4b1a9ca95254a5107fb91387f4a95b91"
HISTORICAL_FIXTURE_SHA256 = (
    "578810835df8328547df8d52ce0654a179aab22df2636fa9284d8cb4065ed3c6"
)

EXPECTED_FILES = {
    "test_verify_security_workflows.py": {
        "base_blob": "e0a50e777c53663f2fdb8a6b727413acc0123e0f",
        "base_sha256": "f5c510ffa50dbde9f1fe8c26094599025199c8487eec6a915cbbd5090434efa3",
        "head_blob": "34f75c87a3f3279cc503ecdff3625ce0d7e551bd",
        "head_sha256": "c5506f4d7c9be0b868a739a36463e3d7e620fd7256ce0c96404469e389c22449",
    },
    "verify_security_workflows.py": {
        "base_blob": "1b7ac7958841a2ece7d4fafbdc34ff610856d2b9",
        "base_sha256": "d2b48c6b1c12447f894506ec6af0b3f91d0c979c50dfd8c7f4acee396f02a0d9",
        "head_blob": "e86f03d55576117144a70b38fe47fade33c534b8",
        "head_sha256": "a9302b19541cee04a99e55365ce00b15dbd9a47aa1f9e989cacb7f31fbc4dc2e",
    },
}

AUDIT_LOCK = (
    "04f514da5dddb6aa83723cfba28448972c8a38ac",
    "e1f6d6d95efa753187742474ae0a13199f9e8e7777decd3464bc9928780333c2",
)
POLICY_LOCK = (
    "b11e8ca274a5426789be10d24919679c8da0aa4f",
    "2c8257dff9274ba95c7a2d21757ac79acc816e295e45062d0ad8c05d7a2d2f6c",
)


class Rejected(ValueError):
    """Fail-closed witness rejection."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Rejected(message)


def sha(value: str) -> str:
    require(bool(re.fullmatch(r"[0-9a-f]{40}", value)), "immutable SHA required")
    return value


def git(root: Path, *args: str) -> bytes:
    return subprocess.check_output(
        ["git", "-C", str(root), *args],
        stderr=subprocess.PIPE,
    )


def canonical(raw: bytes) -> None:
    raw.decode("utf-8", errors="strict")
    require(not raw.startswith(b"\xef\xbb\xbf"), "BOM rejected")
    require(b"\r" not in raw and b"\0" not in raw, "CR/NUL rejected")
    require(raw.endswith(b"\n") and not raw.endswith(b"\n\n"), "one final LF required")


def validate_source(root: Path, workflow_ref: str, workflow_sha: str) -> None:
    require(
        workflow_ref == f"{SOURCE}/{WORKFLOW}@refs/heads/{SOURCE_BRANCH}",
        "independent workflow source mismatch",
    )
    require(
        git(root, "remote", "get-url", "origin").decode().strip().removesuffix(".git")
        == "https://github.com/" + SOURCE,
        "certifier repository substitution",
    )
    require(
        git(root, "rev-parse", "HEAD").decode().strip() == sha(workflow_sha),
        "certifier source substitution",
    )


def clean_committed_root(root: Path, revision: str, repository: str) -> None:
    require(
        git(root, "rev-parse", "--is-shallow-repository") == b"false\n",
        "incomplete Git history",
    )
    git(root, "-c", "core.commitGraph=false", "rev-list", "--parents", revision)
    require(root.is_absolute() and root.resolve(strict=True) == root, "noncanonical root")
    require(
        git(root, "remote", "get-url", "origin").decode().strip().removesuffix(".git")
        == "https://github.com/" + repository,
        "wrong Git repository",
    )
    require(
        git(root, "rev-parse", "HEAD").decode().strip() == sha(revision),
        "checkout substitution",
    )
    require(
        not git(root, "status", "--porcelain", "--untracked-files=all"),
        "dirty checkout",
    )
    for path in root.rglob("*"):
        if ".git" not in path.relative_to(root).parts:
            require(path.name != "__pycache__" and path.suffix != ".pyc", "bytecode residue")
    for entry in git(root, "ls-tree", "-r", "-z", revision).split(b"\0"):
        if not entry:
            continue
        metadata, raw_path = entry.split(b"\t", 1)
        mode, kind, oid = metadata.split()
        require(mode == b"100644" and kind == b"blob", "nonregular tree entry")
        path = root / raw_path.decode("utf-8")
        require(path.resolve(strict=True) == path and path.is_file(), "redirected file")
        require(
            path.read_bytes() == git(root, "cat-file", "blob", oid.decode()),
            "worktree bytes differ from committed bytes",
        )
    git(root, "fsck", "--no-dangling", "--no-reflogs")


def separate_roots(*roots: Path) -> None:
    for index, left in enumerate(roots):
        for right in roots[index + 1 :]:
            require(
                left != right
                and not left.is_relative_to(right)
                and not right.is_relative_to(left),
                "root separation",
            )


def validate_event(
    event: dict,
    event_name: str,
    repository: str,
    evaluation_sha: str,
) -> tuple[str, str, str]:
    require(event_name == "pull_request" and repository == TARGET, "wrong target/event")
    require(event.get("number") == PR_NUMBER, "pull request substitution")
    pr = event["pull_request"]
    require(
        pr["base"]["repo"]["full_name"] == TARGET
        and pr["head"]["repo"]["full_name"] == TARGET,
        "repository substitution",
    )
    require(
        pr["base"]["ref"] == "main" and pr["base"]["sha"] == BASE,
        "protected base substitution",
    )
    require(pr["head"]["sha"] == HEAD, "candidate substitution")
    require(pr["state"] == "open" and not pr["merged"], "PR is not open/unmerged")
    require(sha(evaluation_sha) == MERGE, "synthetic merge substitution")
    return HEAD, BASE, MERGE


def _check_blob(
    root: Path,
    revision: str,
    path: str,
    blob: str,
    digest: str,
) -> bytes:
    require(
        git(root, "ls-tree", revision, "--", path).decode().strip()
        == f"100644 blob {blob}\t{path}",
        "file identity/mode substitution: " + path,
    )
    raw = git(root, "cat-file", "blob", blob)
    require(hashlib.sha256(raw).hexdigest() == digest, "file byte substitution: " + path)
    canonical(raw)
    return raw


def verify(
    base_root: Path,
    candidate_root: Path,
    merge_root: Path,
    head: str = HEAD,
    tree: str = HEAD_TREE,
    base: str = BASE,
    merge: str = MERGE,
) -> dict:
    require(
        (base, head, tree, merge) == (BASE, HEAD, HEAD_TREE, MERGE),
        "finite identity substitution",
    )
    base_root = base_root.resolve(strict=True)
    candidate_root = candidate_root.resolve(strict=True)
    merge_root = merge_root.resolve(strict=True)
    separate_roots(base_root, candidate_root, merge_root)

    for root, revision, expected_tree in (
        (base_root, BASE, BASE_TREE),
        (candidate_root, HEAD, HEAD_TREE),
        (merge_root, MERGE, HEAD_TREE),
    ):
        clean_committed_root(root, revision, TARGET)
        require(
            git(root, "rev-parse", "HEAD^{tree}").decode().strip() == expected_tree,
            "tree substitution",
        )

    require(
        git(candidate_root, "rev-list", "--parents", "-n", "1", HEAD).decode().split()
        == [HEAD, BASE],
        "sole parent substitution",
    )
    require(
        git(candidate_root, "rev-list", "--count", f"{BASE}..{HEAD}").strip() == b"1",
        "commit count substitution",
    )
    require(
        git(merge_root, "rev-list", "--parents", "-n", "1", MERGE).decode().split()
        == [MERGE, BASE, HEAD],
        "synthetic merge parent substitution",
    )

    expected_cone = "".join(
        "M\t" + path + "\n" for path in sorted(EXPECTED_FILES)
    ).encode()
    require(
        git(candidate_root, "diff", "--name-status", "--no-renames", BASE, HEAD)
        == expected_cone,
        "changed path substitution",
    )

    for path, identity in EXPECTED_FILES.items():
        _check_blob(
            base_root,
            BASE,
            path,
            identity["base_blob"],
            identity["base_sha256"],
        )
        raw = _check_blob(
            candidate_root,
            HEAD,
            path,
            identity["head_blob"],
            identity["head_sha256"],
        )
        require(
            HISTORICAL_FIXTURE_SHA256.encode() in raw,
            "historical fixture identity binding removed",
        )

    for root, revision, path, expected in (
        (base_root, BASE, "requirements-audit.lock", AUDIT_LOCK),
        (candidate_root, HEAD, "requirements-audit.lock", AUDIT_LOCK),
        (base_root, BASE, "requirements-policy.lock", POLICY_LOCK),
        (candidate_root, HEAD, "requirements-policy.lock", POLICY_LOCK),
    ):
        _check_blob(root, revision, path, expected[0], expected[1])

    return {
        "repository": TARGET,
        "pull_request": PR_NUMBER,
        "base": BASE,
        "base_tree": BASE_TREE,
        "head": HEAD,
        "tree": HEAD_TREE,
        "merge": MERGE,
        "parent": BASE,
        "commits": 1,
        "files": sorted(EXPECTED_FILES),
        "historical_fixture_sha256": HISTORICAL_FIXTURE_SHA256,
        "cleanliness": "PASS",
        "result": "EXACT_FINITE_BINDING_PASS",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("base_root", type=Path)
    parser.add_argument("candidate_root", type=Path)
    parser.add_argument("merge_root", type=Path)
    args = parser.parse_args()
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
    head, base, merge = validate_event(
        event,
        os.environ["GITHUB_EVENT_NAME"],
        os.environ["GITHUB_REPOSITORY"],
        os.environ["GITHUB_SHA"],
    )
    source_root = Path(__file__).resolve().parent.parent
    validate_source(
        source_root,
        os.environ["GITHUB_WORKFLOW_REF"],
        os.environ["GITHUB_WORKFLOW_SHA"],
    )
    clean_committed_root(source_root, os.environ["GITHUB_WORKFLOW_SHA"], SOURCE)
    roots = tuple(
        path.resolve(strict=True)
        for path in (args.base_root, args.candidate_root, args.merge_root)
    )
    separate_roots(source_root, *roots)
    result = verify(*roots, head=head, base=base, merge=merge)
    result["certifier_source"] = os.environ["GITHUB_WORKFLOW_SHA"]
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (Rejected, KeyError, OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"MAINTENANCE_REJECTED: {error}", file=sys.stderr)
        sys.exit(1)
