"""Finite independent certification of one sealed F1-T policy correction.

Local proposal only until the owner freezes this source branch and binds its
exact sealed SHA in the organization required-workflow rule. GitHub's trusted
workflow identity, never candidate input, selects the independent source.
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
SOURCE_BRANCH = "f1t-pr64-conditional-policy-certifier-v1"
WORKFLOW = ".github/workflows/security-policy-maintenance.yml"
BASE = "523d81fc6f4d8788e2b6b8cbab72a87b1d8accc6"
BASE_TREE = "cd07407a2d1442defe4a60908ada77dfa39a6472"
HEAD = "f49b7f0770d0bba83be074a078431fc356d0912e"
HEAD_TREE = "eaab2cff8f02ac1fc6214c303d1b0758f3fac488"
EXPECTED_FILES = {
    "verify_security_workflows.py": (
        "842cc6367a964d1972c4a842ac535c9c0e411878",
        "43d7a840597b3395a55f66b94d24cab78ddad623a4f60b1726d6bcfd6cdc746e"),
    "test_verify_security_workflows.py": (
        "c1fa205e4187f785ef2809d00a48b454b098f3af",
        "05366db94a8a13e4b26047b7e51c7c758d2e4ddb7d72aa758bdf453aa248b56a"),
}
ENV = {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.autocrlf",
       "GIT_CONFIG_VALUE_0": "false", "PYTHONDONTWRITEBYTECODE": "1"}
ALLOWED_SKIPS = {
    "test_verify_security_workflows.RootPolicyTests.test_stage_a_candidate_invariants",
    "test_verify_security_workflows.RootPolicyTests.test_protected_source_and_candidate_target_contract",
}


class Rejected(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Rejected(message)


def sha(value: str) -> str:
    require(bool(re.fullmatch(r"[0-9a-f]{40}", value)), "immutable SHA required")
    return value


def git(root: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(root), *args], stderr=subprocess.PIPE)


def canonical(raw: bytes) -> None:
    raw.decode("utf-8", errors="strict")
    require(not raw.startswith(b"\xef\xbb\xbf"), "BOM rejected")
    require(b"\r" not in raw and b"\0" not in raw, "CR/NUL rejected")
    require(raw.endswith(b"\n") and not raw.endswith(b"\n\n"), "one final LF required")


def validate_source(root: Path, workflow_ref: str, workflow_sha: str) -> None:
    require(workflow_ref == f"{SOURCE}/{WORKFLOW}@refs/heads/{SOURCE_BRANCH}",
            "independent workflow source mismatch")
    require(git(root, "remote", "get-url", "origin").decode().strip().removesuffix(".git")
            == "https://github.com/" + SOURCE, "certifier repository substitution")
    require(git(root, "rev-parse", "HEAD").decode().strip() == sha(workflow_sha),
            "certifier source substitution")


def clean_committed_root(root: Path, revision: str, repository: str) -> None:
    require(root.is_absolute() and root.resolve(strict=True) == root, "noncanonical root")
    require(git(root, "remote", "get-url", "origin").decode().strip().removesuffix(".git")
            == "https://github.com/" + repository, "wrong Git repository")
    require(git(root, "rev-parse", "HEAD").decode().strip() == sha(revision),
            "checkout substitution")
    require(not git(root, "status", "--porcelain", "--untracked-files=all"), "dirty checkout")
    for path in root.rglob("*"):
        if ".git" not in path.relative_to(root).parts:
            require(path.name != "__pycache__" and path.suffix != ".pyc", "bytecode residue")
    for entry in git(root, "ls-tree", "-rz", revision).split(b"\0"):
        if not entry:
            continue
        metadata, raw_path = entry.split(b"\t", 1)
        mode, kind, oid = metadata.split()
        require(mode == b"100644" and kind == b"blob", "nonregular tree entry")
        path = root / raw_path.decode("utf-8")
        require(path.resolve(strict=True) == path and path.is_file(), "redirected file")
        require(path.read_bytes() == git(root, "cat-file", "blob", oid.decode()),
                "worktree bytes differ from committed bytes")
    git(root, "fsck", "--no-dangling", "--no-reflogs")


def separate_roots(*roots: Path) -> None:
    for index, left in enumerate(roots):
        for right in roots[index + 1:]:
            require(left != right and not left.is_relative_to(right)
                    and not right.is_relative_to(left), "root separation")


def validate_event(event: dict, event_name: str, repository: str) -> tuple[str, str]:
    require(event_name == "pull_request" and repository == TARGET, "wrong target/event")
    pr = event["pull_request"]
    require(pr["base"]["repo"]["full_name"] == TARGET
            and pr["head"]["repo"]["full_name"] == TARGET, "repository substitution")
    require(pr["base"]["ref"] == "main" and pr["base"]["sha"] == BASE,
            "protected base substitution")
    require(pr["head"]["sha"] == HEAD, "candidate substitution")
    require(pr["state"] == "open" and not pr["merged"] and not pr["draft"],
            "PR is not open/non-draft/unmerged")
    return HEAD, BASE


def verify(base_root: Path, candidate: Path, head: str = HEAD,
           tree: str = HEAD_TREE, base: str = BASE) -> dict:
    require((base, head, tree) == (BASE, HEAD, HEAD_TREE), "finite identity substitution")
    separate_roots(base_root, candidate)
    for root, revision, expected_tree in ((base_root, BASE, BASE_TREE),
                                          (candidate, HEAD, HEAD_TREE)):
        clean_committed_root(root, revision, TARGET)
        require(git(root, "rev-parse", "HEAD^{tree}").decode().strip() == expected_tree,
                "tree substitution")
    require(git(candidate, "rev-list", "--parents", "-n", "1", HEAD).decode().split()
            == [HEAD, BASE], "sole parent substitution")
    require(git(candidate, "rev-list", "--count", f"{BASE}..{HEAD}").strip() == b"1",
            "commit count substitution")
    expected_cone = "".join("M\t" + path + "\n" for path in sorted(EXPECTED_FILES)).encode()
    require(git(candidate, "diff", "--name-status", "--no-renames", BASE, HEAD)
            == expected_cone, "changed path substitution")
    for path, (blob, digest) in EXPECTED_FILES.items():
        require(git(candidate, "rev-parse", f"{HEAD}:{path}").decode().strip() == blob,
                "candidate blob substitution: " + path)
        raw = git(candidate, "cat-file", "blob", blob)
        require(hashlib.sha256(raw).hexdigest() == digest,
                "candidate byte substitution: " + path)
        canonical(raw)
    require((candidate / ".gitattributes").read_bytes()
            == b".github/workflows/security-workflows-policy.yml text eol=lf\n",
            "canonical attributes changed")
    return {"repository": TARGET, "base": BASE, "base_tree": BASE_TREE,
            "head": HEAD, "tree": HEAD_TREE, "parent": BASE, "commits": 1,
            "files": EXPECTED_FILES, "cleanliness": "PASS",
            "result": "EXACT_FINITE_BINDING_PASS"}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("base_root", type=Path)
    parser.add_argument("candidate_root", type=Path)
    args = parser.parse_args()
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
    head, base = validate_event(event, os.environ["GITHUB_EVENT_NAME"],
                                os.environ["GITHUB_REPOSITORY"])
    source_root = Path(__file__).resolve().parent.parent
    validate_source(source_root, os.environ["GITHUB_WORKFLOW_REF"], os.environ["GITHUB_WORKFLOW_SHA"])
    clean_committed_root(source_root, os.environ["GITHUB_WORKFLOW_SHA"], SOURCE)
    base_root = args.base_root.resolve(strict=True)
    candidate = args.candidate_root.resolve(strict=True)
    separate_roots(source_root, base_root, candidate)
    result = verify(base_root, candidate, head, HEAD_TREE, base)
    result["certifier_source"] = os.environ["GITHUB_WORKFLOW_SHA"]
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (Rejected, KeyError, OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"MAINTENANCE_REJECTED: {error}", file=sys.stderr)
        sys.exit(1)
