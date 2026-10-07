"""Finite independent witness for one policy fixture-maintenance operation.

This source is proposal evidence until its exact commit is owner-established,
protected, and selected by an organization required-workflow rule.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

TARGET = "KiloAlpha021/security-policy"
SOURCE = "KiloAlpha021/security-workflows"
SOURCE_BRANCH = "f7-policy-maintenance-certifier-v4"
WORKFLOW = ".github/workflows/security-policy-maintenance.yml"
BASE = "c047a203fc7e1e3326e044f128a7323dea60041b"
BASE_TREE = "c49bebd5d6106da224da733d30b4c2d97c430bfc"
TEST_PATH = "test_verify_security_workflows.py"
BASE_TEST_SHA256 = "1122349d3923d59efcb30c00784ab5c5d50c4c4f518adb9e6d9538be181f694f"
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


def replace_once(text: str, before: str, after: str) -> str:
    require(text.count(before) == 1, "protected fixture anchor mismatch")
    return text.replace(before, after, 1)


def projected_tests(base: bytes) -> bytes:
    """Independent closed byte oracle, not a candidate-controlled patch."""
    require(hashlib.sha256(base).hexdigest() == BASE_TEST_SHA256,
            "protected test identity mismatch")
    text = base.decode("utf-8")
    tree = ast.parse(text)
    lines = text.splitlines(keepends=True)
    replacements = []
    names = {"test_native_s2c_is_exactly_one_s2_anchored_layer",
             "test_native_one_use_and_closed_selection_schema",
             "test_prebootstrap_preparation_restores_windows_checkout_bytes",
             "test_bootstrap_is_standard_library_only_and_pre_environment_importable"}
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef) or node.name not in names:
            continue
        start, end = node.lineno - 1, node.end_lineno
        require(end is not None, "fixture location missing")
        block = "".join(lines[start:end])
        if node.name.startswith("test_native_"):
            block = replace_once(block,
                '["git", "clone", "--quiet", str(source), str(repo)]',
                '["git", "-c", "core.autocrlf=false", "clone", "--quiet", str(source), str(repo)]')
            block = replace_once(block,
                '                           check=True, capture_output=True)\n',
                '                           check=True, capture_output=True)\n'
                '            repo = repo.resolve(strict=True)\n')
            if "s2c_is" in node.name:
                block = replace_once(block,
                    'git(repo, "checkout", "--detach", self.S2)',
                    'git(repo, "-c", "core.autocrlf=false", "checkout", "--detach", self.S2)')
        elif node.name == "test_bootstrap_is_standard_library_only_and_pre_environment_importable":
            block = replace_once(block,
                '[os.sys.executable, "-I", "-S", "-c",',
                '[os.sys.executable, "-I", "-S", "-B", "-c",')
        else:
            begin = block.index('            workflow_path.unlink()\n')
            finish = block.index('\n            workflow = yaml.load(', begin)
            attack = block[begin:finish]
            snapshot = ('            fixture_env = {key: os.environ.get(key) for key in\n'
                        '                           ("GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0")}\n'
                        '            with mock.patch.dict(os.environ, {\n'
                        '                    "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.autocrlf",\n'
                        '                    "GIT_CONFIG_VALUE_0": "true"}):\n')
            attack = "".join("    " + line if line.strip() else line
                             for line in attack.splitlines(keepends=True))
            restore = ('            self.assertEqual(\n'
                       '                {key: os.environ.get(key) for key in fixture_env}, fixture_env)\n')
            block = block[:begin] + snapshot + attack + restore + block[finish:]
        replacements.append((start, end, block))
    require(len(replacements) == 4, "exact four fixture/probe methods required")
    for start, end, block in sorted(replacements, reverse=True):
        lines[start:end] = [block]
    result = "".join(lines).encode("utf-8")
    canonical(result)
    compile(result, TEST_PATH, "exec")
    return result


def validate_event(event: dict, event_name: str, repository: str) -> tuple[str, str]:
    require(event_name == "pull_request" and repository == TARGET, "wrong target/event")
    pr = event["pull_request"]
    require(pr["base"]["repo"]["full_name"] == TARGET
            and pr["head"]["repo"]["full_name"] == TARGET, "repository substitution")
    require(pr["base"]["ref"] == "main" and pr["base"]["sha"] == BASE,
            "protected base substitution")
    require(not pr["merged"] and pr["state"] == "open", "PR is not open")
    return sha(pr["head"]["sha"]), sha(pr["base"]["sha"])


def validate_source(root: Path, workflow_ref: str, workflow_sha: str) -> None:
    require(workflow_ref == f"{SOURCE}/{WORKFLOW}@refs/heads/{SOURCE_BRANCH}",
            "independent workflow source mismatch")
    require(git(root, "remote", "get-url", "origin").decode().strip().removesuffix(".git")
            == "https://github.com/" + SOURCE, "certifier repository substitution")
    require(git(root, "rev-parse", "HEAD").decode().strip() == sha(workflow_sha),
            "certifier source substitution")


def verify(base_root: Path, candidate: Path, head: str, tree: str, base: str = BASE) -> dict:
    """Verify every committed entry and every executable worktree byte."""
    sha(head)
    sha(tree)
    require(base == BASE, "wrong protected base")
    for root in (base_root, candidate):
        require(root.is_absolute() and root.resolve(strict=True) == root,
                "noncanonical root")
        require(git(root, "remote", "get-url", "origin").decode().strip().removesuffix(".git")
                == "https://github.com/" + TARGET, "wrong Git repository")
        require(git(root, "rev-parse", f"{BASE}^{{tree}}").decode().strip() == BASE_TREE,
                "protected tree mismatch")
    require(base_root != candidate and not base_root.is_relative_to(candidate)
            and not candidate.is_relative_to(base_root), "root separation")
    require(git(base_root, "rev-parse", "HEAD").decode().strip() == BASE, "base checkout mismatch")
    require(git(candidate, "rev-parse", "HEAD").decode().strip() == head, "head checkout mismatch")
    require(git(candidate, "rev-parse", "HEAD^{tree}").decode().strip() == tree, "tree mismatch")
    require(git(candidate, "rev-list", "--parents", "-n", "1", head).decode().split()
            == [head, BASE], "one ordinary successor required")
    require(git(candidate, "diff", "--name-status", "--no-renames", BASE, head)
            == ("M\t" + TEST_PATH + "\n").encode(), "unauthorized change cone")
    expected = projected_tests(git(base_root, "show", f"{BASE}:{TEST_PATH}"))
    actual = git(candidate, "show", f"{head}:{TEST_PATH}")
    require(actual == expected, "fixture assertions or correction differ from independent oracle")
    for root, revision in ((base_root, BASE), (candidate, head)):
        require(not git(root, "status", "--porcelain", "--untracked-files=all"), "dirty checkout")
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
    return {"repository": TARGET, "base": BASE, "head": head, "tree": tree,
            "changed_paths": [TEST_PATH], "test_sha256": hashlib.sha256(actual).hexdigest(),
            "result": "IDENTITY_AND_INDEPENDENT_ORACLE_PASS"}


R3C_BASE = "416b6fded406e6d2ff425e3192885f2dc3341900"
R3C_BASE_TREE = "ce45c73908adc77cbaa2151cf2b724ded6ff87bc"
R3C_PREDECESSOR = "6a014b050b020c7ee938a90a3df5c6924ea96803"
R3C_HEAD = "91a4d6c156b635ddf2ce153c71a7a10042a6f9c7"
R3C_HEAD_TREE = "ea3ee03815399077b2101c68b8f245ef9d39e970"
R3C_EVALUATION = "ec6106b7ff7eb717c86714d70d7d7aaad695a165"
R3C_EVALUATION_TREE = "876b188971836e659a7c6409918a23e79eebba66"
R3C_METHODS = (
    "test_prebootstrap_preparation_restores_windows_checkout_bytes",
    "test_bootstrap_is_standard_library_only_and_pre_environment_importable",
    "test_native_s2c_is_exactly_one_s2_anchored_layer",
    "test_native_one_use_and_closed_selection_schema",
)


def validate_r3c_event(event: dict, event_name: str, repository: str,
                       evaluation: str) -> tuple[str, str, str]:
    require(event_name == "pull_request" and repository == TARGET, "wrong target/event")
    pr = event["pull_request"]
    require(event["number"] == 21 and pr["state"] == "open"
            and not pr["merged"] and not pr["draft"], "wrong PR lifecycle")
    require(pr["base"]["repo"]["full_name"] == TARGET
            and pr["head"]["repo"]["full_name"] == TARGET, "repository substitution")
    # GitHub retains PR21's historical base metadata after main advances.
    # Neither metadata value selects authority: verify_r3c requires the exact
    # protected checkout and exact ordered evaluation parents independently.
    require(pr["base"]["ref"] == "main" and pr["base"]["sha"] in (BASE, R3C_BASE),
            "PR base metadata substitution")
    require(pr["head"]["sha"] == R3C_HEAD, "PR21 substitution")
    require(evaluation == R3C_EVALUATION, "evaluation substitution")
    return R3C_BASE, R3C_HEAD, R3C_EVALUATION


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


def verify_r3c(base_root: Path, head_root: Path, evaluation_root: Path,
               base: str = R3C_BASE, head: str = R3C_HEAD,
               evaluation: str = R3C_EVALUATION) -> dict:
    require((base, head, evaluation) == (R3C_BASE, R3C_HEAD, R3C_EVALUATION),
            "R3C immutable binding substitution")
    roots = (base_root, head_root, evaluation_root)
    for i, left in enumerate(roots):
        for right in roots[i + 1:]:
            require(left != right and not left.is_relative_to(right)
                    and not right.is_relative_to(left), "root separation")
    for root, revision, tree in zip(roots, (base, head, evaluation),
                                   (R3C_BASE_TREE, R3C_HEAD_TREE, R3C_EVALUATION_TREE)):
        clean_committed_root(root, revision, TARGET)
        require(git(root, "rev-parse", "HEAD^{tree}").decode().strip() == tree,
                "R3C tree substitution")
    require(git(head_root, "rev-list", "--parents", "-n", "1", head).decode().split()
            == [head, R3C_PREDECESSOR], "PR21 parent substitution")
    require(git(evaluation_root, "rev-list", "--parents", "-n", "1", evaluation)
            .decode().split() == [evaluation, base, head], "evaluation ordered parents")
    require(git(head_root, "diff", "--name-status", "--no-renames", R3C_PREDECESSOR, head)
            == ("M\t" + TEST_PATH + "\n").encode(), "PR21 successor cone")
    require(git(evaluation_root, "diff", "--name-status", "--no-renames", base, evaluation)
            == ("A\t.gitattributes\nM\t.github/workflows/security-workflows-policy.yml\n"
                "M\t" + TEST_PATH + "\n").encode(), "R3C evaluation cone")
    require(git(evaluation_root, "merge-base", base, head).decode().strip() == BASE,
            "historical merge base")
    base_tests = git(base_root, "show", f"{base}:{TEST_PATH}")
    require(base_tests == projected_tests(git(base_root, "show", f"{BASE}:{TEST_PATH}")),
            "protected R3B projection mismatch")
    evaluated = git(evaluation_root, "show", f"{evaluation}:{TEST_PATH}")

    def methods(raw: bytes) -> dict[str, str]:
        text = raw.decode("utf-8")
        lines = text.splitlines(keepends=True)
        return {n.name: "".join(lines[n.lineno - 1:n.end_lineno])
                for n in ast.walk(ast.parse(text)) if isinstance(n, ast.FunctionDef)}

    protected_methods, evaluated_methods = methods(base_tests), methods(evaluated)
    require(all(protected_methods[n] == evaluated_methods[n] for n in R3C_METHODS),
            "R3B fixture/cleanliness preservation")
    workflow = evaluation_root / ".github/workflows/security-workflows-policy.yml"
    canonical(workflow.read_bytes())
    require((evaluation_root / ".gitattributes").read_bytes()
            == b".github/workflows/security-workflows-policy.yml text eol=lf\n",
            "canonical attributes changed")
    return {"repository": TARGET, "base": base, "head": head,
            "evaluation": evaluation, "evaluation_tree": R3C_EVALUATION_TREE,
            "r3b_preservation": "PASS", "cleanliness": "PASS",
            "result": "R3C_IDENTITY_AND_PRESERVATION_PASS"}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("base_root", type=Path)
    parser.add_argument("head_root", type=Path)
    parser.add_argument("candidate_root", type=Path)
    args = parser.parse_args()
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
    base, head, evaluation = validate_r3c_event(
        event, os.environ["GITHUB_EVENT_NAME"], os.environ["GITHUB_REPOSITORY"],
        os.environ["GITHUB_SHA"])
    source_root = Path(__file__).resolve().parent.parent
    validate_source(source_root, os.environ["GITHUB_WORKFLOW_REF"], os.environ["GITHUB_WORKFLOW_SHA"])
    clean_committed_root(source_root, os.environ["GITHUB_WORKFLOW_SHA"], SOURCE)
    candidate = args.candidate_root.resolve(strict=True)
    result = verify_r3c(args.base_root.resolve(strict=True),
                        args.head_root.resolve(strict=True), candidate,
                        base, head, evaluation)
    result["pr_base_metadata"] = event["pull_request"]["base"]["sha"]
    result["certifier_source"] = os.environ["GITHUB_WORKFLOW_SHA"]
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (Rejected, KeyError, OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"MAINTENANCE_REJECTED: {error}", file=sys.stderr)
        sys.exit(1)
