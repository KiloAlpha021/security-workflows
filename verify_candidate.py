"""Fail closed when the trading candidate and protected controls are confused."""

from __future__ import annotations

import argparse
import re
import subprocess
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse

CANDIDATE_REPOSITORY = "KiloAlpha021/automated-trading-bot"
TRUSTED_REPOSITORY = "KiloAlpha021/security-workflows"
TRUSTED_REF = "refs/remotes/origin/main"
SHA = re.compile(r"[0-9a-f]{40}\Z")
IDENTITY = re.compile(r"([0-9a-f]{40})  (.+)\Z")


def git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *args], check=False, capture_output=True, text=True
    )
    if result.returncode:
        raise ValueError(f"Git identity check failed: {args[0]}")
    return result.stdout.strip()


def repository(root: Path) -> str:
    url = urlparse(git(root, "remote", "get-url", "origin"))
    if url.scheme != "https" or url.hostname != "github.com" or url.username:
        raise ValueError("Unexpected repository remote")
    return url.path.removeprefix("/").removesuffix(".git")


def verify(
    candidate: Path, trusted: Path, event_repository: str,
    candidate_sha: str, event_name: str,
) -> None:
    candidate = candidate.resolve(strict=True)
    trusted = trusted.resolve(strict=True)
    if candidate == trusted or candidate in trusted.parents or trusted in candidate.parents:
        raise ValueError("Candidate and trusted roots must be separate")
    if event_repository != CANDIDATE_REPOSITORY:
        raise ValueError("Wrong target repository")
    if event_name not in {"pull_request", "merge_group"}:
        raise ValueError("Unsupported required-workflow event")
    if not SHA.fullmatch(candidate_sha):
        raise ValueError("Invalid candidate SHA")
    if repository(candidate) != CANDIDATE_REPOSITORY:
        raise ValueError("Wrong candidate checkout")
    if git(candidate, "rev-parse", "HEAD") != candidate_sha:
        raise ValueError("Candidate checkout does not match event SHA")
    if git(candidate, "rev-parse", "--is-shallow-repository") != "false":
        raise ValueError("Required candidate history is unavailable")
    if repository(trusted) != TRUSTED_REPOSITORY:
        raise ValueError("Wrong trusted checkout")
    if git(trusted, "rev-parse", "HEAD") != git(trusted, "rev-parse", TRUSTED_REF):
        raise ValueError("Trusted checkout is not protected main")

    identities = (trusted / "trusted-git-blobs.txt").read_text(encoding="utf-8")
    seen: set[str] = set()
    for line in identities.splitlines():
        match = IDENTITY.fullmatch(line)
        if match is None:
            raise ValueError("Malformed trusted identity")
        expected, name = match.groups()
        path = PurePosixPath(name)
        if name in seen or path.is_absolute() or ".." in path.parts or "\\" in name:
            raise ValueError("Unsafe or duplicate trusted identity")
        seen.add(name)
        actual = git(candidate, "rev-parse", f"HEAD:{name}")
        if actual != expected:
            raise ValueError(f"Trusted M1 control mismatch: {name}")
    if not seen:
        raise ValueError("No trusted identities")
    if "pyproject.toml" not in seen:
        raise ValueError("Candidate pyproject.toml is not protected")
    expected_lock = git(trusted, "rev-parse", "HEAD:requirements-dev.lock")
    actual_lock = git(candidate, "rev-parse", "HEAD:requirements-dev.lock")
    if actual_lock != expected_lock:
        raise ValueError("Candidate dependency lock differs from trusted lock")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--trusted", type=Path, required=True)
    parser.add_argument("--event-repository", required=True)
    parser.add_argument("--candidate-sha", required=True)
    parser.add_argument("--event-name", required=True)
    args = parser.parse_args()
    verify(
        args.candidate, args.trusted, args.event_repository,
        args.candidate_sha, args.event_name,
    )
    print("Exact trading candidate and protected trusted controls verified")


if __name__ == "__main__":
    main()
