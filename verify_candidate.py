"""Fail closed when trading candidates and protected trust profiles are confused."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse

CANDIDATE_REPOSITORY = "KiloAlpha021/automated-trading-bot"
TRUSTED_REPOSITORY = "KiloAlpha021/security-workflows"
TRUSTED_REF = "refs/remotes/origin/main"
HISTORICAL_PROFILE = "historical-m1"
HISTORICAL_LOCK = PurePosixPath("requirements-dev.lock")
PROFILE_ROOT = PurePosixPath("profiles")
DEPENDENCY_PROFILE_FILES = {
    "profile.json",
    "trusted-git-blobs.txt",
    "requirements-dev.lock",
}
CONTROL_PROFILE_FILES = {"profile.json", "trusted-git-blobs.txt"}
EVOLVABLE_PATHS = {
    "pyproject.toml",
    "requirements-dev.in",
    "requirements-dev.lock",
    "tests/test_dependency_lock.py",
}
SHA = re.compile(r"[0-9a-f]{40}\Z")
PROFILE_ID = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
IDENTITY = re.compile(r"([0-9a-f]{40})  (.+)\Z")
PROFILE_KEYS = {
    "schema_version",
    "profile_id",
    "target_repository",
    "purpose",
    "predecessor_profile",
    "allowed_evolved_paths",
    "successor_blobs",
    "trusted_lock_path",
    "trusted_lock_blob",
    "authority_limitations",
}
CONTROL_PROFILE_KEYS = {
    "schema_version",
    "profile_id",
    "profile_type",
    "policy_id",
    "target_repository",
    "purpose",
    "predecessor_profile",
    "target_base",
    "target_head",
    "target_head_tree",
    "activation_state",
    "allowed_evolved_paths",
    "transitions",
    "preserved_security_invariants",
    "authority_limitations",
}
AUTHORITY_LIMITATIONS = [
    "NO_CORPUS_MERGE_AUTHORITY",
    "NO_STAGE3_IMPLEMENTATION_AUTHORITY",
    "NO_PROVIDER_SELECTION_AUTHORITY",
    "NO_PROGRAMME_CONTROL_MUTATION_AUTHORITY",
    "NO_STAGE4_AUTHORITY",
    "NO_FINANCIAL_OR_TRADING_AUTHORITY",
]
CONTROL_AUTHORITY_LIMITATIONS = [
    "NO_ATIS_MERGE_AUTHORITY",
    "NO_IMPLEMENTATION_AUTHORITY",
    "NO_PROVIDER_OR_STORAGE_AUTHORITY",
    "NO_TRADING_OR_FINANCIAL_AUTHORITY",
    "NO_AI_TRADING_AUTHORITY",
]
PRESERVED_SECURITY_INVARIANTS = [
    "FROZEN_M1_EVIDENCE_MEMBERSHIP",
    "EXACT_HISTORICAL_IDENTITY",
    "MISSING_SOURCE_REJECTION",
    "CHANGED_HISTORICAL_OBJECT_REJECTION",
    "HISTORICAL_REPRODUCIBILITY",
    "CANDIDATE_TRUSTED_SEPARATION",
    "NO_SELF_CERTIFICATION",
]


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


def safe_relative_path(value: object, *, label: str) -> PurePosixPath:
    if not isinstance(value, str):
        raise TypeError(f"Malformed {label}")
    path = PurePosixPath(value)
    if (
        not value
        or path.is_absolute()
        or ".." in path.parts
        or "." in path.parts
        or "\\" in value
        or ":" in value
    ):
        raise ValueError(f"Unsafe {label}")
    return path


def read_identities(path: Path) -> dict[str, str]:
    identities: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = IDENTITY.fullmatch(line)
        if match is None:
            raise ValueError("Malformed trusted identity")
        expected, name = match.groups()
        safe_relative_path(name, label="trusted identity")
        if name in identities:
            raise ValueError("Unsafe or duplicate trusted identity")
        identities[name] = expected
    if not identities:
        raise ValueError("No trusted identities")
    return identities


def candidate_blob(candidate: Path, name: str) -> str | None:
    result = subprocess.run(
        ["git", "-C", str(candidate), "rev-parse", f"HEAD:{name}"],
        check=False,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def load_profiles(trusted: Path) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    profile_root = trusted / PROFILE_ROOT
    if not profile_root.is_dir():
        return [], []
    dependency_profiles: list[dict[str, object]] = []
    control_profiles: list[dict[str, object]] = []
    seen_ids: set[str] = set()
    profile_directories = sorted(profile_root.iterdir())
    if not profile_directories or not all(path.is_dir() for path in profile_directories):
        raise ValueError("Malformed trusted successor profile structure")
    for directory in profile_directories:
        entries = {path.name for path in directory.iterdir()}
        if directory.is_symlink() or frozenset(entries) not in {
            frozenset(DEPENDENCY_PROFILE_FILES),
            frozenset(CONTROL_PROFILE_FILES),
        }:
            raise ValueError("Malformed trusted successor profile structure")
        metadata_path = directory / "profile.json"
        try:
            profile = json.loads(metadata_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise ValueError("Malformed trusted successor profile") from error
        if not isinstance(profile, dict):
            raise TypeError("Malformed trusted successor profile")
        profile_id = profile.get("profile_id")
        if not isinstance(profile_id, str) or not PROFILE_ID.fullmatch(profile_id):
            raise ValueError("Malformed trusted successor profile ID")
        if profile_id in seen_ids or metadata_path.parent.name != profile_id:
            raise ValueError("Duplicate or misplaced trusted successor profile")
        seen_ids.add(profile_id)
        if profile.get("schema_version") != 1:
            raise ValueError("Unsupported trusted successor profile schema")
        if profile.get("target_repository") != CANDIDATE_REPOSITORY:
            raise ValueError("Wrong successor target repository")
        if profile.get("predecessor_profile") != HISTORICAL_PROFILE:
            raise ValueError("Wrong predecessor/profile lineage")
        if not isinstance(profile.get("purpose"), str) or not profile["purpose"].strip():
            raise ValueError("Missing successor profile purpose")
        if entries == DEPENDENCY_PROFILE_FILES:
            if set(profile) != PROFILE_KEYS:
                raise ValueError("Malformed trusted successor profile")
            _validate_dependency_profile(trusted, metadata_path, profile)
            dependency_profiles.append(profile)
        else:
            if set(profile) != CONTROL_PROFILE_KEYS:
                raise ValueError("Malformed trusted control successor profile")
            _validate_control_profile(metadata_path, profile)
            control_profiles.append(profile)
    return dependency_profiles, control_profiles


def _validate_dependency_profile(
    trusted: Path, metadata_path: Path, profile: dict[str, object]
) -> None:
    if profile["authority_limitations"] != AUTHORITY_LIMITATIONS:
        raise ValueError("Invalid successor authority limitations")
    evolved = profile["allowed_evolved_paths"]
    if not isinstance(evolved, list) or set(evolved) != EVOLVABLE_PATHS:
        raise ValueError("Invalid evolved dependency surface")
    if len(evolved) != len(set(evolved)):
        raise ValueError("Duplicate evolved dependency surface")
    blobs = profile["successor_blobs"]
    if not isinstance(blobs, dict) or set(blobs) != EVOLVABLE_PATHS:
        raise ValueError("Invalid successor blob set")
    if not all(
        isinstance(value, str) and SHA.fullmatch(value) for value in blobs.values()
    ):
        raise ValueError("Malformed successor blob identity")

    manifest_path = metadata_path.parent / "trusted-git-blobs.txt"
    if read_identities(manifest_path) != blobs:
        raise ValueError("Successor manifest/profile identity mismatch")
    lock_path = safe_relative_path(profile["trusted_lock_path"], label="trusted lock path")
    expected_lock = (
        PurePosixPath("profiles") / metadata_path.parent.name / "requirements-dev.lock"
    )
    if lock_path != expected_lock:
        raise ValueError("Untrusted dependency-lock path")
    resolved_lock = (trusted / lock_path).resolve(strict=True)
    profile_root_resolved = metadata_path.parent.resolve(strict=True)
    if resolved_lock.parent != profile_root_resolved:
        raise ValueError("Trusted lock escapes successor profile")
    actual_lock = git(trusted, "hash-object", str(resolved_lock))
    if actual_lock != profile["trusted_lock_blob"]:
        raise ValueError("Successor lock/profile identity mismatch")
    if blobs["requirements-dev.lock"] != profile["trusted_lock_blob"]:
        raise ValueError("Successor candidate/trusted lock mismatch")


def _validate_control_profile(metadata_path: Path, profile: dict[str, object]) -> None:
    if profile["profile_type"] != "TRUSTED_CONTROL_SUCCESSOR":
        raise ValueError("Invalid trusted control profile type")
    if profile["policy_id"] != "ATIS_STAGE3_TRUSTED_CONTROL_SUCCESSOR_POLICY_V1":
        raise ValueError("Invalid trusted control successor policy")
    for field in ("target_base", "target_head", "target_head_tree"):
        if not isinstance(profile[field], str) or not SHA.fullmatch(profile[field]):
            raise ValueError("Malformed trusted control target identity")
    if profile["activation_state"] != "ACTIVE_ON_PROTECTED_MAIN":
        raise ValueError("Inactive trusted control successor profile")
    if profile["authority_limitations"] != CONTROL_AUTHORITY_LIMITATIONS:
        raise ValueError("Invalid trusted control authority limitations")
    if profile["preserved_security_invariants"] != PRESERVED_SECURITY_INVARIANTS:
        raise ValueError("Trusted control invariant preservation mismatch")
    evolved = profile["allowed_evolved_paths"]
    transitions = profile["transitions"]
    if (
        not isinstance(evolved, list)
        or not evolved
        or len(evolved) != len(set(evolved))
        or not all(isinstance(value, str) for value in evolved)
        or not isinstance(transitions, list)
        or len(transitions) != len(evolved)
    ):
        raise ValueError("Invalid trusted control transition set")
    if any("*" in value or "?" in value for value in evolved):
        raise ValueError("Wildcard trusted control path")
    normalized = []
    for value in evolved:
        normalized.append(safe_relative_path(value, label="evolved trusted control").as_posix())
    if normalized != evolved:
        raise ValueError("Noncanonical trusted control path")
    transition_paths: list[str] = []
    successor_blobs: dict[str, str] = {}
    for transition in transitions:
        if not isinstance(transition, dict) or set(transition) != {
            "path",
            "predecessor_blob",
            "successor_blob",
        }:
            raise ValueError("Malformed trusted control transition")
        path = transition["path"]
        predecessor = transition["predecessor_blob"]
        successor = transition["successor_blob"]
        if (
            not isinstance(path, str)
            or path not in evolved
            or not isinstance(predecessor, str)
            or not SHA.fullmatch(predecessor)
            or not isinstance(successor, str)
            or not SHA.fullmatch(successor)
            or predecessor == successor
        ):
            raise ValueError("Invalid trusted control transition")
        transition_paths.append(path)
        successor_blobs[path] = successor
    if set(transition_paths) != set(evolved) or len(transition_paths) != len(set(transition_paths)):
        raise ValueError("Duplicate or missing trusted control transition")
    manifest = read_identities(metadata_path.parent / "trusted-git-blobs.txt")
    if manifest != successor_blobs:
        raise ValueError("Trusted control manifest/profile identity mismatch")


def verify_immutable(
    candidate: Path, historical: dict[str, str], evolved: set[str]
) -> None:
    for name, expected in historical.items():
        if name in EVOLVABLE_PATHS or name in evolved:
            continue
        if candidate_blob(candidate, name) != expected:
            raise ValueError(f"Trusted M1 control mismatch: {name}")


def select_dependency_lock(
    candidate: Path, trusted: Path, historical: dict[str, str]
) -> PurePosixPath:
    historical_matches = all(
        candidate_blob(candidate, name) == expected
        for name, expected in historical.items()
        if name in EVOLVABLE_PATHS
    )
    if historical_matches:
        expected_lock = git(trusted, "rev-parse", "HEAD:requirements-dev.lock")
        if candidate_blob(candidate, "requirements-dev.lock") != expected_lock:
            raise ValueError("Candidate dependency lock differs from trusted lock")
        return HISTORICAL_LOCK

    matches = []
    dependency_profiles, _ = load_profiles(trusted)
    for profile in dependency_profiles:
        blobs = profile["successor_blobs"]
        if all(candidate_blob(candidate, name) == expected for name, expected in blobs.items()):
            matches.append(profile)
    if not matches:
        raise ValueError("No applicable trusted successor profile")
    if len(matches) != 1:
        raise ValueError("Multiple applicable trusted successor profiles")
    return safe_relative_path(matches[0]["trusted_lock_path"], label="trusted lock path")


def select_control_profile(
    candidate: Path,
    trusted: Path,
    historical: dict[str, str],
    event_name: str,
    event_base_sha: str,
    event_head_sha: str,
) -> dict[str, object] | None:
    changed = {
        name
        for name, expected in historical.items()
        if name not in EVOLVABLE_PATHS and candidate_blob(candidate, name) != expected
    }
    if not changed:
        return None
    _, profiles = load_profiles(trusted)
    matches: list[dict[str, object]] = []
    for profile in profiles:
        if set(profile["allowed_evolved_paths"]) != changed:
            continue
        if (
            event_name != "pull_request"
            or profile["target_base"] != event_base_sha
            or profile["target_head"] != event_head_sha
        ):
            continue
        try:
            if (
                git(candidate, "rev-parse", f"{profile['target_head']}^{{tree}}")
                != profile["target_head_tree"]
            ):
                continue
        except ValueError:
            continue
        transitions = {item["path"]: item for item in profile["transitions"]}
        if any(
            historical.get(path) != transition["predecessor_blob"]
            or candidate_blob(candidate, path) != transition["successor_blob"]
            or git(candidate, "rev-parse", f"{profile['target_head']}:{path}")
            != transition["successor_blob"]
            for path, transition in transitions.items()
        ):
            continue
        matches.append(profile)
    if not matches:
        raise ValueError("No applicable trusted control successor profile")
    if len(matches) != 1:
        raise ValueError("Multiple applicable trusted control successor profiles")
    return matches[0]


def verify(
    candidate: Path,
    trusted: Path,
    event_repository: str,
    candidate_sha: str,
    event_name: str,
    event_base_sha: str,
    event_head_sha: str,
) -> tuple[PurePosixPath, str]:
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
    if not SHA.fullmatch(event_base_sha) or not SHA.fullmatch(event_head_sha):
        raise ValueError("Invalid event base/head identity")
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

    historical = read_identities(trusted / "trusted-git-blobs.txt")
    if "pyproject.toml" not in historical or "requirements-dev.lock" not in historical:
        raise ValueError("Historical dependency controls are incomplete")
    control_profile = select_control_profile(
        candidate,
        trusted,
        historical,
        event_name,
        event_base_sha,
        event_head_sha,
    )
    evolved = set(control_profile["allowed_evolved_paths"]) if control_profile else set()
    verify_immutable(candidate, historical, evolved)
    lock = select_dependency_lock(candidate, trusted, historical)
    selected = str(control_profile["profile_id"]) if control_profile else HISTORICAL_PROFILE
    return lock, selected


def write_github_output(
    output_file: Path,
    trusted_lock: PurePosixPath,
    selected_profile: str,
    candidate_head: str,
    candidate_tree: str,
    trusted_commit: str,
) -> None:
    value = trusted_lock.as_posix()
    safe_relative_path(value, label="trusted lock output")
    with output_file.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write(f"dependency_lock={value}\n")
        stream.write(f"selected_trusted_profile={selected_profile}\n")
        stream.write(f"evaluated_candidate_head={candidate_head}\n")
        stream.write(f"evaluated_candidate_tree={candidate_tree}\n")
        stream.write(f"trusted_commit={trusted_commit}\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--trusted", type=Path, required=True)
    parser.add_argument("--event-repository", required=True)
    parser.add_argument("--candidate-sha", required=True)
    parser.add_argument("--event-name", required=True)
    parser.add_argument("--event-base-sha", required=True)
    parser.add_argument("--event-head-sha", required=True)
    parser.add_argument("--github-output", type=Path, required=True)
    args = parser.parse_args()
    trusted_lock, selected_profile = verify(
        args.candidate,
        args.trusted,
        args.event_repository,
        args.candidate_sha,
        args.event_name,
        args.event_base_sha,
        args.event_head_sha,
    )
    write_github_output(
        args.github_output,
        trusted_lock,
        selected_profile,
        args.event_head_sha,
        git(candidate := args.candidate.resolve(strict=True), "rev-parse", f"{args.event_head_sha}^{{tree}}"),
        git(args.trusted.resolve(strict=True), "rev-parse", "HEAD"),
    )
    print(
        "Exact trading candidate and protected trusted controls verified: "
        f"head={args.event_head_sha} tree={git(candidate, 'rev-parse', f'{args.event_head_sha}^{{tree}}')} "
        f"trusted={git(args.trusted.resolve(strict=True), 'rev-parse', 'HEAD')} "
        f"profile={selected_profile}"
    )


if __name__ == "__main__":
    main()
