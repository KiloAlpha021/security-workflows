"""Adversarial repository-context checks for the trusted evaluator."""

from __future__ import annotations

import inspect
import json
import subprocess
import tempfile
import unittest
from pathlib import Path, PurePosixPath

from verify_candidate import AUTHORITY_LIMITATIONS, verify, write_github_output


def git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *args], check=True, capture_output=True, text=True
    ).stdout.strip()


class CandidateVerificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.candidate = base / "candidate"
        self.trusted = base / "trusted"
        self.candidate.mkdir()
        self.trusted.mkdir()
        for root, branch, remote in (
            (self.candidate, "master", "automated-trading-bot"),
            (self.trusted, "main", "security-workflows"),
        ):
            git(root, "init", "-b", branch)
            git(root, "config", "user.name", "Test")
            git(root, "config", "user.email", "test@example.invalid")
            git(root, "remote", "add", "origin", f"https://github.com/KiloAlpha021/{remote}.git")

        self.write_candidate("pyproject.toml", "[project]\nname='test'\n")
        self.write_candidate("requirements-dev.lock", "historical locked\n")
        self.write_candidate("tests/test_dependency_lock.py", "# historical dependency control\n")
        self.write_candidate("scripts/immutable.py", "# immutable M1 control\n")
        git(self.candidate, "add", ".")
        git(self.candidate, "commit", "-m", "historical candidate")

        historical_paths = [
            "pyproject.toml",
            "requirements-dev.lock",
            "tests/test_dependency_lock.py",
            "scripts/immutable.py",
        ]
        identities = "".join(
            f"{git(self.candidate, 'rev-parse', f'HEAD:{name}')}  {name}\n"
            for name in historical_paths
        )
        (self.trusted / "trusted-git-blobs.txt").write_text(identities, encoding="utf-8")
        (self.trusted / "requirements-dev.lock").write_text(
            "historical locked\n", encoding="utf-8"
        )
        git(self.trusted, "add", ".")
        git(self.trusted, "commit", "-m", "historical trust")
        git(self.trusted, "update-ref", "refs/remotes/origin/main", "HEAD")
        self.sha = git(self.candidate, "rev-parse", "HEAD")

    def write_candidate(self, name: str, content: str) -> None:
        path = self.candidate / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", newline="\n")

    def commit_candidate(self, message: str) -> None:
        git(self.candidate, "add", ".")
        git(self.candidate, "commit", "-m", message)
        self.sha = git(self.candidate, "rev-parse", "HEAD")

    def successor_candidate(self) -> dict[str, str]:
        self.write_candidate("pyproject.toml", "[project]\nname='successor'\n")
        self.write_candidate("requirements-dev.in", "jsonschema==4.26.0\n")
        self.write_candidate("requirements-dev.lock", "successor locked\n")
        self.write_candidate("tests/test_dependency_lock.py", "# exact successor control\n")
        self.commit_candidate("successor candidate")
        return {
            name: git(self.candidate, "rev-parse", f"HEAD:{name}")
            for name in (
                "pyproject.toml",
                "requirements-dev.in",
                "requirements-dev.lock",
                "tests/test_dependency_lock.py",
            )
        }

    def add_profile(
        self,
        blobs: dict[str, str],
        profile_id: str = "stage3-corpus-assurance",
        **overrides,
    ) -> Path:
        directory = self.trusted / "profiles" / profile_id
        directory.mkdir(parents=True, exist_ok=True)
        lock = directory / "requirements-dev.lock"
        lock.write_text("successor locked\n", encoding="utf-8", newline="\n")
        lock_blob = git(self.trusted, "hash-object", str(lock))
        profile = {
            "schema_version": 1,
            "profile_id": profile_id,
            "target_repository": "KiloAlpha021/automated-trading-bot",
            "purpose": "STAGE-3 SPECIFICATION CORPUS ASSURANCE",
            "predecessor_profile": "historical-m1",
            "allowed_evolved_paths": list(blobs),
            "successor_blobs": blobs,
            "trusted_lock_path": f"profiles/{profile_id}/requirements-dev.lock",
            "trusted_lock_blob": lock_blob,
            "authority_limitations": AUTHORITY_LIMITATIONS,
        }
        profile.update(overrides)
        (directory / "profile.json").write_text(
            json.dumps(profile, indent=2) + "\n", encoding="utf-8", newline="\n"
        )
        (directory / "trusted-git-blobs.txt").write_text(
            "".join(f"{blob}  {name}\n" for name, blob in blobs.items()),
            encoding="utf-8",
            newline="\n",
        )
        git(self.trusted, "add", ".")
        git(self.trusted, "commit", "-m", f"add {profile_id}")
        git(self.trusted, "update-ref", "refs/remotes/origin/main", "HEAD")
        return directory

    def check(
        self,
        candidate: Path | None = None,
        trusted: Path | None = None,
        repository: str = "KiloAlpha021/automated-trading-bot",
        sha: str | None = None,
        event: str = "pull_request",
    ) -> PurePosixPath:
        return verify(
            candidate or self.candidate,
            trusted or self.trusted,
            repository,
            sha or self.sha,
            event,
        )

    def test_valid_historical_candidate_uses_unchanged_historical_lock(self) -> None:
        self.assertEqual(self.check(), PurePosixPath("requirements-dev.lock"))

    def test_exact_approved_successor_uses_trusted_profile_lock(self) -> None:
        blobs = self.successor_candidate()
        self.add_profile(blobs)
        self.assertEqual(
            self.check(),
            PurePosixPath("profiles/stage3-corpus-assurance/requirements-dev.lock"),
        )

    def test_reversed_roots_fail(self) -> None:
        with self.assertRaises(ValueError):
            self.check(candidate=self.trusted, trusted=self.candidate)

    def test_wrong_candidate_sha_fails(self) -> None:
        with self.assertRaisesRegex(ValueError, "event SHA"):
            self.check(sha="0" * 40)

    def test_wrong_target_repository_fails(self) -> None:
        with self.assertRaisesRegex(ValueError, "target repository"):
            self.check(repository="KiloAlpha021/security-workflows")

    def test_wrong_trusted_repository_fails(self) -> None:
        git(self.trusted, "remote", "set-url", "origin", "https://github.com/KiloAlpha021/other.git")
        with self.assertRaisesRegex(ValueError, "trusted checkout"):
            self.check()

    def test_wrong_trusted_ref_fails(self) -> None:
        git(self.trusted, "update-ref", "refs/remotes/origin/main", "0" * 40)
        with self.assertRaises(ValueError):
            self.check()

    def test_changed_immutable_m1_control_fails(self) -> None:
        self.write_candidate("scripts/immutable.py", "changed\n")
        self.commit_candidate("change immutable")
        with self.assertRaisesRegex(ValueError, "M1 control mismatch"):
            self.check()

    def test_missing_candidate_pyproject_fails(self) -> None:
        (self.candidate / "pyproject.toml").unlink()
        git(self.candidate, "add", "-u")
        git(self.candidate, "commit", "-m", "remove pyproject")
        self.sha = git(self.candidate, "rev-parse", "HEAD")
        with self.assertRaisesRegex(ValueError, "No applicable"):
            self.check()

    def test_candidate_blob_mismatch_fails(self) -> None:
        self.write_candidate("pyproject.toml", "changed\n")
        self.commit_candidate("change blob")
        with self.assertRaisesRegex(ValueError, "No applicable"):
            self.check()

    def test_historical_lock_mismatch_fails(self) -> None:
        self.write_candidate("requirements-dev.lock", "changed\n")
        self.commit_candidate("change lock")
        with self.assertRaisesRegex(ValueError, "No applicable"):
            self.check()

    def test_malformed_historical_identity_fails(self) -> None:
        (self.trusted / "trusted-git-blobs.txt").write_text("invalid\n")
        git(self.trusted, "add", ".")
        git(self.trusted, "commit", "-m", "malformed identity")
        git(self.trusted, "update-ref", "refs/remotes/origin/main", "HEAD")
        with self.assertRaisesRegex(ValueError, "Malformed"):
            self.check()

    def test_unknown_successor_fails(self) -> None:
        self.write_candidate("pyproject.toml", "unknown\n")
        self.commit_candidate("unknown successor")
        with self.assertRaisesRegex(ValueError, "No applicable"):
            self.check()

    def assert_wrong_successor_blob_fails(self, changed_path: str) -> None:
        blobs = self.successor_candidate()
        self.add_profile(blobs)
        (self.candidate / changed_path).write_text("unauthorized\n", encoding="utf-8")
        self.commit_candidate(f"change {changed_path}")
        with self.assertRaisesRegex(ValueError, "No applicable"):
            self.check()

    def test_wrong_successor_pyproject_blob_fails(self) -> None:
        self.assert_wrong_successor_blob_fails("pyproject.toml")

    def test_wrong_successor_requirements_input_blob_fails(self) -> None:
        self.assert_wrong_successor_blob_fails("requirements-dev.in")

    def test_wrong_successor_lock_blob_fails(self) -> None:
        self.assert_wrong_successor_blob_fails("requirements-dev.lock")

    def test_wrong_successor_dependency_test_blob_fails(self) -> None:
        self.assert_wrong_successor_blob_fails("tests/test_dependency_lock.py")

    def test_malformed_profile_fails(self) -> None:
        blobs = self.successor_candidate()
        directory = self.add_profile(blobs)
        profile = json.loads((directory / "profile.json").read_text())
        profile["unexpected"] = True
        (directory / "profile.json").write_text(json.dumps(profile))
        git(self.trusted, "add", ".")
        git(self.trusted, "commit", "-m", "malformed profile")
        git(self.trusted, "update-ref", "refs/remotes/origin/main", "HEAD")
        with self.assertRaisesRegex(ValueError, "Malformed"):
            self.check()

    def test_wrong_profile_repository_fails(self) -> None:
        blobs = self.successor_candidate()
        self.add_profile(blobs, target_repository="KiloAlpha021/other")
        with self.assertRaisesRegex(ValueError, "target repository"):
            self.check()

    def test_wrong_profile_lineage_fails(self) -> None:
        blobs = self.successor_candidate()
        self.add_profile(blobs, predecessor_profile="untrusted")
        with self.assertRaisesRegex(ValueError, "lineage"):
            self.check()

    def test_multiple_matching_profiles_fail(self) -> None:
        blobs = self.successor_candidate()
        self.add_profile(blobs)
        self.add_profile(blobs, profile_id="duplicate-successor")
        with self.assertRaisesRegex(ValueError, "Multiple applicable"):
            self.check()

    def test_candidate_cannot_choose_profile(self) -> None:
        self.assertNotIn("profile", inspect.signature(verify).parameters)

    def assert_untrusted_lock_path_fails(self, value: str) -> None:
        blobs = self.successor_candidate()
        self.add_profile(blobs, trusted_lock_path=value)
        with self.assertRaisesRegex(ValueError, "lock path"):
            self.check()

    def test_parent_traversal_lock_path_fails(self) -> None:
        self.assert_untrusted_lock_path_fails("../requirements-dev.lock")

    def test_absolute_lock_path_fails(self) -> None:
        self.assert_untrusted_lock_path_fails("/tmp/lock")

    def test_backslash_lock_path_fails(self) -> None:
        self.assert_untrusted_lock_path_fails("profiles\\lock")

    def test_successor_lock_profile_identity_mismatch_fails(self) -> None:
        blobs = self.successor_candidate()
        directory = self.add_profile(blobs)
        (directory / "requirements-dev.lock").write_text("wrong trusted lock\n")
        with self.assertRaisesRegex(ValueError, "lock/profile"):
            self.check()

    def test_successor_cannot_use_historical_lock(self) -> None:
        blobs = self.successor_candidate()
        directory = self.add_profile(blobs)
        (directory / "requirements-dev.lock").write_text("historical locked\n")
        with self.assertRaisesRegex(ValueError, "lock/profile"):
            self.check()

    def test_validated_lock_output_is_deterministic(self) -> None:
        output = Path(self.temp.name) / "github-output"
        write_github_output(output, PurePosixPath("requirements-dev.lock"))
        self.assertEqual(output.read_text(), "dependency_lock=requirements-dev.lock\n")
        with self.assertRaisesRegex(ValueError, "Unsafe"):
            write_github_output(output, PurePosixPath("../candidate/lock"))

    def test_workflow_commands_are_candidate_scoped_and_trusted_lock_controlled(self) -> None:
        workflow = (Path(__file__).parent / ".github/workflows/m1-trusted.yml").read_text()
        self.assertIn("path: candidate", workflow)
        self.assertIn("path: trusted", workflow)
        self.assertIn("ref: ${{ github.sha }}", workflow)
        self.assertIn("ref: main", workflow)
        self.assertIn("--github-output $env:GITHUB_OUTPUT", workflow)
        self.assertIn("steps.trust_profile.outputs.dependency_lock", workflow)
        self.assertNotIn("--profile", workflow)
        self.assertNotIn("../trusted/requirements-dev.lock\n", workflow)
        for step in (
            "Install exact trusted dependencies",
            "Verify dependency and project identity",
            "Run independent M1 quality and acceptance gate",
            "Run explicit M1 security and provenance controls",
        ):
            self.assertIn(f"- name: {step}\n        working-directory: candidate", workflow)


if __name__ == "__main__":
    unittest.main()
