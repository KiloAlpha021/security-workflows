"""Adversarial repository-context checks for the trusted evaluator."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from verify_candidate import verify


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
        (self.candidate / "pyproject.toml").write_text("[project]\nname='test'\n")
        (self.candidate / "requirements-dev.lock").write_text("locked\n")
        git(self.candidate, "add", ".")
        git(self.candidate, "commit", "-m", "candidate")
        blob = git(self.candidate, "rev-parse", "HEAD:pyproject.toml")
        (self.trusted / "trusted-git-blobs.txt").write_text(
            f"{blob}  pyproject.toml\n", encoding="utf-8"
        )
        (self.trusted / "requirements-dev.lock").write_text("locked\n")
        git(self.trusted, "add", ".")
        git(self.trusted, "commit", "-m", "trusted")
        git(self.trusted, "update-ref", "refs/remotes/origin/main", "HEAD")
        self.sha = git(self.candidate, "rev-parse", "HEAD")

    def check(self, candidate: Path | None = None, trusted: Path | None = None,
              repository: str = "KiloAlpha021/automated-trading-bot",
              sha: str | None = None, event: str = "pull_request") -> None:
        verify(candidate or self.candidate, trusted or self.trusted,
               repository, sha or self.sha, event)

    def test_valid_candidate_and_protected_controls(self) -> None:
        self.check()

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

    def test_missing_candidate_pyproject_fails(self) -> None:
        (self.candidate / "pyproject.toml").unlink()
        git(self.candidate, "add", "-u")
        git(self.candidate, "commit", "-m", "remove pyproject")
        with self.assertRaises(ValueError):
            self.check(sha=git(self.candidate, "rev-parse", "HEAD"))

    def test_candidate_blob_mismatch_fails(self) -> None:
        (self.candidate / "pyproject.toml").write_text("changed\n")
        git(self.candidate, "add", ".")
        git(self.candidate, "commit", "-m", "change blob")
        with self.assertRaisesRegex(ValueError, "control mismatch"):
            self.check(sha=git(self.candidate, "rev-parse", "HEAD"))

    def test_lock_mismatch_fails(self) -> None:
        (self.candidate / "requirements-dev.lock").write_text("changed\n")
        git(self.candidate, "add", ".")
        git(self.candidate, "commit", "-m", "change lock")
        with self.assertRaisesRegex(ValueError, "lock differs"):
            self.check(sha=git(self.candidate, "rev-parse", "HEAD"))

    def test_malformed_identity_fails(self) -> None:
        (self.trusted / "trusted-git-blobs.txt").write_text("invalid\n")
        git(self.trusted, "add", ".")
        git(self.trusted, "commit", "-m", "malformed")
        git(self.trusted, "update-ref", "refs/remotes/origin/main", "HEAD")
        with self.assertRaisesRegex(ValueError, "Malformed"):
            self.check()

    def test_workflow_commands_are_candidate_scoped(self) -> None:
        workflow = (Path(__file__).parent / ".github/workflows/m1-trusted.yml").read_text()
        self.assertIn("path: candidate", workflow)
        self.assertIn("path: trusted", workflow)
        self.assertIn("ref: ${{ github.sha }}", workflow)
        self.assertIn("working-directory: candidate", workflow)
        for step in (
            "Install exact trusted dependencies", "Verify dependency and project identity",
            "Run independent M1 quality and acceptance gate",
            "Run explicit M1 security and provenance controls",
        ):
            self.assertIn(f"- name: {step}\n        working-directory: candidate", workflow)
        self.assertNotIn("_trusted", workflow)


if __name__ == "__main__":
    unittest.main()
