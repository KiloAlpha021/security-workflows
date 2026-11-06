"""Focused positive and negative tests for the finite PR #31 witness."""
from __future__ import annotations

import argparse
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


_SPEC = importlib.util.spec_from_file_location("maintenance_pr31_witness", Path(__file__).with_name("witness.py"))
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError("witness import specification unavailable")
witness = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(witness)


def git(root: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(root), *args],
        text=True,
        stderr=subprocess.PIPE,
    ).strip()


def event() -> dict:
    return {
        "number": witness.PR_NUMBER,
        "pull_request": {
            "base": {
                "ref": "main",
                "sha": witness.BASE,
                "repo": {"full_name": witness.TARGET},
            },
            "head": {
                "sha": witness.HEAD,
                "repo": {"full_name": witness.TARGET},
            },
            "state": "open",
            "merged": False,
            "draft": True,
        },
    }


class SuccessorWitnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.base = Path(os.environ["WITNESS_BASE_ROOT"]).resolve(strict=True)
        cls.head = Path(os.environ["WITNESS_HEAD_ROOT"]).resolve(strict=True)
        cls.merge = Path(os.environ["WITNESS_MERGE_ROOT"]).resolve(strict=True)

    def test_01_exact_pr31_positive(self) -> None:
        result = witness.verify(self.base, self.head, self.merge)
        self.assertEqual(result["result"], "EXACT_FINITE_BINDING_PASS")
        self.assertEqual(result["pull_request"], 31)
        self.assertEqual(result["files"], sorted(witness.EXPECTED_FILES))

    def test_02_exact_event_positive(self) -> None:
        self.assertEqual(
            witness.validate_event(
                event(), "pull_request", witness.TARGET, witness.MERGE
            ),
            (witness.HEAD, witness.BASE, witness.MERGE),
        )

    def assert_event_rejected(self, mutate, message: str) -> None:
        candidate = event()
        mutate(candidate)
        with self.assertRaisesRegex(witness.Rejected, message):
            witness.validate_event(
                candidate, "pull_request", witness.TARGET, witness.MERGE
            )

    def test_03_wrong_base_rejected(self) -> None:
        self.assert_event_rejected(
            lambda value: value["pull_request"]["base"].update({"sha": "0" * 40}),
            "protected base substitution",
        )

    def test_04_wrong_head_rejected(self) -> None:
        self.assert_event_rejected(
            lambda value: value["pull_request"]["head"].update({"sha": "0" * 40}),
            "candidate substitution",
        )

    def test_05_wrong_repository_rejected(self) -> None:
        with self.assertRaisesRegex(witness.Rejected, "wrong target/event"):
            witness.validate_event(event(), "pull_request", "attacker/repo", witness.MERGE)

    def test_06_wrong_pr_number_rejected(self) -> None:
        self.assert_event_rejected(
            lambda value: value.update({"number": 32}),
            "pull request substitution",
        )

    def test_07_wrong_target_branch_rejected(self) -> None:
        self.assert_event_rejected(
            lambda value: value["pull_request"]["base"].update({"ref": "other"}),
            "protected base substitution",
        )

    def test_08_synthetic_merge_substitution_rejected(self) -> None:
        with self.assertRaisesRegex(witness.Rejected, "synthetic merge substitution"):
            witness.validate_event(event(), "pull_request", witness.TARGET, "0" * 40)

    def test_09_closed_pr_rejected(self) -> None:
        self.assert_event_rejected(
            lambda value: value["pull_request"].update({"state": "closed"}),
            "open/unmerged",
        )

    def test_10_merged_pr_rejected(self) -> None:
        self.assert_event_rejected(
            lambda value: value["pull_request"].update({"merged": True}),
            "open/unmerged",
        )

    def test_11_wrong_candidate_tree_rejected(self) -> None:
        with self.assertRaisesRegex(witness.Rejected, "finite identity substitution"):
            witness.verify(self.base, self.head, self.merge, tree="0" * 40)

    def test_12_wrong_merge_identity_rejected(self) -> None:
        with self.assertRaisesRegex(witness.Rejected, "finite identity substitution"):
            witness.verify(self.base, self.head, self.merge, merge="0" * 40)

    def test_13_added_file_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "candidate"
            shutil.copytree(self.head, root, symlinks=True)
            (root / "unauthorised.py").write_text("raise SystemExit\n", encoding="utf-8")
            with self.assertRaisesRegex(witness.Rejected, "dirty checkout"):
                witness.verify(self.base, root, self.merge)

    def test_14_removed_file_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "candidate"
            shutil.copytree(self.head, root, symlinks=True)
            (root / "verify_security_workflows.py").unlink()
            with self.assertRaisesRegex(witness.Rejected, "dirty checkout|redirected file"):
                witness.verify(self.base, root, self.merge)

    def test_15_changed_candidate_blob_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "candidate"
            shutil.copytree(self.head, root, symlinks=True)
            path = root / "verify_security_workflows.py"
            path.write_bytes(path.read_bytes() + b"# mutation\n")
            with self.assertRaisesRegex(witness.Rejected, "dirty checkout"):
                witness.verify(self.base, root, self.merge)

    def test_16_changed_protected_blob_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "base"
            shutil.copytree(self.base, root, symlinks=True)
            path = root / "verify_security_workflows.py"
            path.write_bytes(path.read_bytes() + b"# mutation\n")
            with self.assertRaisesRegex(witness.Rejected, "dirty checkout"):
                witness.verify(root, self.head, self.merge)

    def test_17_candidate_controlled_source_ref_rejected(self) -> None:
        with self.assertRaisesRegex(witness.Rejected, "workflow source mismatch"):
            witness.validate_source(
                self.head,
                f"{witness.SOURCE}/{witness.WORKFLOW}@refs/heads/attacker",
                witness.HEAD,
            )

    def test_18_witness_self_approval_rejected(self) -> None:
        with self.assertRaisesRegex(witness.Rejected, "wrong target/event"):
            witness.validate_event(
                event(), "pull_request", witness.SOURCE, witness.MERGE
            )

    def test_19_unauthorised_witness_version_rejected(self) -> None:
        with self.assertRaisesRegex(witness.Rejected, "immutable SHA required"):
            witness.sha("main")

    def test_20_governance_bypass_event_rejected(self) -> None:
        with self.assertRaisesRegex(witness.Rejected, "wrong target/event"):
            witness.validate_event(event(), "workflow_dispatch", witness.TARGET, witness.MERGE)

    def test_21_required_paths_are_exact(self) -> None:
        self.assertEqual(
            sorted(witness.EXPECTED_FILES),
            ["test_verify_security_workflows.py", "verify_security_workflows.py"],
        )

    def test_22_historical_fixture_identity_is_exact(self) -> None:
        self.assertEqual(
            witness.HISTORICAL_FIXTURE_SHA256,
            "578810835df8328547df8d52ce0654a179aab22df2636fa9284d8cb4065ed3c6",
        )

    def test_23_dependency_locks_are_exact(self) -> None:
        result = witness.verify(self.base, self.head, self.merge)
        self.assertEqual(result["cleanliness"], "PASS")

    def test_24_partial_identity_override_rejected(self) -> None:
        with self.assertRaisesRegex(witness.Rejected, "finite identity substitution"):
            witness.verify(self.base, self.head, self.merge, head=witness.BASE)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--merge", required=True)
    arguments, remaining = parser.parse_known_args()
    os.environ["WITNESS_BASE_ROOT"] = str(Path(arguments.base).resolve())
    os.environ["WITNESS_HEAD_ROOT"] = str(Path(arguments.head).resolve())
    os.environ["WITNESS_MERGE_ROOT"] = str(Path(arguments.merge).resolve())
    unittest.main(argv=[__file__, *remaining], verbosity=2)


if __name__ == "__main__":
    main()
