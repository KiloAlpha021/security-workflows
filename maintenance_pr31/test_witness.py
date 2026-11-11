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


_SPEC = importlib.util.spec_from_file_location(
    "maintenance_pr31_witness", Path(__file__).with_name("witness.py")
)
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


def event(merge: str) -> dict:
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
            "merge_commit_sha": merge,
        },
    }


def synthetic_root(
    source: Path,
    directory: Path,
    parents: list[str],
    *,
    alter_tree: bool = False,
) -> tuple[Path, str]:
    root = directory / "synthetic"
    subprocess.run(
        [
            "git", "-c", "core.autocrlf=false", "-c", "core.eol=lf",
            "clone", "--no-hardlinks", str(source), str(root),
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    subprocess.run(
        [
            "git", "-C", str(root), "remote", "set-url", "origin",
            "https://github.com/" + witness.TARGET,
        ],
        check=True,
    )
    tree = witness.HEAD_TREE
    if alter_tree:
        (root / "unauthorised.txt").write_text("unauthorised\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(root), "add", "unauthorised.txt"], check=True)
        tree = git(root, "write-tree")
    command = ["git", "-C", str(root), "commit-tree", tree]
    for parent in parents:
        command.extend(["-p", parent])
    commit_environment = {
        **os.environ,
        "GIT_AUTHOR_NAME": "Independent witness fixture",
        "GIT_AUTHOR_EMAIL": "witness-fixture@example.invalid",
        "GIT_COMMITTER_NAME": "Independent witness fixture",
        "GIT_COMMITTER_EMAIL": "witness-fixture@example.invalid",
    }
    generated = subprocess.check_output(
        command,
        input=b"regenerated synthetic merge\n",
        env=commit_environment,
    ).decode().strip()
    subprocess.run(
        [
            "git", "-c", "core.autocrlf=false", "-c", "core.eol=lf",
            "-C", str(root), "reset", "--hard", generated,
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return root, generated


class SuccessorWitnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.base = Path(os.environ["WITNESS_BASE_ROOT"]).resolve(strict=True)
        cls.head = Path(os.environ["WITNESS_HEAD_ROOT"]).resolve(strict=True)
        cls.merge = Path(os.environ["WITNESS_MERGE_ROOT"]).resolve(strict=True)
        cls.merge_sha = git(cls.merge, "rev-parse", "HEAD")

    def test_01_exact_pr31_positive(self) -> None:
        result = witness.verify(self.base, self.head, self.merge)
        self.assertEqual(result["result"], "EXACT_STABLE_MERGE_BINDING_PASS")
        self.assertEqual(result["merge"], self.merge_sha)
        self.assertEqual(result["pull_request"], 31)
        self.assertEqual(result["files"], sorted(witness.EXPECTED_FILES))

    def test_02_exact_event_positive(self) -> None:
        self.assertEqual(
            witness.validate_event(
                event(self.merge_sha), "pull_request", witness.TARGET, self.merge_sha
            ),
            (witness.HEAD, witness.BASE, self.merge_sha),
        )

    def assert_event_rejected(self, mutate, message: str) -> None:
        candidate = event(self.merge_sha)
        mutate(candidate)
        with self.assertRaisesRegex(witness.Rejected, message):
            witness.validate_event(
                candidate, "pull_request", witness.TARGET, self.merge_sha
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
            witness.validate_event(
                event(self.merge_sha), "pull_request", "attacker/repo", self.merge_sha
            )

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

    def test_08_malformed_evaluation_identity_rejected(self) -> None:
        with self.assertRaisesRegex(witness.Rejected, "immutable SHA required"):
            witness.validate_event(
                event(self.merge_sha), "pull_request", witness.TARGET, "invalid"
            )

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
        with self.assertRaisesRegex(witness.Rejected, "synthetic merge checkout substitution"):
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
                event(self.merge_sha), "pull_request", witness.SOURCE, self.merge_sha
            )

    def test_19_unauthorised_witness_version_rejected(self) -> None:
        with self.assertRaisesRegex(witness.Rejected, "immutable SHA required"):
            witness.sha("main")

    def test_20_governance_bypass_event_rejected(self) -> None:
        with self.assertRaisesRegex(witness.Rejected, "wrong target/event"):
            witness.validate_event(
                event(self.merge_sha), "workflow_dispatch", witness.TARGET, self.merge_sha
            )

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

    def test_25_legitimate_merge_regeneration_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, regenerated = synthetic_root(
                self.merge,
                Path(directory),
                [witness.BASE, witness.HEAD],
            )
            result = witness.verify(self.base, self.head, root, merge=regenerated)
            self.assertEqual(result["merge"], regenerated)
            self.assertNotEqual(regenerated, witness.HISTORICAL_MERGE)

    def test_26_stale_event_merge_metadata_accepts_authenticated_rerun(self) -> None:
        stale = event("1" * 40)
        self.assertEqual(
            witness.validate_event(
                stale, "pull_request", witness.TARGET, self.merge_sha
            ),
            (witness.HEAD, witness.BASE, self.merge_sha),
        )

    def test_27_reversed_merge_parents_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, generated = synthetic_root(
                self.merge, Path(directory), [witness.HEAD, witness.BASE]
            )
            with self.assertRaisesRegex(witness.Rejected, "synthetic merge parent substitution"):
                witness.verify(self.base, self.head, root, merge=generated)

    def test_28_missing_merge_parent_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, generated = synthetic_root(
                self.merge, Path(directory), [witness.BASE]
            )
            with self.assertRaisesRegex(witness.Rejected, "synthetic merge parent substitution"):
                witness.verify(self.base, self.head, root, merge=generated)

    def test_29_altered_synthetic_merge_tree_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, generated = synthetic_root(
                self.merge,
                Path(directory),
                [witness.BASE, witness.HEAD],
                alter_tree=True,
            )
            with self.assertRaisesRegex(witness.Rejected, "tree substitution"):
                witness.verify(self.base, self.head, root, merge=generated)

    def test_30_tree_equivalent_untrusted_merge_rejected_by_checkout_binding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            _root, generated = synthetic_root(
                self.merge, Path(directory), [witness.BASE, witness.HEAD]
            )
            with self.assertRaisesRegex(
                witness.Rejected, "synthetic merge checkout substitution"
            ):
                witness.verify(
                    self.base, self.head, self.merge, merge=generated
                )

    def test_31_missing_event_merge_metadata_is_not_authority(self) -> None:
        candidate = event(self.merge_sha)
        del candidate["pull_request"]["merge_commit_sha"]
        self.assertEqual(
            witness.validate_event(
                candidate, "pull_request", witness.TARGET, self.merge_sha
            ),
            (witness.HEAD, witness.BASE, self.merge_sha),
        )

    def test_32_workflow_uses_event_selected_merge(self) -> None:
        workflow = (
            Path(__file__).resolve().parents[1]
            / ".github"
            / "workflows"
            / "security-policy-maintenance-pr31.yml"
        ).read_text(encoding="utf-8")
        self.assertNotIn("ref: refs/pull/31/merge", workflow)
        self.assertEqual(
            workflow.count(
                "ref: 0d97deeb37274622089242be00e0057fa3892d19"
            ),
            1,
        )
        self.assertEqual(workflow.count("ref: ${{ github.sha }}"), 1)
        self.assertNotIn(witness.HISTORICAL_MERGE, workflow)


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
