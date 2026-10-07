"""Independent negative proofs; no candidate test selects the acceptance oracle."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import witness


class WitnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = Path(os.environ["WITNESS_POLICY_REPO"]).resolve(strict=True)
        cls.original = witness.git(cls.source, "show", f"{witness.BASE}:{witness.TEST_PATH}")
        cls.expected = witness.projected_tests(cls.original)
        cls.temporary = tempfile.TemporaryDirectory(prefix="independent-witness-")
        cls.root = Path(cls.temporary.name).resolve(strict=True)
        for name in ("base", "candidate"):
            path = cls.root / name
            subprocess.run(["git", "-c", "core.autocrlf=false", "clone", "--quiet",
                            "--no-hardlinks", "--no-checkout", str(cls.source), str(path)], check=True)
            witness.git(path, "-c", "core.autocrlf=false", "checkout", "--detach", witness.BASE)
            witness.git(path, "remote", "set-url", "origin", "https://github.com/" + witness.TARGET)
        cls.base = cls.root / "base"
        cls.candidate = cls.root / "candidate"
        (cls.candidate / witness.TEST_PATH).write_bytes(cls.expected)
        witness.git(cls.candidate, "-c", "core.autocrlf=false", "add", witness.TEST_PATH)
        witness.git(cls.candidate, "-c", "user.name=Witness Fixture",
                    "-c", "user.email=witness@example.invalid", "commit", "-m", "SIMULATION ONLY")
        cls.head = witness.git(cls.candidate, "rev-parse", "HEAD").decode().strip()
        cls.tree = witness.git(cls.candidate, "rev-parse", "HEAD^{tree}").decode().strip()

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_exact_projection_admitted(self):
        result = witness.verify(self.base, self.candidate, self.head, self.tree)
        self.assertEqual(result["changed_paths"], [witness.TEST_PATH])

    def test_fourth_projection_only_prevents_isolated_probe_bytecode(self):
        before = b'[os.sys.executable, "-I", "-S", "-c",'
        after = b'[os.sys.executable, "-I", "-S", "-B", "-c",'
        self.assertEqual(self.expected.count(after), 1)
        prior_projection = self.expected.replace(after, before, 1)
        self.assertEqual(hashlib.sha256(prior_projection).hexdigest(),
                         "13e0448a564d4d16d3d016e7559ccfd0ab5c057299af86a4fe059d2372d227f3")
        original = witness.git
        for replacement in (before, after.replace(b'"-B"', b'"-E"')):
            payload = self.expected.replace(after, replacement, 1)
            def changed(root, *args):
                if root == self.candidate and args == ("show", f"{self.head}:{witness.TEST_PATH}"):
                    return payload
                return original(root, *args)
            with self.subTest(replacement=replacement), mock.patch.object(
                    witness, "git", side_effect=changed), self.assertRaisesRegex(
                    witness.Rejected, "differ from independent oracle"):
                witness.verify(self.base, self.candidate, self.head, self.tree)

    def test_post_test_bytecode_residue_remains_rejected(self):
        original = witness.git
        def dirty(root, *args):
            if root == self.candidate and args == ("status", "--porcelain", "--untracked-files=all"):
                return b"?? __pycache__/protected_policy_bootstrap.cpython-312.pyc\n"
            return original(root, *args)
        with mock.patch.object(witness, "git", side_effect=dirty), self.assertRaisesRegex(
                witness.Rejected, "dirty checkout"):
            witness.verify(self.base, self.candidate, self.head, self.tree)

    def test_wrong_sha_base_tree_and_mutable_id_rejected(self):
        cases = [("0" * 40, self.tree, witness.BASE),
                 (self.head, "0" * 40, witness.BASE),
                 (self.head, self.tree, "0" * 40),
                 ("main", self.tree, witness.BASE)]
        for head, tree, base in cases:
            with self.subTest(head=head, tree=tree, base=base), self.assertRaises(witness.Rejected):
                witness.verify(self.base, self.candidate, head, tree, base)

    def test_candidate_assertion_removal_and_historical_rewrite_rejected(self):
        path = self.candidate / witness.TEST_PATH
        for payload in (self.expected.replace(b"self.assertEqual", b"self.assertNotEqual", 1),
                        self.expected.replace(b"f8f41127efe2c27cc7ba8f3132754b5c363636a1", b"0" * 40),
                        self.expected + b"\n# candidate-selected certification\n"):
            try:
                path.write_bytes(payload)
                with self.assertRaises(witness.Rejected):
                    witness.verify(self.base, self.candidate, self.head, self.tree)
            finally:
                path.write_bytes(self.expected)

    def test_unauthorized_file_and_certifier_injection_rejected(self):
        path = self.candidate / "witness.py"
        try:
            path.write_text("raise SystemExit(0)\n", encoding="utf-8")
            with self.assertRaises(witness.Rejected):
                witness.verify(self.base, self.candidate, self.head, self.tree)
        finally:
            path.unlink()

    def test_committed_foreign_path_and_wrong_parent_rejected(self):
        original = witness.git
        for command, response in (
                (("diff", "--name-status", "--no-renames", witness.BASE, self.head),
                 b"M\tprotected_policy_bootstrap.py\n"),
                (("rev-list", "--parents", "-n", "1", self.head),
                 f"{self.head} {witness.BASE} {witness.BASE}\n".encode())):
            def changed(root, *args):
                return response if args == command else original(root, *args)
            with mock.patch.object(witness, "git", side_effect=changed), self.assertRaises(witness.Rejected):
                witness.verify(self.base, self.candidate, self.head, self.tree)

    def test_committed_assertion_or_manifest_substitution_rejected(self):
        original = witness.git
        for replacement in (b"", self.expected.replace(b"self.assertEqual", b"self.assertNotEqual", 1)):
            def changed(root, *args):
                if root == self.candidate and args == ("show", f"{self.head}:{witness.TEST_PATH}"):
                    return replacement
                return original(root, *args)
            with mock.patch.object(witness, "git", side_effect=changed), self.assertRaises(witness.Rejected):
                witness.verify(self.base, self.candidate, self.head, self.tree)

    def test_workflow_is_finite_readonly_and_guards_native_failures(self):
        workflow = Path(__file__).resolve().parent.parent / witness.WORKFLOW
        raw = workflow.read_bytes()
        witness.canonical(raw)
        text = raw.decode()
        self.assertIn("permissions:\n  contents: read\n", text)
        for forbidden in ("continue-on-error", "secrets.", "workflow_dispatch:", "  if:",
                          "pull_request_target:", "checks: write", "contents: write"):
            self.assertNotIn(forbidden, text)
        self.assertIn("ref: ${{ github.workflow_sha }}", text)
        self.assertIn("ref: " + witness.R3C_BASE, text)
        self.assertIn("ref: ${{ github.sha }}", text)
        self.assertIn("path: pr21", text)
        lines = text.splitlines()
        commands = 0
        for index, line in enumerate(lines):
            if line.startswith(("          git ", "          python ", "          .\\")):
                commands += 1
                self.assertEqual(lines[index + 1].strip(),
                                 "if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }")
        self.assertEqual(commands, 16)

    def test_preflight_restoration_updates_index_without_environment_expansion(self):
        text = (Path(__file__).resolve().parent.parent / witness.WORKFLOW).read_text()
        def require_preflight_contract(source):
            start = source.index("      - name: Restore committed representations")
            end = source.index("      - name: Install independently pinned", start)
            step = source[start:end]
            expected = [
                f"          git -C {root} -c core.autocrlf=false -c core.eol=lf "
                "checkout-index --index --all --force"
                for root in ("witness", "protected", "pr21", "candidate")
            ]
            commands = [line for line in step.splitlines() if "checkout-index" in line]
            self.assertEqual(commands, expected)
            self.assertNotIn("GIT_CONFIG_", step)
            self.assertIn(
                "          python -I -S -B witness/maintenance/witness.py protected pr21 candidate",
                step,
            )
        require_preflight_contract(text)
        for root in ("witness", "protected", "pr21", "candidate"):
            original = (f"git -C {root} -c core.autocrlf=false -c core.eol=lf "
                        "checkout-index --index --all --force")
            for replacement in (
                    original.replace(" --index", ""),
                    original.replace(" --index", " --no-create"),
                    original.replace("core.autocrlf=false", "core.autocrlf=true"),
                    original.replace("core.eol=lf", "core.eol=crlf")):
                with self.subTest(root=root, replacement=replacement):
                    with self.assertRaises(AssertionError):
                        require_preflight_contract(text.replace(original, replacement, 1))

    def test_independent_source_initial_checkout_is_canonical(self):
        import yaml
        workflow = yaml.load((Path(__file__).resolve().parent.parent / witness.WORKFLOW)
                             .read_text(), Loader=yaml.BaseLoader)
        expected = {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.autocrlf",
                    "GIT_CONFIG_VALUE_0": "false"}

        def source_contract(document):
            self.assertNotIn("env", document)
            job = document["jobs"]["independent-maintenance"]
            self.assertNotIn("env", job)
            checkout = job["steps"][0]
            self.assertEqual(checkout["name"], "Check out independent witness")
            self.assertEqual(checkout["env"], expected)
            for step in job["steps"][1:]:
                if "uses" in step:
                    self.assertNotIn("env", step)

        source_contract(workflow)
        for key, value in (("GIT_CONFIG_COUNT", "2"), ("GIT_CONFIG_KEY_0", "core.eol"),
                           ("GIT_CONFIG_VALUE_0", "true"), ("GIT_CONFIG_KEY_1", "core.safecrlf")):
            changed = copy.deepcopy(workflow)
            changed["jobs"]["independent-maintenance"]["steps"][0]["env"][key] = value
            with self.assertRaises(AssertionError):
                source_contract(changed)
        for key in expected:
            changed = copy.deepcopy(workflow)
            del changed["jobs"]["independent-maintenance"]["steps"][0]["env"][key]
            with self.assertRaises(AssertionError):
                source_contract(changed)
        source = Path(__file__).resolve().parent.parent
        with tempfile.TemporaryDirectory(prefix="source-canonical-") as directory:
            checkout = Path(directory).resolve() / "witness"
            env = {**os.environ, **expected}
            subprocess.run(["git", "clone", "--quiet", "--no-hardlinks", str(source), str(checkout)],
                           env=env, check=True)
            witness.git(checkout, "remote", "set-url", "origin", "https://github.com/" + witness.SOURCE)
            revision = witness.git(checkout, "rev-parse", "HEAD").decode().strip()
            witness.clean_committed_root(checkout, revision, witness.SOURCE)

    def test_event_binding_rejects_candidate_selection(self):
        event = {"pull_request": {"base": {"repo": {"full_name": witness.TARGET},
                 "ref": "main", "sha": witness.BASE}, "head": {
                 "repo": {"full_name": witness.TARGET}, "sha": self.head},
                 "merged": False, "state": "open"}}
        self.assertEqual(witness.validate_event(event, "pull_request", witness.TARGET),
                         (self.head, witness.BASE))
        for part, key, value in (("base", "sha", "0" * 40), ("base", "ref", "other"),
                                 ("head", "sha", "main")):
            mutated = copy.deepcopy(event)
            mutated["pull_request"][part][key] = value
            with self.assertRaises(witness.Rejected):
                witness.validate_event(mutated, "pull_request", witness.TARGET)
        for name, repository in (("workflow_dispatch", witness.TARGET),
                                 ("pull_request", witness.SOURCE)):
            with self.assertRaises(witness.Rejected):
                witness.validate_event(event, name, repository)

    def test_base_oracle_and_canonical_mutations_rejected(self):
        with self.assertRaises(witness.Rejected):
            witness.projected_tests(self.original + b"\n")
        for payload in (b"a\r\n", b"\xef\xbb\xbfa\n", b"a\0\n", b"a", b"a\n\n"):
            with self.assertRaises(witness.Rejected):
                witness.canonical(payload)

    def test_independent_source_cannot_be_selected_by_candidate(self):
        root = Path(__file__).resolve().parent.parent
        actual = witness.git(root, "rev-parse", "HEAD").decode().strip()
        valid_ref = f"{witness.SOURCE}/{witness.WORKFLOW}@refs/heads/{witness.SOURCE_BRANCH}"
        witness.validate_source(root, valid_ref, actual)
        for ref, revision in ((valid_ref, "main"), (valid_ref, "0" * 40),
                              (valid_ref.replace(witness.SOURCE, witness.TARGET), actual),
                              (valid_ref.replace(witness.SOURCE_BRANCH, "main"), actual)):
            with self.assertRaises(witness.Rejected):
                witness.validate_source(root, ref, revision)

    def test_native_failures_cannot_be_masked(self):
        for fail in (0, 1, 2, None):
            lines = ["$ErrorActionPreference = 'Stop'"]
            for index in range(3):
                code = 37 if index == fail else 0
                lines.extend([f"& '{sys.executable}' -c 'import sys; sys.exit({code})'",
                              "if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }",
                              f"Write-Output 'COMPLETED_{index}'"])
            result = subprocess.run(["pwsh", "-NoProfile", "-NonInteractive", "-Command", "\n".join(lines)],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0 if fail is None else 37)
            expected = [f"COMPLETED_{n}" for n in range(3 if fail is None else fail)]
            self.assertEqual(result.stdout.splitlines(), expected)

    def test_production_root_rejections_preserved(self):
        spec = importlib.util.spec_from_file_location("independent_bootstrap", self.base / "protected_policy_bootstrap.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        self.assertEqual(module._root(self.base, "fixture"), self.base)
        for path in (Path("relative"), self.base / "missing", self.base / ".." / "base"):
            with self.assertRaises(module.BootstrapError):
                module._root(path, "fixture")
        alias = self.root / "alias"
        if os.name == "nt":
            command = f'New-Item -ItemType Junction -Path \'{alias}\' -Target \'{self.base}\' | Out-Null'
            subprocess.run(["pwsh", "-NoProfile", "-Command", command], check=True)
        else:
            alias.symlink_to(self.base, target_is_directory=True)
        try:
            with self.assertRaises(module.BootstrapError):
                module._root(alias, "fixture")
        finally:
            if os.name == "nt":
                os.rmdir(alias)
            else:
                alias.unlink()


class R3CBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="r3c-binding-")
        cls.root = Path(cls.temporary.name).resolve(strict=True)
        source = Path(os.environ["WITNESS_R3C_REPO"]).resolve(strict=True)
        cls.roots = []
        for name, revision in (("base", witness.R3C_BASE), ("head", witness.R3C_HEAD),
                               ("evaluation", witness.R3C_EVALUATION)):
            path = cls.root / name
            subprocess.run(["git", "-c", "core.autocrlf=false", "clone", "--quiet",
                            "--no-hardlinks", "--no-checkout", str(source), str(path)], check=True)
            witness.git(path, "-c", "core.autocrlf=false", "checkout", "--detach", revision)
            witness.git(path, "remote", "set-url", "origin", "https://github.com/" + witness.TARGET)
            cls.roots.append(path)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_exact_r3c_composition_admitted(self):
        result = witness.verify_r3c(*self.roots)
        self.assertEqual(result["result"], "R3C_IDENTITY_AND_PRESERVATION_PASS")

    def test_base_head_evaluation_and_mutable_substitution_rejected(self):
        for index in range(3):
            for invalid in ("0" * 40, "main", witness.BASE):
                values = [witness.R3C_BASE, witness.R3C_HEAD, witness.R3C_EVALUATION]
                values[index] = invalid
                with self.subTest(index=index, invalid=invalid), self.assertRaises(witness.Rejected):
                    witness.verify_r3c(*self.roots, *values)

    def test_exact_event_and_candidate_certifier_selection_boundary(self):
        event = {"number": 21, "pull_request": {
            "state": "open", "draft": False, "merged": False,
            "base": {"repo": {"full_name": witness.TARGET}, "ref": "main", "sha": witness.R3C_BASE},
            "head": {"repo": {"full_name": witness.TARGET}, "sha": witness.R3C_HEAD}}}
        expected = (witness.R3C_BASE, witness.R3C_HEAD, witness.R3C_EVALUATION)
        self.assertEqual(witness.validate_r3c_event(
            event, "pull_request", witness.TARGET, witness.R3C_EVALUATION), expected)
        historical_metadata = copy.deepcopy(event)
        historical_metadata["pull_request"]["base"]["sha"] = witness.BASE
        self.assertEqual(witness.validate_r3c_event(
            historical_metadata, "pull_request", witness.TARGET, witness.R3C_EVALUATION), expected)
        for part, key, invalid in (("base", "sha", "0" * 40), ("base", "ref", "other"),
                                   ("head", "sha", witness.R3C_PREDECESSOR)):
            changed = copy.deepcopy(event)
            changed["pull_request"][part][key] = invalid
            with self.assertRaises(witness.Rejected):
                witness.validate_r3c_event(changed, "pull_request", witness.TARGET, witness.R3C_EVALUATION)
        for name, repository, evaluation in (("merge_group", witness.TARGET, witness.R3C_EVALUATION),
                ("pull_request", witness.SOURCE, witness.R3C_EVALUATION),
                ("pull_request", witness.TARGET, "main")):
            with self.assertRaises(witness.Rejected):
                witness.validate_r3c_event(event, name, repository, evaluation)
        source = Path(__file__).resolve().parent.parent
        revision = witness.git(source, "rev-parse", "HEAD").decode().strip()
        reference = f"{witness.SOURCE}/{witness.WORKFLOW}@refs/heads/{witness.SOURCE_BRANCH}"
        witness.validate_source(source, reference, revision)
        for ref, sha in ((reference, "0" * 40), (reference.replace(witness.SOURCE_BRANCH, "main"), revision),
                         (reference.replace(witness.SOURCE, witness.TARGET), revision)):
            with self.assertRaises(witness.Rejected):
                witness.validate_source(source, ref, sha)

    def test_wrong_tree_parents_and_cone_rejected(self):
        original = witness.git
        evaluation = self.roots[2]
        cases = [
            (("rev-parse", "HEAD^{tree}"), b"0" * 40 + b"\n"),
            (("rev-list", "--parents", "-n", "1", witness.R3C_EVALUATION),
             f"{witness.R3C_EVALUATION} {witness.R3C_HEAD} {witness.R3C_BASE}\n".encode()),
            (("diff", "--name-status", "--no-renames", witness.R3C_BASE, witness.R3C_EVALUATION),
             b"M\tprotected_policy_bootstrap.py\n"),
        ]
        for command, response in cases:
            def changed(root, *args):
                return response if root == evaluation and args == command else original(root, *args)
            with self.subTest(command=command), mock.patch.object(witness, "git", side_effect=changed), \
                 self.assertRaises(witness.Rejected):
                witness.verify_r3c(*self.roots)

    def test_dirty_bytecode_and_self_certification_files_rejected(self):
        evaluation = self.roots[2]
        for relative in ("__pycache__/injected.pyc", "maintenance/witness.py"):
            path = evaluation / relative
            path.parent.mkdir(exist_ok=True)
            try:
                path.write_bytes(b"candidate-controlled\n")
                with self.assertRaises(witness.Rejected):
                    witness.verify_r3c(*self.roots)
            finally:
                path.unlink()
                path.parent.rmdir()

    def test_r3b_method_or_historical_identity_rewrite_rejected(self):
        evaluation = self.roots[2]
        path = evaluation / witness.TEST_PATH
        original = path.read_bytes()
        try:
            for changed in (original.replace(b'"-I", "-S", "-B"', b'"-I", "-S"', 1),
                            original.replace(b"f8f41127efe2c27cc7ba8f3132754b5c363636a1", b"0" * 40)):
                self.assertNotEqual(changed, original)
                path.write_bytes(changed)
                with self.assertRaises(witness.Rejected):
                    witness.verify_r3c(*self.roots)
        finally:
            path.write_bytes(original)


def run_policy(root: Path) -> None:
    root = root.resolve(strict=True)
    sys.path.insert(0, str(root))
    os.environ.update(witness.ENV)
    suite = unittest.defaultTestLoader.discover(str(root), pattern="test_verify_security_workflows.py")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    witness.require(result.wasSuccessful() and result.testsRun == 126, "policy suite incomplete/failed")
    witness.require({test.id() for test, _reason in result.skipped} == witness.ALLOWED_SKIPS,
                    "unexpected skip set")
    witness.require(len(result.skipped) == 2 and not result.expectedFailures
                    and not result.unexpectedSuccesses, "unexpected test disposition")
    print(json.dumps({"suite": "FULL_POLICY_AND_ADVERSARIAL", "run": result.testsRun,
                      "passed": result.testsRun - len(result.skipped), "authorized_skips": 2,
                      "result": "PASS"}, sort_keys=True))


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "run-policy":
        run_policy(Path(sys.argv[2]))
    else:
        unittest.main()
