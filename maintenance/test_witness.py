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
        cls.temporary = tempfile.TemporaryDirectory(prefix="finite-witness-")
        cls.root = Path(cls.temporary.name).resolve(strict=True)
        for name, revision in (("base", witness.BASE), ("candidate", witness.HEAD)):
            path = cls.root / name
            subprocess.run(["git", "-c", "core.autocrlf=false", "clone", "--quiet",
                            "--no-hardlinks", "--no-checkout", str(cls.source), str(path)], check=True)
            witness.git(path, "-c", "core.autocrlf=false", "checkout", "--detach", revision)
            witness.git(path, "remote", "set-url", "origin", "https://github.com/" + witness.TARGET)
        cls.base, cls.candidate = cls.root / "base", cls.root / "candidate"

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_previous_finite_tuple_is_historical_only(self):
        source = Path(__file__).resolve().parent.parent
        predecessor = "532fa64abc856063f624ec0aff6838127e7a780b"
        self.assertEqual(witness.git(source, "rev-parse", predecessor + "^{tree}")
                         .decode().strip(), "cf16f0e3baccafb0d4014eff54c55a392fd4f92b")
        old = witness.git(source, "show", predecessor + ":maintenance/witness.py")
        self.assertIn(b'HEAD = "f49b7f0770d0bba83be074a078431fc356d0912e"', old)
        with self.assertRaisesRegex(witness.Rejected, "finite identity substitution"):
            witness.verify(self.base, self.candidate,
                           "f49b7f0770d0bba83be074a078431fc356d0912e",
                           "eaab2cff8f02ac1fc6214c303d1b0758f3fac488",
                           "523d81fc6f4d8788e2b6b8cbab72a87b1d8accc6")

    def test_each_expected_sha256_is_independently_bound(self):
        for path, (blob, _digest) in witness.EXPECTED_FILES.items():
            changed = dict(witness.EXPECTED_FILES)
            changed[path] = (blob, "0" * 64)
            with self.subTest(path=path), mock.patch.object(
                    witness, "EXPECTED_FILES", changed), mock.patch.object(
                    witness, "clean_committed_root"), self.assertRaisesRegex(
                    witness.Rejected, "candidate byte substitution"):
                witness.verify(self.base, self.candidate)

    def test_exact_finite_candidate_admitted(self):
        result = witness.verify(self.base, self.candidate)
        self.assertEqual(result["result"], "EXACT_FINITE_BINDING_PASS")
        self.assertEqual(result["files"], witness.EXPECTED_FILES)
        self.assertEqual(result["parent"], witness.BASE)
        self.assertEqual(result["commits"], 1)

    def test_independent_immutable_argument_substitutions(self):
        for index in range(3):
            for wrong in ("0" * 40, "main", "HEAD", "refs/heads/main", witness.SOURCE):
                values = [witness.HEAD, witness.HEAD_TREE, witness.BASE]
                values[index] = wrong
                with self.subTest(index=index, wrong=wrong), self.assertRaisesRegex(
                        witness.Rejected, "finite identity"):
                    witness.verify(self.base, self.candidate, *values)

    def test_trees_parent_count_and_every_path_are_independently_bound(self):
        cone = "".join("M\t" + path + "\n" for path in sorted(witness.EXPECTED_FILES)).encode()
        cases = [
            (self.base, ("rev-parse", "HEAD^{tree}"), b"0" * 40 + b"\n", "tree substitution"),
            (self.candidate, ("rev-parse", "HEAD^{tree}"), b"0" * 40 + b"\n", "tree substitution"),
            (self.candidate, ("rev-list", "--parents", "-n", "1", witness.HEAD),
             f"{witness.HEAD} {'0' * 40}\n".encode(), "sole parent"),
        ]
        for parents in ([], [witness.BASE, witness.BASE]):
            cases.append((self.candidate, ("rev-list", "--parents", "-n", "1", witness.HEAD),
                          (" ".join([witness.HEAD, *parents]) + "\n").encode(), "sole parent"))
        for count in (b"0\n", b"2\n"):
            cases.append((self.candidate, ("rev-list", "--count", f"{witness.BASE}..{witness.HEAD}"),
                          count, "commit count"))
        diff = ("diff", "--name-status", "--no-renames", witness.BASE, witness.HEAD)
        for path in witness.EXPECTED_FILES:
            line = ("M\t" + path + "\n").encode()
            for response in (cone.replace(line, b""), cone.replace(line, b"M\tunauthorized.py\n"),
                             cone.replace(line, line.replace(b"M\t", b"A\t"))):
                cases.append((self.candidate, diff, response, "changed path"))
        cases.append((self.candidate, diff, cone + b"M\textra.py\n", "changed path"))
        real = witness.git
        for target, command, response, message in cases:
            def changed(root, *args):
                return response if root == target and args == command else real(root, *args)
            # Isolate each binding's oracle; the positive and physical mutation
            # tests exercise the real clean-root verifier independently.
            with self.subTest(command=command, response=response), mock.patch.object(
                    witness, "clean_committed_root"), mock.patch.object(
                    witness, "git", side_effect=changed), self.assertRaisesRegex(witness.Rejected, message):
                witness.verify(self.base, self.candidate)

    def test_each_candidate_blob_and_bytes_are_independently_bound(self):
        real = witness.git
        for path, (blob, _digest) in witness.EXPECTED_FILES.items():
            for command, response, message in (
                    (("rev-parse", f"{witness.HEAD}:{path}"), b"0" * 40 + b"\n", "blob substitution"),
                    (("cat-file", "blob", blob), b"replacement\n", "byte substitution")):
                def changed(root, *args):
                    return response if root == self.candidate and args == command else real(root, *args)
                with self.subTest(path=path, command=command), mock.patch.object(
                        witness, "clean_committed_root"), mock.patch.object(
                        witness, "git", side_effect=changed), self.assertRaisesRegex(witness.Rejected, message):
                    witness.verify(self.base, self.candidate)

    def test_tracked_mutation_and_raw_checkout_transformation_rejected(self):
        for relative in witness.EXPECTED_FILES:
            path = self.candidate / relative
            original = path.read_bytes()
            try:
                for changed in (original + b"# unauthorized\n", original.replace(b"\n", b"\r\n"),
                                b"\xef\xbb\xbf" + original, original + b"\0"):
                    path.write_bytes(changed)
                    with self.subTest(path=relative), self.assertRaises(witness.Rejected):
                        witness.clean_committed_root(self.candidate, witness.HEAD, witness.TARGET)
            finally:
                path.write_bytes(original)

    def test_untracked_bytecode_empty_cache_and_self_certification_rejected(self):
        for relative in ("extra.txt", "injected.pyc", "__pycache__/injected.pyc", "maintenance/witness.py"):
            path = self.candidate / relative
            created = not path.parent.exists()
            path.parent.mkdir(exist_ok=True)
            try:
                path.write_bytes(b"candidate controlled\n")
                with self.subTest(path=relative), self.assertRaises(witness.Rejected):
                    witness.clean_committed_root(self.candidate, witness.HEAD, witness.TARGET)
            finally:
                path.unlink()
                if created:
                    path.parent.rmdir()
        cache = self.candidate / "__pycache__"
        cache.mkdir()
        try:
            with self.assertRaisesRegex(witness.Rejected, "bytecode residue"):
                witness.clean_committed_root(self.candidate, witness.HEAD, witness.TARGET)
        finally:
            cache.rmdir()

    def test_root_separation_repository_and_checkout_rejection(self):
        for roots in ((self.base, self.base), (self.base, self.base / "nested")):
            with self.assertRaisesRegex(witness.Rejected, "root separation"):
                witness.separate_roots(*roots)
        real = witness.git
        for command, response in ((("remote", "get-url", "origin"), b"https://github.com/other/repo\n"),
                                  (("rev-parse", "HEAD"), b"0" * 40 + b"\n")):
            def changed(root, *args):
                return response if args == command else real(root, *args)
            with mock.patch.object(witness, "git", side_effect=changed), self.assertRaises(witness.Rejected):
                witness.clean_committed_root(self.candidate, witness.HEAD, witness.TARGET)

    def test_event_has_no_candidate_selected_authority(self):
        event = {"pull_request": {
            "base": {"repo": {"full_name": witness.TARGET}, "ref": "main", "sha": witness.BASE},
            "head": {"repo": {"full_name": witness.TARGET}, "sha": witness.HEAD},
            "state": "open", "merged": False, "draft": False}}
        self.assertEqual(witness.validate_event(event, "pull_request", witness.TARGET),
                         (witness.HEAD, witness.BASE))
        for part, key, value in (("base", "sha", "0" * 40), ("base", "ref", "other"),
                                 ("head", "sha", "main"), ("head", "sha", "0" * 40)):
            changed = copy.deepcopy(event)
            changed["pull_request"][part][key] = value
            with self.assertRaises(witness.Rejected):
                witness.validate_event(changed, "pull_request", witness.TARGET)
        for part in ("base", "head"):
            changed = copy.deepcopy(event)
            changed["pull_request"][part]["repo"]["full_name"] = witness.SOURCE
            with self.assertRaises(witness.Rejected):
                witness.validate_event(changed, "pull_request", witness.TARGET)
        for key, value in (("draft", True), ("merged", True), ("state", "closed")):
            changed = copy.deepcopy(event)
            changed["pull_request"][key] = value
            with self.assertRaises(witness.Rejected):
                witness.validate_event(changed, "pull_request", witness.TARGET)
        for name, repository in (("merge_group", witness.TARGET), ("push", witness.TARGET),
                                 ("pull_request", witness.SOURCE)):
            with self.assertRaises(witness.Rejected):
                witness.validate_event(event, name, repository)

    def test_canonical_mutations_rejected(self):
        witness.canonical(b"canonical\n")
        for raw in (b"CR\r\n", b"\xef\xbb\xbfBOM\n", b"NUL\0\n", b"no newline", b"two\n\n", b"\xff\n"):
            with self.subTest(raw=raw), self.assertRaises((witness.Rejected, UnicodeError)):
                witness.canonical(raw)

    def test_historical_authority_and_assertions_cannot_be_rewritten(self):
        path = self.candidate / "test_verify_security_workflows.py"
        original = path.read_bytes()
        try:
            for before, after in ((b"f8f41127efe2c27cc7ba8f3132754b5c363636a1", b"0" * 40),
                                  (b'"-I", "-S", "-B"', b'"-I", "-S"')):
                changed = original.replace(before, after)
                self.assertNotEqual(changed, original)
                path.write_bytes(changed)
                with self.assertRaises(witness.Rejected):
                    witness.clean_committed_root(self.candidate, witness.HEAD, witness.TARGET)
        finally:
            path.write_bytes(original)

    def test_r3c_is_historical_not_successor_authority(self):
        source = Path(__file__).resolve().parent.parent
        current = (source / "maintenance/witness.py").read_text()
        for obsolete in ("R3C_", "validate_r3c_event", "verify_r3c", "projected_tests", 'event["number"]'):
            self.assertNotIn(obsolete, current)
        old = witness.git(source, "show", "737163e87eef8c61f16d3abb995f5fbcfd25616b:maintenance/witness.py")
        self.assertIn(b"verify_r3c", old)
        self.assertEqual(witness.git(source, "rev-parse", "737163e87eef8c61f16d3abb995f5fbcfd25616b^{tree}")
                         .decode().strip(), "a8af4462e3affade01fbebad00f362e3ef147be9")

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
        self.assertIn("ref: " + witness.BASE, text)
        self.assertIn("ref: " + witness.HEAD, text)
        self.assertNotIn("pr21", text)
        lines = text.splitlines()
        commands = 0
        for index, line in enumerate(lines):
            if line.startswith(("          git ", "          python ", "          .\\")):
                commands += 1
                self.assertEqual(lines[index + 1].strip(),
                                 "if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }")
        self.assertEqual(commands, 15)

    def test_preflight_restoration_updates_index_without_environment_expansion(self):
        text = (Path(__file__).resolve().parent.parent / witness.WORKFLOW).read_text()
        def require_preflight_contract(source):
            start = source.index("      - name: Restore committed representations")
            end = source.index("      - name: Install independently pinned", start)
            step = source[start:end]
            expected = [
                f"          git -C {root} -c core.autocrlf=false -c core.eol=lf "
                "checkout-index --index --all --force"
                for root in ("witness", "protected", "candidate")
            ]
            commands = [line for line in step.splitlines() if "checkout-index" in line]
            self.assertEqual(commands, expected)
            self.assertNotIn("GIT_CONFIG_", step)
            self.assertIn(
                "          python -I -S -B witness/maintenance/witness.py protected candidate",
                step,
            )
        require_preflight_contract(text)
        for root in ("witness", "protected", "candidate"):
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

    def test_independent_source_cannot_be_selected_by_candidate(self):
        root = Path(__file__).resolve().parent.parent
        actual = witness.git(root, "rev-parse", "HEAD").decode().strip()
        valid_ref = f"{witness.SOURCE}/{witness.WORKFLOW}@refs/heads/{witness.SOURCE_BRANCH}"
        witness.validate_source(root, valid_ref, actual)
        for ref, revision in ((valid_ref, "main"), (valid_ref, "0" * 40),
                              (valid_ref.replace(witness.SOURCE, witness.TARGET), actual),
                              (valid_ref.replace(witness.SOURCE_BRANCH, "main"), actual),
                              (valid_ref.replace(witness.WORKFLOW, "other.yml"), actual)):
            with self.assertRaises(witness.Rejected):
                witness.validate_source(root, ref, revision)

    def test_locked_pipeline_and_finite_checkout_contract(self):
        import yaml
        source = Path(__file__).resolve().parent.parent
        document = yaml.load((source / witness.WORKFLOW).read_text(), Loader=yaml.BaseLoader)
        job = document["jobs"]["independent-maintenance"]
        self.assertEqual(document["permissions"], {"contents": "read"})
        self.assertEqual(job["runs-on"], "windows-latest")
        steps = job["steps"]
        expected_roots = ((witness.SOURCE, "${{ github.workflow_sha }}", "witness"),
                          (witness.TARGET, witness.BASE, "protected"),
                          (witness.TARGET, witness.HEAD, "candidate"))
        for step, (repo, ref, path) in zip(steps[:3], expected_roots):
            self.assertEqual(step["uses"], "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683")
            self.assertEqual(step["with"], {"repository": repo, "ref": ref, "path": path,
                                         "persist-credentials": "false", "fetch-depth": "0"})
        self.assertEqual(steps[3]["with"], {"python-version": "3.12.10"})
        names = [step["name"] for step in steps]
        self.assertEqual(names[4:], [
            "Restore committed representations and verify independent bindings",
            "Install independently pinned policy environment",
            "Independent adversarial witness tests",
            "Full admitted policy compatibility and adversarial suite",
            "Audit independently pinned dependencies"])
        prior = yaml.load(witness.git(source, "show",
                         "737163e87eef8c61f16d3abb995f5fbcfd25616b:" + witness.WORKFLOW),
                         Loader=yaml.BaseLoader)
        old_steps = {s["name"]: s for s in prior["jobs"]["independent-maintenance"]["steps"]}
        for step in (steps[3], steps[5], steps[8]):
            self.assertEqual(step, old_steps[step["name"]])
        self.assertEqual(steps[6]["env"], {**witness.ENV,
                         "WITNESS_POLICY_REPO": "${{ github.workspace }}/candidate"})
        full = steps[7]["run"]
        self.assertLess(full.index("run-policy candidate"), full.index("witness.py protected candidate"))
        self.assertIn("-I -S -B witness/maintenance/witness.py protected candidate", full)
        for step in steps:
            self.assertNotIn("if", step)
            self.assertNotIn("continue-on-error", step)

    def test_integrity_failure_propagates(self):
        real = witness.git
        def broken(root, *args):
            if args == ("fsck", "--no-dangling", "--no-reflogs"):
                raise subprocess.CalledProcessError(1, ["git", *args])
            return real(root, *args)
        with mock.patch.object(witness, "git", side_effect=broken), self.assertRaises(subprocess.CalledProcessError):
            witness.clean_committed_root(self.candidate, witness.HEAD, witness.TARGET)

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


def run_policy(root: Path) -> None:
    root = root.resolve(strict=True)
    sys.path.insert(0, str(root))
    os.environ.update(witness.ENV)
    suite = unittest.defaultTestLoader.discover(str(root), pattern="test_verify_security_workflows.py")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    witness.require(result.wasSuccessful() and result.testsRun == 132, "policy suite incomplete/failed")
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
