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
        predecessor = "ed41da21243c4949b3eb890f444c10e5bde0546a"
        self.assertEqual(witness.git(source, "rev-parse", predecessor + "^{tree}")
                         .decode().strip(), "fb3a3c1e8713aae3a6e500a756ddecc37d97d8b9")
        old = witness.git(source, "show", predecessor + ":maintenance/witness.py")
        self.assertIn(b'HEAD = "ab2c511a38def0e7721492ac1213e845133c6840"', old)
        with self.assertRaisesRegex(witness.Rejected, "finite identity substitution"):
            witness.verify(self.base, self.candidate,
                           "ab2c511a38def0e7721492ac1213e845133c6840",
                           "f8e879cc5aa4aa393f198f4e082d73162a4ef68f",
                           "5c7922d626e5835da606a65c6dd9658352afc29c")

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
        for step in (steps[3], steps[5]):
            self.assertEqual(step, old_steps[step["name"]])
        expected_audit = copy.deepcopy(old_steps[steps[8]["name"]])
        expected_audit["run"] = expected_audit["run"].replace(
            "-r protected/requirements-audit.lock", "-r candidate/requirements-audit.lock")
        expected_audit["run"] += (
            " .\\audit-env\\Scripts\\python.exe -m pip_audit --local\n".lstrip()
            + "if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }\n")
        self.assertEqual(steps[8], expected_audit)
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


    def test_s1_predecessor_source_and_historical_tuple(self):
        source = Path(__file__).resolve().parent.parent
        old = "21b5fa56b25d20b686be22445d06759e5e467458"
        self.assertEqual(witness.git(source, "rev-parse", old + "^{tree}").decode().strip(),
                         "057afc086b63eefbae3627118eeb33006b693e72")
        self.assertIn(b'a2ec12753af1634db4136dcb83820fa9351540b8',
                      witness.git(source, "show", old + ":maintenance/witness.py"))
        with self.assertRaises(witness.Rejected):
            witness.verify(self.base, self.candidate,
                           "a2ec12753af1634db4136dcb83820fa9351540b8")

    def test_both_lock_mutations_rejected(self):
        for name in ("requirements-policy.lock", "requirements-audit.lock"):
            path = self.candidate / name
            original = path.read_bytes()
            try:
                path.write_bytes(original + b"# unauthorized\n")
                with self.assertRaises(witness.Rejected):
                    witness.verify(self.base, self.candidate)
            finally:
                path.write_bytes(original)

    def test_shallow_missing_history_and_file_mode_rejected(self):
        real = witness.git
        for failure in ("shallow", "history", "mode"):
            def changed(root, *args):
                if failure == "shallow" and args == ("rev-parse", "--is-shallow-repository"):
                    return b"true\n"
                if failure == "history" and args[:3] == ("-c", "core.commitGraph=false", "rev-list"):
                    raise subprocess.CalledProcessError(128, ["git", *args], stderr=b"missing object")
                result = real(root, *args)
                if failure == "mode" and args[:2] == ("ls-tree", "-rz"):
                    return result.replace(b"100644 blob", b"100755 blob", 1)
                return result
            with self.subTest(failure=failure), mock.patch.object(witness, "git", side_effect=changed):
                with self.assertRaises((witness.Rejected, subprocess.CalledProcessError)):
                    witness.clean_committed_root(self.candidate, witness.HEAD, witness.TARGET)

    def test_fixture_environment_separate_from_checkout(self):
        import yaml
        document = yaml.load((Path(__file__).resolve().parent.parent / witness.WORKFLOW).read_text(),
                             Loader=yaml.BaseLoader)
        steps = document["jobs"]["independent-maintenance"]["steps"]
        for step in steps[1:]:
            self.assertFalse(any(k.startswith("GIT_CONFIG") for k in step.get("env", {})))
        self.assertEqual(witness.ENV, {"PYTHONDONTWRITEBYTECODE": "1"})
        self.assertIn("run-policy candidate protected", steps[7]["run"])


    def test_s1_source_preserved_but_policy_subject_rejected(self):
        source = Path(__file__).resolve().parent.parent
        prior = "1dc2e670171825eb013e6f3797c9f1ded053c203"
        self.assertEqual(witness.git(source, "rev-parse", prior + "^{tree}").decode().strip(),
                         "38bf286427c4ec95c2040f65c10a12be079f3033")
        self.assertIn(b'HEAD = "ff87a7b9597255d37ddd2504de7af46408b5267c"',
                      witness.git(source, "show", prior + ":maintenance/witness.py"))
        with self.assertRaisesRegex(witness.Rejected, "finite identity substitution"):
            witness.verify(self.base, self.candidate,
                           "ff87a7b9597255d37ddd2504de7af46408b5267c",
                           "708e33a981ea7218208cae5a9da930ff19de5063",
                           "af7a95105466649a538734a16919a81705b5ad8f")

    def test_unchanged_audit_and_policy_locks_are_pinned(self):
        for field in ("AUDIT_LOCK", "POLICY_LOCK"):
            blob, digest = getattr(witness, field)
            for replacement in (("0" * 40, digest), (blob, "0" * 64)):
                with self.subTest(field=field, replacement=replacement), mock.patch.object(
                        witness, field, replacement), mock.patch.object(
                        witness, "clean_committed_root"), self.assertRaisesRegex(
                        witness.Rejected, "dependency"):
                    witness.verify(self.base, self.candidate)

    def test_test_only_successor_preserves_protected_bootstrap_and_locks(self):
        for relative in ("protected_policy_bootstrap.py", "requirements-policy.lock",
                         "requirements-audit.lock", ".github/workflows/security-workflows-policy.yml"):
            self.assertEqual(witness.git(self.base, "show", f"{witness.BASE}:{relative}"),
                             witness.git(self.candidate, "show", f"{witness.HEAD}:{relative}"))


    def test_merge_fixture_topology_and_attribution_fail_closed(self):
        revision = "1" * 40
        parents = f"{revision} {witness.BASE} {witness.HEAD}\n".encode()
        def fake(root, *args):
            if args == ("rev-list", "--parents", "-n", "1", revision):
                return parents
            if args == ("rev-parse", revision + "^{tree}"):
                return (witness.HEAD_TREE + "\n").encode()
            raise AssertionError(args)
        with mock.patch.object(witness, "clean_committed_root"), mock.patch.object(witness, "git", side_effect=fake):
            record = witness.verify_merge_fixture(self.candidate, revision, "SYNTHETIC_LOCAL_COMPATIBILITY")
            self.assertIs(record["protected_activation"], False)
            for kind in ("PROTECTED_ACTIVATION", "HOSTED_PASS", "", "OWNER_ACCEPTED"):
                with self.subTest(kind=kind), self.assertRaises(witness.Rejected):
                    witness.verify_merge_fixture(self.candidate, revision, kind)
            for value in (f"{revision} {witness.BASE}\n",
                          f"{revision} {'0' * 40} {witness.HEAD}\n",
                          f"{revision} {witness.BASE} {'0' * 40}\n",
                          f"{revision} {witness.HEAD} {witness.BASE}\n"):
                parents = value.encode()
                with self.subTest(parents=value), self.assertRaisesRegex(witness.Rejected, "merge parent"):
                    witness.verify_merge_fixture(self.candidate, revision, "SYNTHETIC_LOCAL_COMPATIBILITY")
            parents = f"{revision} {witness.BASE} {witness.HEAD}\n".encode()
            with mock.patch.object(witness, "HEAD_TREE", "0" * 40):
                # Keep the observed tree independent of the substituted expected tree.
                def wrong_tree(root, *args):
                    return parents if args[0] == "rev-list" else b"2" * 40 + b"\n"
                with mock.patch.object(witness, "git", side_effect=wrong_tree), self.assertRaisesRegex(witness.Rejected, "merge tree"):
                    witness.verify_merge_fixture(self.candidate, revision, "SYNTHETIC_LOCAL_COMPATIBILITY")


def run_merge_policy_checks(root: Path, protected: Path, names=None) -> None:
    """Exercise unchanged Stage A on a disposable, labelled merge fixture."""
    root = root.resolve(strict=True)
    protected = protected.resolve(strict=True)
    witness.verify(protected, root)
    witness.require(witness.git(protected, "rev-parse", "refs/remotes/origin/main")
                    .decode().strip() == witness.BASE, "protected origin/main mismatch")
    if names is None:
        names = ["test_protected_source_and_candidate_target_contract",
                 "test_stage_a_candidate_invariants"]
    witness.require(bool(names) and len(names) == len(set(names)) and set(names) <= {
        "test_protected_source_and_candidate_target_contract",
        "test_stage_a_candidate_invariants"}, "unknown compatibility test")
    with tempfile.TemporaryDirectory(prefix="s2-merge-") as directory:
        merge_root = Path(directory).resolve() / "evaluation"
        subprocess.run(["git", "-c", "core.autocrlf=false", "clone", "--quiet",
                        "--no-hardlinks", "--no-checkout", str(root), str(merge_root)], check=True)
        witness.git(merge_root, "remote", "set-url", "origin", "https://github.com/" + witness.TARGET)
        fixture_env = {**os.environ,
                       "GIT_AUTHOR_NAME": "Synthetic compatibility fixture",
                       "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
                       "GIT_COMMITTER_NAME": "Synthetic compatibility fixture",
                       "GIT_COMMITTER_EMAIL": "fixture@example.invalid"}
        merge_sha = subprocess.check_output(
            ["git", "-C", str(merge_root), "commit-tree", witness.HEAD_TREE,
             "-p", witness.BASE, "-p", witness.HEAD],
            input=b"SYNTHETIC_LOCAL_COMPATIBILITY: not protected activation\n",
            env=fixture_env).decode().strip()
        witness.git(merge_root, "-c", "core.autocrlf=false", "checkout", "--detach", merge_sha)
        witness.separate_roots(root, protected, merge_root)
        record = witness.verify_merge_fixture(merge_root, merge_sha, "SYNTHETIC_LOCAL_COMPATIBILITY")
        print(json.dumps(record, sort_keys=True), flush=True)
        env = {**os.environ, **witness.ENV,
               "POLICY_CANDIDATE_ROOT": str(merge_root), "POLICY_PROTECTED_ROOT": str(protected),
               "POLICY_EXPECTED_REPOSITORY": witness.TARGET,
               "POLICY_EXPECTED_CANDIDATE_SHA": merge_sha,
               "POLICY_EXPECTED_BASE_REPOSITORY": witness.TARGET,
               "POLICY_EXPECTED_BASE_BRANCH": "main", "POLICY_EXPECTED_EVENT": "pull_request",
               "POLICY_EXPECTED_PROTECTED_SHA": witness.BASE}
        command = (
            "import sys,json,unittest;sys.path.insert(0,sys.argv[1]);"
            "import test_verify_security_workflows as t;"
            "names=json.loads(sys.argv[2]);"
            "s=unittest.TestSuite(t.RootPolicyTests(n) for n in names);"
            "r=unittest.TextTestRunner(verbosity=2,failfast=True).run(s);"
            "sys.exit(not(r.wasSuccessful() and r.testsRun==len(names) and not r.skipped))")
        subprocess.run([sys.executable, "-I", "-B", "-c", command, str(protected), json.dumps(names)],
                       env=env, check=True)
        witness.verify_merge_fixture(merge_root, merge_sha, "SYNTHETIC_LOCAL_COMPATIBILITY")
        witness.verify(protected, root)


def run_policy(root: Path, protected: Path) -> None:
    root = root.resolve(strict=True)
    for index in range(int(os.environ.get("GIT_CONFIG_COUNT", "0"))):
        witness.require(os.environ.get(f"GIT_CONFIG_KEY_{index}", "").lower()
                        not in {"core.autocrlf", "core.eol"}, "fixture normalization override")
    sys.path.insert(0, str(root))
    os.environ.update(witness.ENV)
    suite = unittest.defaultTestLoader.discover(str(root), pattern="test_verify_security_workflows.py")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    witness.require(result.wasSuccessful() and result.testsRun == 155, "policy suite incomplete/failed")
    witness.require({test.id() for test, _reason in result.skipped} == witness.ALLOWED_SKIPS,
                    "unexpected skip set")
    witness.require(len(result.skipped) == 2 and not result.expectedFailures
                    and not result.unexpectedSuccesses, "unexpected test disposition")
    protected = protected.resolve(strict=True)
    witness.verify(protected, root)
    run_merge_policy_checks(root, protected)
    print(json.dumps({"suite": "FULL_POLICY_AND_ADVERSARIAL", "run": result.testsRun,
                      "passed": result.testsRun - len(result.skipped), "authorized_skips": 2,
                      "result": "PASS"}, sort_keys=True))


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "run-policy":
        run_policy(Path(sys.argv[2]), Path(sys.argv[3]))
    else:
        unittest.main()
