"""Validation-job structure/provenance checks, not native guest evidence."""

import hashlib
import json
from pathlib import Path
import re
import subprocess
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[3]
WORKFLOW = ROOT / ".github/workflows/validate-package-onboarding.yml"
PROVENANCE = ROOT / ".github/scripts/tests/microvm_preparation_sources.json"
API_HELPER = ROOT / ".github/scripts/tests/firecracker_preboot_api_preparation.sh"
JOBS = {
    "libkrun": "libkrun-build-only",
    "microsandbox": "microsandbox-cli-only",
    "firecracker": "firecracker-preboot-only",
}


class MicrovmPreparationTests(unittest.TestCase):
    def setUp(self):
        self.workflow = yaml.load(WORKFLOW.read_text(), Loader=yaml.BaseLoader)
        self.sources = json.loads(PROVENANCE.read_text())["candidates"]

    def test_native_jobs_are_explicitly_not_guest_validation(self):
        self.assertEqual(self.workflow["permissions"], {"contents": "read"})
        for slug, key in JOBS.items():
            with self.subTest(slug=slug):
                job = self.workflow["jobs"][key]
                self.assertEqual(job["runs-on"], "ubuntu-24.04-arm")
                self.assertIn("no guest execution", job["name"])
                self.assertNotIn("outputs", job)
                self.assertNotIn("secrets", job)
                checkout = job["steps"][0]
                self.assertEqual(
                    checkout["uses"],
                    "actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
                )
                self.assertEqual(checkout["with"]["persist-credentials"], "false")
                for step in job["steps"]:
                    self.assertNotIn("continue-on-error", step)
                summary = job["steps"][-1]
                self.assertEqual(summary["if"], "always()")
                self.assertIn("guest boot and guest execution NOT tested", summary["run"])
                self.assertIn("job.status", summary["env"]["JOB_STATUS"])

    def test_install_and_version_scripts_match_recorded_candidate_bytes(self):
        for slug, key in JOBS.items():
            with self.subTest(slug=slug):
                candidate = self.sources[slug]
                self.assertRegex(candidate["candidate_commit"], r"^[0-9a-f]{40}$")
                job = self.workflow["jobs"][key]
                for name, value in candidate["candidate_env"].items():
                    self.assertEqual(job["env"][name], value)
                steps = {step["id"]: step for step in job["steps"] if "id" in step}
                for step_id, expected in candidate["copied_run_sha256"].items():
                    actual = hashlib.sha256(steps[step_id]["run"].encode()).hexdigest()
                    self.assertEqual(actual, expected, step_id)

    def test_new_steps_have_valid_shell_and_embedded_python_syntax(self):
        for key in JOBS.values():
            for step in self.workflow["jobs"][key]["steps"]:
                if "run" not in step:
                    continue
                shell = re.sub(r"\$\{\{.*?\}\}", "fixture", step["run"])
                result = subprocess.run(
                    ["/bin/bash", "-n"], input=shell, text=True, capture_output=True,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                for code in re.findall(r"<<'PY'\n(.*?)\nPY", shell, re.S):
                    compile(code, str(WORKFLOW), "exec")
        subprocess.run(["/bin/bash", "-n", str(API_HELPER)], check=True)

    def test_api_helper_is_exact_supplied_candidate_helper(self):
        self.assertEqual(
            hashlib.sha256(API_HELPER.read_bytes()).hexdigest(),
            self.sources["firecracker"]["api_helper_sha256"],
        )
        source = API_HELPER.read_text()
        self.assertIn("request GET /version 200", source)
        self.assertIn("request PUT /machine-config 400", source)
        self.assertIn("guest boot not tested", source)
        for forbidden in ("InstanceStart", "/boot-source", "/drives", "/actions"):
            self.assertNotIn(forbidden, source)

    def test_libkrun_probe_never_enters_a_vm(self):
        runs = "\n".join(
            step.get("run", "") for step in self.workflow["jobs"][JOBS["libkrun"]]["steps"]
        )
        self.assertIn("libkrun-header-check.c", runs)
        self.assertIn("krun_create_ctx()", runs)
        self.assertIn("ctypes.CDLL(str(path))", runs)
        self.assertNotIn("krun_start_enter(", runs)
        self.assertNotIn("libkrun_guest_smoke.sh", runs)

    def test_microsandbox_only_parses_cli_without_doctor_or_image_pull(self):
        steps = self.workflow["jobs"][JOBS["microsandbox"]]["steps"]
        runs = "\n".join(step.get("run", "") for step in steps)
        self.assertIn('"$MSB_PATH" run --help', runs)
        self.assertIn('"$MSB_PATH" rm --help', runs)
        for forbidden in ('"$MSB_PATH" doctor', '"$MSB_PATH" pull',
                          '"$MSB_PATH" create --name', "microsandbox_guest_smoke.sh"):
            self.assertNotIn(forbidden, runs)


if __name__ == "__main__":
    unittest.main()
