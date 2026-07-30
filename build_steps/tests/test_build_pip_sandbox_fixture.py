from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
import unittest

from build_steps import build_pip_sandbox_fixture as fixture


def _canonical_json(payload: object) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _replace_env(workflow: str, name: str, value: str) -> str:
    pattern = rf'(^  {re.escape(name)}: ")[^"\n]+("$)'
    replaced, count = re.subn(
        pattern,
        rf"\g<1>{value}\g<2>",
        workflow,
        count=1,
        flags=re.MULTILINE,
    )
    if count != 1:
        raise AssertionError(f"could not replace {name}")
    return replaced


def _replace_embedded_payload(workflow: str, prefix: str, payload: object) -> bytes:
    canonical = _canonical_json(payload)
    encoded = base64.b64encode(canonical).decode("ascii")
    digest = hashlib.sha256(canonical).hexdigest()
    workflow = _replace_env(workflow, f"{prefix}_B64", encoded)
    workflow = _replace_env(workflow, f"{prefix}_DIGEST", digest)
    return workflow.encode("utf-8")


class PipSandboxFixtureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.pypi_raw = fixture._read(fixture.PYPI_SNAPSHOT)
        self.pypi = json.loads(self.pypi_raw)
        self.github_raw = fixture._read(fixture.GITHUB_SNAPSHOT)
        self.github = json.loads(self.github_raw)
        self.npm_review = fixture._read(fixture.NPM_REVIEW)
        self.workflow_raw = fixture._read(fixture.WORKFLOW_PATH)
        self.result = json.loads(fixture._read(fixture.SEED_RESULT))
        self.index = json.loads(fixture._read(fixture.SEED_INDEX))

    def test_accepts_reviewed_fixture_inputs(self) -> None:
        fixture._validate_pypi_snapshot(self.pypi, self.pypi_raw)
        fixture._validate_github_snapshot(self.github, self.github_raw)
        fixture._validate_npm_review(self.npm_review)
        fixture._validate_workflow(self.workflow_raw)
        fixture._validate_seed_results(self.result, self.index)

        catalog = fixture._catalog_payload()
        registries = catalog["records"][0]["registries"]
        self.assertFalse(registries["pip"]["exhaustive"])
        self.assertFalse(registries["npm"]["exhaustive"])
        self.assertEqual(registries["npm"]["evidence"][0]["source_kind"], "pypi_api")

    def test_rejects_archived_latest_version_mismatch(self) -> None:
        altered = copy.deepcopy(self.pypi)
        altered["info"]["version"] = "2.5.0"
        with self.assertRaisesRegex(SystemExit, "latest version"):
            fixture._validate_pypi_snapshot(altered, self.pypi_raw)

    def test_rejects_newer_stable_release_in_snapshot(self) -> None:
        altered = copy.deepcopy(self.pypi)
        altered["releases"]["2.5.2"] = []
        with self.assertRaisesRegex(SystemExit, "newer stable version"):
            fixture._validate_pypi_snapshot(altered, self.pypi_raw)

    def test_rejects_wrong_aarch64_wheel_hash(self) -> None:
        altered = copy.deepcopy(self.pypi)
        wheel = next(
            item
            for item in altered["releases"][fixture.BASELINE_VERSION]
            if item["url"] == fixture.WHEEL_URL
        )
        wheel["digests"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(SystemExit, "wheel identity"):
            fixture._validate_pypi_snapshot(altered, self.pypi_raw)

    def test_rejects_mutable_github_commit_locator(self) -> None:
        altered = copy.deepcopy(self.github)
        altered["url"] = "https://api.github.com/repos/numpy/numpy/commits/HEAD"
        with self.assertRaisesRegex(SystemExit, "immutable NumPy commit"):
            fixture._validate_github_snapshot(altered, self.github_raw)

    def test_rejects_modified_npm_manual_review(self) -> None:
        with self.assertRaisesRegex(SystemExit, "reviewed boundary"):
            fixture._validate_npm_review(self.npm_review + b"\nchanged\n")

    def test_rejects_noncanonical_smoke_plan(self) -> None:
        workflow = self.workflow_raw.decode("utf-8")
        plan = fixture._decode_embedded_payload(workflow, "SMOKE_PLAN")
        self.assertIsInstance(plan, dict)
        altered = copy.deepcopy(plan)
        altered["baseline_version"] = "2.5.0"
        mutated = _replace_embedded_payload(workflow, "SMOKE_PLAN", altered)
        with self.assertRaisesRegex(SystemExit, "trusted NumPy plan"):
            fixture._validate_workflow(mutated)

    def test_rejects_noncanonical_wheel_pin(self) -> None:
        workflow = self.workflow_raw.decode("utf-8")
        pins = fixture._decode_embedded_payload(workflow, "SMOKE_ARTIFACT_PINS")
        self.assertIsInstance(pins, list)
        altered = copy.deepcopy(pins)
        altered[0]["artifact_sha256"] = ["0" * 64]
        mutated = _replace_embedded_payload(workflow, "SMOKE_ARTIFACT_PINS", altered)
        with self.assertRaisesRegex(SystemExit, "exact AArch64 NumPy wheel"):
            fixture._validate_workflow(mutated)

    def test_rejects_dishonest_historical_counts(self) -> None:
        altered = copy.deepcopy(self.result)
        altered["tests"]["passed"] = 6
        altered["tests"]["skipped"] = 0
        with self.assertRaisesRegex(SystemExit, "honest 5/0/1"):
            fixture._validate_seed_results(altered, {"numpy": altered})

    def test_rejects_historical_test6_reported_as_passed(self) -> None:
        altered = copy.deepcopy(self.result)
        altered["tests"]["details"][5]["status"] = "passed"
        with self.assertRaisesRegex(SystemExit, "detail statuses"):
            fixture._validate_seed_results(altered, {"numpy": altered})

    def test_rejects_seed_index_drift(self) -> None:
        altered_index = copy.deepcopy(self.index)
        altered_index["numpy"]["run"]["attempt"] = "2"
        with self.assertRaisesRegex(SystemExit, "exactly consistent"):
            fixture._validate_seed_results(self.result, altered_index)

    def test_rejects_seed_without_legacy_label(self) -> None:
        altered = copy.deepcopy(self.result)
        del altered["metadata"]["evidence_kind"]
        with self.assertRaisesRegex(SystemExit, "explicitly labeled legacy"):
            fixture._validate_seed_results(altered, {"numpy": altered})


if __name__ == "__main__":
    unittest.main()
