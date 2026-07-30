from __future__ import annotations

import base64
import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest
from collections.abc import Callable
from datetime import UTC, date, datetime
from pathlib import Path

import yaml

from build_steps.validate_pip_sandbox_candidate import (
    CandidateValidationError,
    _TRUSTED_SANDBOX_PACKAGE_IDENTITIES,
    _approved_import_root,
    _candidate_workflow_identity,
    _normalized_package_template,
    _trusted_pypi_boundary,
    _yaml,
)
from build_steps.validate_pip_sandbox_candidate import (
    validate as validate_candidate,
)

CHECKOUT = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
UPLOAD = "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
REQUEST_ID = "request-1"
RUN_ID = 12345
RUN_ATTEMPT = 1
IMAGE_DIGEST = "sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90"
TRUSTED_SOURCE_REVISION = "a" * 40
TRUSTED_VERIFIED_AT = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)
TRUSTED_MINIMUM_RELEASE_DATE = date(2021, 7, 17)
AUTOMATION_IDENTITY = "ecosystem-package-onboarding/package-identity-catalog@1.1"
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _encoded_parent_segment(levels: int) -> str:
    value = "%2e%2e"
    for _ in range(levels - 1):
        value = value.replace("%", "%25")
    return value


def _write(root: Path, relative: str, payload: bytes | str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload.encode() if isinstance(payload, str) else payload)


def validate(base: Path, candidate: Path) -> None:
    validate_candidate(
        base,
        candidate,
        expected_source_revision=TRUSTED_SOURCE_REVISION,
        expected_verified_at=TRUSTED_VERIFIED_AT,
    )


def _catalog_record(slug: str, page: bytes, workflow: bytes) -> dict[str, object]:
    common_evidence = {
        "evidence_sha256": _sha(workflow),
        "source_kind": "generated_workflow",
        "source_locator": f".github/workflows/test-{slug}.yml",
        "source_revision": TRUSTED_SOURCE_REVISION,
        "verified_at": TRUSTED_VERIFIED_AT.isoformat(),
        "verified_by": AUTOMATION_IDENTITY,
    }
    pip_evidence = {
        **common_evidence,
        "rationale": (
            f"Canonical generated workflow binds pip:{slug} to this package entry."
        ),
    }
    npm_evidence = {
        **common_evidence,
        "rationale": (
            "Canonical generated workflow selects pip; whether this package also "
            "has npm identities remains unknown."
        ),
    }
    return {
        "content_path": f"content/linux/opensource_packages/{slug}.md",
        "content_sha256": _sha(page),
        "registries": {
            "npm": {
                "evidence": [npm_evidence],
                "exhaustive": False,
                "identities": [],
                "status": "unknown",
            },
            "pip": {
                "evidence": [pip_evidence],
                "exhaustive": False,
                "identities": [slug],
                "status": "verified",
            },
        },
        "slug": slug,
        "workflow": {
            "path": f".github/workflows/test-{slug}.yml",
            "presence": "present",
            "sha256": _sha(workflow),
        },
    }


def _catalog(records: list[dict[str, object]]) -> bytes:
    return (
        json.dumps(
            {
                "corpus": {
                    "content_root": "content/linux/opensource_packages",
                    "corpus_sha256": "0" * 64,
                    "entry_count": len(records),
                },
                "records": records,
                "schema_version": "1.1",
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode()


def _ninja_page(
    *,
    name: str = "Ninja",
    download_url: str = (
        "https://github.com/scikit-build/ninja-python-distributions/releases"
    ),
    minimum_version: str = "1.10.0.post3",
) -> bytes:
    return f"""---
name: {name}
category: Compilers/Tools
description: Ninja is a small build system used by this bounded Arm64 sandbox.
download_url: {download_url}
works_on_arm: true
supported_minimum_version:
  version_number: {minimum_version}
  release_date: 2021/07/17
  support_scope: pypi_binary_distribution
optional_info:
  homepage_url: https://github.com/scikit-build/ninja-python-distributions
  support_caveats: This minimum identifies the earliest stable, non-yanked PyPI release in the complete registry history that publishes a manylinux or musllinux AArch64 wheel. It does not claim that earlier source builds, prereleases, yanked files, or other installation paths were incompatible with Arm.
  alternative_options:
  getting_started_resources:
    official_docs: https://pypi.org/project/ninja/
    arm_content:
    partner_content:
  arm_recommended_minimum_version:
    version_number:
    release_date:
    reference_content:
    rationale:
optional_hidden_info:
  release_notes__supported_minimum: https://github.com/scikit-build/ninja-python-distributions/releases/tag/{minimum_version}
  release_notes__recommended_minimum:
  other_info: Bounded sandbox evidence; human review remains required.
---
""".encode()


def _package_workflow(slug: str) -> bytes:
    package_name = {"numpy": "NumPy", "ninja": "Ninja"}.get(
        slug,
        slug.replace("-", " ").title(),
    )
    repository = {
        "ninja": "https://github.com/scikit-build/ninja-python-distributions",
    }.get(slug, f"https://github.com/{slug}/{slug}")
    baseline_version = "1.10.0.post3"
    candidate_version = "1.13.0"
    plan = {
        "baseline_version": baseline_version,
        "evidence_urls": [
            f"https://pypi.org/pypi/{slug}/json",
            repository,
        ],
        "functional_probe": {
            "assertions": [
                {"expected": 0, "kind": "exit_code"},
                {
                    "case_sensitive": True,
                    "kind": "output_contains",
                    "value": f"import_ok:{slug}",
                },
            ],
            "invocation": {
                "arguments": ["smoke_import.py"],
                "program": "python3",
                "timeout_seconds": 60,
            },
        },
        "recipe": {
            "distribution": slug,
            "import_module": slug,
            "kind": "pip",
        },
        "regression_policy": {
            "candidate_version": candidate_version,
            "deferral_decision": None,
            "mode": "strict",
            "rationale": "A newer stable release is available for native validation.",
        },
        "schema_version": "1.0",
        "version_probe": {
            "arguments": ["smoke_version.py"],
            "program": "python3",
            "timeout_seconds": 30,
        },
    }
    pins = (
        _reviewed_ninja_pins()
        if slug == "ninja"
        else [
            {
                "artifacts": [
                    {
                        "filename": (
                            f"{slug}-{version}-py3-none-manylinux2014_aarch64.whl"
                        ),
                        "integrity": None,
                        "sha256": digest * 64,
                        "url": (
                            "https://files.pythonhosted.org/packages/aa/bb/"
                            f"{slug}-{version}-py3-none-manylinux2014_aarch64.whl"
                        ),
                    }
                ],
                "binary_only": True,
                "recipe_kind": "pip",
                "schema_version": "1.2",
                "version": version,
            }
            for version, digest in (
                (baseline_version, "a"),
                (candidate_version, "b"),
            )
        ]
    )

    def encoded(payload: object) -> tuple[str, str]:
        raw = json.dumps(
            payload,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        return base64.b64encode(raw).decode(), _sha(raw)

    encoded_plan, plan_digest = encoded(plan)
    encoded_pins, pins_digest = encoded(pins)
    output_names = (
        "contract_version",
        "package_slug",
        "package_name",
        "package_version",
        "run_status",
        "badge_status",
        "core_failed",
        "tests_passed",
        "tests_failed",
        "tests_skipped",
        "duration_seconds",
        "regression_status",
        "regression_decision",
        "regression_result",
        "regression_comparison",
        "regression_current_version",
        "regression_latest_version",
        "regression_next_installed_version",
        "regression_policy",
        "run_id",
        "run_attempt",
        "job_name",
        "dashboard_link",
        "timestamp",
    )
    call_outputs = "\n".join(
        f"      {name}:\n"
        f"        description: {name}\n"
        f"        value: ${{{{ jobs.test-{slug}.outputs.{name} }}}}"
        for name in output_names
    )
    dynamic_outputs = {
        "contract_version": '"2.0"',
        "dashboard_link": f"/opensource_packages/{slug}",
        "package_name": package_name,
        "package_slug": slug,
        "package_version": baseline_version,
        "regression_current_version": baseline_version,
        "regression_latest_version": (
            f'"${{{{ steps.test6.outputs.regression_latest_version || '
            f"'{candidate_version}' }}}}\""
        ),
        "regression_policy": "strict",
    }
    job_outputs = "\n".join(
        f"      {name}: {dynamic_outputs.get(name, 'value')}" for name in output_names
    )
    tests = "\n".join(
        f"      - name: Test {number} - Canonical bounded probe\n"
        f"        id: test{number}\n"
        f"        if: always()\n"
        f"        shell: bash\n"
        f"        run: |\n"
        f"          set -euo pipefail\n"
        f"          /usr/bin/timeout --signal=TERM --kill-after=10s "
        f"{900 if number == 6 else 600}s "
        f'/usr/bin/python3 "$SMOKE_HARNESS" {number} "$GITHUB_OUTPUT"'
        for number in range(1, 7)
    )
    return f"""name: Test {slug} on Arm64
permissions:
  contents: read
on:
  workflow_dispatch:
  workflow_call:
    outputs:
{call_outputs}
env:
  SMOKE_PACKAGE_SLUG: "{slug}"
  SMOKE_PACKAGE_NAME_B64: "{base64.b64encode(package_name.encode()).decode()}"
  SMOKE_PACKAGE_REPOSITORY: "{repository}"
  SMOKE_ARTIFACT_PINS_B64: "{encoded_pins}"
  SMOKE_ARTIFACT_PINS_DIGEST: "{pins_digest}"
  SMOKE_PLAN_B64: "{encoded_plan}"
  SMOKE_PLAN_DIGEST: "{plan_digest}"
jobs:
  test-{slug}:
    runs-on: ubuntu-24.04-arm
    timeout-minutes: 45
    permissions:
      contents: read
    outputs:
{job_outputs}
    steps:
      - uses: {CHECKOUT}
        with:
          persist-credentials: false
      - name: Prepare trusted bounded smoke executor
        id: prepare
        shell: bash
        run: |
          set -euo pipefail
          cat > "$RUNNER_TEMP/smoke.py" <<'PY'
          DOCKER = "/usr/bin/docker"
          IMAGE = "docker.io/library/ubuntu@{IMAGE_DIGEST}"
          OPTIONS = ["--read-only", "--network", "none", "--cap-drop", "ALL", "no-new-privileges"]
          PY
{tests}
      - name: Emit canonical six-test result
        id: summary
        if: always()
        uses: ./.github/actions/emit-package-result
      - name: Enforce strict smoke-test result
        id: enforce
        if: always()
        shell: bash
        run: |
          set -euo pipefail
          test "${{{{ steps.summary.outputs.should_fail }}}}" = "0"
""".encode()


def _reviewed_ninja_pins() -> list[dict[str, object]]:
    workflow_path = REPOSITORY_ROOT / "build_steps/fixtures/test-ninja.yml"
    workflow = _yaml(workflow_path.read_bytes(), str(workflow_path))
    environment = workflow.get("env")
    if not isinstance(environment, dict):
        raise AssertionError("reviewed Ninja workflow lacks an environment")
    encoded = environment.get("SMOKE_ARTIFACT_PINS_B64")
    if not isinstance(encoded, str):
        raise AssertionError("reviewed Ninja workflow lacks artifact pins")
    decoded = json.loads(base64.b64decode(encoded, validate=True))
    if not isinstance(decoded, list) or not all(
        isinstance(item, dict) for item in decoded
    ):
        raise AssertionError("reviewed Ninja workflow has malformed artifact pins")
    return decoded


def _set_single_artifact_url(pin: dict[str, object], url: str) -> None:
    artifacts = pin["artifacts"]
    assert isinstance(artifacts, list) and artifacts
    first = artifacts[0]
    assert isinstance(first, dict)
    replacement = dict(first)
    replacement["filename"] = url.rsplit("/", 1)[-1]
    replacement["url"] = url
    pin["artifacts"] = [replacement]


def _batch(slugs: list[str]) -> str:
    jobs = "\n".join(
        f"  test-{slug}:\n    uses: ./.github/workflows/test-{slug}.yml\n"
        for slug in slugs
    )
    needs = "\n".join(
        f"        test-{slug}{',' if index < len(slugs) - 1 else ''}"
        for index, slug in enumerate(slugs)
    )
    return f"""name: Test All Packages (Batch 1) on Arm64
on:
  workflow_dispatch:
  workflow_call:
permissions:
  contents: read
jobs:
{jobs}
  summary:
    permissions:
      actions: read
      contents: read
    needs:
      [
{needs}
      ]
    runs-on: ubuntu-24.04-arm
    steps:
      - uses: {CHECKOUT}
        with:
          persist-credentials: false
      - name: Collect batch results
        id: collect
        uses: ./.github/actions/collect-batch-results
      - name: Attest complete batch results
        id: attest
        if: steps.collect.outcome == 'success'
        run: |
          set -euo pipefail
          python3 .github/scripts/batch_artifact_attestation.py create
      - name: Upload batch test results
        if: steps.collect.outcome == 'success' && steps.attest.outcome == 'success'
        uses: {UPLOAD}
"""


def _evidence_outputs(slug: str) -> dict[str, object]:
    return {
        "contract_version": "2.0",
        "package_slug": slug,
        "package_name": "Ninja",
        "package_version": "1.10.0.post3",
        "run_status": "success",
        "badge_status": "passing",
        "core_failed": "0",
        "tests_passed": "6",
        "tests_failed": "0",
        "tests_skipped": "0",
        "duration_seconds": "42",
        "regression_status": "passed",
        "regression_decision": "candidate_passed",
        "regression_result": "Candidate passed the bounded probe.",
        "regression_comparison": "Baseline and candidate passed the same probe.",
        "regression_current_version": "1.10.0.post3",
        "regression_latest_version": "1.13.0",
        "regression_next_installed_version": "1.13.0",
        "regression_policy": "applicable",
        "run_id": str(RUN_ID),
        "run_attempt": str(RUN_ATTEMPT),
        "job_name": "Native Arm64 smoke validation",
        "dashboard_link": f"/opensource_packages/{slug}",
        "timestamp": "2026-07-29T12:00:00Z",
    }


def _add_native_evidence(
    candidate: Path,
    *,
    mutate_request: Callable[[dict[str, object]], None] | None = None,
    mutate_report: Callable[[dict[str, object]], None] | None = None,
) -> Path:
    slug = "ninja"
    page = candidate / f"content/linux/opensource_packages/{slug}.md"
    workflow = candidate / f".github/workflows/test-{slug}.yml"
    request: dict[str, object] = {
        "schema_version": "1.0",
        "request_id": REQUEST_ID,
        "package_slug": slug,
        "candidate_sha256": _sha(page.read_bytes()),
        "workflow_path": f".github/workflows/test-{slug}.yml",
        "workflow_sha256": _sha(workflow.read_bytes()),
    }
    if mutate_request is not None:
        mutate_request(request)
    request_bytes = (
        json.dumps(request, indent=2, sort_keys=True, separators=(",", ": ")) + "\n"
    ).encode()
    report: dict[str, object] = {
        **request,
        "request_sha256": _sha(request_bytes),
        "run_id": RUN_ID,
        "run_attempt": RUN_ATTEMPT,
        "runner": {
            "label": "ubuntu-24.04-arm",
            "architecture": "aarch64",
            "environment": "github-hosted",
        },
        "status": "completed",
        "conclusion": "success",
        "tests": [{"number": number, "status": "passed"} for number in range(1, 7)],
        "outputs": _evidence_outputs(slug),
    }
    if mutate_report is not None:
        mutate_report(report)
    report_bytes = (
        json.dumps(report, indent=2, sort_keys=True, separators=(",", ": ")) + "\n"
    ).encode()
    directory = candidate / ".arm-validation-evidence" / REQUEST_ID
    directory.mkdir(parents=True)
    (directory / "request.json").write_bytes(request_bytes)
    (directory / "report.json").write_bytes(report_bytes)
    (directory / "SHA256SUMS").write_text(
        f"{_sha(request_bytes)}  request.json\n{_sha(report_bytes)}  report.json\n"
    )
    return directory


class CandidateValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.base = root / "base"
        self.candidate = root / "candidate"
        self.base.mkdir()

        numpy_page = (
            b"---\nname: NumPy\n"
            b"download_url: https://github.com/numpy/numpy/releases\n---\n"
        )
        numpy_workflow = _package_workflow("numpy")
        _write(self.base, "content/linux/opensource_packages/_index.md", "index\n")
        _write(
            self.base,
            "content/linux/opensource_packages/numpy.md",
            numpy_page,
        )
        _write(self.base, ".github/workflows/test-numpy.yml", numpy_workflow)
        _write(
            self.base,
            ".github/workflows/test-all-packages-batch1.yml",
            _batch(["numpy"]),
        )
        _write(
            self.base,
            ".github/package-identity-catalog.json",
            _catalog([_catalog_record("numpy", numpy_page, numpy_workflow)]),
        )
        _write(self.base, ".github/actions/control/action.yml", "name: control\n")
        _write(self.base, ".github/actions/service/action.yml", "name: service\n")
        _write(self.base, ".github/evidence/seed.json", "{}\n")
        ninja_snapshot = (
            REPOSITORY_ROOT / ".github/catalog-evidence/ninja/pypi.json"
        ).read_bytes()
        _write(
            self.base,
            ".github/catalog-evidence/ninja/pypi.json",
            ninja_snapshot,
        )

        manifest = {
            "evidence": {
                ".github/evidence/seed.json": _sha(b"{}\n"),
                ".github/catalog-evidence/ninja/pypi.json": _sha(ninja_snapshot),
            },
            "fixture_control_files": {
                ".github/actions/control/action.yml": _sha(b"name: control\n"),
            },
            "service_support_files": {
                ".github/actions/service/action.yml": _sha(b"name: service\n"),
            },
            "source_files": {
                ".github/actions/control/action.yml": _sha(b"name: control\n"),
                ".github/workflows/test-numpy.yml": _sha(numpy_workflow),
                "content/linux/opensource_packages/numpy.md": _sha(numpy_page),
            },
        }
        _write(
            self.base,
            ".github/fixture-manifest.json",
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        )
        shutil.copytree(self.base, self.candidate)

        ninja_page = _ninja_page()
        ninja_workflow = _package_workflow("ninja")
        _write(
            self.candidate,
            "content/linux/opensource_packages/ninja.md",
            ninja_page,
        )
        _write(
            self.candidate,
            ".github/workflows/test-ninja.yml",
            ninja_workflow,
        )
        _write(
            self.candidate,
            ".github/workflows/test-all-packages-batch1.yml",
            _batch(["numpy", "ninja"]),
        )
        _write(
            self.candidate,
            ".github/package-identity-catalog.json",
            _catalog(
                [
                    _catalog_record("numpy", numpy_page, numpy_workflow),
                    _catalog_record("ninja", ninja_page, ninja_workflow),
                ]
            ),
        )

    def _replace_candidate_workflow(self, old: str, new: str) -> None:
        workflow_path = self.candidate / ".github/workflows/test-ninja.yml"
        workflow = workflow_path.read_text().replace(old, new)
        self._write_candidate_workflow(workflow)

    def _write_candidate_workflow(self, workflow: str) -> None:
        workflow_path = self.candidate / ".github/workflows/test-ninja.yml"
        workflow_path.write_text(workflow)
        catalog_path = self.candidate / ".github/package-identity-catalog.json"
        catalog = json.loads(catalog_path.read_text())
        record = next(item for item in catalog["records"] if item["slug"] == "ninja")
        workflow_digest = _sha(workflow.encode())
        record["workflow"]["sha256"] = workflow_digest
        record["registries"]["pip"]["evidence"][0]["evidence_sha256"] = workflow_digest
        record["registries"]["npm"]["evidence"][0]["evidence_sha256"] = workflow_digest
        catalog_path.write_text(json.dumps(catalog, indent=2, sort_keys=True) + "\n")

    def _write_candidate_page(self, page: bytes) -> None:
        page_path = self.candidate / "content/linux/opensource_packages/ninja.md"
        page_path.write_bytes(page)
        catalog_path = self.candidate / ".github/package-identity-catalog.json"
        catalog = json.loads(catalog_path.read_text())
        record = next(item for item in catalog["records"] if item["slug"] == "ninja")
        record["content_sha256"] = _sha(page)
        catalog_path.write_text(json.dumps(catalog, indent=2, sort_keys=True) + "\n")

    def _mutate_candidate_plan(
        self,
        mutate_plan: Callable[[dict[str, object]], None],
        *,
        mutate_pins: Callable[[list[dict[str, object]]], None] | None = None,
        repository: str | None = None,
    ) -> None:
        workflow_path = self.candidate / ".github/workflows/test-ninja.yml"
        workflow = _yaml(workflow_path.read_bytes(), "candidate test workflow")
        environment = workflow["env"]
        plan = json.loads(base64.b64decode(environment["SMOKE_PLAN_B64"]))
        pins = json.loads(base64.b64decode(environment["SMOKE_ARTIFACT_PINS_B64"]))
        mutate_plan(plan)
        if mutate_pins is not None:
            mutate_pins(pins)

        def encode(payload: object) -> tuple[str, str]:
            raw = json.dumps(
                payload,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
            return base64.b64encode(raw).decode(), _sha(raw)

        plan_b64, plan_digest = encode(plan)
        pins_b64, pins_digest = encode(pins)
        environment["SMOKE_PLAN_B64"] = plan_b64
        environment["SMOKE_PLAN_DIGEST"] = plan_digest
        environment["SMOKE_ARTIFACT_PINS_B64"] = pins_b64
        environment["SMOKE_ARTIFACT_PINS_DIGEST"] = pins_digest
        if repository is not None:
            environment["SMOKE_PACKAGE_REPOSITORY"] = repository
        rendered = yaml.safe_dump(
            workflow,
            allow_unicode=False,
            sort_keys=False,
            width=10_000,
        )
        self._write_candidate_workflow(rendered)

    def test_accepts_one_exact_candidate(self) -> None:
        validate(self.base, self.candidate)

    def test_rejects_candidate_without_binary_only_artifact_policy(self) -> None:
        def mutate_pins(pins: list[dict[str, object]]) -> None:
            for pin in pins:
                pin["binary_only"] = False

        self._mutate_candidate_plan(lambda plan: None, mutate_pins=mutate_pins)
        with self.assertRaisesRegex(
            CandidateValidationError,
            "requires binary-only artifact pins",
        ):
            validate(self.base, self.candidate)

    def test_rejects_binary_only_non_arm64_wheel(self) -> None:
        def mutate_pins(pins: list[dict[str, object]]) -> None:
            _set_single_artifact_url(
                pins[1],
                "https://files.pythonhosted.org/packages/aa/bb/"
                "ninja-1.13.0-py3-none-any.whl",
            )

        self._mutate_candidate_plan(lambda plan: None, mutate_pins=mutate_pins)
        with self.assertRaisesRegex(
            CandidateValidationError,
            "not a Linux Arm64 wheel",
        ):
            validate(self.base, self.candidate)

    def test_rejects_artifact_digest_not_in_protected_snapshot(self) -> None:
        def mutate_pins(pins: list[dict[str, object]]) -> None:
            artifacts = pins[0]["artifacts"]
            assert isinstance(artifacts, list) and artifacts
            artifact = artifacts[0]
            assert isinstance(artifact, dict)
            artifact["sha256"] = "0" * 64

        self._mutate_candidate_plan(lambda plan: None, mutate_pins=mutate_pins)

        with self.assertRaisesRegex(
            CandidateValidationError,
            "artifact pins do not match the reviewed PyPI snapshot",
        ):
            validate(self.base, self.candidate)

    def test_rejects_unreviewed_newer_candidate_version(self) -> None:
        def mutate(plan: dict[str, object]) -> None:
            regression = plan["regression_policy"]
            assert isinstance(regression, dict)
            regression["candidate_version"] = "1.14.0"

        def mutate_pins(pins: list[dict[str, object]]) -> None:
            pins[1]["version"] = "1.14.0"
            _set_single_artifact_url(
                pins[1],
                "https://files.pythonhosted.org/packages/aa/bb/"
                "ninja-1.14.0-py3-none-manylinux2014_aarch64.whl",
            )

        self._mutate_candidate_plan(mutate, mutate_pins=mutate_pins)
        with self.assertRaisesRegex(
            CandidateValidationError,
            "trusted sandbox package identity",
        ):
            validate(self.base, self.candidate)

    def test_derives_catalog_provenance_from_trusted_base_commit(self) -> None:
        git = shutil.which("git")
        if git is None:
            self.skipTest("Git is required for trusted provenance derivation")
        environment = {
            "GIT_AUTHOR_DATE": "2026-07-29T12:00:00+00:00",
            "GIT_COMMITTER_DATE": "2026-07-29T12:00:00+00:00",
        }

        def run_git(*arguments: str) -> str:
            completed = subprocess.run(
                [
                    git,
                    "-c",
                    "user.name=Fixture",
                    "-c",
                    "user.email=fixture@example.invalid",
                    "-C",
                    str(self.base),
                    *arguments,
                ],
                check=True,
                capture_output=True,
                text=True,
                env=environment,
            )
            return completed.stdout.strip()

        run_git("init", "-q", "-b", "main")
        run_git("add", "-A")
        run_git("commit", "-q", "-m", "trusted fixture base")
        source_revision = run_git("rev-parse", "--verify", "HEAD^{commit}")
        verified_at = run_git("show", "-s", "--format=%cI", source_revision)

        catalog_path = self.candidate / ".github/package-identity-catalog.json"
        catalog = json.loads(catalog_path.read_text())
        record = next(item for item in catalog["records"] if item["slug"] == "ninja")
        for dimension in ("pip", "npm"):
            evidence = record["registries"][dimension]["evidence"][0]
            evidence["source_revision"] = source_revision
            evidence["verified_at"] = verified_at
        catalog_path.write_text(json.dumps(catalog, indent=2, sort_keys=True) + "\n")

        validate_candidate(self.base, self.candidate)

    def test_trusted_import_mapping_includes_reviewed_aliases(self) -> None:
        self.assertTrue(_approved_import_root("beautifulsoup4", "bs4"))
        self.assertTrue(_approved_import_root("scikit-learn", "sklearn"))
        self.assertTrue(_approved_import_root("Pillow", "PIL"))
        self.assertFalse(_approved_import_root("unreviewed-distribution", "json"))

    def test_rejects_mislabeled_package_identity(self) -> None:
        def mutate(plan: dict[str, object]) -> None:
            recipe = plan["recipe"]
            assert isinstance(recipe, dict)
            recipe["distribution"] = "beautifulsoup4"
            recipe["import_module"] = "bs4"
            plan["evidence_urls"] = [
                "https://pypi.org/pypi/beautifulsoup4/json",
                "https://github.com/wention/BeautifulSoup4",
            ]
            functional = plan["functional_probe"]
            assert isinstance(functional, dict)
            assertions = functional["assertions"]
            assert isinstance(assertions, list)
            marker = next(
                assertion
                for assertion in assertions
                if isinstance(assertion, dict)
                and assertion.get("kind") == "output_contains"
            )
            marker["value"] = "import_ok:bs4"

        def mutate_pins(pins: list[dict[str, object]]) -> None:
            for pin in pins:
                version = pin["version"]
                _set_single_artifact_url(
                    pin,
                    "https://files.pythonhosted.org/packages/aa/bb/"
                    f"beautifulsoup4-{version}-py3-none-manylinux2014_aarch64.whl",
                )

        self._mutate_candidate_plan(
            mutate,
            mutate_pins=mutate_pins,
            repository="https://github.com/wention/BeautifulSoup4",
        )
        page_path = self.candidate / "content/linux/opensource_packages/ninja.md"
        page_path.write_bytes(
            _ninja_page(
                download_url="https://github.com/wention/BeautifulSoup4/releases"
            )
        )
        catalog_path = self.candidate / ".github/package-identity-catalog.json"
        catalog = json.loads(catalog_path.read_text())
        record = next(item for item in catalog["records"] if item["slug"] == "ninja")
        record["content_sha256"] = _sha(page_path.read_bytes())
        record["registries"]["pip"]["identities"] = ["beautifulsoup4"]
        record["registries"]["pip"]["evidence"][0]["rationale"] = (
            "Canonical generated workflow binds pip:beautifulsoup4 to this package entry."
        )
        catalog_path.write_text(json.dumps(catalog, indent=2, sort_keys=True) + "\n")

        with self.assertRaisesRegex(
            CandidateValidationError,
            "trusted sandbox package identity",
        ):
            validate(self.base, self.candidate)

    def test_rejects_regression_candidate_older_than_baseline(self) -> None:
        def mutate(plan: dict[str, object]) -> None:
            regression = plan["regression_policy"]
            assert isinstance(regression, dict)
            regression["candidate_version"] = "0.9.0"

        def mutate_pins(pins: list[dict[str, object]]) -> None:
            pins[1]["version"] = "0.9.0"
            _set_single_artifact_url(
                pins[1],
                "https://files.pythonhosted.org/packages/aa/bb/"
                "ninja-0.9.0-py3-none-manylinux2014_aarch64.whl",
            )

        self._mutate_candidate_plan(mutate, mutate_pins=mutate_pins)
        with self.assertRaisesRegex(
            CandidateValidationError,
            "candidate is not newer than baseline",
        ):
            validate(self.base, self.candidate)

    def test_rejects_nonstable_regression_candidate(self) -> None:
        def mutate(plan: dict[str, object]) -> None:
            regression = plan["regression_policy"]
            assert isinstance(regression, dict)
            regression["candidate_version"] = "1.13.0rc1"

        def mutate_pins(pins: list[dict[str, object]]) -> None:
            pins[1]["version"] = "1.13.0rc1"
            _set_single_artifact_url(
                pins[1],
                "https://files.pythonhosted.org/packages/aa/bb/"
                "ninja-1.13.0rc1-py3-none-manylinux2014_aarch64.whl",
            )

        self._mutate_candidate_plan(mutate, mutate_pins=mutate_pins)
        with self.assertRaisesRegex(
            CandidateValidationError,
            "must identify a stable public release",
        ):
            validate(self.base, self.candidate)

    def test_rejects_artifact_filename_for_another_distribution(self) -> None:
        def mutate_pins(pins: list[dict[str, object]]) -> None:
            _set_single_artifact_url(
                pins[1],
                "https://files.pythonhosted.org/packages/aa/bb/"
                "numpy-1.13.0-py3-none-manylinux2014_aarch64.whl",
            )

        self._mutate_candidate_plan(lambda plan: None, mutate_pins=mutate_pins)
        with self.assertRaisesRegex(
            CandidateValidationError,
            "does not match its pip identity and version",
        ):
            validate(self.base, self.candidate)

    def test_rejects_untrusted_candidate_download_urls(self) -> None:
        catalog_path = self.candidate / ".github/package-identity-catalog.json"
        original_catalog = catalog_path.read_text()
        for download_url in (
            "javascript:alert(1)",
            "http://user:pass@pypi.org/project/ninja",
            "https://example.invalid/not-ninja",
            "https://github.com/numpy/numpy/releases",
            (
                "https://github.com/scikit-build/ninja-python-distributions/"
                "../../numpy/numpy"
            ),
            (
                "https://github.com/scikit-build/ninja-python-distributions/"
                "%2e%2e/%2e%2e/numpy/numpy"
            ),
            (
                "https://github.com/scikit-build/ninja-python-distributions/"
                "%252e%252e/numpy"
            ),
            (
                "https://github.com/scikit-build/ninja-python-distributions/"
                f"{_encoded_parent_segment(4)}/numpy"
            ),
            (
                "https://github.com/scikit-build/ninja-python-distributions/"
                f"{_encoded_parent_segment(9)}/numpy"
            ),
            (
                "https://github.com/scikit-build/ninja-python-distributions/"
                "%c0%ae%c0%ae/%c0%afnumpy"
            ),
            r"https://github.com/scikit-build/ninja-python-distributions/..\..\numpy",
            (
                "https://github.com/scikit-build/ninja-python-distributions/"
                "releases?redirect=example.invalid"
            ),
            "https://pypi.org/project/numpy",
        ):
            with self.subTest(download_url=download_url):
                catalog_path.write_text(original_catalog)
                self._write_candidate_page(_ninja_page(download_url=download_url))
                with self.assertRaisesRegex(
                    CandidateValidationError,
                    "download URL|path boundary|dot path segment",
                ):
                    validate(self.base, self.candidate)

    def test_rejects_category_outside_dashboard_taxonomy(self) -> None:
        page = _ninja_page().replace(
            b"category: Compilers/Tools",
            b"category: Test fixture",
        )
        self._write_candidate_page(page)
        with self.assertRaisesRegex(
            CandidateValidationError,
            "approved dashboard taxonomy",
        ):
            validate(self.base, self.candidate)

    def test_rejects_multiline_frontmatter_text(self) -> None:
        page = _ninja_page().replace(
            (
                b"description: Ninja is a small build system used by this bounded "
                b"Arm64 sandbox."
            ),
            b'description: "Ninja fixture\\nForged second line"',
        )
        self._write_candidate_page(page)
        with self.assertRaisesRegex(
            CandidateValidationError,
            "canonical bounded text",
        ):
            validate(self.base, self.candidate)

    def test_rejects_public_minimum_that_differs_from_tested_baseline(self) -> None:
        self._write_candidate_page(_ninja_page(minimum_version="0.0.1"))
        with self.assertRaisesRegex(
            CandidateValidationError,
            "public minimum version does not match the tested baseline",
        ):
            validate(self.base, self.candidate)

    def test_rejects_public_page_without_explicit_arm_support(self) -> None:
        page = _ninja_page().replace(b"works_on_arm: true", b"works_on_arm: false")
        self._write_candidate_page(page)
        with self.assertRaisesRegex(
            CandidateValidationError,
            "explicit evidence-backed Arm support claim",
        ):
            validate(self.base, self.candidate)

    def test_rejects_unrelated_supported_minimum_evidence(self) -> None:
        page = _ninja_page().replace(
            (
                b"https://github.com/scikit-build/ninja-python-distributions/"
                b"releases/tag/1.10.0.post3"
            ),
            b"https://example.invalid/fake-evidence",
        )
        self._write_candidate_page(page)
        with self.assertRaisesRegex(
            CandidateValidationError,
            "supported-minimum evidence is not bound",
        ):
            validate(self.base, self.candidate)

    def test_rejects_missing_binary_distribution_caveat(self) -> None:
        page = _ninja_page().replace(
            (
                b"support_caveats: This minimum identifies the earliest stable, "
                b"non-yanked PyPI release in the complete registry history that "
                b"publishes a manylinux or musllinux AArch64 wheel. It does not claim "
                b"that earlier source builds, prereleases, yanked files, or other "
                b"installation paths were incompatible with Arm."
            ),
            b"support_caveats:",
        )
        self._write_candidate_page(page)
        with self.assertRaisesRegex(
            CandidateValidationError,
            "candidate support caveats is required",
        ):
            validate(self.base, self.candidate)

    def test_rejects_broadened_binary_distribution_claim(self) -> None:
        page = _ninja_page().replace(
            (
                b"support_caveats: This minimum identifies the earliest stable, "
                b"non-yanked PyPI release in the complete registry history that "
                b"publishes a manylinux or musllinux AArch64 wheel. It does not claim "
                b"that earlier source builds, prereleases, yanked files, or other "
                b"installation paths were incompatible with Arm."
            ),
            b"support_caveats: This is the first version that supports Arm.",
        )
        self._write_candidate_page(page)
        with self.assertRaisesRegex(
            CandidateValidationError,
            "does not preserve the reviewed binary scope",
        ):
            validate(self.base, self.candidate)

    def test_rejects_broadened_support_scope(self) -> None:
        page = _ninja_page().replace(
            b"support_scope: pypi_binary_distribution",
            b"support_scope: general",
        )
        self._write_candidate_page(page)
        with self.assertRaisesRegex(
            CandidateValidationError,
            "does not preserve the reviewed binary boundary",
        ):
            validate(self.base, self.candidate)

    def test_rejects_nonexact_supported_minimum_evidence_url(self) -> None:
        page = _ninja_page().replace(
            (
                b"https://github.com/scikit-build/ninja-python-distributions/"
                b"releases/tag/1.10.0.post3"
            ),
            (
                b"https://github.com/scikit-build/ninja-python-distributions/"
                b"releases/tag/1.10.0.post3#files"
            ),
        )
        self._write_candidate_page(page)
        with self.assertRaisesRegex(
            CandidateValidationError,
            "supported-minimum evidence is not bound to the reviewed release",
        ):
            validate(self.base, self.candidate)

    def test_rejects_minimum_release_date_not_in_trusted_pypi_evidence(self) -> None:
        page = _ninja_page().replace(
            b"release_date: 2021/07/17", b"release_date: 2099/12/31", 1
        )
        self._write_candidate_page(page)
        with self.assertRaisesRegex(
            CandidateValidationError,
            "release date does not match trusted PyPI evidence",
        ):
            validate(self.base, self.candidate)

    def test_rejects_unrelated_official_documentation(self) -> None:
        page = _ninja_page().replace(
            b"official_docs: https://pypi.org/project/ninja/",
            b"official_docs: https://example.invalid/fake-docs",
        )
        self._write_candidate_page(page)
        with self.assertRaisesRegex(
            CandidateValidationError,
            "official documentation URL is not bound",
        ):
            validate(self.base, self.candidate)

    def test_rejects_non_arm_content_labelled_as_arm_guidance(self) -> None:
        page = _ninja_page().replace(
            b"    arm_content:\n",
            b"    arm_content: https://example.invalid/fake-arm-guide\n",
        )
        self._write_candidate_page(page)
        with self.assertRaisesRegex(
            CandidateValidationError,
            "not on an approved Arm-owned domain",
        ):
            validate(self.base, self.candidate)

    def test_rejects_unreviewed_arm_recommendation_claim(self) -> None:
        page = _ninja_page().replace(
            b"  arm_recommended_minimum_version:\n"
            b"    version_number:\n"
            b"    release_date:\n"
            b"    reference_content:\n"
            b"    rationale:\n",
            b"  arm_recommended_minimum_version:\n"
            b"    version_number: 999.0.0\n"
            b"    release_date: 2099/12/31\n"
            b"    reference_content: https://example.invalid/fake-arm-claim\n"
            b"    rationale: Arm recommends this unsupported version.\n",
        )
        self._write_candidate_page(page)
        with self.assertRaisesRegex(
            CandidateValidationError,
            "Arm recommendation requires a separately reviewed policy",
        ):
            validate(self.base, self.candidate)

    def test_rejects_dot_segment_repository_evidence(self) -> None:
        for suffix in (
            "../../numpy/numpy",
            "%2e%2e/%2e%2e/numpy/numpy",
            "%252e%252e/%252e%252e/numpy/numpy",
            f"{_encoded_parent_segment(4)}/numpy/numpy",
            f"{_encoded_parent_segment(9)}/numpy/numpy",
            "%c0%ae%c0%ae/%c0%afnumpy/numpy",
            r"..\..\numpy\numpy",
        ):
            with self.subTest(suffix=suffix):

                def mutate(
                    plan: dict[str, object],
                    suffix: str = suffix,
                ) -> None:
                    plan["evidence_urls"] = [
                        "https://pypi.org/pypi/ninja/json",
                        (
                            "https://github.com/scikit-build/"
                            f"ninja-python-distributions/{suffix}"
                        ),
                    ]

                self._mutate_candidate_plan(mutate)
                with self.assertRaisesRegex(
                    CandidateValidationError,
                    (
                        "dot path segment|encoded path boundary|noncanonical path|"
                        "does not stabilize|invalid UTF-8"
                    ),
                ):
                    validate(self.base, self.candidate)

    def test_rejects_dot_segment_registry_artifact(self) -> None:
        for suffix in (
            "../../outside",
            "%2e%2e/%2e%2e/outside",
            "%252e%252e/%252e%252e/outside",
            f"{_encoded_parent_segment(4)}/outside",
            f"{_encoded_parent_segment(9)}/outside",
            "%c0%ae%c0%ae/%c0%afoutside",
            r"..\..\outside",
        ):
            with self.subTest(suffix=suffix):

                def mutate_pins(
                    pins: list[dict[str, object]],
                    suffix: str = suffix,
                ) -> None:
                    _set_single_artifact_url(
                        pins[1],
                        f"https://files.pythonhosted.org/packages/{suffix}/"
                        "ninja-1.13.0-py3-none-manylinux2014_aarch64.whl",
                    )

                self._mutate_candidate_plan(
                    lambda plan: None,
                    mutate_pins=mutate_pins,
                )
                with self.assertRaisesRegex(
                    CandidateValidationError,
                    (
                        "dot path segment|encoded path boundary|noncanonical path|"
                        "does not stabilize|invalid UTF-8"
                    ),
                ):
                    validate(self.base, self.candidate)

    def test_accepts_protected_complete_pypi_boundary_snapshot(self) -> None:
        identity = _TRUSTED_SANDBOX_PACKAGE_IDENTITIES["ninja"]
        boundary = _trusted_pypi_boundary(REPOSITORY_ROOT, identity)

        self.assertEqual(
            boundary.minimum_release_date,
            TRUSTED_MINIMUM_RELEASE_DATE,
        )
        self.assertEqual(
            [version for version, _ in boundary.artifacts_by_version],
            ["1.10.0.post3", "1.13.0"],
        )
        self.assertEqual(
            [len(artifacts) for _, artifacts in boundary.artifacts_by_version],
            [1, 2],
        )

    def test_real_renderer_workflows_share_exact_executable_template(self) -> None:
        numpy_path = REPOSITORY_ROOT / ".github/workflows/test-numpy.yml"
        ninja_path = REPOSITORY_ROOT / "build_steps/fixtures/test-ninja.yml"
        numpy = _yaml(numpy_path.read_bytes(), str(numpy_path))
        ninja = _yaml(ninja_path.read_bytes(), str(ninja_path))

        self.assertEqual(
            _normalized_package_template(
                numpy,
                slug="numpy",
                label=str(numpy_path),
            ),
            _normalized_package_template(
                ninja,
                slug="ninja",
                label=str(ninja_path),
            ),
        )
        identity = _candidate_workflow_identity(
            ninja,
            slug="ninja",
            label=str(ninja_path),
        )
        self.assertTrue(identity.binary_only)
        self.assertEqual(
            [len(artifacts) for _, artifacts in identity.artifacts_by_version],
            [1, 2],
        )

    def test_rejects_tampered_pypi_boundary_snapshot(self) -> None:
        source = REPOSITORY_ROOT / ".github/catalog-evidence/ninja/pypi.json"
        document = json.loads(source.read_text())
        document["info"]["name"] = "not-ninja"
        _write(
            self.base,
            ".github/catalog-evidence/ninja/pypi.json",
            json.dumps(document),
        )
        with self.assertRaisesRegex(
            CandidateValidationError,
            "does not match the reviewed package identity",
        ):
            _trusted_pypi_boundary(
                self.base,
                _TRUSTED_SANDBOX_PACKAGE_IDENTITIES["ninja"],
            )

    def test_rejects_candidate_controlled_catalog_provenance(self) -> None:
        catalog_path = self.candidate / ".github/package-identity-catalog.json"
        original_catalog = catalog_path.read_text()
        mutations = (
            ("source_revision", "b" * 40),
            ("verified_by", "untrusted-candidate"),
            ("verified_at", "2026-07-30T12:00:00+00:00"),
        )
        for dimension in ("pip", "npm"):
            for field, value in mutations:
                with self.subTest(dimension=dimension, field=field):
                    catalog = json.loads(original_catalog)
                    record = next(
                        item for item in catalog["records"] if item["slug"] == "ninja"
                    )
                    record["registries"][dimension]["evidence"][0][field] = value
                    catalog_path.write_text(
                        json.dumps(catalog, indent=2, sort_keys=True) + "\n"
                    )
                    with self.assertRaisesRegex(
                        CandidateValidationError,
                        f"{dimension} provenance",
                    ):
                        validate(self.base, self.candidate)

    def test_rejects_workflow_for_a_different_pip_distribution(self) -> None:
        def mutate(plan: dict[str, object]) -> None:
            recipe = plan["recipe"]
            assert isinstance(recipe, dict)
            recipe["distribution"] = "numpy"
            recipe["import_module"] = "numpy"
            plan["evidence_urls"] = [
                "https://pypi.org/pypi/numpy/json",
                "https://github.com/numpy/numpy",
            ]
            functional = plan["functional_probe"]
            assert isinstance(functional, dict)
            assertions = functional["assertions"]
            assert isinstance(assertions, list)
            marker = next(
                assertion
                for assertion in assertions
                if isinstance(assertion, dict)
                and assertion.get("kind") == "output_contains"
            )
            marker["value"] = "import_ok:numpy"

        def mutate_pins(pins: list[dict[str, object]]) -> None:
            for pin in pins:
                _set_single_artifact_url(
                    pin,
                    "https://files.pythonhosted.org/packages/aa/bb/"
                    f"numpy-{pin['version']}-py3-none-manylinux2014_aarch64.whl",
                )

        self._mutate_candidate_plan(
            mutate,
            mutate_pins=mutate_pins,
            repository="https://github.com/numpy/numpy",
        )
        with self.assertRaisesRegex(
            CandidateValidationError,
            "trusted sandbox package identity",
        ):
            validate(self.base, self.candidate)

    def test_rejects_probe_that_treats_a_failed_import_as_success(self) -> None:
        def mutate(plan: dict[str, object]) -> None:
            functional = plan["functional_probe"]
            assert isinstance(functional, dict)
            functional["assertions"] = [
                {"expected": 1, "kind": "exit_code"},
                {
                    "case_sensitive": True,
                    "kind": "output_contains",
                    "value": "AssertionError",
                },
            ]

        self._mutate_candidate_plan(mutate)
        with self.assertRaisesRegex(
            CandidateValidationError,
            "can only prove a successful import",
        ):
            validate(self.base, self.candidate)

    def test_rejects_unproved_candidate_regression_deferral(self) -> None:
        def mutate(plan: dict[str, object]) -> None:
            regression = plan["regression_policy"]
            assert isinstance(regression, dict)
            regression.update(
                {
                    "candidate_version": None,
                    "deferral_decision": "no_newer_stable_available",
                    "mode": "approved_deferral",
                    "rationale": (
                        "The candidate claims that no newer stable release is available."
                    ),
                }
            )

        def mutate_pins(pins: list[dict[str, object]]) -> None:
            pins.pop()

        self._mutate_candidate_plan(mutate, mutate_pins=mutate_pins)
        with self.assertRaisesRegex(
            CandidateValidationError,
            "new sandbox candidates require a strict, executed Test 6",
        ):
            validate(self.base, self.candidate)

    def test_rejects_page_name_that_differs_from_tested_package(self) -> None:
        self._write_candidate_page(_ninja_page(name="NumPy"))
        with self.assertRaisesRegex(
            CandidateValidationError,
            "page name does not match",
        ):
            validate(self.base, self.candidate)

    def test_rejects_unexpected_added_file(self) -> None:
        _write(self.candidate, "unexpected.txt", "no\n")
        with self.assertRaisesRegex(
            CandidateValidationError,
            "added unexpected files",
        ):
            validate(self.base, self.candidate)

    def test_rejects_seed_mutation(self) -> None:
        _write(
            self.candidate,
            "content/linux/opensource_packages/numpy.md",
            "changed\n",
        )
        with self.assertRaisesRegex(
            CandidateValidationError,
            "changed trusted fixture input",
        ):
            validate(self.base, self.candidate)

    def test_rejects_existing_catalog_record_mutation(self) -> None:
        catalog_path = self.candidate / ".github/package-identity-catalog.json"
        catalog = json.loads(catalog_path.read_text())
        catalog["records"][0]["slug"] = "changed"
        catalog_path.write_text(json.dumps(catalog, indent=2, sort_keys=True) + "\n")
        with self.assertRaisesRegex(
            CandidateValidationError,
            "changed existing catalog record",
        ):
            validate(self.base, self.candidate)

    def test_rejects_missing_batch_registration(self) -> None:
        _write(
            self.candidate,
            ".github/workflows/test-all-packages-batch1.yml",
            _batch(["numpy"]) + "\n",
        )
        with self.assertRaisesRegex(
            CandidateValidationError,
            "append one package job",
        ):
            validate(self.base, self.candidate)

    def test_rejects_summary_needs_omission(self) -> None:
        batch_path = self.candidate / ".github/workflows/test-all-packages-batch1.yml"
        batch_path.write_text(
            batch_path.read_text().replace(
                "        test-numpy,\n        test-ninja\n",
                "        test-numpy\n",
            )
        )
        with self.assertRaisesRegex(
            CandidateValidationError,
            "summary.needs must append only",
        ):
            validate(self.base, self.candidate)

    def test_rejects_unpinned_batch_summary_action(self) -> None:
        batch_path = self.candidate / ".github/workflows/test-all-packages-batch1.yml"
        batch_path.write_text(
            batch_path.read_text().replace(CHECKOUT, "actions/checkout@v4")
        )
        with self.assertRaisesRegex(
            CandidateValidationError,
            "outside its package registration",
        ):
            validate(self.base, self.candidate)

    def test_rejects_unapproved_external_action(self) -> None:
        self._replace_candidate_workflow(
            CHECKOUT,
            "example/action@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        with self.assertRaisesRegex(
            CandidateValidationError,
            "unapproved external action",
        ):
            validate(self.base, self.candidate)

    def test_rejects_secret_reference(self) -> None:
        self._replace_candidate_workflow(
            "        shell: bash\n        run: |\n"
            "          set -euo pipefail\n"
            '          test "${{ steps.summary.outputs.should_fail }}" = "0"',
            "        shell: bash\n"
            "        env:\n"
            "          TOKEN: ${{ secrets.TOKEN }}\n"
            "        run: |\n"
            "          set -euo pipefail\n"
            '          test "${{ steps.summary.outputs.should_fail }}" = "0"',
        )
        with self.assertRaisesRegex(
            CandidateValidationError,
            "must not receive secrets",
        ):
            validate(self.base, self.candidate)

    def test_rejects_github_token_reference(self) -> None:
        self._replace_candidate_workflow(
            'test "${{ steps.summary.outputs.should_fail }}" = "0"',
            'test "${{ github.token }}" = "never-allowed"',
        )
        with self.assertRaisesRegex(
            CandidateValidationError,
            "must not receive secrets",
        ):
            validate(self.base, self.candidate)

    def test_rejects_whole_secrets_context(self) -> None:
        self._replace_candidate_workflow(
            "      - name: Enforce strict smoke-test result",
            "      - name: Expose context\n"
            "        run: echo '${{ toJSON(secrets) }}'\n"
            "      - name: Enforce strict smoke-test result",
        )
        with self.assertRaisesRegex(
            CandidateValidationError,
            "must not receive secrets",
        ):
            validate(self.base, self.candidate)

    def test_rejects_whole_github_context(self) -> None:
        self._replace_candidate_workflow(
            "      - name: Enforce strict smoke-test result",
            "      - name: Expose context\n"
            "        run: echo '${{ toJSON(github) }}'\n"
            "      - name: Enforce strict smoke-test result",
        )
        with self.assertRaisesRegex(
            CandidateValidationError,
            "must not receive secrets",
        ):
            validate(self.base, self.candidate)

    def test_rejects_additional_host_run_step(self) -> None:
        self._replace_candidate_workflow(
            "      - name: Enforce strict smoke-test result",
            "      - name: Unreviewed host command\n"
            '        run: "true"\n'
            "      - name: Enforce strict smoke-test result",
        )
        with self.assertRaisesRegex(
            CandidateValidationError,
            "trusted canonical template",
        ):
            validate(self.base, self.candidate)

    def test_rejects_fake_green_enforcement(self) -> None:
        self._replace_candidate_workflow(
            '          test "${{ steps.summary.outputs.should_fail }}" = "0"',
            "          true",
        )
        with self.assertRaisesRegex(
            CandidateValidationError,
            "trusted canonical template",
        ):
            validate(self.base, self.candidate)

    def test_rejects_modified_job_output_contract(self) -> None:
        self._replace_candidate_workflow(
            "      run_status: value",
            "      run_status: success",
        )
        with self.assertRaisesRegex(
            CandidateValidationError,
            "trusted canonical template",
        ):
            validate(self.base, self.candidate)

    def test_rejects_modified_batch_attestation_command(self) -> None:
        batch_path = self.candidate / ".github/workflows/test-all-packages-batch1.yml"
        batch_path.write_text(
            batch_path.read_text().replace(
                "          python3 .github/scripts/batch_artifact_attestation.py create",
                "          true",
            )
        )
        with self.assertRaisesRegex(
            CandidateValidationError,
            "outside its package registration",
        ):
            validate(self.base, self.candidate)

    def test_rejects_trigger_spoofed_only_in_comment(self) -> None:
        self._replace_candidate_workflow(
            "  workflow_call:\n",
            "  # workflow_call:\n  workflow_run:\n",
        )
        with self.assertRaisesRegex(
            CandidateValidationError,
            "unapproved or missing triggers",
        ):
            validate(self.base, self.candidate)

    def test_rejects_permissions_spoofed_in_comment_and_run_block(self) -> None:
        self._replace_candidate_workflow(
            "permissions:\n  contents: read\non:",
            "# permissions:\n#   contents: read\non:",
        )
        self._replace_candidate_workflow(
            '          set -euo pipefail\n          cat > "$RUNNER_TEMP/smoke.py"',
            "          set -euo pipefail\n"
            "          printf '%s\\n' 'permissions:' '  contents: read'\n"
            '          cat > "$RUNNER_TEMP/smoke.py"',
        )
        with self.assertRaisesRegex(
            CandidateValidationError,
            "permissions.*string-keyed mapping",
        ):
            validate(self.base, self.candidate)

    def test_ignores_nonexecutable_secret_reference_in_yaml_comment(self) -> None:
        self._replace_candidate_workflow(
            "name: Test ninja",
            "# Documentation only: ${{ secrets.NOT_EXECUTED }}\nname: Test ninja",
        )
        validate(self.base, self.candidate)

    def test_rejects_non_arm_runner_spoofed_in_run_block(self) -> None:
        self._replace_candidate_workflow(
            "    runs-on: ubuntu-24.04-arm",
            "    runs-on: ubuntu-latest",
        )
        self._replace_candidate_workflow(
            '          set -euo pipefail\n          cat > "$RUNNER_TEMP/smoke.py"',
            "          set -euo pipefail\n"
            "          printf '%s\\n' 'runs-on: ubuntu-24.04-arm'\n"
            '          cat > "$RUNNER_TEMP/smoke.py"',
        )
        with self.assertRaisesRegex(
            CandidateValidationError,
            "run only on ubuntu-24.04-arm",
        ):
            validate(self.base, self.candidate)

    def test_rejects_test_step_spoofed_in_run_block(self) -> None:
        self._replace_candidate_workflow("        id: test6", "        id: omitted")
        self._replace_candidate_workflow(
            "          set -euo pipefail\n"
            "          /usr/bin/timeout --signal=TERM --kill-after=10s 900s",
            "          set -euo pipefail\n"
            "          printf '%s\\n' 'id: test6'\n"
            "          /usr/bin/timeout --signal=TERM --kill-after=10s 900s",
        )
        with self.assertRaisesRegex(
            CandidateValidationError,
            "lacks six-test steps",
        ):
            validate(self.base, self.candidate)

    def test_accepts_candidate_without_optional_public_native_evidence(self) -> None:
        validate(self.base, self.candidate)

    def test_rejects_self_asserted_public_native_evidence(self) -> None:
        _add_native_evidence(self.candidate)
        with self.assertRaisesRegex(
            CandidateValidationError,
            "added unexpected files",
        ):
            validate(self.base, self.candidate)

    def test_rejects_native_evidence_checksum_mismatch(self) -> None:
        directory = _add_native_evidence(self.candidate)
        (directory / "SHA256SUMS").write_text(
            f"{'0' * 64}  request.json\n{'0' * 64}  report.json\n"
        )
        with self.assertRaisesRegex(
            CandidateValidationError,
            "added unexpected files",
        ):
            validate(self.base, self.candidate)

    def test_rejects_incomplete_optional_native_evidence_bundle(self) -> None:
        directory = self.candidate / ".arm-validation-evidence" / REQUEST_ID
        directory.mkdir(parents=True)
        (directory / "request.json").write_text("{}\n")
        with self.assertRaisesRegex(
            CandidateValidationError,
            "added unexpected files",
        ):
            validate(self.base, self.candidate)

    def test_rejects_malformed_native_evidence_json(self) -> None:
        directory = _add_native_evidence(self.candidate)
        request = b"{malformed"
        report = (directory / "report.json").read_bytes()
        (directory / "request.json").write_bytes(request)
        (directory / "SHA256SUMS").write_text(
            f"{_sha(request)}  request.json\n{_sha(report)}  report.json\n"
        )
        with self.assertRaisesRegex(
            CandidateValidationError,
            "added unexpected files",
        ):
            validate(self.base, self.candidate)

    def test_rejects_failed_native_evidence_run(self) -> None:
        _add_native_evidence(
            self.candidate,
            mutate_report=lambda report: report.update({"conclusion": "failure"}),
        )
        with self.assertRaisesRegex(
            CandidateValidationError,
            "added unexpected files",
        ):
            validate(self.base, self.candidate)

    def test_rejects_native_evidence_bound_to_other_workflow(self) -> None:
        _add_native_evidence(
            self.candidate,
            mutate_report=lambda report: report.update({"workflow_sha256": "f" * 64}),
        )
        with self.assertRaisesRegex(
            CandidateValidationError,
            "added unexpected files",
        ):
            validate(self.base, self.candidate)

    def test_rejects_native_evidence_from_non_arm_runner(self) -> None:
        def change_runner(report: dict[str, object]) -> None:
            report["runner"] = {
                "label": "ubuntu-24.04",
                "architecture": "x86_64",
                "environment": "github-hosted",
            }

        _add_native_evidence(self.candidate, mutate_report=change_runner)
        with self.assertRaisesRegex(
            CandidateValidationError,
            "added unexpected files",
        ):
            validate(self.base, self.candidate)

    def test_rejects_native_evidence_run_attempt_substitution(self) -> None:
        def change_attempt(report: dict[str, object]) -> None:
            outputs = report["outputs"]
            assert isinstance(outputs, dict)
            outputs["run_attempt"] = "2"

        _add_native_evidence(self.candidate, mutate_report=change_attempt)
        with self.assertRaisesRegex(
            CandidateValidationError,
            "added unexpected files",
        ):
            validate(self.base, self.candidate)

    def test_rejects_native_evidence_fake_green_core_outputs(self) -> None:
        def fake_core(report: dict[str, object]) -> None:
            outputs = report["outputs"]
            assert isinstance(outputs, dict)
            outputs["core_failed"] = "1"

        _add_native_evidence(self.candidate, mutate_report=fake_core)
        with self.assertRaisesRegex(
            CandidateValidationError,
            "added unexpected files",
        ):
            validate(self.base, self.candidate)

    def test_rejects_native_evidence_six_test_count_mismatch(self) -> None:
        def fake_counts(report: dict[str, object]) -> None:
            outputs = report["outputs"]
            assert isinstance(outputs, dict)
            outputs["tests_passed"] = "5"
            outputs["tests_skipped"] = "1"

        _add_native_evidence(self.candidate, mutate_report=fake_counts)
        with self.assertRaisesRegex(
            CandidateValidationError,
            "added unexpected files",
        ):
            validate(self.base, self.candidate)

    def test_rejects_native_evidence_regression_mismatch(self) -> None:
        def fake_regression(report: dict[str, object]) -> None:
            outputs = report["outputs"]
            assert isinstance(outputs, dict)
            outputs["regression_decision"] = "runtime_validation_not_automated"

        _add_native_evidence(self.candidate, mutate_report=fake_regression)
        with self.assertRaisesRegex(
            CandidateValidationError,
            "added unexpected files",
        ):
            validate(self.base, self.candidate)


if __name__ == "__main__":
    unittest.main()
