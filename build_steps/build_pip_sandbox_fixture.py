"""Build and verify the bounded pip-onboarding sandbox trust root."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
from pathlib import Path
from typing import Any

try:
    from .validate_package_identity_catalog import calculate_corpus_sha256
except ImportError:
    from validate_package_identity_catalog import calculate_corpus_sha256

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
CONTENT_PATH = Path("content/linux/opensource_packages/numpy.md")
WORKFLOW_PATH = Path(".github/workflows/test-numpy.yml")
CATALOG_PATH = Path(".github/package-identity-catalog.json")
MANIFEST_PATH = Path(".github/fixture-manifest.json")
EVIDENCE_ROOT = Path(".github/catalog-evidence/numpy")
PYPI_SNAPSHOT = EVIDENCE_ROOT / "pypi.json"
GITHUB_SNAPSHOT = EVIDENCE_ROOT / "github-commit.json"
NPM_REVIEW = EVIDENCE_ROOT / "npm-review.md"
NINJA_EVIDENCE_ROOT = Path(".github/catalog-evidence/ninja")
NINJA_PYPI_SNAPSHOT = NINJA_EVIDENCE_ROOT / "pypi.json"
NINJA_SHA256SUMS = NINJA_EVIDENCE_ROOT / "SHA256SUMS"
NINJA_WORKFLOW_FIXTURE = Path("build_steps/fixtures/test-ninja.yml")
CORPUS_REVIEW = Path("docs/sandbox-pip-e2e-fixture.md")
PACKAGE_DISPLAY_PARTIAL = Path(
    "themes/arm-design-system-hugo-theme/layouts/partials/package-display/row-sub.html"
)
SEED_RESULT = Path("data/test-results/numpy.json")
SEED_INDEX = Path("data/test-results-index.json")
SOURCE_DASHBOARD_COMMIT = "550f5cbc578783170b9b0706e9257653ed4dddea"
SOURCE_SERVICE_COMMIT = "1ce6a0db14f99fa560f681fe8a7fd57934070bf0"
VERIFIED_AT = "2026-07-30T19:59:51+00:00"
VERIFIER = f"arm-ecosystem-sandbox-fixture-builder@{SOURCE_SERVICE_COMMIT}"
PYPI_LOCATOR = "https://pypi.org/pypi/numpy/json"
GITHUB_COMMIT = "4350526858b0e8ce8932538da664aa8d1a182410"
GITHUB_LOCATOR = f"https://api.github.com/repos/numpy/numpy/commits/{GITHUB_COMMIT}"
BASELINE_VERSION = "2.5.1"
WHEEL_FILENAME = (
    "numpy-2.5.1-cp312-cp312-manylinux_2_27_aarch64.manylinux_2_28_aarch64.whl"
)
WHEEL_URL = (
    "https://files.pythonhosted.org/packages/a9/4b/"
    "a2b32dd94ee9ffbeecb28152240042a3949db33b1c834d44090b80e1b3b8/"
    f"{WHEEL_FILENAME}"
)
WHEEL_SHA256 = "61ac47e772e6b8ea489e1d2f441a34c5c3ac17327e7ce294cbdf535795ad4e75"
PYPI_SNAPSHOT_SHA256 = (
    "796d8cfb1e101561086725e9dcecafb48c740b01e0e157b11d53958e000096e1"
)
GITHUB_SNAPSHOT_SHA256 = (
    "56406eb1e1ad9a4abfccf6e66ff35a935c0cb3d7368a4cf1be15848d2f6c6de0"
)
NPM_REVIEW_SHA256 = "e0a5e28123d90cc913f33bb784d1ec09bc53e302dbeb46f9fc15784db5cce87a"
WORKFLOW_SHA256 = "0f4d6617a75c2e6634f6f27985c9ac932c5539d5d57a51e19afaef7ae78f8be0"
NINJA_PYPI_SNAPSHOT_SHA256 = (
    "1a5a8a5b0c93bf0004add485acc7b373d54ea486c1088c9f5f50f9bf8badb4e5"
)
NINJA_WORKFLOW_SHA256 = (
    "295ec8a344e613d6dd9b489178c0eca9811bb526bb0d96f67a30661a1584e4de"
)
LEGACY_RUN_ID = "30413367209"
LEGACY_RUN_ATTEMPT = "1"
LEGACY_RUN_URL = (
    "https://github.com/ArmDeveloperEcosystem/ecosystem-dashboard-for-arm/"
    f"actions/runs/{LEGACY_RUN_ID}/job/90454371578"
)
TEST_LABELS = (
    "Test 1 - Import NumPy",
    "Test 2 - Check installed version",
    "Test 3 - Check f2py help",
    "Test 4 - Verify architecture",
    "Test 5 - Run array operations",
    "Regression applicability - package manager installed",
)


def _read(relative: Path) -> bytes:
    path = REPOSITORY_ROOT / relative
    if path.is_symlink() or not path.is_file():
        raise SystemExit(f"required fixture file is missing or unsafe: {relative}")
    return path.read_bytes()


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical(payload: dict[str, Any]) -> bytes:
    return (
        json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def _evidence_sort_key(record: dict[str, Any]) -> str:
    return json.dumps(record, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _assert_exact_fixture_inventory() -> None:
    content_root = REPOSITORY_ROOT / CONTENT_PATH.parent
    pages = sorted(
        path.name
        for path in content_root.glob("*.md")
        if path.name not in {"_index.md", "index.md"}
    )
    if pages != ["numpy.md"]:
        raise SystemExit(f"unexpected package-page fixture inventory: {pages}")

    workflow_root = REPOSITORY_ROOT / ".github/workflows"
    package_workflows = sorted(
        path.name
        for path in workflow_root.glob("test-*.yml")
        if not path.name.startswith("test-all-packages-")
    )
    if package_workflows != ["test-numpy.yml"]:
        raise SystemExit(
            f"unexpected package-workflow fixture inventory: {package_workflows}"
        )


def _require_mapping(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise SystemExit(f"{label} must be a JSON object with string keys")
    return value


def _decode_json(payload: bytes, label: str) -> dict[str, Any]:
    try:
        return _require_mapping(json.loads(payload), label)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SystemExit(f"{label} is not valid JSON") from exc


def _stable_version_key(value: str) -> tuple[int, ...] | None:
    if re.fullmatch(r"[0-9]+(?:\.[0-9]+)*", value) is None:
        return None
    return tuple(int(part) for part in value.split("."))


def _validate_pypi_snapshot(payload: dict[str, Any], raw: bytes) -> None:
    if _sha256(raw) != PYPI_SNAPSHOT_SHA256:
        raise SystemExit("archived PyPI evidence differs from the reviewed snapshot")
    info = _require_mapping(payload.get("info"), "archived PyPI info")
    if info.get("name") != "numpy" or info.get("version") != BASELINE_VERSION:
        raise SystemExit("archived PyPI latest version is not NumPy 2.5.1")
    project_urls = _require_mapping(
        info.get("project_urls"), "archived PyPI project URLs"
    )
    source_url = next(
        (value for key, value in project_urls.items() if key.casefold() == "source"),
        None,
    )
    if source_url != "https://github.com/numpy/numpy":
        raise SystemExit("archived PyPI evidence does not bind numpy/numpy")

    releases = _require_mapping(payload.get("releases"), "archived PyPI releases")
    stable_versions = {
        version: key
        for version in releases
        if (key := _stable_version_key(version)) is not None
    }
    latest_stable = (
        max(stable_versions, key=stable_versions.__getitem__)
        if stable_versions
        else None
    )
    if latest_stable != BASELINE_VERSION:
        raise SystemExit("archived PyPI releases contain a newer stable version")
    release_files = releases.get(BASELINE_VERSION)
    if not isinstance(release_files, list):
        raise SystemExit("archived PyPI evidence lacks the NumPy 2.5.1 release")
    matches = [
        _require_mapping(item, "archived PyPI release file")
        for item in release_files
        if isinstance(item, dict) and item.get("url") == WHEEL_URL
    ]
    if len(matches) != 1:
        raise SystemExit(
            "archived PyPI evidence lacks the exact CPython 3.12 AArch64 wheel"
        )
    wheel = matches[0]
    digests = _require_mapping(wheel.get("digests"), "archived wheel digests")
    if (
        wheel.get("filename") != WHEEL_FILENAME
        or wheel.get("packagetype") != "bdist_wheel"
        or wheel.get("python_version") != "cp312"
        or wheel.get("yanked") is not False
        or digests.get("sha256") != WHEEL_SHA256
    ):
        raise SystemExit("archived CPython 3.12 AArch64 wheel identity is not trusted")


def _validate_github_snapshot(payload: dict[str, Any], raw: bytes) -> None:
    if _sha256(raw) != GITHUB_SNAPSHOT_SHA256:
        raise SystemExit("archived GitHub evidence differs from the reviewed snapshot")
    expected_html = f"https://github.com/numpy/numpy/commit/{GITHUB_COMMIT}"
    if (
        payload.get("sha") != GITHUB_COMMIT
        or payload.get("url") != GITHUB_LOCATOR
        or payload.get("html_url") != expected_html
    ):
        raise SystemExit(
            "archived GitHub evidence is not bound to the immutable NumPy commit"
        )


def _validate_npm_review(raw: bytes) -> None:
    if _sha256(raw) != NPM_REVIEW_SHA256:
        raise SystemExit(
            "npm manual-review evidence differs from the reviewed boundary"
        )
    text = raw.decode("utf-8")
    required = (
        "makes no claim that the npm package named `numpy` belongs",
        "does not claim that NumPy has no npm identity",
        "`unknown`, non-exhaustive",
        "contains\nno identities",
    )
    if any(marker not in text for marker in required):
        raise SystemExit(
            "npm manual-review evidence does not state the fail-closed boundary"
        )


def _validate_ninja_evidence(
    pypi_snapshot: bytes,
    checksums: bytes,
    workflow: bytes,
) -> None:
    if _sha256(pypi_snapshot) != NINJA_PYPI_SNAPSHOT_SHA256:
        raise SystemExit(
            "archived Ninja PyPI evidence differs from the reviewed snapshot"
        )
    expected_checksums = f"{NINJA_PYPI_SNAPSHOT_SHA256}  pypi.json\n".encode("ascii")
    if checksums != expected_checksums:
        raise SystemExit("Ninja evidence checksum manifest is not canonical")
    if _sha256(workflow) != NINJA_WORKFLOW_SHA256:
        raise SystemExit(
            "Ninja workflow differs from the reviewed official renderer output"
        )


def _validate_binary_scope_rendering(raw: bytes) -> None:
    text = raw.decode("utf-8")
    required = (
        'support_scope "pypi_binary_distribution"',
        "official Linux AArch64 binary wheels for",
        "earliest stable, non-yanked PyPI",
        "does not establish when source compatibility",
    )
    if any(marker not in text for marker in required):
        raise SystemExit(
            "dashboard template does not preserve the binary-distribution scope"
        )


def _workflow_env(workflow: str, name: str) -> str:
    match = re.search(
        rf'^  {re.escape(name)}: "([^"\n]+)"$', workflow, flags=re.MULTILINE
    )
    if match is None:
        raise SystemExit(f"renderer workflow lacks the exact {name} environment value")
    return match.group(1)


def _decode_embedded_payload(workflow: str, prefix: str) -> object:
    encoded = _workflow_env(workflow, f"{prefix}_B64")
    expected_digest = _workflow_env(workflow, f"{prefix}_DIGEST")
    try:
        decoded = base64.b64decode(encoded, validate=True)
        payload = json.loads(decoded)
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SystemExit(f"{prefix} is not valid canonical base64 JSON") from exc
    actual_digest = _sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    if actual_digest != expected_digest:
        raise SystemExit(f"{prefix} digest does not match its embedded payload")
    return payload


def _expected_plan() -> dict[str, Any]:
    return {
        "baseline_version": BASELINE_VERSION,
        "evidence_urls": [
            PYPI_LOCATOR,
            f"https://github.com/numpy/numpy/commit/{GITHUB_COMMIT}",
        ],
        "functional_probe": {
            "assertions": [
                {"expected": 0, "kind": "exit_code"},
                {
                    "case_sensitive": True,
                    "kind": "output_contains",
                    "value": "import_ok:numpy",
                },
            ],
            "invocation": {
                "arguments": ["smoke_import.py"],
                "program": "python3",
                "timeout_seconds": 60,
            },
        },
        "recipe": {
            "distribution": "numpy",
            "import_module": "numpy",
            "kind": "pip",
        },
        "regression_policy": {
            "candidate_version": None,
            "deferral_decision": "no_newer_stable_available",
            "mode": "approved_deferral",
            "rationale": (
                "The archived PyPI snapshot identifies 2.5.1 as the latest stable "
                "release, so there is no newer stable candidate to test."
            ),
        },
        "schema_version": "1.0",
        "version_probe": {
            "arguments": ["smoke_version.py"],
            "program": "python3",
            "timeout_seconds": 30,
        },
    }


def _expected_artifact_pins() -> list[dict[str, Any]]:
    return [
        {
            "artifacts": [
                {
                    "filename": WHEEL_FILENAME,
                    "integrity": None,
                    "sha256": WHEEL_SHA256,
                    "url": WHEEL_URL,
                }
            ],
            "binary_only": False,
            "recipe_kind": "pip",
            "schema_version": "1.2",
            "version": BASELINE_VERSION,
        }
    ]


def _validate_workflow(raw: bytes) -> None:
    try:
        workflow = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SystemExit("renderer workflow is not UTF-8") from exc
    if _workflow_env(workflow, "SMOKE_PACKAGE_SLUG") != "numpy":
        raise SystemExit("renderer workflow has the wrong package slug")
    if (
        _workflow_env(workflow, "SMOKE_PACKAGE_REPOSITORY")
        != "https://github.com/numpy/numpy"
    ):
        raise SystemExit("renderer workflow has the wrong package repository")
    try:
        package_name = base64.b64decode(
            _workflow_env(workflow, "SMOKE_PACKAGE_NAME_B64"),
            validate=True,
        ).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError) as exc:
        raise SystemExit("renderer workflow has an invalid package name") from exc
    if package_name != "NumPy":
        raise SystemExit("renderer workflow has the wrong package name")

    plan = _decode_embedded_payload(workflow, "SMOKE_PLAN")
    pins = _decode_embedded_payload(workflow, "SMOKE_ARTIFACT_PINS")
    if plan != _expected_plan():
        raise SystemExit("embedded smoke plan is not the trusted NumPy plan")
    if pins != _expected_artifact_pins():
        raise SystemExit("embedded artifact pin is not the exact AArch64 NumPy wheel")

    required_markers = (
        "runs-on: ubuntu-24.04-arm",
        "TRUSTED_RUNNER_ENVIRONMENT",
        "TRUSTED_RUNNER_ARCH",
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
        "docker.io/library/ubuntu@",
        "--read-only",
        '--network",\n                      "none"',
        "--cap-drop",
        "no-new-privileges",
        "Test 1 - Install exact baseline package",
        "Test 2 - Verify exact baseline version",
        "Test 3 - Validate installed artifact metadata",
        "Test 4 - Verify native Arm64 architecture",
        "Test 5 - Run package-specific functional probe",
        "Test 6 - Validate isolated candidate or explicit deferral",
        "uses: ./.github/actions/emit-package-result",
        "Enforce strict smoke-test result",
        'regression_policy: "approved_deferral"',
    )
    if any(marker not in workflow for marker in required_markers):
        raise SystemExit(
            "renderer workflow is missing a required isolation or result contract"
        )
    forbidden_markers = (
        "continue-on-error:",
        "pull_request_target:",
        "id-token:",
        "secrets.",
        "--privileged",
    )
    if any(marker in workflow for marker in forbidden_markers):
        raise SystemExit("renderer workflow contains a forbidden execution capability")
    if _sha256(raw) != WORKFLOW_SHA256:
        raise SystemExit(
            "NumPy workflow differs from the reviewed official renderer output"
        )


def _validate_seed_results(result: dict[str, Any], index: dict[str, Any]) -> None:
    if set(index) != {"numpy"} or index.get("numpy") != result:
        raise SystemExit("seed result index is not exactly consistent with numpy.json")
    if set(result) != {"schema_version", "package", "run", "tests", "metadata"}:
        raise SystemExit("historical NumPy seed has unexpected top-level fields")
    package = _require_mapping(result.get("package"), "historical seed package")
    run = _require_mapping(result.get("run"), "historical seed run")
    tests = _require_mapping(result.get("tests"), "historical seed tests")
    metadata = _require_mapping(result.get("metadata"), "historical seed metadata")
    if result.get("schema_version") != "2.0" or package != {
        "name": "NumPy",
        "version": BASELINE_VERSION,
    }:
        raise SystemExit("historical NumPy seed has the wrong package identity")
    if (
        run.get("id") != LEGACY_RUN_ID
        or run.get("attempt") != LEGACY_RUN_ATTEMPT
        or run.get("url") != LEGACY_RUN_URL
        or run.get("status") != "success"
        or run.get("runner") != {"os": "ubuntu-24.04", "arch": "arm64"}
    ):
        raise SystemExit(
            "historical NumPy seed does not identify the real legacy Arm64 run"
        )
    if (
        tests.get("passed") != 5
        or tests.get("failed") != 0
        or tests.get("skipped") != 1
    ):
        raise SystemExit("historical NumPy seed must report the honest 5/0/1 result")
    details = tests.get("details")
    if not isinstance(details, list) or len(details) != 6:
        raise SystemExit("historical NumPy seed must contain exactly six test details")
    for index_number, (detail, expected_name) in enumerate(
        zip(details, TEST_LABELS, strict=True),
        start=1,
    ):
        item = _require_mapping(detail, f"historical seed Test {index_number}")
        expected_status = "skipped" if index_number == 6 else "passed"
        if item.get("name") != expected_name or item.get("status") != expected_status:
            raise SystemExit(
                "historical NumPy seed detail statuses contradict the real run"
            )
        if (
            not isinstance(item.get("duration_seconds"), int)
            or item["duration_seconds"] < 0
        ):
            raise SystemExit("historical NumPy seed has an invalid test duration")
        if not isinstance(item.get("url"), str) or not item["url"].startswith(
            LEGACY_RUN_URL
        ):
            raise SystemExit("historical NumPy seed test detail points to another run")
    if (
        metadata.get("package_slug") != "numpy"
        or metadata.get("core_failed") != 0
        or metadata.get("badge_status") != "passing"
        or metadata.get("regression_reason") != "package_manager_installed"
        or metadata.get("evidence_kind") != "historical_legacy_workflow_run"
    ):
        raise SystemExit(
            "historical NumPy seed is not explicitly labeled legacy evidence"
        )


def _catalog_payload() -> dict[str, Any]:
    _assert_exact_fixture_inventory()
    content = _read(CONTENT_PATH)
    workflow = _read(WORKFLOW_PATH)
    pypi = _read(PYPI_SNAPSHOT)
    github = _read(GITHUB_SNAPSHOT)
    npm_review = _read(NPM_REVIEW)
    ninja_pypi = _read(NINJA_PYPI_SNAPSHOT)
    ninja_checksums = _read(NINJA_SHA256SUMS)
    ninja_workflow = _read(NINJA_WORKFLOW_FIXTURE)
    corpus_review = _read(CORPUS_REVIEW)
    package_display_partial = _read(PACKAGE_DISPLAY_PARTIAL)
    result = _decode_json(_read(SEED_RESULT), "historical NumPy seed result")
    result_index = _decode_json(_read(SEED_INDEX), "historical NumPy seed index")

    pypi_payload = _decode_json(pypi, "archived PyPI evidence")
    github_payload = _decode_json(github, "archived GitHub evidence")
    _validate_pypi_snapshot(pypi_payload, pypi)
    _validate_github_snapshot(github_payload, github)
    _validate_npm_review(npm_review)
    _validate_ninja_evidence(ninja_pypi, ninja_checksums, ninja_workflow)
    _validate_binary_scope_rendering(package_display_partial)
    _validate_workflow(workflow)
    _validate_seed_results(result, result_index)

    content_sha = _sha256(content)
    workflow_sha = _sha256(workflow)
    pypi_sha = _sha256(pypi)
    github_evidence_sha = _sha256(github)
    corpus_review_sha = _sha256(corpus_review)
    pip_evidence = sorted(
        [
            {
                "evidence_sha256": github_evidence_sha,
                "rationale": (
                    "Archived GitHub API evidence binds the canonical NumPy source "
                    "repository to an immutable commit."
                ),
                "source_kind": "github_api",
                "source_locator": GITHUB_LOCATOR,
                "source_revision": GITHUB_COMMIT,
                "verified_at": VERIFIED_AT,
                "verified_by": VERIFIER,
            },
            {
                "evidence_sha256": pypi_sha,
                "rationale": (
                    "Archived PyPI API evidence identifies the normalized numpy "
                    "distribution and the reviewed GitHub evidence independently "
                    "binds it to the canonical numpy/numpy source repository."
                ),
                "source_kind": "pypi_api",
                "source_locator": PYPI_LOCATOR,
                "source_revision": pypi_sha,
                "verified_at": VERIFIED_AT,
                "verified_by": VERIFIER,
            },
            {
                "evidence_sha256": corpus_review_sha,
                "rationale": (
                    "A manual review of the exact one-page, one-workflow bounded "
                    "fixture confirms that numpy is its sole pip identity. This "
                    "exhaustive decision applies only to this sandbox corpus."
                ),
                "source_kind": "manual_review",
                "source_locator": (
                    "docs/sandbox-pip-e2e-fixture.md#identity-trust-root"
                ),
                "source_revision": corpus_review_sha,
                "verified_at": VERIFIED_AT,
                "verified_by": ("ranimandepudi+required-independent-codeowner-review"),
            },
        ],
        key=_evidence_sort_key,
    )
    npm_evidence = [
        {
            "evidence_sha256": pypi_sha,
            "rationale": (
                "The archived PyPI project evidence identifies NumPy's Python "
                "distribution but does not establish ownership of any npm identity; "
                "the npm dimension remains unknown and non-exhaustive."
            ),
            "source_kind": "pypi_api",
            "source_locator": PYPI_LOCATOR,
            "source_revision": pypi_sha,
            "verified_at": VERIFIED_AT,
            "verified_by": VERIFIER,
        }
    ]
    corpus_sha = calculate_corpus_sha256(
        [
            (CONTENT_PATH.as_posix(), content_sha),
            (WORKFLOW_PATH.as_posix(), workflow_sha),
        ]
    )
    return {
        "corpus": {
            "content_root": "content/linux/opensource_packages",
            "corpus_sha256": corpus_sha,
            "entry_count": 1,
        },
        "records": [
            {
                "content_path": CONTENT_PATH.as_posix(),
                "content_sha256": content_sha,
                "registries": {
                    "npm": {
                        "evidence": npm_evidence,
                        "exhaustive": False,
                        "identities": [],
                        "status": "unknown",
                    },
                    "pip": {
                        "evidence": pip_evidence,
                        "exhaustive": True,
                        "identities": ["numpy"],
                        "status": "verified",
                    },
                },
                "slug": "numpy",
                "workflow": {
                    "path": WORKFLOW_PATH.as_posix(),
                    "presence": "present",
                    "sha256": workflow_sha,
                },
            }
        ],
        "schema_version": "1.1",
    }


def _manifest_payload(catalog_bytes: bytes) -> dict[str, Any]:
    dashboard_files = (
        CONTENT_PATH,
        WORKFLOW_PATH,
        Path(".github/actions/apt-bootstrap/action.yml"),
        Path(".github/actions/apt-bootstrap/bootstrap.sh"),
        Path(".github/actions/collect-batch-results/action.yml"),
        Path(".github/actions/emit-package-result/action.yml"),
    )
    service_files = (Path(".github/actions/setup-hugo/action.yml"),)
    fixture_control_files = (
        Path(".github/CODEOWNERS"),
        Path(".github/PACKAGE_IDENTITY_CATALOG.md"),
        Path(".github/workflows/sandbox-dashboard-validation.yml"),
        Path(".github/workflows/test-all-packages-orchestrator.yml"),
        Path(".github/workflows/test-all-packages-summary.yml"),
        Path(".github/scripts/batch_artifact_attestation.py"),
        Path(".github/scripts/orchestration_contract.py"),
        Path(
            ".github/actions/publish-generated-data-pr/tests/test_orchestration_contract.py"
        ),
        Path(
            ".github/actions/publish-generated-data-pr/tests/test_batch_artifact_attestation.py"
        ),
        Path("build_steps/build_pip_sandbox_fixture.py"),
        Path("build_steps/requirements-validation.txt"),
        Path("build_steps/tests/test_build_pip_sandbox_fixture.py"),
        Path("build_steps/tests/test_validate_pip_sandbox_candidate.py"),
        Path("build_steps/validate_package_identity_catalog.py"),
        Path("build_steps/validate_pip_sandbox_candidate.py"),
        NINJA_WORKFLOW_FIXTURE,
        SEED_INDEX,
        SEED_RESULT,
        Path("docs/sandbox-pip-e2e-fixture.md"),
        PACKAGE_DISPLAY_PARTIAL,
    )
    evidence_files = (
        PYPI_SNAPSHOT,
        GITHUB_SNAPSHOT,
        NPM_REVIEW,
        NINJA_PYPI_SNAPSHOT,
        NINJA_SHA256SUMS,
    )
    return {
        "catalog_sha256": _sha256(catalog_bytes),
        "evidence": {path.as_posix(): _sha256(_read(path)) for path in evidence_files},
        "fixture_kind": "bounded-real-pip-onboarding",
        "fixture_control_files": {
            path.as_posix(): _sha256(_read(path)) for path in fixture_control_files
        },
        "schema_version": "1.0",
        "seed_package": {
            "name": "NumPy",
            "pip_identity": "numpy",
            "slug": "numpy",
        },
        "source_dashboard_commit": SOURCE_DASHBOARD_COMMIT,
        "source_files": {
            path.as_posix(): _sha256(_read(path)) for path in dashboard_files
        },
        "source_service_commit": SOURCE_SERVICE_COMMIT,
        "service_support_files": {
            path.as_posix(): _sha256(_read(path)) for path in service_files
        },
        "unsupported_claims": [
            "npm identity coverage",
            "production dashboard corpus coverage",
            "production activation approval",
        ],
    }


def _compare_or_write(path: Path, expected: bytes, *, check: bool) -> None:
    target = REPOSITORY_ROOT / path
    if check:
        if (
            target.is_symlink()
            or not target.is_file()
            or target.read_bytes() != expected
        ):
            raise SystemExit(f"fixture output is stale: {path}")
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(expected)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify checked-in outputs instead of writing them.",
    )
    args = parser.parse_args()

    catalog = _canonical(_catalog_payload())
    manifest = _canonical(_manifest_payload(catalog))
    _compare_or_write(CATALOG_PATH, catalog, check=args.check)
    _compare_or_write(MANIFEST_PATH, manifest, check=args.check)
    print("PASS: bounded pip sandbox fixture is internally consistent.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
