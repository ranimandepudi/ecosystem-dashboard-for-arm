"""Validate one bounded package-onboarding change against the trusted fixture."""

from __future__ import annotations

import argparse
import base64
import binascii
import copy
import hashlib
import json
import re
import shutil
import subprocess
import urllib.error
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import SplitResult, quote, unquote, unquote_to_bytes, urlsplit

import yaml
from packaging.utils import (
    InvalidSdistFilename,
    InvalidWheelFilename,
    canonicalize_name,
    parse_sdist_filename,
    parse_wheel_filename,
)
from packaging.version import InvalidVersion, Version

CATALOG_PATH = PurePosixPath(".github/package-identity-catalog.json")
MANIFEST_PATH = PurePosixPath(".github/fixture-manifest.json")
CONTENT_ROOT = PurePosixPath("content/linux/opensource_packages")
WORKFLOW_ROOT = PurePosixPath(".github/workflows")
BATCH_PATH = WORKFLOW_ROOT / "test-all-packages-batch1.yml"
MAX_FILE_BYTES = 20_000_000
MAX_BATCH_JOBS = 45
MAX_PYPI_RESPONSE_BYTES = 5_000_000

_SLUG_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_VERSION_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._+!-]{0,127}$")
_PIP_DISTRIBUTION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_PYTHON_IMPORT_RE = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]{0,127}(?:\.[A-Za-z_][A-Za-z0-9_]{0,127})*$"
)
_GITHUB_REPOSITORY_RE = re.compile(
    r"^https://github\.com/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/"
    r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$"
)
_PACKAGE_WORKFLOW_RE = re.compile(r"^test-([a-z0-9]+(?:-[a-z0-9]+)*)\.yml$")
_BATCH_WORKFLOW_RE = re.compile(r"^test-all-packages-batch([1-9][0-9]*)\.yml$")
_BATCH_PACKAGE_USE_RE = re.compile(
    r"^\./\.github/workflows/(test-[a-z0-9]+(?:-[a-z0-9]+)*\.yml)$"
)
_CONTEXT_EXPRESSION_RE = re.compile(r"\$\{\{(.*?)\}\}", re.DOTALL)
_SECRET_CONTEXT_RE = re.compile(r"\bsecrets\b", re.IGNORECASE)
_GITHUB_TOKEN_RE = re.compile(
    r"\bgithub\s*(?:\.\s*token\b|\[\s*['\"]token['\"]\s*\])",
    re.IGNORECASE,
)
_WHOLE_GITHUB_CONTEXT_RE = re.compile(
    r"(?:tojson|fromjson)\s*\(\s*github\s*\)|^\s*github\s*$",
    re.IGNORECASE,
)
_ALLOWED_CHECKOUTS = {
    "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
    "actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803",
}
_ALLOWED_LOCAL_ACTIONS = {"./.github/actions/emit-package-result"}
_COLLECT_ACTION = "./.github/actions/collect-batch-results"
_ATTESTED_UPLOAD = "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
_REQUIRED_OUTPUTS = (
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
_EVIDENCE_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")
_EVIDENCE_ROOT = PurePosixPath(".arm-validation-evidence")
_APPROVED_REGRESSION_DEFERRALS = {
    "no_newer_stable_available",
    "not_applicable_package_manager",
    "runtime_validation_not_automated",
}
_FORBIDDEN_OUTPUT_SENTINELS = {"not_configured", "unknown"}
_ISOLATED_IMAGE_DIGEST = (
    "sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90"
)
_TEMPLATE_WORKFLOW = WORKFLOW_ROOT / "test-numpy.yml"
_DYNAMIC_JOB_OUTPUTS = {
    "package_slug",
    "package_name",
    "package_version",
    "regression_current_version",
    "regression_latest_version",
    "regression_policy",
    "dashboard_link",
}
_DYNAMIC_SUMMARY_INPUTS = {
    "package_slug",
    "package_name",
    "version",
    "regression_current_version",
    "regression_latest_version",
}
_AUTOMATION_IDENTITY = "ecosystem-package-onboarding/package-identity-catalog@1.1"
_APPROVED_PIP_IMPORT_ROOTS = {
    "beautifulsoup4": frozenset({"bs4"}),
    "pillow": frozenset({"PIL"}),
    "scikit-learn": frozenset({"sklearn"}),
}
_GIT = shutil.which("git")


class CandidateValidationError(ValueError):
    """Raised when a sandbox candidate is not one exact onboarding change."""


@dataclass(frozen=True)
class _WorkflowIdentity:
    package_name: str
    repository: str
    distribution: str
    import_module: str
    baseline_version: str
    candidate_version: str | None
    regression_mode: str


@dataclass(frozen=True)
class _TrustedPackageIdentity:
    package_name: str
    repository: str
    distribution: str
    import_module: str
    official_hosts: tuple[str, ...]


_TRUSTED_SANDBOX_PACKAGE_IDENTITIES = {
    "requests": _TrustedPackageIdentity(
        package_name="Requests",
        repository="https://github.com/psf/requests",
        distribution="requests",
        import_module="requests",
        official_hosts=("requests.readthedocs.io",),
    ),
}
_ARM_CONTENT_HOSTS = frozenset(
    {
        "community.arm.com",
        "developer.arm.com",
        "learn.arm.com",
        "www.arm.com",
    }
)
_DASHBOARD_CATEGORIES = frozenset(
    {
        "AI/ML",
        "Compilers/Tools",
        "Compression",
        "Containers and Orchestration",
        "Content mgmt platforms",
        "Crypto",
        "Data-format",
        "Database",
        "Databases - Big-data",
        "Databases - noSQL",
        "DevOps",
        "E-commerce platforms",
        "EDA",
        "Gaming",
        "HPC",
        "Languages and Frameworks",
        "Messaging/Comms",
        "Miscellaneous",
        "Monitoring/Observability",
        "Networking",
        "Operating System",
        "Runtimes",
        "Security applications",
        "Service Mesh",
        "Storage",
        "Video",
        "Web",
        "Web Server",
    }
)


class _GitHubWorkflowLoader(yaml.SafeLoader):
    """YAML 1.2-like loader that preserves GitHub's literal ``on`` key."""


_GitHubWorkflowLoader.yaml_implicit_resolvers = {
    character: [
        (tag, pattern) for tag, pattern in resolvers if tag != "tag:yaml.org,2002:bool"
    ]
    for character, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
_GitHubWorkflowLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool",
    re.compile(r"^(?:true|false)$", re.IGNORECASE),
    list("tTfF"),
)  # type: ignore[no-untyped-call]


def _construct_unique_mapping(
    loader: _GitHubWorkflowLoader,
    node: yaml.nodes.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as exc:
            raise CandidateValidationError(
                "workflow YAML contains an unhashable key"
            ) from exc
        if duplicate:
            raise CandidateValidationError(
                f"workflow YAML contains duplicate key: {key}"
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_GitHubWorkflowLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _safe_root(path: Path) -> Path:
    root = path.expanduser().resolve(strict=True)
    if not root.is_dir():
        raise CandidateValidationError(f"repository root is not a directory: {root}")
    return root


def _path(root: Path, relative: PurePosixPath) -> Path:
    if relative.is_absolute() or ".." in relative.parts:
        raise CandidateValidationError(f"unsafe repository path: {relative}")
    candidate = root.joinpath(*relative.parts)
    resolved_parent = candidate.parent.resolve(strict=True)
    expected_parent = root.joinpath(*relative.parent.parts).resolve(strict=True)
    if resolved_parent != expected_parent:
        raise CandidateValidationError(f"path escapes repository root: {relative}")
    return candidate


def _read(root: Path, relative: PurePosixPath) -> bytes:
    candidate = _path(root, relative)
    if candidate.is_symlink() or not candidate.is_file():
        raise CandidateValidationError(f"required regular file is missing: {relative}")
    size = candidate.stat().st_size
    if size > MAX_FILE_BYTES:
        raise CandidateValidationError(f"file exceeds bounded size: {relative}")
    return candidate.read_bytes()


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _json(payload: bytes, label: str) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise CandidateValidationError(f"{label} has duplicate key: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(payload, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CandidateValidationError(f"{label} is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise CandidateValidationError(f"{label} must contain one JSON object")
    return value


def _yaml(payload: bytes, label: str) -> dict[str, Any]:
    try:
        text = payload.decode("utf-8")
        value = yaml.load(text, Loader=_GitHubWorkflowLoader)
    except UnicodeDecodeError as exc:
        raise CandidateValidationError(f"{label} is not valid UTF-8 YAML") from exc
    except yaml.YAMLError as exc:
        raise CandidateValidationError(f"{label} is not valid YAML") from exc
    return _mapping(value, label)


def _mapping(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise CandidateValidationError(f"{label} must be a string-keyed mapping")
    return value


def _steps(value: object, label: str) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise CandidateValidationError(f"{label} must be a sequence")
    result: list[dict[str, Any]] = []
    for index, step in enumerate(value, start=1):
        result.append(_mapping(step, f"{label} step {index}"))
    if not result:
        raise CandidateValidationError(f"{label} must not be empty")
    return result


def _contains_sensitive_context(value: object) -> bool:
    if isinstance(value, Mapping):
        return any(
            (isinstance(key, str) and key.casefold() == "secrets")
            or _contains_sensitive_context(key)
            or _contains_sensitive_context(item)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(_contains_sensitive_context(item) for item in value)
    if not isinstance(value, str):
        return False
    for expression in _CONTEXT_EXPRESSION_RE.findall(value):
        if (
            _SECRET_CONTEXT_RE.search(expression)
            or _GITHUB_TOKEN_RE.search(expression)
            or _WHOLE_GITHUB_CONTEXT_RE.search(expression)
        ):
            return True
    return False


def _require_exact_keys(
    value: Mapping[str, Any], expected: set[str], label: str
) -> None:
    if set(value) != expected:
        raise CandidateValidationError(f"{label} must contain the exact approved keys")


def _normalize_pip_identity(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).casefold()


def _canonical_url_path_parts(parsed: SplitResult, label: str) -> tuple[str, ...]:
    decoded_path = parsed.path
    for _ in range(8):
        if re.search(r"%(?![0-9a-f]{2})", decoded_path, re.IGNORECASE):
            raise CandidateValidationError(f"{label} contains malformed URL encoding")
        if re.search(r"%(?:2e|2f|5c)", decoded_path, re.IGNORECASE):
            raise CandidateValidationError(f"{label} contains an encoded path boundary")
        try:
            next_path = unquote_to_bytes(decoded_path).decode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise CandidateValidationError(
                f"{label} contains invalid UTF-8 URL encoding"
            ) from exc
        if next_path == decoded_path:
            break
        decoded_path = next_path
    else:
        raise CandidateValidationError(
            f"{label} URL encoding does not stabilize within the approved bound"
        )
    if re.search(r"%(?:2e|2f|5c)", decoded_path, re.IGNORECASE):
        raise CandidateValidationError(f"{label} contains an encoded path boundary")
    if (
        "\\" in decoded_path
        or "\x00" in decoded_path
        or any(ord(character) < 32 for character in decoded_path)
        or "//" in decoded_path
    ):
        raise CandidateValidationError(f"{label} contains a noncanonical path")
    parts = tuple(part for part in decoded_path.strip("/").split("/") if part)
    if any(part in {".", ".."} for part in parts):
        raise CandidateValidationError(f"{label} contains a dot path segment")
    return parts


def _stable_pep440_version(value: str, label: str) -> Version:
    try:
        parsed = Version(value)
    except InvalidVersion as exc:
        raise CandidateValidationError(
            f"{label} is not a valid PEP 440 version"
        ) from exc
    if parsed.is_prerelease or parsed.is_devrelease or parsed.local is not None:
        raise CandidateValidationError(f"{label} must identify a stable public release")
    return parsed


def _approved_import_root(distribution: str, import_module: str) -> bool:
    import_root = import_module.split(".", 1)[0]
    normalized_distribution = _normalize_pip_identity(distribution)
    if _normalize_pip_identity(import_root) == normalized_distribution:
        return True
    return import_root in _APPROVED_PIP_IMPORT_ROOTS.get(
        normalized_distribution,
        frozenset(),
    )


def _artifact_filename_identity(raw_url: str, label: str) -> tuple[str, Version]:
    parsed = urlsplit(raw_url)
    filename = unquote(PurePosixPath(parsed.path).name)
    try:
        if filename.endswith(".whl"):
            distribution, version, _, _ = parse_wheel_filename(filename)
        else:
            distribution, version = parse_sdist_filename(filename)
    except (InvalidSdistFilename, InvalidWheelFilename) as exc:
        raise CandidateValidationError(
            f"generated registry artifact filename is not a valid Python distribution: {label}"
        ) from exc
    return str(distribution), version


def _git_output(root: Path, *arguments: str) -> str:
    if _GIT is None:
        raise CandidateValidationError(
            "Git is required to bind trusted base provenance"
        )
    try:
        completed = subprocess.run(
            [_GIT, "-C", str(root), *arguments],
            check=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CandidateValidationError(
            "trusted base Git provenance could not be read"
        ) from exc
    if completed.returncode != 0:
        raise CandidateValidationError("trusted base Git provenance could not be read")
    try:
        return completed.stdout.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise CandidateValidationError(
            "trusted base Git provenance is not UTF-8"
        ) from exc


def _trusted_base_provenance(root: Path) -> tuple[str, datetime]:
    source_revision = _git_output(root, "rev-parse", "--verify", "HEAD^{commit}")
    if _GIT_SHA_RE.fullmatch(source_revision) is None:
        raise CandidateValidationError(
            "trusted base revision is not an immutable commit"
        )
    raw_timestamp = _git_output(
        root,
        "show",
        "-s",
        "--format=%cI",
        source_revision,
    )
    try:
        verified_at = datetime.fromisoformat(raw_timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CandidateValidationError(
            "trusted base commit time is not valid ISO-8601"
        ) from exc
    if verified_at.utcoffset() is None:
        raise CandidateValidationError("trusted base commit time lacks a timezone")
    return source_revision, verified_at


def _frontmatter(payload: bytes, label: str) -> dict[str, Any]:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CandidateValidationError(f"{label} is not valid UTF-8") from exc
    if not text.startswith("---\n"):
        raise CandidateValidationError(f"{label} lacks canonical YAML front matter")
    boundary = text.find("\n---\n", 4)
    if boundary < 0:
        raise CandidateValidationError(f"{label} has unterminated YAML front matter")
    try:
        value = yaml.load(text[4:boundary], Loader=_GitHubWorkflowLoader)
    except yaml.YAMLError as exc:
        raise CandidateValidationError(
            f"{label} front matter is not valid YAML"
        ) from exc
    return _mapping(value, f"{label} front matter")


def _tree(root: Path) -> dict[PurePosixPath, str]:
    files: dict[PurePosixPath, str] = {}
    for candidate in sorted(root.rglob("*")):
        relative = PurePosixPath(candidate.relative_to(root).as_posix())
        if relative.parts and relative.parts[0] == ".git":
            continue
        if candidate.is_symlink():
            raise CandidateValidationError(f"repository contains symlink: {relative}")
        if candidate.is_dir():
            continue
        if not candidate.is_file():
            raise CandidateValidationError(
                f"repository contains nonregular entry: {relative}"
            )
        size = candidate.stat().st_size
        if size > MAX_FILE_BYTES:
            raise CandidateValidationError(f"file exceeds bounded size: {relative}")
        files[relative] = _sha256(candidate.read_bytes())
    return files


def _manifest_hashes(manifest: dict[str, Any]) -> dict[PurePosixPath, str]:
    expected: dict[PurePosixPath, str] = {}
    for section in (
        "source_files",
        "service_support_files",
        "fixture_control_files",
        "evidence",
    ):
        records = manifest.get(section)
        if not isinstance(records, dict) or not records:
            raise CandidateValidationError(f"fixture manifest lacks {section}")
        for raw_path, digest in records.items():
            if not isinstance(raw_path, str) or not isinstance(digest, str):
                raise CandidateValidationError(
                    f"fixture manifest {section} is malformed"
                )
            relative = PurePosixPath(raw_path)
            if relative.is_absolute() or ".." in relative.parts:
                raise CandidateValidationError(
                    f"fixture manifest contains unsafe path: {raw_path}"
                )
            if _SHA256_RE.fullmatch(digest) is None:
                raise CandidateValidationError(
                    f"fixture manifest contains invalid digest: {raw_path}"
                )
            if relative in expected and expected[relative] != digest:
                raise CandidateValidationError(
                    f"fixture manifest conflicts for path: {raw_path}"
                )
            expected[relative] = digest
    return expected


def _records(catalog: dict[str, Any], label: str) -> dict[str, dict[str, Any]]:
    raw_records = catalog.get("records")
    if not isinstance(raw_records, list):
        raise CandidateValidationError(f"{label} records must be an array")
    records: dict[str, dict[str, Any]] = {}
    for record in raw_records:
        if not isinstance(record, dict):
            raise CandidateValidationError(f"{label} record must be an object")
        path = record.get("content_path")
        if not isinstance(path, str) or path in records:
            raise CandidateValidationError(
                f"{label} contains a missing or duplicate content path"
            )
        records[path] = record
    return records


def _package_pages(files: dict[PurePosixPath, str]) -> set[PurePosixPath]:
    return {
        path
        for path in files
        if path.parent == CONTENT_ROOT
        and path.suffix == ".md"
        and path.name not in {"_index.md", "index.md"}
    }


def _package_workflows(files: dict[PurePosixPath, str]) -> set[PurePosixPath]:
    result: set[PurePosixPath] = set()
    for path in files:
        if path.parent != WORKFLOW_ROOT:
            continue
        if path.name.startswith("test-all-packages-"):
            continue
        if _PACKAGE_WORKFLOW_RE.fullmatch(path.name):
            result.add(path)
    return result


def _batch_registrations_and_needs(
    workflow: dict[str, Any],
    *,
    batch_number: int,
) -> tuple[list[str], list[str]]:
    jobs = _mapping(workflow.get("jobs"), f"batch {batch_number} jobs")
    summary = _mapping(jobs.get("summary"), f"batch {batch_number} summary")
    registrations: dict[str, str] = {}
    for job_id, raw_job in jobs.items():
        if job_id == "summary":
            continue
        job = _mapping(raw_job, f"batch {batch_number} job {job_id}")
        if set(job) != {"uses"} or not isinstance(job.get("uses"), str):
            raise CandidateValidationError(
                f"batch {batch_number} package job {job_id} must only call one local workflow"
            )
        match = _BATCH_PACKAGE_USE_RE.fullmatch(job["uses"])
        if match is None:
            raise CandidateValidationError(
                f"batch {batch_number} package job {job_id} has an invalid workflow call"
            )
        registrations[job_id] = match.group(1)

    raw_needs = summary.get("needs")
    if not isinstance(raw_needs, list) or any(
        not isinstance(item, str) for item in raw_needs
    ):
        raise CandidateValidationError(
            f"batch {batch_number} summary.needs is malformed"
        )
    needs = list(raw_needs)
    if set(needs) != set(registrations) or len(needs) != len(set(needs)):
        raise CandidateValidationError(
            f"batch {batch_number} summary.needs must match package jobs exactly"
        )
    return list(registrations.values()), needs


def _validate_batch_registry(
    candidate_root: Path,
    package_workflows: set[PurePosixPath],
) -> None:
    workflow_directory = _path(candidate_root, WORKFLOW_ROOT)
    batch_files: list[tuple[int, Path]] = []
    for path in workflow_directory.glob("test-all-packages-batch*.yml"):
        match = _BATCH_WORKFLOW_RE.fullmatch(path.name)
        if match is None:
            raise CandidateValidationError(f"invalid batch workflow name: {path.name}")
        batch_files.append((int(match.group(1)), path))
    batch_files.sort()
    numbers = [number for number, _ in batch_files]
    if numbers != list(range(1, len(numbers) + 1)):
        raise CandidateValidationError("batch workflow numbers must be contiguous")

    registered: list[str] = []
    for number, path in batch_files:
        if path.is_symlink() or not path.is_file():
            raise CandidateValidationError(f"unsafe batch workflow: {path.name}")
        workflow = _yaml(path.read_bytes(), f"batch {number} workflow")
        if _contains_sensitive_context(workflow):
            raise CandidateValidationError(
                f"batch {number} must not receive credentials"
            )
        permissions = _mapping(
            workflow.get("permissions"),
            f"batch {number} top-level permissions",
        )
        if permissions != {"contents": "read"}:
            raise CandidateValidationError(
                f"batch {number} top-level permissions must be contents: read only"
            )
        triggers = _mapping(workflow.get("on"), f"batch {number} triggers")
        if set(triggers) != {"workflow_call", "workflow_dispatch"}:
            raise CandidateValidationError(
                f"batch {number} must use only the approved reusable/manual triggers"
            )

        jobs = _mapping(workflow.get("jobs"), f"batch {number} jobs")
        summary = _mapping(jobs.get("summary"), f"batch {number} summary")
        if summary.get("runs-on") != "ubuntu-24.04-arm":
            raise CandidateValidationError(
                f"batch {number} summary must use the GitHub-hosted Arm64 runner"
            )
        summary_permissions = _mapping(
            summary.get("permissions"),
            f"batch {number} summary permissions",
        )
        if summary_permissions != {"actions": "read", "contents": "read"}:
            raise CandidateValidationError(
                f"batch {number} summary permissions are not read-only"
            )
        steps = _steps(summary.get("steps"), f"batch {number} summary steps")
        checkout = [
            step
            for step in steps
            if step.get("uses")
            == "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
        ]
        collect = [
            step
            for step in steps
            if step.get("id") == "collect" and step.get("uses") == _COLLECT_ACTION
        ]
        attest = [step for step in steps if step.get("id") == "attest"]
        upload = [step for step in steps if step.get("uses") == _ATTESTED_UPLOAD]
        if (
            len(checkout) != 1
            or _mapping(checkout[0].get("with"), f"batch {number} checkout.with")
            != {"persist-credentials": False}
            or len(collect) != 1
            or len(attest) != 1
            or len(upload) != 1
        ):
            raise CandidateValidationError(
                f"batch {number} must retain pinned summary actions"
            )
        attest_run = attest[0].get("run")
        executable_attestation_lines = (
            [
                line.strip()
                for line in attest_run.splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            ]
            if isinstance(attest_run, str)
            else []
        )
        if (
            attest[0].get("name") != "Attest complete batch results"
            or attest[0].get("if") != "steps.collect.outcome == 'success'"
            or not any(
                line.startswith(
                    "python3 .github/scripts/batch_artifact_attestation.py create"
                )
                for line in executable_attestation_lines
            )
            or upload[0].get("if")
            != "steps.collect.outcome == 'success' && steps.attest.outcome == 'success'"
        ):
            raise CandidateValidationError(
                f"batch {number} must retain artifact attestation"
            )
        batch_registrations, _ = _batch_registrations_and_needs(
            workflow,
            batch_number=number,
        )
        if not batch_registrations or len(batch_registrations) > MAX_BATCH_JOBS:
            raise CandidateValidationError(
                f"batch {number} must contain 1-{MAX_BATCH_JOBS} package jobs"
            )
        registered.extend(batch_registrations)

    expected = sorted(path.name for path in package_workflows)
    if sorted(registered) != expected or len(registered) != len(set(registered)):
        raise CandidateValidationError(
            "batch registry must register every package workflow exactly once"
        )


def _decode_canonical_environment_json(
    environment: Mapping[str, Any],
    *,
    encoded_name: str,
    digest_name: str,
    label: str,
) -> object:
    encoded = environment.get(encoded_name)
    digest = environment.get(digest_name)
    if (
        not isinstance(encoded, str)
        or not encoded
        or not isinstance(digest, str)
        or _SHA256_RE.fullmatch(digest) is None
    ):
        raise CandidateValidationError(f"{label} encoding or digest is malformed")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise CandidateValidationError(f"{label} is not canonical base64") from exc
    if base64.b64encode(raw).decode("ascii") != encoded:
        raise CandidateValidationError(f"{label} is not canonical base64")

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise CandidateValidationError(f"{label} contains duplicate key: {key}")
            result[key] = value
        return result

    try:
        payload = json.loads(raw, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CandidateValidationError(f"{label} is not valid UTF-8 JSON") from exc
    canonical = json.dumps(
        payload,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    if raw != canonical or _sha256(canonical) != digest:
        raise CandidateValidationError(f"{label} is not canonical or digest-bound")
    return payload


def _canonical_environment_identity(
    environment: Mapping[str, Any],
    *,
    slug: str,
    label: str,
) -> _WorkflowIdentity:
    if environment.get("SMOKE_PACKAGE_SLUG") != slug:
        raise CandidateValidationError(
            f"generated package workflow env slug does not match: {label}"
        )
    repository = environment.get("SMOKE_PACKAGE_REPOSITORY")
    if (
        not isinstance(repository, str)
        or _GITHUB_REPOSITORY_RE.fullmatch(repository) is None
    ):
        raise CandidateValidationError(
            f"generated package workflow repository is not canonical: {label}"
        )
    encoded_name = environment.get("SMOKE_PACKAGE_NAME_B64")
    if not isinstance(encoded_name, str) or not encoded_name:
        raise CandidateValidationError(
            f"generated package workflow package name is malformed: {label}"
        )
    try:
        name_bytes = base64.b64decode(encoded_name, validate=True)
        package_name = name_bytes.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError) as exc:
        raise CandidateValidationError(
            f"generated package workflow package name is not canonical base64: {label}"
        ) from exc
    if (
        base64.b64encode(name_bytes).decode("ascii") != encoded_name
        or not package_name.strip()
        or package_name != package_name.strip()
        or len(package_name) > 200
        or any(ord(character) < 32 for character in package_name)
    ):
        raise CandidateValidationError(
            f"generated package workflow package name is malformed: {label}"
        )

    plan = _decode_canonical_environment_json(
        environment,
        encoded_name="SMOKE_PLAN_B64",
        digest_name="SMOKE_PLAN_DIGEST",
        label=f"generated smoke plan {label}",
    )
    pins = _decode_canonical_environment_json(
        environment,
        encoded_name="SMOKE_ARTIFACT_PINS_B64",
        digest_name="SMOKE_ARTIFACT_PINS_DIGEST",
        label=f"generated artifact pins {label}",
    )
    if not isinstance(plan, dict) or set(plan) != {
        "baseline_version",
        "evidence_urls",
        "functional_probe",
        "recipe",
        "regression_policy",
        "schema_version",
        "version_probe",
    }:
        raise CandidateValidationError(
            f"generated smoke plan shape is invalid: {label}"
        )
    baseline_version = plan.get("baseline_version")
    recipe = plan.get("recipe")
    regression = plan.get("regression_policy")
    if (
        plan.get("schema_version") != "1.0"
        or not isinstance(baseline_version, str)
        or _VERSION_RE.fullmatch(baseline_version) is None
        or not isinstance(recipe, dict)
        or set(recipe) != {"distribution", "import_module", "kind"}
        or recipe.get("kind") != "pip"
        or not isinstance(recipe.get("distribution"), str)
        or _PIP_DISTRIBUTION_RE.fullmatch(recipe["distribution"]) is None
        or not isinstance(recipe.get("import_module"), str)
        or _PYTHON_IMPORT_RE.fullmatch(recipe["import_module"]) is None
        or not isinstance(regression, dict)
        or set(regression)
        != {"candidate_version", "deferral_decision", "mode", "rationale"}
        or regression.get("mode") not in {"strict", "approved_deferral"}
        or not isinstance(regression.get("rationale"), str)
        or not 10 <= len(regression["rationale"]) <= 2000
    ):
        raise CandidateValidationError(
            f"generated smoke plan policy is invalid: {label}"
        )
    distribution = recipe["distribution"]
    import_module = recipe["import_module"]
    baseline_pep440 = _stable_pep440_version(
        baseline_version,
        f"generated smoke plan baseline version {label}",
    )
    if not _approved_import_root(distribution, import_module):
        raise CandidateValidationError(
            f"generated pip import root is not in the trusted distribution mapping: {label}"
        )

    if plan.get("version_probe") != {
        "arguments": ["smoke_version.py"],
        "program": "python3",
        "timeout_seconds": 30,
    }:
        raise CandidateValidationError(
            f"generated pip version probe is not canonical: {label}"
        )
    functional_probe = plan.get("functional_probe")
    if not isinstance(functional_probe, dict) or set(functional_probe) != {
        "assertions",
        "invocation",
    }:
        raise CandidateValidationError(
            f"generated pip functional probe is not canonical: {label}"
        )
    if functional_probe.get("invocation") != {
        "arguments": ["smoke_import.py"],
        "program": "python3",
        "timeout_seconds": 60,
    }:
        raise CandidateValidationError(
            f"generated pip functional invocation is not canonical: {label}"
        )
    assertions = functional_probe.get("assertions")
    if not isinstance(assertions, list) or len(assertions) not in {1, 2}:
        raise CandidateValidationError(
            f"generated pip functional assertions are not canonical: {label}"
        )
    expected_marker = {
        "case_sensitive": True,
        "kind": "output_contains",
        "value": f"import_ok:{import_module}",
    }
    marker_count = sum(assertion == expected_marker for assertion in assertions)
    exit_count = sum(
        assertion == {"expected": 0, "kind": "exit_code"} for assertion in assertions
    )
    if marker_count != 1 or marker_count + exit_count != len(assertions):
        raise CandidateValidationError(
            f"generated pip functional assertions can only prove a successful import: {label}"
        )

    evidence_urls = plan.get("evidence_urls")
    if (
        not isinstance(evidence_urls, list)
        or not 1 <= len(evidence_urls) <= 8
        or len(evidence_urls) != len(set(evidence_urls))
        or any(not isinstance(url, str) for url in evidence_urls)
    ):
        raise CandidateValidationError(
            f"generated smoke plan evidence URLs are invalid: {label}"
        )
    normalized_distribution = _normalize_pip_identity(distribution)
    expected_pypi_path = f"/pypi/{distribution}/json"
    repository_parts = tuple(urlsplit(repository).path.strip("/").split("/"))
    pypi_bound = False
    repository_bound = False
    for evidence_url in evidence_urls:
        try:
            parsed_evidence = urlsplit(evidence_url)
            evidence_port = parsed_evidence.port
        except ValueError as exc:
            raise CandidateValidationError(
                f"generated smoke plan evidence URL is malformed: {label}"
            ) from exc
        if (
            parsed_evidence.scheme != "https"
            or parsed_evidence.username is not None
            or parsed_evidence.password is not None
            or evidence_port not in (None, 443)
            or parsed_evidence.query
            or parsed_evidence.fragment
        ):
            raise CandidateValidationError(
                f"generated smoke plan evidence URL is not canonical: {label}"
            )
        if (
            parsed_evidence.hostname == "pypi.org"
            and _normalize_pip_identity(
                parsed_evidence.path.removeprefix("/pypi/").removesuffix("/json")
            )
            == normalized_distribution
            and parsed_evidence.path.casefold() == expected_pypi_path.casefold()
        ):
            pypi_bound = True
        evidence_parts = _canonical_url_path_parts(
            parsed_evidence,
            f"generated smoke plan evidence URL {label}",
        )
        if (
            parsed_evidence.hostname == "github.com"
            and len(evidence_parts) >= 2
            and tuple(part.casefold() for part in evidence_parts[:2])
            == tuple(part.casefold() for part in repository_parts)
        ):
            repository_bound = True
    if not pypi_bound or not repository_bound:
        raise CandidateValidationError(
            f"generated smoke plan does not bind its pip and source identities: {label}"
        )

    candidate_version = regression.get("candidate_version")
    if candidate_version is not None and (
        not isinstance(candidate_version, str)
        or _VERSION_RE.fullmatch(candidate_version) is None
    ):
        raise CandidateValidationError(
            f"generated smoke plan candidate version is invalid: {label}"
        )
    regression_mode = regression["mode"]
    if regression_mode == "strict":
        if candidate_version is None or regression.get("deferral_decision") is not None:
            raise CandidateValidationError(
                f"generated strict regression policy is invalid: {label}"
            )
        candidate_pep440 = _stable_pep440_version(
            candidate_version,
            f"generated smoke plan candidate version {label}",
        )
        if candidate_pep440 <= baseline_pep440:
            raise CandidateValidationError(
                f"generated strict regression candidate is not newer than baseline: {label}"
            )
    elif (
        candidate_version is not None
        or regression.get("deferral_decision") not in _APPROVED_REGRESSION_DEFERRALS
    ):
        raise CandidateValidationError(
            f"generated deferred regression policy is invalid: {label}"
        )
    if (
        not isinstance(pins, list)
        or not pins
        or any(
            not isinstance(pin, dict)
            or set(pin)
            != {
                "artifact_integrity",
                "artifact_sha256",
                "artifact_urls",
                "recipe_kind",
                "schema_version",
                "version",
            }
            or pin.get("schema_version") != "1.0"
            or pin.get("recipe_kind") != "pip"
            or pin.get("artifact_integrity") is not None
            or not isinstance(pin.get("version"), str)
            or _VERSION_RE.fullmatch(pin["version"]) is None
            or not isinstance(pin.get("artifact_urls"), list)
            or not pin["artifact_urls"]
            or pin["artifact_urls"] != sorted(set(pin["artifact_urls"]))
            or not isinstance(pin.get("artifact_sha256"), list)
            or not pin["artifact_sha256"]
            or pin["artifact_sha256"] != sorted(set(pin["artifact_sha256"]))
            or any(
                not isinstance(digest, str) or _SHA256_RE.fullmatch(digest) is None
                for digest in pin["artifact_sha256"]
            )
            for pin in pins
        )
    ):
        raise CandidateValidationError(
            f"generated registry artifact pins are invalid: {label}"
        )
    required_versions = [baseline_version]
    if regression_mode == "strict" and candidate_version is not None:
        required_versions.append(candidate_version)
    if [pin["version"] for pin in pins] != required_versions:
        raise CandidateValidationError(
            f"generated registry artifact pins do not exactly match required versions: {label}"
        )
    for pin in pins:
        pin_version = _stable_pep440_version(
            pin["version"],
            f"generated registry artifact version {label}",
        )
        for raw_url in pin["artifact_urls"]:
            if not isinstance(raw_url, str):
                raise CandidateValidationError(
                    f"generated registry artifact URL is malformed: {label}"
                )
            try:
                parsed = urlsplit(raw_url)
                artifact_port = parsed.port
            except ValueError as exc:
                raise CandidateValidationError(
                    f"generated registry artifact URL is malformed: {label}"
                ) from exc
            if (
                parsed.scheme != "https"
                or parsed.hostname != "files.pythonhosted.org"
                or parsed.username is not None
                or parsed.password is not None
                or artifact_port not in (None, 443)
                or not parsed.path.startswith("/packages/")
                or parsed.query
                or parsed.fragment
            ):
                raise CandidateValidationError(
                    f"generated registry artifact URL is not approved: {label}"
                )
            artifact_parts = _canonical_url_path_parts(
                parsed,
                f"generated registry artifact URL {label}",
            )
            if not artifact_parts or artifact_parts[0] != "packages":
                raise CandidateValidationError(
                    f"generated registry artifact URL is outside the approved path: {label}"
                )
            artifact_distribution, artifact_version = _artifact_filename_identity(
                raw_url,
                label,
            )
            if (
                canonicalize_name(artifact_distribution)
                != canonicalize_name(distribution)
                or artifact_version != pin_version
            ):
                raise CandidateValidationError(
                    f"generated registry artifact does not match its pip identity and version: {label}"
                )
    return _WorkflowIdentity(
        package_name=package_name,
        repository=repository,
        distribution=distribution,
        import_module=import_module,
        baseline_version=baseline_version,
        candidate_version=candidate_version,
        regression_mode=regression_mode,
    )


def _normalized_package_template(
    workflow: dict[str, Any],
    *,
    slug: str,
    label: str,
) -> dict[str, Any]:
    normalized = copy.deepcopy(workflow)
    if normalized.get("name") != f"Test {slug} on Arm64":
        raise CandidateValidationError(
            f"generated package workflow name is not canonical: {label}"
        )
    normalized["name"] = "Test <PACKAGE> on Arm64"
    environment_identity: _WorkflowIdentity | None = None

    triggers = _mapping(normalized.get("on"), f"package workflow triggers {label}")
    workflow_call = _mapping(
        triggers.get("workflow_call"),
        f"package workflow workflow_call {label}",
    )
    call_outputs = _mapping(
        workflow_call.get("outputs"),
        f"package workflow_call outputs {label}",
    )
    for name in _REQUIRED_OUTPUTS:
        specification = _mapping(
            call_outputs.get(name),
            f"workflow_call output {name} {label}",
        )
        expected = f"${{{{ jobs.test-{slug}.outputs.{name} }}}}"
        if specification.get("value") != expected:
            raise CandidateValidationError(
                f"generated package workflow_call output is not canonical: {label}: {name}"
            )
        specification["value"] = f"${{{{ jobs.test-<PACKAGE>.outputs.{name} }}}}"

    environment = normalized.get("env")
    if environment is not None:
        env = _mapping(environment, f"package workflow env {label}")
        expected_env = {
            "SMOKE_PACKAGE_SLUG",
            "SMOKE_PACKAGE_NAME_B64",
            "SMOKE_PACKAGE_REPOSITORY",
            "SMOKE_ARTIFACT_PINS_B64",
            "SMOKE_ARTIFACT_PINS_DIGEST",
            "SMOKE_PLAN_B64",
            "SMOKE_PLAN_DIGEST",
        }
        if set(env) != expected_env or any(
            not isinstance(value, str) or not value for value in env.values()
        ):
            raise CandidateValidationError(
                f"generated package workflow env is not canonical: {label}"
            )
        if any("${{" in value for value in env.values()):
            raise CandidateValidationError(
                f"generated package workflow env must contain only literals: {label}"
            )
        environment_identity = _canonical_environment_identity(
            env,
            slug=slug,
            label=label,
        )
        for name in expected_env:
            env[name] = f"<DYNAMIC:{name}>"

    jobs = _mapping(normalized.get("jobs"), f"package workflow jobs {label}")
    job_id = f"test-{slug}"
    if set(jobs) != {job_id}:
        raise CandidateValidationError(
            f"package workflow must contain exactly one package job: {label}"
        )
    job = _mapping(jobs[job_id], f"package workflow job {label}")
    normalized["jobs"] = {"test-<PACKAGE>": job}

    outputs = _mapping(job.get("outputs"), f"package job outputs {label}")
    if environment_identity is not None:
        package_name = environment_identity.package_name
        baseline_version = environment_identity.baseline_version
        latest_version = (
            environment_identity.candidate_version
            or environment_identity.baseline_version
        )
        regression_mode = environment_identity.regression_mode
        expected_dynamic_outputs = {
            "package_slug": slug,
            "package_name": package_name,
            "package_version": baseline_version,
            "regression_current_version": baseline_version,
            "regression_latest_version": (
                f"${{{{ steps.test6.outputs.regression_latest_version || '{latest_version}' }}}}"
            ),
            "regression_policy": regression_mode,
            "dashboard_link": f"/opensource_packages/{slug}",
        }
        if any(
            outputs.get(name) != expected
            for name, expected in expected_dynamic_outputs.items()
        ):
            raise CandidateValidationError(
                f"generated package workflow dynamic outputs are inconsistent: {label}"
            )
    for name in _DYNAMIC_JOB_OUTPUTS:
        if name not in outputs:
            raise CandidateValidationError(
                f"generated package workflow lacks dynamic output {name}: {label}"
            )
        outputs[name] = f"<DYNAMIC:{name}>"

    steps = _steps(job.get("steps"), f"package workflow job steps {label}")
    prepare = [step for step in steps if step.get("id") == "prepare"]
    if len(prepare) != 1 or not isinstance(prepare[0].get("run"), str):
        raise CandidateValidationError(
            f"generated package workflow lacks canonical prepare step: {label}"
        )
    prepare_run = prepare[0]["run"]
    prepare_run = prepare_run.replace(
        f"arm-smoke-{slug}-executor.py",
        "arm-smoke-<PACKAGE>-executor.py",
    )
    prepare[0]["run"] = prepare_run.replace(
        f"arm-smoke-{slug}",
        "arm-smoke-<PACKAGE>",
    )

    summary = [step for step in steps if step.get("id") == "summary"]
    if len(summary) == 1 and "with" in summary[0]:
        summary_inputs = _mapping(
            summary[0].get("with"),
            f"package summary inputs {label}",
        )
        if environment_identity is not None:
            package_name = environment_identity.package_name
            baseline_version = environment_identity.baseline_version
            latest_version = (
                environment_identity.candidate_version
                or environment_identity.baseline_version
            )
            expected_dynamic_inputs = {
                "package_slug": slug,
                "package_name": package_name,
                "version": baseline_version,
                "regression_current_version": baseline_version,
                "regression_latest_version": (
                    "${{ steps.test6.outputs.regression_latest_version || "
                    f"'{latest_version}' }}}}"
                ),
            }
            if any(
                summary_inputs.get(name) != expected
                for name, expected in expected_dynamic_inputs.items()
            ):
                raise CandidateValidationError(
                    f"generated package summary dynamic inputs are inconsistent: {label}"
                )
        for name in _DYNAMIC_SUMMARY_INPUTS:
            if name not in summary_inputs:
                raise CandidateValidationError(
                    f"generated package summary lacks dynamic input {name}: {label}"
                )
            summary_inputs[name] = f"<DYNAMIC:{name}>"

    return normalized


def _candidate_workflow_identity(
    workflow: dict[str, Any],
    *,
    slug: str,
    label: str,
) -> _WorkflowIdentity:
    environment = _mapping(workflow.get("env"), f"package workflow env {label}")
    return _canonical_environment_identity(
        environment,
        slug=slug,
        label=label,
    )


def _frontmatter_text(
    value: object,
    label: str,
    *,
    required: bool,
    maximum: int = 4_000,
) -> str | None:
    if value is None and not required:
        return None
    if (
        not isinstance(value, str)
        or not value.strip()
        or value != value.strip()
        or len(value) > maximum
        or any(character in value for character in ("\x00", "\r", "\n"))
    ):
        raise CandidateValidationError(f"{label} is not canonical bounded text")
    return value


def _frontmatter_https_url(
    value: object,
    label: str,
    *,
    required: bool,
) -> str | None:
    text = _frontmatter_text(value, label, required=required, maximum=2_000)
    if text is None:
        return None
    try:
        parsed = urlsplit(text)
        port = parsed.port
    except ValueError as exc:
        raise CandidateValidationError(f"{label} is malformed") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
        or parsed.query
    ):
        raise CandidateValidationError(f"{label} is not canonical HTTPS")
    _canonical_url_path_parts(parsed, label)
    return text


def _identity_bound_public_url(
    value: object,
    label: str,
    *,
    identity: _WorkflowIdentity,
    trusted_identity: _TrustedPackageIdentity,
    required: bool,
) -> str | None:
    text = _frontmatter_https_url(value, label, required=required)
    if text is None:
        return None
    parsed = urlsplit(text)
    parts = _canonical_url_path_parts(parsed, label)
    repository_parts = _canonical_url_path_parts(
        urlsplit(identity.repository),
        "trusted package repository URL",
    )
    github_bound = (
        parsed.hostname == "github.com"
        and len(parts) >= 2
        and tuple(part.casefold() for part in parts[:2])
        == tuple(part.casefold() for part in repository_parts)
    )
    pypi_bound = (
        parsed.hostname == "pypi.org"
        and len(parts) >= 2
        and parts[0].casefold() == "project"
        and _normalize_pip_identity(parts[1])
        == _normalize_pip_identity(identity.distribution)
    )
    official_host_bound = parsed.hostname in trusted_identity.official_hosts
    if not github_bound and not pypi_bound and not official_host_bound:
        raise CandidateValidationError(
            f"{label} is not bound to the trusted package identity"
        )
    return text


def _trusted_pypi_release_date(distribution: str, version: str) -> date:
    encoded_distribution = quote(distribution, safe="")
    encoded_version = quote(version, safe="")
    expected_path = f"/pypi/{encoded_distribution}/{encoded_version}/json"
    url = f"https://pypi.org{expected_path}"
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "arm-ecosystem-sandbox-validator/1.0"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            final_url = urlsplit(response.geturl())
            final_port = final_url.port
            if (
                final_url.scheme != "https"
                or final_url.hostname != "pypi.org"
                or final_url.username is not None
                or final_url.password is not None
                or final_port not in (None, 443)
                or final_url.path.casefold() != expected_path.casefold()
                or final_url.query
                or final_url.fragment
            ):
                raise CandidateValidationError(
                    "trusted PyPI release lookup redirected outside its exact identity"
                )
            declared_length = response.headers.get("Content-Length")
            if (
                declared_length is not None
                and int(declared_length) > MAX_PYPI_RESPONSE_BYTES
            ):
                raise CandidateValidationError(
                    "trusted PyPI release response exceeds the bounded size"
                )
            payload = response.read(MAX_PYPI_RESPONSE_BYTES + 1)
    except CandidateValidationError:
        raise
    except (OSError, ValueError, urllib.error.URLError) as exc:
        raise CandidateValidationError(
            "trusted PyPI release evidence could not be retrieved"
        ) from exc
    if len(payload) > MAX_PYPI_RESPONSE_BYTES:
        raise CandidateValidationError(
            "trusted PyPI release response exceeds the bounded size"
        )
    document = _json(payload, "trusted PyPI release response")
    info = _mapping(document.get("info"), "trusted PyPI release info")
    if (
        not isinstance(info.get("name"), str)
        or _normalize_pip_identity(info["name"])
        != _normalize_pip_identity(distribution)
        or not isinstance(info.get("version"), str)
        or _stable_pep440_version(
            info["version"],
            "trusted PyPI release version",
        )
        != _stable_pep440_version(version, "tested baseline version")
    ):
        raise CandidateValidationError(
            "trusted PyPI release response does not match the tested identity"
        )
    urls = document.get("urls")
    if not isinstance(urls, list) or not urls:
        raise CandidateValidationError(
            "trusted PyPI release response has no installable release files"
        )
    upload_dates: list[date] = []
    for index, raw_file in enumerate(urls):
        file_record = _mapping(raw_file, f"trusted PyPI release file {index}")
        raw_timestamp = file_record.get("upload_time_iso_8601")
        if not isinstance(raw_timestamp, str):
            raise CandidateValidationError(
                "trusted PyPI release file lacks an upload timestamp"
            )
        try:
            timestamp = datetime.fromisoformat(raw_timestamp.replace("Z", "+00:00"))
        except ValueError as exc:
            raise CandidateValidationError(
                "trusted PyPI release file timestamp is invalid"
            ) from exc
        if timestamp.utcoffset() is None:
            raise CandidateValidationError(
                "trusted PyPI release file timestamp lacks a timezone"
            )
        upload_dates.append(timestamp.astimezone(UTC).date())
    return min(upload_dates)


def _validate_candidate_frontmatter(
    frontmatter: dict[str, Any],
    *,
    identity: _WorkflowIdentity,
    trusted_identity: _TrustedPackageIdentity,
    expected_minimum_release_date: date,
) -> None:
    _require_exact_keys(
        frontmatter,
        {
            "category",
            "description",
            "download_url",
            "name",
            "optional_hidden_info",
            "optional_info",
            "supported_minimum_version",
            "works_on_arm",
        },
        "candidate package front matter",
    )
    _frontmatter_text(frontmatter.get("name"), "candidate page name", required=True)
    category = _frontmatter_text(
        frontmatter.get("category"),
        "candidate page category",
        required=True,
        maximum=200,
    )
    if category not in _DASHBOARD_CATEGORIES:
        raise CandidateValidationError(
            "candidate page category is not in the approved dashboard taxonomy"
        )
    _frontmatter_text(
        frontmatter.get("description"),
        "candidate page description",
        required=True,
        maximum=2_000,
    )
    if frontmatter.get("works_on_arm") is not True:
        raise CandidateValidationError(
            "candidate page must make an explicit evidence-backed Arm support claim"
        )

    supported = _mapping(
        frontmatter.get("supported_minimum_version"),
        "candidate supported minimum version",
    )
    _require_exact_keys(
        supported,
        {"release_date", "version_number"},
        "candidate supported minimum version",
    )
    public_version = _frontmatter_text(
        supported.get("version_number"),
        "candidate supported minimum version number",
        required=True,
        maximum=128,
    )
    assert public_version is not None
    if _stable_pep440_version(
        public_version,
        "candidate supported minimum version number",
    ) != _stable_pep440_version(
        identity.baseline_version,
        "tested baseline version",
    ):
        raise CandidateValidationError(
            "candidate public minimum version does not match the tested baseline"
        )
    release_date = _frontmatter_text(
        supported.get("release_date"),
        "candidate supported minimum release date",
        required=True,
        maximum=10,
    )
    assert release_date is not None
    try:
        parsed_release_date = date.fromisoformat(release_date.replace("/", "-"))
    except ValueError as exc:
        raise CandidateValidationError(
            "candidate supported minimum release date is not YYYY/MM/DD"
        ) from exc
    if parsed_release_date.strftime("%Y/%m/%d") != release_date:
        raise CandidateValidationError(
            "candidate supported minimum release date is not canonical"
        )
    if parsed_release_date != expected_minimum_release_date:
        raise CandidateValidationError(
            "candidate supported minimum release date does not match trusted PyPI evidence"
        )

    optional = _mapping(frontmatter.get("optional_info"), "candidate optional info")
    _require_exact_keys(
        optional,
        {
            "alternative_options",
            "arm_recommended_minimum_version",
            "getting_started_resources",
            "homepage_url",
            "support_caveats",
        },
        "candidate optional info",
    )
    _identity_bound_public_url(
        optional.get("homepage_url"),
        "candidate homepage URL",
        identity=identity,
        trusted_identity=trusted_identity,
        required=False,
    )
    _frontmatter_text(
        optional.get("support_caveats"),
        "candidate support caveats",
        required=False,
    )
    _frontmatter_text(
        optional.get("alternative_options"),
        "candidate alternative options",
        required=False,
    )
    resources = _mapping(
        optional.get("getting_started_resources"),
        "candidate getting-started resources",
    )
    _require_exact_keys(
        resources,
        {"arm_content", "official_docs", "partner_content"},
        "candidate getting-started resources",
    )
    _identity_bound_public_url(
        resources.get("official_docs"),
        "candidate official documentation URL",
        identity=identity,
        trusted_identity=trusted_identity,
        required=False,
    )
    arm_content = _frontmatter_https_url(
        resources.get("arm_content"), "candidate Arm content URL", required=False
    )
    if (
        arm_content is not None
        and urlsplit(arm_content).hostname not in _ARM_CONTENT_HOSTS
    ):
        raise CandidateValidationError(
            "candidate Arm content URL is not on an approved Arm-owned domain"
        )
    partner_content = resources.get("partner_content")
    if partner_content is not None:
        raise CandidateValidationError(
            "candidate partner content is not approved in this bounded sandbox"
        )

    recommended = _mapping(
        optional.get("arm_recommended_minimum_version"),
        "candidate Arm recommended minimum version",
    )
    _require_exact_keys(
        recommended,
        {"rationale", "reference_content", "release_date", "version_number"},
        "candidate Arm recommended minimum version",
    )
    if any(value is not None for value in recommended.values()):
        raise CandidateValidationError(
            "candidate Arm recommendation requires a separately reviewed policy"
        )

    hidden = _mapping(
        frontmatter.get("optional_hidden_info"),
        "candidate optional hidden info",
    )
    _require_exact_keys(
        hidden,
        {
            "other_info",
            "release_notes__recommended_minimum",
            "release_notes__supported_minimum",
        },
        "candidate optional hidden info",
    )
    supported_evidence = _frontmatter_https_url(
        hidden.get("release_notes__supported_minimum"),
        "candidate supported-minimum evidence URL",
        required=True,
    )
    assert supported_evidence is not None
    parsed_supported_evidence = urlsplit(supported_evidence)
    evidence_parts = _canonical_url_path_parts(
        parsed_supported_evidence,
        "candidate supported-minimum evidence URL",
    )
    if (
        parsed_supported_evidence.hostname != "pypi.org"
        or parsed_supported_evidence.query
        or parsed_supported_evidence.fragment not in {"", "files"}
        or len(evidence_parts) != 3
        or evidence_parts[0].casefold() != "project"
        or _normalize_pip_identity(evidence_parts[1])
        != _normalize_pip_identity(identity.distribution)
        or _stable_pep440_version(
            evidence_parts[2],
            "candidate supported-minimum evidence version",
        )
        != _stable_pep440_version(
            identity.baseline_version,
            "tested baseline version",
        )
    ):
        raise CandidateValidationError(
            "candidate supported-minimum evidence is not bound to the tested PyPI release"
        )
    if hidden.get("release_notes__recommended_minimum") is not None:
        raise CandidateValidationError(
            "candidate recommended-minimum hidden evidence must remain null"
        )
    _frontmatter_text(
        hidden.get("other_info"),
        "candidate hidden notes",
        required=False,
    )


def _validate_candidate_semantic_binding(
    *,
    page_payload: bytes,
    workflow_payload: bytes,
    workflow: dict[str, Any],
    record: dict[str, Any],
    slug: str,
    expected_source_revision: str,
    expected_verified_at: datetime,
    expected_minimum_release_date: date | None,
) -> None:
    workflow_path = WORKFLOW_ROOT / f"test-{slug}.yml"
    identity = _candidate_workflow_identity(
        workflow,
        slug=slug,
        label=str(workflow_path),
    )
    trusted_identity = _TRUSTED_SANDBOX_PACKAGE_IDENTITIES.get(slug)
    if trusted_identity is None or (
        identity.package_name != trusted_identity.package_name
        or identity.repository != trusted_identity.repository
        or _normalize_pip_identity(identity.distribution)
        != _normalize_pip_identity(trusted_identity.distribution)
        or identity.import_module != trusted_identity.import_module
    ):
        raise CandidateValidationError(
            "candidate does not match a trusted sandbox package identity"
        )
    if identity.regression_mode != "strict" or identity.candidate_version is None:
        raise CandidateValidationError(
            "new sandbox candidates require a strict, executed Test 6"
        )
    minimum_release_date = (
        expected_minimum_release_date
        if expected_minimum_release_date is not None
        else _trusted_pypi_release_date(
            identity.distribution,
            identity.baseline_version,
        )
    )

    frontmatter = _frontmatter(
        page_payload,
        f"candidate package page {slug}",
    )
    _validate_candidate_frontmatter(
        frontmatter,
        identity=identity,
        trusted_identity=trusted_identity,
        expected_minimum_release_date=minimum_release_date,
    )
    if frontmatter.get("name") != identity.package_name:
        raise CandidateValidationError(
            "candidate page name does not match the tested package name"
        )
    download_url = frontmatter.get("download_url")
    if not isinstance(download_url, str) or not download_url:
        raise CandidateValidationError(
            "candidate page requires a canonical package download URL"
        )
    try:
        parsed_download = urlsplit(download_url)
        download_port = parsed_download.port
    except ValueError as exc:
        raise CandidateValidationError(
            "candidate page download URL is malformed"
        ) from exc
    if (
        parsed_download.scheme != "https"
        or parsed_download.username is not None
        or parsed_download.password is not None
        or download_port not in (None, 443)
        or parsed_download.query
        or parsed_download.fragment
    ):
        raise CandidateValidationError(
            "candidate page download URL is not canonical HTTPS"
        )
    download_parts = _canonical_url_path_parts(
        parsed_download,
        "candidate page download URL",
    )
    repository_parts = _canonical_url_path_parts(
        urlsplit(identity.repository),
        "trusted package repository URL",
    )
    pypi_download = (
        parsed_download.hostname == "pypi.org"
        and len(download_parts) == 2
        and download_parts[0].casefold() == "project"
        and _normalize_pip_identity(download_parts[1])
        == _normalize_pip_identity(identity.distribution)
    )
    repository_download = (
        parsed_download.hostname == "github.com"
        and len(download_parts) >= 2
        and tuple(part.casefold() for part in download_parts[:2])
        == tuple(part.casefold() for part in repository_parts)
        and (
            len(download_parts) == 2
            or download_parts[2:] == ("releases",)
            or download_parts[2:] == ("releases", "latest")
            or (
                len(download_parts) == 5
                and download_parts[2:4] == ("releases", "tag")
                and bool(download_parts[4])
            )
        )
    )
    if not pypi_download and not repository_download:
        raise CandidateValidationError(
            "candidate page download URL is not bound to the tested PyPI or GitHub identity"
        )

    registries = _mapping(record.get("registries"), "candidate catalog registries")
    if set(registries) != {"npm", "pip"}:
        raise CandidateValidationError(
            "candidate catalog must contain exact pip and npm dimensions"
        )
    pip_dimension = _mapping(
        registries.get("pip"),
        "candidate catalog pip dimension",
    )
    npm_dimension = _mapping(
        registries.get("npm"),
        "candidate catalog npm dimension",
    )
    pip_identities = pip_dimension.get("identities")
    expected_distribution = _normalize_pip_identity(identity.distribution)
    if (
        pip_dimension.get("status") != "verified"
        or pip_dimension.get("exhaustive") is not False
        or not isinstance(pip_identities, list)
        or len(pip_identities) != 1
        or not isinstance(pip_identities[0], str)
        or _normalize_pip_identity(pip_identities[0]) != expected_distribution
        or npm_dimension.get("status") != "unknown"
        or npm_dimension.get("exhaustive") is not False
        or npm_dimension.get("identities") != []
    ):
        raise CandidateValidationError(
            "candidate catalog registry identity does not match the tested pip distribution"
        )

    pip_evidence = pip_dimension.get("evidence")
    npm_evidence = npm_dimension.get("evidence")
    if (
        not isinstance(pip_evidence, list)
        or len(pip_evidence) != 1
        or not isinstance(npm_evidence, list)
        or len(npm_evidence) != 1
    ):
        raise CandidateValidationError(
            "candidate catalog dimensions require one workflow-bound evidence record each"
        )
    expected_rationales = {
        "pip": (
            f"Canonical generated workflow binds pip:{expected_distribution} "
            "to this package entry."
        ),
        "npm": (
            "Canonical generated workflow selects pip; whether this package also "
            "has npm identities remains unknown."
        ),
    }
    for dimension, raw_evidence in (
        ("pip", pip_evidence[0]),
        ("npm", npm_evidence[0]),
    ):
        evidence = _mapping(
            raw_evidence,
            f"candidate catalog {dimension} evidence",
        )
        verified_at = evidence.get("verified_at")
        try:
            parsed_verified_at = (
                datetime.fromisoformat(verified_at.replace("Z", "+00:00"))
                if isinstance(verified_at, str)
                else None
            )
        except ValueError:
            parsed_verified_at = None
        if (
            evidence.get("source_kind") != "generated_workflow"
            or evidence.get("source_locator") != workflow_path.as_posix()
            or evidence.get("source_revision") != expected_source_revision
            or evidence.get("evidence_sha256") != _sha256(workflow_payload)
            or evidence.get("verified_by") != _AUTOMATION_IDENTITY
            or parsed_verified_at != expected_verified_at
            or evidence.get("rationale") != expected_rationales[dimension]
        ):
            raise CandidateValidationError(
                f"candidate catalog {dimension} provenance is not bound to the trusted base and workflow"
            )


def _validate_batch_transition(
    base_root: Path,
    candidate_root: Path,
    *,
    package_slug: str,
) -> None:
    base_workflow = _yaml(_read(base_root, BATCH_PATH), "trusted base batch workflow")
    candidate_workflow = _yaml(
        _read(candidate_root, BATCH_PATH),
        "candidate batch workflow",
    )
    base_jobs = _mapping(base_workflow.get("jobs"), "trusted base batch jobs")
    candidate_jobs = _mapping(candidate_workflow.get("jobs"), "candidate batch jobs")
    job_id = f"test-{package_slug}"
    expected_order = [*list(base_jobs)[:-1], job_id, "summary"]
    if list(base_jobs)[-1:] != ["summary"] or list(candidate_jobs) != expected_order:
        raise CandidateValidationError(
            "candidate batch must append one package job immediately before summary"
        )
    expected_job = {
        "uses": f"./.github/workflows/test-{package_slug}.yml",
    }
    if candidate_jobs.get(job_id) != expected_job:
        raise CandidateValidationError(
            "candidate batch package job does not call the exact generated workflow"
        )

    base_summary = _mapping(base_jobs.get("summary"), "trusted base batch summary")
    candidate_summary = _mapping(
        candidate_jobs.get("summary"),
        "candidate batch summary",
    )
    base_needs = base_summary.get("needs")
    candidate_needs = candidate_summary.get("needs")
    if (
        not isinstance(base_needs, list)
        or any(not isinstance(item, str) for item in base_needs)
        or candidate_needs != [*base_needs, job_id]
    ):
        raise CandidateValidationError(
            "candidate batch summary.needs must append only the generated package job"
        )

    reduced = copy.deepcopy(candidate_workflow)
    reduced_jobs = _mapping(reduced.get("jobs"), "candidate batch jobs")
    del reduced_jobs[job_id]
    reduced_summary = _mapping(
        reduced_jobs.get("summary"),
        "candidate batch summary",
    )
    reduced_summary["needs"] = list(base_needs)
    if reduced != base_workflow:
        raise CandidateValidationError(
            "candidate changed the trusted batch contract outside its package registration"
        )


def _validate_package_workflow_security(
    candidate_root: Path,
    package_workflows: set[PurePosixPath],
) -> None:
    template = _yaml(
        _read(candidate_root, _TEMPLATE_WORKFLOW),
        "trusted package workflow template",
    )
    normalized_template = _normalized_package_template(
        template,
        slug="numpy",
        label=str(_TEMPLATE_WORKFLOW),
    )
    for relative in sorted(package_workflows):
        workflow = _yaml(
            _read(candidate_root, relative), f"package workflow {relative}"
        )
        if _contains_sensitive_context(workflow):
            raise CandidateValidationError(
                f"package workflow must not receive secrets: {relative}"
            )
        permissions = _mapping(
            workflow.get("permissions"),
            f"package workflow permissions {relative}",
        )
        if permissions != {"contents": "read"}:
            raise CandidateValidationError(
                f"package workflow permissions are not read-only: {relative}"
            )
        match = _PACKAGE_WORKFLOW_RE.fullmatch(relative.name)
        if match is None:
            raise CandidateValidationError(f"invalid package workflow path: {relative}")
        slug = match.group(1)

        triggers = _mapping(workflow.get("on"), f"package workflow triggers {relative}")
        if set(triggers) != {"workflow_call", "workflow_dispatch"}:
            raise CandidateValidationError(
                f"package workflow has unapproved or missing triggers: {relative}"
            )
        workflow_call = _mapping(
            triggers.get("workflow_call"),
            f"package workflow workflow_call {relative}",
        )
        workflow_dispatch = triggers.get("workflow_dispatch")
        if workflow_dispatch not in (None, {}):
            raise CandidateValidationError(
                f"generated package workflow_dispatch must not accept inputs: {relative}"
            )

        jobs = _mapping(workflow.get("jobs"), f"package workflow jobs {relative}")
        expected_job_id = f"test-{slug}"
        if set(jobs) != {expected_job_id}:
            raise CandidateValidationError(
                f"package workflow must contain exactly one package job: {relative}"
            )
        job = _mapping(jobs[expected_job_id], f"package workflow job {relative}")
        if job.get("runs-on") != "ubuntu-24.04-arm":
            raise CandidateValidationError(
                f"package workflow must run only on ubuntu-24.04-arm: {relative}"
            )

        steps = _steps(job.get("steps"), f"package workflow job steps {relative}")
        uses: list[str] = []
        for index, step in enumerate(steps, start=1):
            if "uses" in step and "run" in step:
                raise CandidateValidationError(
                    f"package workflow step {index} mixes uses and run: {relative}"
                )
            if "uses" in step:
                spec = step["uses"]
                if not isinstance(spec, str):
                    raise CandidateValidationError(
                        f"package workflow step uses must be a string: {relative}"
                    )
                uses.append(spec)
        external = [spec for spec in uses if not spec.startswith("./")]
        local = [spec for spec in uses if spec.startswith("./")]
        if len(external) != 1 or external[0] not in _ALLOWED_CHECKOUTS:
            raise CandidateValidationError(
                f"package workflow has an unapproved external action: {relative}"
            )
        if any(spec not in _ALLOWED_LOCAL_ACTIONS for spec in local):
            raise CandidateValidationError(
                f"package workflow has an unapproved local action: {relative}"
            )
        checkout = [step for step in steps if step.get("uses") in _ALLOWED_CHECKOUTS]
        if len(checkout) != 1 or _mapping(
            checkout[0].get("with"), f"package checkout.with {relative}"
        ) != {"persist-credentials": False}:
            raise CandidateValidationError(
                f"package workflow checkout persists credentials: {relative}"
            )

        ids = [step.get("id") for step in steps if "id" in step]
        if any(not isinstance(step_id, str) for step_id in ids) or len(ids) != len(
            set(ids)
        ):
            raise CandidateValidationError(
                f"package workflow step ids are invalid: {relative}"
            )
        missing_tests = [
            number for number in range(1, 7) if ids.count(f"test{number}") != 1
        ]
        if missing_tests:
            raise CandidateValidationError(
                f"package workflow lacks six-test steps: {relative}: {missing_tests}"
            )

        call_outputs = _mapping(
            workflow_call.get("outputs"),
            f"package workflow_call outputs {relative}",
        )
        job_outputs = _mapping(job.get("outputs"), f"package job outputs {relative}")
        if set(call_outputs) != set(_REQUIRED_OUTPUTS) or set(job_outputs) != set(
            _REQUIRED_OUTPUTS
        ):
            raise CandidateValidationError(
                f"generated package workflow lacks the exact 24-output contract: {relative}"
            )
        for name, raw_specification in call_outputs.items():
            specification = _mapping(
                raw_specification,
                f"workflow_call output {name} {relative}",
            )
            if (
                set(specification) != {"description", "value"}
                or not isinstance(specification.get("description"), str)
                or specification.get("value")
                != f"${{{{ jobs.{expected_job_id}.outputs.{name} }}}}"
            ):
                raise CandidateValidationError(
                    f"generated package workflow_call output is malformed: {relative}: {name}"
                )
        job_permissions = _mapping(
            job.get("permissions"),
            f"generated package job permissions {relative}",
        )
        if job_permissions != {"contents": "read"}:
            raise CandidateValidationError(
                f"generated package job permissions are not read-only: {relative}"
            )
        if job.get("timeout-minutes") != 45:
            raise CandidateValidationError(
                f"generated package workflow lacks its bounded job timeout: {relative}"
            )
        forbidden_job_keys = {"container", "env", "services", "secrets", "strategy"}
        if forbidden_job_keys & set(job):
            raise CandidateValidationError(
                f"generated package workflow uses a forbidden job capability: {relative}"
            )
        for number in range(1, 7):
            timeout = 900 if number == 6 else 600
            command = (
                "/usr/bin/timeout --signal=TERM --kill-after=10s "
                f'{timeout}s /usr/bin/python3 "$SMOKE_HARNESS" '
                f'{number} "$GITHUB_OUTPUT"'
            )
            test_step = next(
                step for step in steps if step.get("id") == f"test{number}"
            )
            run = test_step.get("run")
            expected_run = f"set -euo pipefail\n{command}"
            step_name = test_step.get("name")
            if (
                not isinstance(step_name, str)
                or not step_name.startswith(f"Test {number} ")
                or test_step.get("if") != "always()"
                or test_step.get("shell") != "bash"
                or not isinstance(run, str)
                or run.strip() != expected_run
            ):
                raise CandidateValidationError(
                    f"generated package test {number} bypasses the bounded harness: {relative}"
                )

        prepare = [
            step
            for step in steps
            if step.get("name") == "Prepare trusted bounded smoke executor"
            and step.get("id") == "prepare"
        ]
        summary = [
            step
            for step in steps
            if step.get("id") == "summary"
            and step.get("uses") == "./.github/actions/emit-package-result"
        ]
        enforcement = [step for step in steps if step.get("id") == "enforce"]
        if (
            len(prepare) != 1
            or prepare[0].get("shell") != "bash"
            or not isinstance(prepare[0].get("run"), str)
            or len(summary) != 1
            or summary[0].get("if") != "always()"
            or len(enforcement) != 1
            or enforcement[0].get("name") != "Enforce strict smoke-test result"
            or enforcement[0].get("if") != "always()"
            or enforcement[0].get("shell") != "bash"
            or not isinstance(enforcement[0].get("run"), str)
        ):
            raise CandidateValidationError(
                f"generated package workflow lacks canonical result steps: {relative}"
            )
        prepare_run = prepare[0]["run"]
        required_isolation = (
            'DOCKER = "/usr/bin/docker"',
            "docker.io/library/ubuntu@",
            "--read-only",
            "--network",
            "--cap-drop",
            "no-new-privileges",
            _ISOLATED_IMAGE_DIGEST,
        )
        if any(marker not in prepare_run for marker in required_isolation):
            raise CandidateValidationError(
                f"generated package workflow lacks canonical isolation controls: {relative}"
            )
        normalized = _normalized_package_template(
            workflow,
            slug=slug,
            label=str(relative),
        )
        if normalized != normalized_template:
            raise CandidateValidationError(
                f"generated package workflow differs from the trusted canonical template: "
                f"{relative}"
            )


def _canonical_integer(
    value: object,
    label: str,
    *,
    minimum: int = 0,
    maximum: int | None = None,
) -> int:
    if isinstance(value, bool):
        raise CandidateValidationError(f"{label} must be a canonical integer")
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str) and re.fullmatch(r"(?:0|[1-9][0-9]*)", value):
        parsed = int(value)
    else:
        raise CandidateValidationError(f"{label} must be a canonical integer")
    if parsed < minimum or (maximum is not None and parsed > maximum):
        raise CandidateValidationError(f"{label} is outside its allowed range")
    return parsed


def _bounded_output_text(
    outputs: Mapping[str, Any],
    name: str,
    *,
    maximum: int = 4000,
) -> str:
    value = outputs.get(name)
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > maximum
        or any(character in value for character in ("\x00", "\r"))
        or value.strip().casefold() in _FORBIDDEN_OUTPUT_SENTINELS
    ):
        raise CandidateValidationError(
            f"native evidence output {name} is unresolved or malformed"
        )
    return value


def _validate_evidence_outputs(
    raw_outputs: object,
    *,
    package_slug: str,
    run_id: int,
    run_attempt: int,
    test_statuses: list[str],
) -> None:
    outputs = _mapping(raw_outputs, "native validation report outputs")
    _require_exact_keys(
        outputs, set(_REQUIRED_OUTPUTS), "native validation report outputs"
    )
    if (
        outputs.get("contract_version") != "2.0"
        or outputs.get("package_slug") != package_slug
    ):
        raise CandidateValidationError(
            "native evidence outputs do not identify the exact package contract"
        )
    if (
        _canonical_integer(
            outputs.get("run_id"), "native evidence output run_id", minimum=1
        )
        != run_id
        or _canonical_integer(
            outputs.get("run_attempt"),
            "native evidence output run_attempt",
            minimum=1,
        )
        != run_attempt
    ):
        raise CandidateValidationError(
            "native evidence output run identity does not match report"
        )

    passed = sum(status == "passed" for status in test_statuses)
    failed = sum(status == "failed" for status in test_statuses)
    skipped = sum(status in {"skipped", "deferred"} for status in test_statuses)
    core_failed = sum(status != "passed" for status in test_statuses[:5])
    reported_counts = (
        _canonical_integer(
            outputs.get("tests_passed"),
            "native evidence tests_passed",
            maximum=6,
        ),
        _canonical_integer(
            outputs.get("tests_failed"),
            "native evidence tests_failed",
            maximum=6,
        ),
        _canonical_integer(
            outputs.get("tests_skipped"),
            "native evidence tests_skipped",
            maximum=6,
        ),
    )
    if reported_counts != (passed, failed, skipped) or sum(reported_counts) != 6:
        raise CandidateValidationError(
            "native evidence six-test outputs do not match individual outcomes"
        )
    if (
        _canonical_integer(
            outputs.get("core_failed"),
            "native evidence core_failed",
            maximum=5,
        )
        != core_failed
        or core_failed != 0
        or failed != 0
        or outputs.get("run_status") != "success"
        or outputs.get("badge_status") != "passing"
    ):
        raise CandidateValidationError(
            "native evidence baseline package health is not green"
        )

    regression_status = outputs.get("regression_status")
    regression_decision = outputs.get("regression_decision")
    regression_policy = outputs.get("regression_policy")
    if test_statuses[5] == "passed":
        if (
            regression_status != "passed"
            or regression_decision != "candidate_passed"
            or regression_policy != "applicable"
            or reported_counts != (6, 0, 0)
        ):
            raise CandidateValidationError(
                "native evidence passing regression outputs are inconsistent"
            )
    elif test_statuses[5] in {"skipped", "deferred"}:
        if (
            regression_status != "skipped"
            or regression_decision not in _APPROVED_REGRESSION_DEFERRALS
            or regression_policy != "approved_deferral"
            or reported_counts != (5, 0, 1)
        ):
            raise CandidateValidationError(
                "native evidence deferred regression outputs are not policy-approved"
            )
    else:
        raise CandidateValidationError(
            "native evidence Test 6 did not finish policy-green"
        )

    for name in (
        "package_name",
        "package_version",
        "regression_decision",
        "regression_result",
        "regression_comparison",
        "regression_current_version",
        "regression_latest_version",
        "regression_next_installed_version",
        "regression_policy",
        "job_name",
        "dashboard_link",
        "timestamp",
    ):
        _bounded_output_text(outputs, name)
    if outputs["dashboard_link"] != f"/opensource_packages/{package_slug}":
        raise CandidateValidationError(
            "native evidence dashboard link does not match package"
        )
    _canonical_integer(
        outputs.get("duration_seconds"),
        "native evidence duration_seconds",
        maximum=86_400,
    )
    try:
        timestamp = datetime.fromisoformat(outputs["timestamp"].replace("Z", "+00:00"))
    except ValueError as exc:
        raise CandidateValidationError(
            "native evidence timestamp is not valid ISO-8601"
        ) from exc
    if timestamp.utcoffset() != UTC.utcoffset(timestamp):
        raise CandidateValidationError("native evidence timestamp must be UTC")


def _validate_native_evidence(
    candidate_root: Path,
    added: set[PurePosixPath],
    *,
    package_slug: str,
    candidate_sha256: str,
    workflow_path: PurePosixPath,
    workflow_sha256: str,
) -> set[PurePosixPath]:
    evidence = {path for path in added if path.parts[:1] == _EVIDENCE_ROOT.parts}
    if not evidence:
        return set()
    parts = [path.parts for path in evidence]
    request_ids = {part[1] for part in parts if len(part) == 3}
    names = {part[2] for part in parts if len(part) == 3}
    if (
        any(len(part) != 3 for part in parts)
        or len(request_ids) != 1
        or not all(_EVIDENCE_REQUEST_ID_RE.fullmatch(value) for value in request_ids)
        or names != {"request.json", "report.json", "SHA256SUMS"}
        or len(evidence) != 3
    ):
        raise CandidateValidationError(
            "native evidence must be one exact request/report/checksum bundle"
        )
    request_id = next(iter(request_ids))
    directory = _EVIDENCE_ROOT / request_id
    request_bytes = _read(candidate_root, directory / "request.json")
    report_bytes = _read(candidate_root, directory / "report.json")
    sums = _read(candidate_root, directory / "SHA256SUMS").decode("ascii")
    expected_sums = f"{_sha256(request_bytes)}  request.json\n{_sha256(report_bytes)}  report.json\n"
    if sums != expected_sums:
        raise CandidateValidationError(
            "native evidence checksums do not bind request.json and report.json"
        )

    request = _json(request_bytes, "native validation request")
    report = _json(report_bytes, "native validation report")
    _require_exact_keys(
        request,
        {
            "schema_version",
            "request_id",
            "package_slug",
            "candidate_sha256",
            "workflow_path",
            "workflow_sha256",
        },
        "native validation request",
    )
    _require_exact_keys(
        report,
        {
            "schema_version",
            "request_id",
            "request_sha256",
            "package_slug",
            "candidate_sha256",
            "workflow_path",
            "workflow_sha256",
            "run_id",
            "run_attempt",
            "runner",
            "status",
            "conclusion",
            "tests",
            "outputs",
        },
        "native validation report",
    )
    expected_bindings = {
        "schema_version": "1.0",
        "request_id": request_id,
        "package_slug": package_slug,
        "candidate_sha256": candidate_sha256,
        "workflow_path": workflow_path.as_posix(),
        "workflow_sha256": workflow_sha256,
    }
    if any(request.get(name) != value for name, value in expected_bindings.items()):
        raise CandidateValidationError(
            "native evidence request is not bound to the exact candidate package and workflow"
        )
    if any(report.get(name) != value for name, value in expected_bindings.items()):
        raise CandidateValidationError(
            "native evidence report is not bound to the exact candidate package and workflow"
        )
    if report.get("request_sha256") != _sha256(request_bytes):
        raise CandidateValidationError(
            "native evidence report is not bound to request.json"
        )

    run_id = _canonical_integer(
        report.get("run_id"),
        "native evidence run_id",
        minimum=1,
    )
    run_attempt = _canonical_integer(
        report.get("run_attempt"),
        "native evidence run_attempt",
        minimum=1,
    )
    runner = _mapping(report.get("runner"), "native validation report runner")
    if runner != {
        "label": "ubuntu-24.04-arm",
        "architecture": "aarch64",
        "environment": "github-hosted",
    }:
        raise CandidateValidationError(
            "native evidence was not produced by the required GitHub-hosted Arm64 runner"
        )
    if report.get("status") != "completed" or report.get("conclusion") != "success":
        raise CandidateValidationError(
            "native evidence run did not finish successfully"
        )

    raw_tests = report.get("tests")
    if not isinstance(raw_tests, list) or len(raw_tests) != 6:
        raise CandidateValidationError(
            "native evidence must contain exactly six test outcomes"
        )
    test_statuses: list[str] = []
    for expected_number, raw_test in enumerate(raw_tests, start=1):
        test = _mapping(raw_test, f"native evidence Test {expected_number}")
        _require_exact_keys(
            test,
            {"number", "status"},
            f"native evidence Test {expected_number}",
        )
        status = test.get("status")
        if test.get("number") != expected_number or status not in {
            "passed",
            "failed",
            "skipped",
            "deferred",
        }:
            raise CandidateValidationError(
                "native evidence test outcomes are malformed or out of order"
            )
        test_statuses.append(status)
    _validate_evidence_outputs(
        report.get("outputs"),
        package_slug=package_slug,
        run_id=run_id,
        run_attempt=run_attempt,
        test_statuses=test_statuses,
    )
    return evidence


def validate_repository(repository_root: Path) -> None:
    root = _safe_root(repository_root)
    files = _tree(root)
    package_workflows = _package_workflows(files)
    if not package_workflows:
        raise CandidateValidationError("sandbox repository has no package workflows")
    _validate_package_workflow_security(root, package_workflows)
    _validate_batch_registry(root, package_workflows)


def validate(
    base_root: Path,
    candidate_root: Path,
    *,
    expected_source_revision: str | None = None,
    expected_verified_at: datetime | None = None,
    expected_minimum_release_date: date | None = None,
) -> None:
    base = _safe_root(base_root)
    candidate = _safe_root(candidate_root)
    if (expected_source_revision is None) != (expected_verified_at is None):
        raise CandidateValidationError(
            "trusted source revision and verification time must be supplied together"
        )
    if expected_source_revision is None or expected_verified_at is None:
        expected_source_revision, expected_verified_at = _trusted_base_provenance(base)
    if (
        _GIT_SHA_RE.fullmatch(expected_source_revision) is None
        or expected_verified_at.utcoffset() is None
    ):
        raise CandidateValidationError("trusted base provenance is malformed")
    base_tree = _tree(base)
    candidate_tree = _tree(candidate)

    base_manifest_bytes = _read(base, MANIFEST_PATH)
    if _read(candidate, MANIFEST_PATH) != base_manifest_bytes:
        raise CandidateValidationError("candidate changed the fixture trust manifest")
    manifest = _json(base_manifest_bytes, "fixture manifest")
    for path, expected_digest in _manifest_hashes(manifest).items():
        if candidate_tree.get(path) != expected_digest:
            raise CandidateValidationError(
                f"candidate changed trusted fixture input: {path}"
            )

    deleted = sorted(set(base_tree) - set(candidate_tree))
    if deleted:
        raise CandidateValidationError(
            "candidate deleted files: " + ", ".join(map(str, deleted))
        )
    added = set(candidate_tree) - set(base_tree)
    modified = {
        path
        for path in set(base_tree) & set(candidate_tree)
        if base_tree[path] != candidate_tree[path]
    }

    base_pages = _package_pages(base_tree)
    candidate_pages = _package_pages(candidate_tree)
    new_pages = candidate_pages - base_pages
    base_workflows = _package_workflows(base_tree)
    candidate_workflows = _package_workflows(candidate_tree)
    new_workflows = candidate_workflows - base_workflows
    if len(new_pages) != 1 or len(new_workflows) != 1:
        raise CandidateValidationError(
            "candidate must add exactly one package page and one package workflow"
        )
    page = next(iter(new_pages))
    workflow = next(iter(new_workflows))
    slug = page.stem
    if _SLUG_RE.fullmatch(slug) is None:
        raise CandidateValidationError(f"candidate package slug is invalid: {slug}")
    expected_workflow = WORKFLOW_ROOT / f"test-{slug}.yml"
    if workflow != expected_workflow:
        raise CandidateValidationError(
            "candidate page and package workflow slugs do not match"
        )

    _validate_batch_transition(
        base,
        candidate,
        package_slug=slug,
    )
    allowed_added = {page, workflow}
    allowed_modified = {CATALOG_PATH, BATCH_PATH}
    if added != allowed_added:
        raise CandidateValidationError(
            "candidate added unexpected files: "
            + ", ".join(map(str, sorted(added - allowed_added)))
        )
    if modified != allowed_modified:
        unexpected = sorted(modified - allowed_modified)
        missing = sorted(allowed_modified - modified)
        details = []
        if unexpected:
            details.append("unexpected=" + ",".join(map(str, unexpected)))
        if missing:
            details.append("missing=" + ",".join(map(str, missing)))
        raise CandidateValidationError(
            "candidate must modify only catalog and batch1: " + "; ".join(details)
        )

    base_catalog = _json(_read(base, CATALOG_PATH), "base catalog")
    candidate_catalog = _json(_read(candidate, CATALOG_PATH), "candidate catalog")
    base_records = _records(base_catalog, "base catalog")
    candidate_records = _records(candidate_catalog, "candidate catalog")
    new_record_paths = set(candidate_records) - set(base_records)
    if new_record_paths != {page.as_posix()}:
        raise CandidateValidationError(
            "candidate catalog must add exactly the new package record"
        )
    for record_path, record in base_records.items():
        if candidate_records.get(record_path) != record:
            raise CandidateValidationError(
                f"candidate changed existing catalog record: {record_path}"
            )
    record = candidate_records[page.as_posix()]
    if record.get("slug") != slug:
        raise CandidateValidationError("candidate catalog slug does not match page")
    workflow_record = record.get("workflow")
    if not isinstance(workflow_record, dict):
        raise CandidateValidationError("candidate catalog workflow is malformed")
    if (
        workflow_record.get("path") != workflow.as_posix()
        or workflow_record.get("presence") != "present"
        or workflow_record.get("sha256") != candidate_tree[workflow]
        or record.get("content_sha256") != candidate_tree[page]
    ):
        raise CandidateValidationError(
            "candidate catalog does not bind the exact new page and workflow bytes"
        )
    workflow_payload = _read(candidate, workflow)
    _validate_candidate_semantic_binding(
        page_payload=_read(candidate, page),
        workflow_payload=workflow_payload,
        workflow=_yaml(workflow_payload, f"candidate package workflow {workflow}"),
        record=record,
        slug=slug,
        expected_source_revision=expected_source_revision,
        expected_verified_at=expected_verified_at,
        expected_minimum_release_date=expected_minimum_release_date,
    )

    corpus = candidate_catalog.get("corpus")
    if not isinstance(corpus, dict) or corpus.get("entry_count") != len(
        candidate_pages
    ):
        raise CandidateValidationError(
            "candidate catalog entry count does not match package pages"
        )
    validate_repository(candidate)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-root", type=Path)
    parser.add_argument("--candidate-root", type=Path)
    parser.add_argument("--repository-root", type=Path)
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    try:
        if args.repository_root is not None:
            if args.base_root is not None or args.candidate_root is not None:
                raise CandidateValidationError(
                    "--repository-root cannot be combined with transition roots"
                )
            validate_repository(args.repository_root)
            message = "PASS: bounded sandbox repository contracts are valid."
        elif args.base_root is not None and args.candidate_root is not None:
            validate(args.base_root, args.candidate_root)
            message = "PASS: candidate is one exact bounded package-onboarding change."
        else:
            raise CandidateValidationError(
                "provide --repository-root or both --base-root and --candidate-root"
            )
    except (CandidateValidationError, OSError, UnicodeError) as exc:
        print(f"sandbox candidate validation failed: {exc}")
        return 1
    print(message)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
