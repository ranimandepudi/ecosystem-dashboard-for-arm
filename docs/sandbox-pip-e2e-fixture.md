# Bounded pip onboarding sandbox

This branch is an isolated test fixture for the AI-assisted package-onboarding
service. It is not a production dashboard branch and must not be merged into
`main`.

Its service-side source revision is the immutable, merged PR 17 commit
`6aa4eebc802685281cee88dfc3101921b1408e97`. Publication of this fixture does
not merge that service change or enable either sandbox or production delivery.

## Purpose

The fixture starts with one real package, NumPy, and one real six-test Arm64
workflow. Its first bounded end-to-end scenario accepts only the reviewed
Requests identity tuple: `Requests`, `requests`, `https://github.com/psf/requests`
and the `requests` import. The service must produce only:

1. one package Markdown page;
2. one six-test package workflow;
3. one package identity catalog update; and
4. one batch-1 registration update.

The fixed identity tuple is part of the protected trust root, not candidate
input. Support code also carries a small reviewed distribution-to-import mapping
for future scenarios such as `beautifulsoup4` to `bs4`, but a mapping alone does
not authorize that package. Every additional scenario requires a reviewed
identity entry. The fixture requires a PEP 440-stable candidate that is strictly
newer than the baseline and an executed strict Test 6. A deferred Test 6
requires a separate reviewed policy.

The generated workflow is executed first in the private preflight repository on
GitHub's `ubuntu-24.04-arm` runner. Only an exact, attested, successful preflight
may proceed to a draft pull request against this branch.

Self-asserted native evidence files are rejected. The private preflight
attestation remains in the private preflight repository until an independently
authenticated public-evidence format is approved.

## Trust boundary

`sandbox-dashboard-validation.yml` uses `pull_request_target` so the validator
comes from the protected base branch. The candidate branch is checked out as
untrusted data and never supplies executable validation code.

The validation job:

- runs on a GitHub-hosted Arm64 runner;
- has read-only repository permission and references no secrets;
- accepts only same-repository candidate branches;
- installs PyYAML and Packaging from checksum-bound Python wheels;
- preserves the fixture manifest, archived evidence and NumPy seed bytes;
- permits only the exact four-file onboarding transition;
- requires the generated workflow to match the trusted executable template;
- binds the page name, catalog pip identity, workflow repository, smoke plan and
  canonical import probe to the protected Requests identity tuple;
- requires a category from the dashboard's reviewed taxonomy and canonical
  single-line bounded front-matter text;
- validates the canonical front-matter structure and binds
  `works_on_arm: true` plus `supported_minimum_version.version_number` to the
  exact baseline release exercised by Tests 1-5;
- verifies the public minimum release date against the exact release's official
  PyPI upload metadata using an exact HTTPS authority and requires the cited
  evidence URL to identify that same PyPI release;
- limits homepage and documentation links to the protected Requests repository,
  PyPI identity or reviewed Requests documentation host; Arm content must use an
  Arm-owned domain;
- leaves partner links and the public "Arm recommends" fields empty until a
  separate human-reviewed policy authorizes those claims;
- binds Python artifact filenames to the exact PyPI distribution and PEP 440
  release and permits only query-free, identity-bound HTTPS PyPI or GitHub
  download URLs;
- decodes URL paths to a bounded fixed point and rejects dot segments,
  backslashes, malformed or invalid UTF-8 encodings and encoded path-boundary
  tricks before host and path policies are evaluated;
- binds generated catalog provenance to the protected base commit, its commit
  timestamp and the fixed onboarding-service automation identity;
- permits only a successful canonical import assertion, never an expected
  failure reclassified as a pass;
- requires new deliverable candidates to execute strict baseline and newer
  release pins rather than self-assert a Test 6 deferral;
- permits the batch diff to add only one package call and one matching need;
- rejects secret references, non-Arm runners and unapproved actions;
- validates the complete catalog, batch registration and six-test outputs; and
- builds the dashboard with a checksum-verified Hugo Extended binary.

Because `pull_request_target` loads its workflow from the default branch, the
bootstrap pull request must first be reviewed and merged into
`sandbox/pip-e2e`. That branch must then become the sandbox repository's default
branch before it can act as the trusted controller for service-created
candidate pull requests.

The validation workflow has no manual-dispatch path. The package orchestrator
is manual-only and is guarded to this repository's `sandbox/pip-e2e` branch, so
making the sandbox branch the default cannot start scheduled or push-triggered
write automation.

## Seed evidence

The immutable evidence snapshots are under
`.github/catalog-evidence/numpy/`. `SHA256SUMS` binds:

- the official PyPI JSON response for `numpy`; and
- the official GitHub API response for an immutable `numpy/numpy` commit.

The npm identity dimension remains explicitly unknown and non-exhaustive. The
fixture makes no claim that the unrelated npm package named `numpy` belongs to
the NumPy project.

## Local validation

Run these commands from the repository root:

```text
python3 build_steps/build_pip_sandbox_fixture.py --check
python3 build_steps/validate_package_identity_catalog.py
python3 build_steps/validate_pip_sandbox_candidate.py --repository-root .
python3 -m unittest -v \
  build_steps.tests.test_build_pip_sandbox_fixture \
  build_steps.tests.test_validate_pip_sandbox_candidate
actionlint .github/workflows/sandbox-dashboard-validation.yml
actionlint -shellcheck= -pyflakes= .github/workflows/*.yml
hugo --minify --config config.toml,config.cloudfront.toml
```

Production and sandbox activation switches in the service remain disabled until
the GitHub Apps, private preflight isolation and independent approvals are in
place.
