# Fortify Aviator remediation for Security Shepherd

This folder adds a Fortify on Demand plus Aviator remediation engine to Security Shepherd.

It is designed to:
- authenticate to Fortify on Demand
- pull vulnerabilities for a configured release
- request Aviator remediation guidance
- apply safe file-level patches only when they pass quality gates
- create a remediation branch and open a GitHub pull request

## Files

- `app/fod_aviator.py` FoD client and Aviator guidance parser
- `app/remediation_engine.py` patch application, gating, branch creation, and PR creation
- `app/metrics.py` telemetry helpers for MTTR and backlog reporting
- `../.github/workflows/fortify.yml` combined Fortify scan and remediation workflow
- `.env.example` local configuration template
- `requirements.txt` Python dependencies

## Required GitHub repository secrets

- `FOD_CLIENT_ID`
- `FOD_CLIENT_SECRET`
- `FOD_RELEASE_ID`

Optional:

- `FOD_TENANT`
- repository variable `FOD_URL`
- repository variable `FOD_BASE_URL`
- repository variable `FOD_VERIFY_SSL`

The workflow uses GitHub's built-in `GITHUB_TOKEN` for branch pushes and PR creation.

## Local run

```bash
python3 -m venv fortify_aviator_remediation/.venv
source fortify_aviator_remediation/.venv/bin/activate
pip install -r fortify_aviator_remediation/requirements.txt
cp fortify_aviator_remediation/.env.example fortify_aviator_remediation/.env
set -a
source fortify_aviator_remediation/.env
set +a
python fortify_aviator_remediation/app/remediation_engine.py
```

## Workflow behavior

The combined workflow:
- runs FoD scans on `push` to `master` and `dev`
- runs FoD scans plus Aviator remediation on `pull_request` for `master` and `dev`
- supports manual `workflow_dispatch`; supply a PR number if you want remediation to run
- uses the numeric FoD release id for both scanning and remediation
- skips fork-based PRs because the workflow relies on repository credentials
- limits staged files to the files Aviator actually changed
- restores only touched files if patch application fails
