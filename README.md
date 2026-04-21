# Fortify FoD Scan And Aviator Remediation Actions

Reusable GitHub Action repository for Fortify on Demand scanning and Aviator remediation.

It is designed to:
- run Fortify on Demand scans through a reusable wrapper around the Fortify AST Scan marketplace action, `fortify/github-action@v3`
- create FoD applications and releases automatically when configured to do so
- authenticate to Fortify on Demand
- fetch vulnerabilities for a configured release
- request Aviator remediation guidance per finding
- apply structured file changes only when the quality gates pass
- optionally validate generated changes with a project-specific command
- create remediation pull requests either by category or one finding at a time
- publish compact remediation metrics and skipped-finding summaries

This folder is self-contained enough to be moved into its own repository. If you publish it as a standalone action repository, keep the contents of this folder at the repository root.

## What You Get

- Root remediation action in `action.yml`
- Fortify FoD scan action in `fod-scan/action.yml`
- Remediation engine in `app/remediation_engine.py`
- Fortify client and guidance parser in `app/fod_aviator.py`
- Metrics and summaries in `app/metrics.py`
- Wrapper scripts in `scripts/`

## Actions In This Repository

| Path | Purpose | Example `uses:` value |
| --- | --- | --- |
| repository root | Aviator remediation action | `your-org/fortify-aviator-remediation-action@v1` |
| `fod-scan/` | Fortify FoD scan wrapper action | `your-org/fortify-aviator-remediation-action/fod-scan@v1` |

## Requirements

Before running this action:
- check out the target repository with `actions/checkout`
- grant the job `contents: write` and `pull-requests: write`
- provide a Fortify release id and FoD API credentials
- provide a GitHub token that can push branches and create or update PRs
- if you want validation, install the target project's toolchain before this action or use the built-in optional Java setup

Recommended checkout:

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0
```

Recommended job permissions:

```yaml
permissions:
  contents: write
  pull-requests: write
```

## Repository FoD Workflow

This repository now includes a self-scan workflow at `.github/workflows/fortify.yml`. It uses the local `./fod-scan` action to run the Fortify AST Scan marketplace integration against this action repository on `push`, `pull_request`, and `workflow_dispatch`.

Required repository secrets:
- `FOD_CLIENT_ID`
- `FOD_CLIENT_SECRET`

Optional repository secrets:
- `FOD_TENANT`

Useful repository variables:
- `FOD_URL`
- `FOD_RELEASE`
- `FOD_DO_SETUP`
- `FOD_APP_OWNER`
- `FOD_AUTO_REQUIRED_ATTRS`
- `FOD_COPY_FROM_RELEASE`
- `FOD_SAST_ASSESSMENT_TYPE`
- `FOD_DO_AVIATOR_AUDIT`
- `FOD_OVERRIDE_SAST_SETTINGS`
- `FOD_SETUP_EXTRA_OPTS`
- `FOD_PACKAGE_EXTRA_OPTS`
- `FCLI_BOOTSTRAP_VERSION`
- `FOD_DO_WAIT`
- `FOD_DO_JOB_SUMMARY`
- `FOD_DO_EXPORT`
- `FOD_DO_SCA_SCAN`

Default workflow behavior:
- If `FOD_RELEASE` is not set, the workflow falls back to `owner/repo:branch`.
- `FOD_DO_SETUP` defaults to `true`, so the workflow will attempt to create the FoD application and release automatically.
- `FOD_DO_SCA_SCAN` defaults to `true`, enabling Software Composition Analysis together with SAST.
- `FOD_DO_AVIATOR_AUDIT` defaults to `true`, enabling Aviator audits when your FoD tenant and policy support it.
- `FOD_COPY_FROM_RELEASE` defaults to `owner/repo:default-branch`, so newly created branch releases can inherit baseline state from the default branch release.

If you authenticate with FoD client credentials and automatic application creation is enabled, set `FOD_APP_OWNER` if your tenant requires an explicit application owner during creation. This requirement is called out in the Fortify GitHub Action documentation.

## Quick Start

```yaml
name: Fortify Aviator Remediation

on:
  workflow_dispatch:

jobs:
  remediate:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Run remediation
        uses: your-org/fortify-aviator-remediation-action@v1
        with:
          fod-client-id: ${{ secrets.FOD_CLIENT_ID }}
          fod-client-secret: ${{ secrets.FOD_CLIENT_SECRET }}
          fod-release-id: ${{ secrets.FOD_RELEASE_ID }}
          github-token: ${{ secrets.REMEDIATION_GITHUB_TOKEN || github.token }}
```

By default, the action does not assume any application language or build tool. Validation is off unless you pass a project-specific command.

## Fortify FoD Scan Action

The scan action is published from the `fod-scan/` subdirectory. It wraps the Fortify AST Scan marketplace action, `fortify/github-action@v3`, with a smaller, reusable input surface for FoD use cases.

### Scan Inputs

| Input | Required | Default | Description |
| --- | --- | --- | --- |
| `fod-url` | No | `https://ams.fortify.com` | Fortify on Demand URL used by the scan action. |
| `fod-client-id` | Yes | - | Fortify on Demand client ID. |
| `fod-client-secret` | Yes | - | Fortify on Demand client secret. |
| `fod-tenant` | No | `""` | Fortify tenant name. |
| `fod-release` | Yes, unless `fod-release-id` is set | `""` | Preferred FoD release selector for the underlying `FOD_RELEASE` environment variable. This can be a numeric release id or a release name like `MyApp:main`. |
| `fod-release-id` | Yes, unless `fod-release` is set | `""` | Backward-compatible alias for `fod-release`. Useful for existing workflows that already pass a numeric release id. |
| `do-setup` | No | `false` | Whether the FoD application and release should be created automatically and SAST setup should be configured if missing. |
| `fod-app-owner` | No | `""` | Optional application owner for automatic FoD application creation. This may be required when authenticating with client credentials. |
| `auto-required-attrs` | No | `false` | Whether automatic FoD setup should try to fill required application and release attributes with default values. |
| `copy-from-release` | No | `""` | Optional FoD release to copy state from when creating a new release. |
| `sast-assessment-type` | No | `""` | Optional FoD SAST assessment type to apply during automatic setup. |
| `do-aviator-audit` | No | `false` | Whether automatic FoD SAST setup should enable Aviator audits. |
| `override-sast-settings` | No | `false` | Whether automatic FoD setup should overwrite existing SAST settings instead of only filling them when missing. |
| `setup-extra-opts` | No | `""` | Additional raw options to pass to the FoD `setup-release` action. |
| `package-extra-opts` | No | `""` | Optional packaging options, for example `-bt mvn`, `-bt gradle`, or other Fortify packaging flags. |
| `fcli-bootstrap-version` | No | `""` | Optional fcli bootstrap version, for example `v3.15.0`, if you want to pin the Fortify AST Scan runtime instead of floating with the latest supported v3 release. |
| `do-wait` | No | `false` | Whether the scan should wait for FoD processing to finish. |
| `do-job-summary` | No | `false` | Whether the Fortify action should publish a job summary. |
| `do-export` | No | `false` | Whether to export findings to GitHub code scanning. |
| `do-sca-scan` | No | `true` | Whether to include software composition analysis. |
| `do-pr-comment` | No | `false` | Whether the Fortify action should comment on PRs. |

This wrapper maps `fod-release` or `fod-release-id` to the official `FOD_RELEASE` environment variable expected by the Fortify AST Scan action.
It also exposes the official FoD setup knobs documented by Fortify, including automatic release creation (`DO_SETUP`), baseline copying (`COPY_FROM_RELEASE`), SCA enablement (`DO_SCA_SCAN`), and Aviator enablement (`DO_AVIATOR_AUDIT`).

### Minimal Scan Example

```yaml
- name: Run Fortify FoD scan
  uses: your-org/fortify-aviator-remediation-action/fod-scan@v1
  with:
    fod-client-id: ${{ secrets.FOD_CLIENT_ID }}
    fod-client-secret: ${{ secrets.FOD_CLIENT_SECRET }}
    fod-release: ${{ secrets.FOD_RELEASE_ID }}
```

### Scan Example With Automatic FoD Setup, SCA, and Aviator

```yaml
- uses: actions/setup-java@v4
  with:
    distribution: temurin
    java-version: "17"

- name: Run FoD scan for a Maven project
  uses: your-org/fortify-aviator-remediation-action/fod-scan@v1
  with:
    fod-client-id: ${{ secrets.FOD_CLIENT_ID }}
    fod-client-secret: ${{ secrets.FOD_CLIENT_SECRET }}
    fod-release: ${{ vars.FOD_RELEASE || format('{0}:{1}', github.repository, github.ref_name) }}
    do-setup: "true"
    fod-app-owner: ${{ vars.FOD_APP_OWNER }}
    copy-from-release: ${{ vars.FOD_COPY_FROM_RELEASE || format('{0}:{1}', github.repository, github.event.repository.default_branch) }}
    do-aviator-audit: "true"
    do-sca-scan: "true"
    package-extra-opts: "-bt mvn"
    fcli-bootstrap-version: "v3.15.0"
    do-wait: "true"
```

### Local Path Usage For The Scan Action

```yaml
- name: Run local FoD scan action
  uses: ./fod-scan
  with:
    fod-client-id: ${{ secrets.FOD_CLIENT_ID }}
    fod-client-secret: ${{ secrets.FOD_CLIENT_SECRET }}
    fod-release: ${{ secrets.FOD_RELEASE_ID }}
```

## Inputs

| Input | Required | Default | Description |
| --- | --- | --- | --- |
| `fod-base-url` | No | `https://api.ams.fortify.com` | Fortify on Demand API base URL. |
| `fod-client-id` | Yes | - | Fortify on Demand client ID. |
| `fod-client-secret` | Yes | - | Fortify on Demand client secret. |
| `fod-tenant` | No | `""` | Fortify tenant name used with password-grant flows. |
| `fod-user` | No | `""` | Fortify username for password or PAT authentication. |
| `fod-password` | No | `""` | Fortify password or PAT for password-grant authentication. |
| `fod-oauth-scope` | No | `api-tenant` | OAuth scope requested from Fortify. |
| `fod-release-id` | Yes | - | Numeric Fortify release identifier. |
| `fod-severity-strings` | No | `Critical` | Comma-separated severities to remediate, for example `Critical,High`. |
| `fod-pr-grouping` | No | `category` | PR grouping mode. Supported values are `category` and `issue`. |
| `fod-verify-ssl` | No | `true` | Whether FoD HTTPS certificates are verified. |
| `github-token` | Yes | - | Token used to push branches and create or update pull requests. |
| `github-repository` | No | current workflow repository | Repository in `owner/repo` form. |
| `pr-number` | No | auto-detected when available | Pull request number for PR-scoped remediation. |
| `github-base-ref` | No | auto-detected when available | Base branch used for worktrees and pull requests. |
| `remediation-validate-command` | No | `false` | Optional project-specific validation command run before publishing changes. Examples: `mvn test`, `npm test`, `pytest -q`, `dotnet build`. |
| `git-user-name` | No | auto-derived | Commit author name used for remediation branches. |
| `git-user-email` | No | auto-derived | Commit author email used for remediation branches. |
| `python-version` | No | `3.11` | Python version used to run the action. |
| `setup-java` | No | `false` | Whether the action should install Java before remediation runs. Useful for Maven or Gradle validation. |
| `java-version` | No | `8` | Java version to install when `setup-java` is enabled. |
| `java-distribution` | No | `temurin` | Java distribution to install when `setup-java` is enabled. |

## Outputs

| Output | Description |
| --- | --- |
| `results-file` | Path to the JSON results file produced by the remediation run. |
| `results-count` | Number of decision records generated by the run. |
| `metrics-summary` | Compact JSON summary of remediation metrics. |
| `results-summary` | Compact JSON summary of PR activity and skipped-bucket results. |
| `metrics-published-to` | Step summary file path when markdown metrics were published in GitHub Actions. |

## Suggested Repository Secrets And Variables

Typical secrets:
- `FOD_CLIENT_ID`
- `FOD_CLIENT_SECRET`
- `FOD_RELEASE_ID`
- `REMEDIATION_GITHUB_TOKEN` if you do not want to rely on the default workflow token

Optional secrets:
- `FOD_TENANT`
- `FOD_USER`
- `FOD_PASSWORD` or `FOD_PAT`

Useful repository variables:
- `FOD_BASE_URL`
- `FOD_OAUTH_SCOPE`
- `FOD_VERIFY_SSL`
- `FOD_SEVERITY_STRINGS`
- `FOD_PR_GROUPING`
- `REMEDIATION_VALIDATE_COMMAND`

## Examples

### Minimal External Usage

```yaml
- name: Run Fortify Aviator remediation
  uses: your-org/fortify-aviator-remediation-action@v1
  with:
    fod-client-id: ${{ secrets.FOD_CLIENT_ID }}
    fod-client-secret: ${{ secrets.FOD_CLIENT_SECRET }}
    fod-release-id: ${{ secrets.FOD_RELEASE_ID }}
    github-token: ${{ secrets.REMEDIATION_GITHUB_TOKEN || github.token }}
```

### Group Findings By Category

`category` is the default, but setting it explicitly can make workflow intent clearer.

```yaml
- name: Group remediation PRs by category
  uses: your-org/fortify-aviator-remediation-action@v1
  with:
    fod-client-id: ${{ secrets.FOD_CLIENT_ID }}
    fod-client-secret: ${{ secrets.FOD_CLIENT_SECRET }}
    fod-release-id: ${{ secrets.FOD_RELEASE_ID }}
    github-token: ${{ secrets.REMEDIATION_GITHUB_TOKEN || github.token }}
    fod-severity-strings: Critical,High
    fod-pr-grouping: category
```

### Create One PR Per Finding

```yaml
- name: Create one remediation PR per finding
  uses: your-org/fortify-aviator-remediation-action@v1
  with:
    fod-client-id: ${{ secrets.FOD_CLIENT_ID }}
    fod-client-secret: ${{ secrets.FOD_CLIENT_SECRET }}
    fod-release-id: ${{ secrets.FOD_RELEASE_ID }}
    github-token: ${{ secrets.REMEDIATION_GITHUB_TOKEN || github.token }}
    fod-pr-grouping: issue
```

### Run In PR Scope

Use this when you want remediation to stay limited to files already touched by the PR.

```yaml
- name: PR-scoped remediation
  uses: your-org/fortify-aviator-remediation-action@v1
  with:
    fod-client-id: ${{ secrets.FOD_CLIENT_ID }}
    fod-client-secret: ${{ secrets.FOD_CLIENT_SECRET }}
    fod-release-id: ${{ secrets.FOD_RELEASE_ID }}
    github-token: ${{ secrets.REMEDIATION_GITHUB_TOKEN || github.token }}
    pr-number: ${{ github.event.pull_request.number }}
    github-base-ref: ${{ github.base_ref }}
```

### Disable Validation

Useful for repositories that do not want any validation gate.

```yaml
- name: Remediation without validation
  uses: your-org/fortify-aviator-remediation-action@v1
  with:
    fod-client-id: ${{ secrets.FOD_CLIENT_ID }}
    fod-client-secret: ${{ secrets.FOD_CLIENT_SECRET }}
    fod-release-id: ${{ secrets.FOD_RELEASE_ID }}
    github-token: ${{ secrets.REMEDIATION_GITHUB_TOKEN || github.token }}
    remediation-validate-command: "false"
```

### Java Or Kotlin Project

```yaml
- name: Java remediation with Maven validation
  uses: your-org/fortify-aviator-remediation-action@v1
  with:
    fod-client-id: ${{ secrets.FOD_CLIENT_ID }}
    fod-client-secret: ${{ secrets.FOD_CLIENT_SECRET }}
    fod-release-id: ${{ secrets.FOD_RELEASE_ID }}
    github-token: ${{ secrets.REMEDIATION_GITHUB_TOKEN || github.token }}
    setup-java: "true"
    java-version: "17"
    remediation-validate-command: "mvn -q -DskipTests compile"
```

### JavaScript Or TypeScript Project

Install Node before the action, then pass your project validation command.

```yaml
- uses: actions/setup-node@v4
  with:
    node-version: "20"

- name: Node remediation with tests
  uses: your-org/fortify-aviator-remediation-action@v1
  with:
    fod-client-id: ${{ secrets.FOD_CLIENT_ID }}
    fod-client-secret: ${{ secrets.FOD_CLIENT_SECRET }}
    fod-release-id: ${{ secrets.FOD_RELEASE_ID }}
    github-token: ${{ secrets.REMEDIATION_GITHUB_TOKEN || github.token }}
    remediation-validate-command: "npm test"
```

### Python Project

```yaml
- uses: actions/setup-python@v5
  with:
    python-version: "3.12"

- run: pip install -r requirements.txt

- name: Python remediation with pytest
  uses: your-org/fortify-aviator-remediation-action@v1
  with:
    fod-client-id: ${{ secrets.FOD_CLIENT_ID }}
    fod-client-secret: ${{ secrets.FOD_CLIENT_SECRET }}
    fod-release-id: ${{ secrets.FOD_RELEASE_ID }}
    github-token: ${{ secrets.REMEDIATION_GITHUB_TOKEN || github.token }}
    remediation-validate-command: "pytest -q"
```

### .NET Project

```yaml
- uses: actions/setup-dotnet@v4
  with:
    dotnet-version: "8.0.x"

- name: .NET remediation with build validation
  uses: your-org/fortify-aviator-remediation-action@v1
  with:
    fod-client-id: ${{ secrets.FOD_CLIENT_ID }}
    fod-client-secret: ${{ secrets.FOD_CLIENT_SECRET }}
    fod-release-id: ${{ secrets.FOD_RELEASE_ID }}
    github-token: ${{ secrets.REMEDIATION_GITHUB_TOKEN || github.token }}
    remediation-validate-command: "dotnet build"
```

### Go Project

```yaml
- uses: actions/setup-go@v5
  with:
    go-version: "1.22"

- name: Go remediation with tests
  uses: your-org/fortify-aviator-remediation-action@v1
  with:
    fod-client-id: ${{ secrets.FOD_CLIENT_ID }}
    fod-client-secret: ${{ secrets.FOD_CLIENT_SECRET }}
    fod-release-id: ${{ secrets.FOD_RELEASE_ID }}
    github-token: ${{ secrets.REMEDIATION_GITHUB_TOKEN || github.token }}
    remediation-validate-command: "go test ./..."
```

### Consume Action Outputs

```yaml
- name: Run remediation
  id: remediation
  uses: your-org/fortify-aviator-remediation-action@v1
  with:
    fod-client-id: ${{ secrets.FOD_CLIENT_ID }}
    fod-client-secret: ${{ secrets.FOD_CLIENT_SECRET }}
    fod-release-id: ${{ secrets.FOD_RELEASE_ID }}
    github-token: ${{ secrets.REMEDIATION_GITHUB_TOKEN || github.token }}

- name: Print summaries
  run: |
    echo '${{ steps.remediation.outputs.metrics-summary }}'
    echo '${{ steps.remediation.outputs.results-summary }}'
```

### Use This Repository’s Local Action Path

This is how the bundled Security Shepherd workflow consumes the action:

```yaml
- name: Run Fortify Aviator remediation action
  uses: ./fortify_aviator_remediation
  with:
    fod-base-url: ${{ vars.FOD_BASE_URL || 'https://api.ams.fortify.com' }}
    fod-client-id: ${{ secrets.FOD_CLIENT_ID }}
    fod-client-secret: ${{ secrets.FOD_CLIENT_SECRET }}
    fod-release-id: ${{ secrets.FOD_RELEASE_ID }}
    github-token: ${{ secrets.REMEDIATION_GITHUB_TOKEN || github.token }}
    fod-severity-strings: ${{ vars.FOD_SEVERITY_STRINGS || 'Critical' }}
    fod-pr-grouping: ${{ vars.FOD_PR_GROUPING || 'category' }}
    remediation-validate-command: ${{ vars.REMEDIATION_VALIDATE_COMMAND || 'mvn -q -DskipTests compile' }}
    setup-java: "true"
    java-version: "8"
```

### Combined Scan Then Remediate

```yaml
jobs:
  fortify-fod:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      issues: write
      pull-requests: write
      security-events: write
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: actions/setup-java@v4
        with:
          distribution: temurin
          java-version: "17"

      - name: Run FoD scan
        uses: your-org/fortify-aviator-remediation-action/fod-scan@v1
        with:
          fod-client-id: ${{ secrets.FOD_CLIENT_ID }}
          fod-client-secret: ${{ secrets.FOD_CLIENT_SECRET }}
          fod-release: ${{ secrets.FOD_RELEASE_ID }}
          package-extra-opts: "-bt mvn"
          do-pr-comment: ${{ github.event_name == 'pull_request' }}

  fortify-aviator-remediation:
    needs: fortify-fod
    runs-on: ubuntu-latest
    permissions:
      contents: write
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Run remediation
        uses: your-org/fortify-aviator-remediation-action@v1
        with:
          fod-client-id: ${{ secrets.FOD_CLIENT_ID }}
          fod-client-secret: ${{ secrets.FOD_CLIENT_SECRET }}
          fod-release-id: ${{ secrets.FOD_RELEASE_ID }}
          github-token: ${{ secrets.REMEDIATION_GITHUB_TOKEN || github.token }}
          remediation-validate-command: "mvn -q -DskipTests compile"
          setup-java: "true"
```

## Local Development

Example local run:

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

Local environment variables are shown in `.env.example`:

```dotenv
FOD_BASE_URL=https://ams.fortify.com
FOD_CLIENT_ID=replace_me
FOD_CLIENT_SECRET=replace_me
FOD_TENANT=
FOD_USER=
FOD_PASSWORD=
FOD_OAUTH_SCOPE=api-tenant
FOD_RELEASE_ID=123456
FOD_VERIFY_SSL=true
FOD_SEVERITY_STRINGS=Critical
FOD_PR_GROUPING=category
GITHUB_TOKEN=replace_me
GITHUB_REPOSITORY=owner/repo
PR_NUMBER=
GITHUB_BASE_REF=main
GIT_USER_NAME=github-actions[bot]
GIT_USER_EMAIL=41898282+github-actions[bot]@users.noreply.github.com
REMEDIATION_VALIDATE_COMMAND=false
```

## Notes

- This repository now contains two actions: a FoD scan wrapper in `fod-scan/` and the Aviator remediation action at the repository root.
- The action prefers FoD client credentials and release id inputs.
- The default grouping mode is `category`.
- The default validation mode is disabled so the action stays language-neutral out of the box.
- If you want validation, pass a project-specific command and install any required toolchain in the workflow before this action runs.
- When grouping by category, failed candidates are skipped and reported while successful candidates can still be published in the same PR.
- Optional Java setup exists for Maven or Gradle projects, but non-Java projects should use their own setup action instead.
- The engine writes compact JSON summaries and can publish markdown metrics to the GitHub Actions job summary.

## Example Workflow In This Repository

The bundled workflow in `../.github/workflows/fortify.yml`:
- runs FoD scans on `push` to `main` and `dev`
- runs FoD scans plus Aviator remediation on `push` to `main` and `dev`
- supports `pull_request` events when you want PR comments from the Fortify action
- supports manual `workflow_dispatch`
- defaults remediation scope to `FOD_SEVERITY_STRINGS=Critical`
- defaults PR grouping to `FOD_PR_GROUPING=category`
- skips fork-based PR remediation because repository credentials are required
- uses PR file scope when a PR number is available
