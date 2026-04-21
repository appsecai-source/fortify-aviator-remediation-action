#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${GITHUB_ACTION_PATH:-}" ]]; then
  echo "GITHUB_ACTION_PATH is not set; this wrapper must run inside GitHub Actions." >&2
  exit 1
fi

if [[ -z "${GITHUB_WORKSPACE:-}" ]]; then
  echo "GITHUB_WORKSPACE is not set; a checked-out repository workspace is required." >&2
  exit 1
fi

if [[ ! -d "${GITHUB_WORKSPACE}/.git" ]]; then
  echo "The target repository must be checked out before running this action." >&2
  exit 1
fi

has_value() {
  [[ -n "${1:-}" && "${1}" != "null" ]]
}

export FOD_BASE_URL="${INPUT_FOD_BASE_URL}"
export FOD_CLIENT_ID="${INPUT_FOD_CLIENT_ID}"
export FOD_CLIENT_SECRET="${INPUT_FOD_CLIENT_SECRET}"
export FOD_TENANT="${INPUT_FOD_TENANT}"
export FOD_USER="${INPUT_FOD_USER}"
export FOD_PASSWORD="${INPUT_FOD_PASSWORD}"
export FOD_OAUTH_SCOPE="${INPUT_FOD_OAUTH_SCOPE}"
export FOD_RELEASE_ID="${INPUT_FOD_RELEASE_ID}"
export FOD_SEVERITY_STRINGS="${INPUT_FOD_SEVERITY_STRINGS}"
export FOD_PR_GROUPING="${INPUT_FOD_PR_GROUPING}"
export FOD_VERIFY_SSL="${INPUT_FOD_VERIFY_SSL}"
export GITHUB_TOKEN="${INPUT_GITHUB_TOKEN}"
export REMEDIATION_VALIDATE_COMMAND="${INPUT_REMEDIATION_VALIDATE_COMMAND}"
export PYTHONUNBUFFERED=1

if has_value "${INPUT_GITHUB_REPOSITORY:-}"; then
  export GITHUB_REPOSITORY="${INPUT_GITHUB_REPOSITORY}"
elif has_value "${ACTION_DEFAULT_GITHUB_REPOSITORY:-}"; then
  export GITHUB_REPOSITORY="${ACTION_DEFAULT_GITHUB_REPOSITORY}"
fi

if has_value "${INPUT_PR_NUMBER:-}"; then
  export PR_NUMBER="${INPUT_PR_NUMBER}"
elif has_value "${ACTION_DEFAULT_PR_NUMBER:-}"; then
  export PR_NUMBER="${ACTION_DEFAULT_PR_NUMBER}"
fi

if has_value "${INPUT_GITHUB_BASE_REF:-}"; then
  export GITHUB_BASE_REF="${INPUT_GITHUB_BASE_REF}"
elif has_value "${ACTION_DEFAULT_BASE_REF:-}"; then
  export GITHUB_BASE_REF="${ACTION_DEFAULT_BASE_REF}"
elif has_value "${ACTION_DEFAULT_REF_NAME:-}"; then
  export GITHUB_BASE_REF="${ACTION_DEFAULT_REF_NAME}"
fi

if has_value "${INPUT_GIT_USER_NAME:-}"; then
  export GIT_USER_NAME="${INPUT_GIT_USER_NAME}"
fi

if has_value "${INPUT_GIT_USER_EMAIL:-}"; then
  export GIT_USER_EMAIL="${INPUT_GIT_USER_EMAIL}"
fi

results_dir="${RUNNER_TEMP:-/tmp}/fortify-aviator-remediation"
mkdir -p "${results_dir}"
results_file="${results_dir}/results-${GITHUB_RUN_ID:-manual}-${GITHUB_RUN_ATTEMPT:-0}.json"
export REMEDIATION_RESULTS_PATH="${results_file}"

cd "${GITHUB_WORKSPACE}"
python -m pip install --upgrade pip
python -m pip install -r "${GITHUB_ACTION_PATH}/requirements.txt"
python "${GITHUB_ACTION_PATH}/app/remediation_engine.py"
python "${GITHUB_ACTION_PATH}/scripts/write_action_outputs.py" "${results_file}" "${GITHUB_OUTPUT:-}"
