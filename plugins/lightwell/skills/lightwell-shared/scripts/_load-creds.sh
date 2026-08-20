# Shared Lightwell credential loader for skill helpers.
# Source this file; do not execute it. Never prints credentials.
# Requires Bash 5+.
#
# On success: LIGHTWELL_USERNAME and LIGHTWELL_TOKEN are set/exported.
# On failure: prints CREDS_FILE_MISSING or CREDS_MISSING to stderr and returns 1.
#
# CI: if LIGHTWELL_USERNAME and LIGHTWELL_TOKEN are already exported (e.g. from
# GitHub Actions secrets), accept them and skip scripts/_creds.sh.
# Local: load from the consumer repo's scripts/_creds.sh (gitignored), not
# from the plugin tree (which may live under ~/.cursor/plugins).

if [[ -n "${LIGHTWELL_TOKEN:-}" && -n "${LIGHTWELL_USERNAME:-}" ]]; then
  export LIGHTWELL_USERNAME LIGHTWELL_TOKEN
  return 0
fi

# Resolve this file's directory under bash (BASH_SOURCE) or zsh (%x).
if [[ -n "${BASH_SOURCE[0]:-}" ]]; then
  _lw_script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
elif [[ -n "${ZSH_VERSION:-}" ]]; then
  # shellcheck disable=SC2296
  _lw_script_dir="$(cd "$(dirname "${(%):-%x}")" && pwd)"
else
  _lw_script_dir="$(cd "$(dirname "$0")" && pwd)"
fi
# shellcheck disable=SC1091
source "${_lw_script_dir}/_repo.sh"
_lw_repo_root="$(lightwell_repo_root "${PWD}")"
_lw_creds="${_lw_repo_root}/scripts/_creds.sh"

if [[ ! -f "${_lw_creds}" ]]; then
  echo "CREDS_FILE_MISSING" >&2
  unset _lw_script_dir _lw_repo_root _lw_creds
  return 1
fi

# shellcheck disable=SC1091
set -a
# shellcheck source=/dev/null
source "${_lw_creds}"
set +a

unset _lw_script_dir _lw_repo_root _lw_creds

if [[ -z "${LIGHTWELL_TOKEN:-}" || -z "${LIGHTWELL_USERNAME:-}" ]]; then
  echo "CREDS_MISSING" >&2
  return 1
fi
