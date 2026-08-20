#!/usr/bin/env bash
# Thin wrapper: load creds then run verify_attestations.py (http_pool + cosign).
# Requires Bash 5+, Python 3.14+, cosign, Maven.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${script_dir}/_load-creds.sh"
exec python3 "${script_dir}/verify_attestations.py" "$@"
