# Shared repository path helpers for Lightwell skill scripts.
# Source this file; do not execute it. Requires Bash 5+.

# Print the consumer Maven/git repo root (not the plugin/skill tree).
# Prefer git toplevel of start_dir (default: PWD). Walk up for .git or pom.xml.
lightwell_repo_root() {
  local start="${1:-$PWD}"
  local root=""
  local dir=""
  if [[ ! -d "$start" ]]; then
    start="$(dirname "$start")"
  fi
  root="$(git -C "${start}" rev-parse --show-toplevel 2>/dev/null || true)"
  if [[ -n "$root" ]]; then
    printf '%s\n' "$root"
    return 0
  fi
  dir="$(cd "$start" && pwd)"
  while [[ "$dir" != "/" ]]; do
    if [[ -d "$dir/.git" || -f "$dir/pom.xml" ]]; then
      printf '%s\n' "$dir"
      return 0
    fi
    dir="$(dirname "$dir")"
  done
  printf '%s\n' "$(cd "$start" && pwd)"
}
