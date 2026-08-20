#!/usr/bin/env bash
# Comment Lightwell remediated OSV summaries onto open Renovate PRs.
# Never prints credentials. Requires Bash 5+, Python 3.14+, gh, jq.
set -euo pipefail

usage() {
  cat <<EOF >&2
Usage: $(basename "$0") [options]

Find open Renovate PRs, query Lightwell remediated OSV for Maven .rhlw-*
bumps, and comment an advisory summary when matches exist.

Options:
  --pr <N>      Process only pull request N (must be open Renovate PR)
  --dry-run     Query OSV and print the comment that would be posted; do not comment
  -v, --verbose Progress on stderr
  -h, --help    Show this help and exit

Exit codes:
  0  success (including all-skips / no matches)
  1  fatal error (gh / creds / OSV infrastructure)
  2  usage error
EOF
}

die() {
  echo "error: $*" >&2
  exit 2
}

verbose=0
dry_run=0
pr_filter=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    -v|--verbose)
      verbose=1
      shift
      ;;
    --dry-run)
      dry_run=1
      shift
      ;;
    --pr)
      [[ $# -ge 2 ]] || die "--pr requires a number"
      pr_filter="$2"
      shift 2
      ;;
    -*)
      die "unknown option: $1"
      ;;
    *)
      die "unexpected argument: $1"
      ;;
  esac
done

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
shared_scripts="$(cd "${script_dir}/../../lightwell-shared/scripts" && pwd)"
parse_py="${script_dir}/parse-renovate-bumps.py"
osv_py="${shared_scripts}/fetch_osv.py"
marker="<!-- lightwell-osv-summary -->"

if [[ ! -f "$parse_py" ]]; then
  echo "ERROR_PARSER_MISSING: ${parse_py}" >&2
  exit 1
fi
if [[ ! -f "$osv_py" ]]; then
  echo "ERROR_OSV_HELPER_MISSING: ${osv_py}" >&2
  exit 1
fi

# shellcheck disable=SC1091
source "${shared_scripts}/_load-creds.sh"

if ! command -v gh >/dev/null 2>&1; then
  echo "ERROR_GH_MISSING" >&2
  exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "ERROR_JQ_MISSING" >&2
  exit 1
fi

logv() {
  if (( verbose )); then
    echo "$*" >&2
  fi
}

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

# --- list open Renovate PRs ---
prs_json="${tmp_dir}/prs.json"
if [[ -n "$pr_filter" ]]; then
  if ! gh pr view "$pr_filter" --json number,title,url,body,author,state >"$prs_json" 2>"${tmp_dir}/gh.err"; then
    echo "ERROR_GH: failed to view PR ${pr_filter}" >&2
    exit 1
  fi
  # Normalize single object → array
  jq '[.]' "$prs_json" >"${prs_json}.arr"
  mv "${prs_json}.arr" "$prs_json"
else
  if ! gh pr list --author "app/renovate" --state open \
    --json number,title,url,body,author >"$prs_json" 2>"${tmp_dir}/gh.err"; then
    echo "ERROR_GH: failed to list Renovate PRs" >&2
    exit 1
  fi
fi

pr_count="$(jq 'length' "$prs_json")"
logv "Open Renovate PRs to consider: ${pr_count}"

if [[ "$pr_count" -eq 0 ]]; then
  echo "NO_OPEN_RENOVATE_PRS"
  exit 0
fi

fatal=0

process_pr() {
  local number="$1"
  local title="$2"
  local url="$3"
  local body_file="$4"

  logv "PR #${number}: ${title}"

  if [[ -n "$pr_filter" ]]; then
    local state author_login
    state="$(jq -r '.[0].state // empty' "$prs_json")"
    author_login="$(jq -r '.[0].author.login // empty' "$prs_json")"
    if [[ "$state" != "OPEN" ]]; then
      echo "PR#${number} SKIP_NOT_OPEN"
      return 0
    fi
    if [[ "$author_login" != "app/renovate" ]]; then
      echo "PR#${number} SKIP_NOT_RENOVATE"
      return 0
    fi
  fi

  local comments_file="${tmp_dir}/comments-${number}.txt"
  if ! gh api "repos/{owner}/{repo}/issues/${number}/comments" --paginate \
    --jq '.[].body' >"$comments_file" 2>"${tmp_dir}/gh-comments.err"; then
    echo "PR#${number} ERROR_GH_COMMENTS"
    fatal=1
    return 0
  fi
  if grep -qF "$marker" "$comments_file" 2>/dev/null; then
    echo "PR#${number} SKIP_ALREADY_COMMENTED ${url}"
    return 0
  fi

  local bumps_file="${tmp_dir}/bumps-${number}.txt"
  local all_maven="${tmp_dir}/maven-${number}.txt"
  if ! python3 "$parse_py" "$body_file" >"$all_maven"; then
    echo "PR#${number} ERROR_PARSE"
    fatal=1
    return 0
  fi
  if [[ ! -s "$all_maven" ]]; then
    echo "PR#${number} SKIP_NO_MAVEN_BUMPS ${url}"
    return 0
  fi
  # rhlw filter without a second parse
  grep -E '\.rhlw-' "$all_maven" >"$bumps_file" || true
  if [[ ! -s "$bumps_file" ]]; then
    echo "PR#${number} SKIP_NO_RHLW ${url}"
    return 0
  fi

  local osv_out="${tmp_dir}/osv-${number}.out"
  local osv_err="${tmp_dir}/osv-${number}.err"
  local osv_args=()
  while read -r g a from to; do
    [[ -z "${g:-}" ]] && continue
    osv_args+=("$g" "$a" "$from" "$to")
  done <"$bumps_file"

  logv "PR #${number}: querying OSV for $((${#osv_args[@]} / 4)) bump(s)"
  set +e
  if (( verbose )); then
    python3 "$osv_py" -v "${osv_args[@]}" >"$osv_out" 2>"$osv_err"
  else
    python3 "$osv_py" "${osv_args[@]}" >"$osv_out" 2>"$osv_err"
  fi
  local osv_rc=$?
  set -e

  if [[ "$osv_rc" -ne 0 ]]; then
    if [[ -s "$osv_err" ]]; then
      tr '\n' ' ' <"$osv_err" | sed 's/[[:space:]]*$//' >&2
      echo >&2
    fi
    echo "PR#${number} ERROR_OSV"
    fatal=1
    return 0
  fi

  if [[ ! -s "$osv_out" ]]; then
    echo "PR#${number} SKIP_NO_OSV_MATCH ${url}"
    return 0
  fi

  local match_count
  match_count="$(wc -l <"$osv_out" | tr -d ' ')"
  local comment_file="${tmp_dir}/comment-${number}.md"
  local format_py
  format_py="$(cd "${script_dir}/../../lightwell-shared/scripts" && pwd)/format-osv-table.py"
  {
    python3 "$format_py" --comment --marker "$marker" <"$osv_out"
  } >"$comment_file"

  if [[ "$dry_run" -eq 1 ]]; then
    echo "PR#${number} DRY_RUN_WOULD_COMMENT ${match_count} ${url}"
    cat "$comment_file"
    return 0
  fi

  if ! gh pr comment "$number" --body-file "$comment_file" >/dev/null 2>"${tmp_dir}/gh-comment.err"; then
    echo "PR#${number} ERROR_GH_COMMENT"
    fatal=1
    return 0
  fi

  echo "PR#${number} COMMENTED ${match_count} ${url}"
}

# Materialize body + meta files, then process each PR
while IFS= read -r num; do
  [[ -z "$num" ]] && continue
  jq -r --argjson n "$num" \
    '.[] | select(.number == $n) | .body // empty' \
    "$prs_json" >"${tmp_dir}/body-${num}.md"
  jq -r --argjson n "$num" \
    '.[] | select(.number == $n) | [.number, ((.title // "") | gsub("\t"; " ")), (.url // "")] | @tsv' \
    "$prs_json" >"${tmp_dir}/meta-${num}.txt"
done < <(jq -r '.[].number' "$prs_json")

while IFS= read -r num; do
  [[ -z "$num" ]] && continue
  IFS=$'\t' read -r number title url <"${tmp_dir}/meta-${num}.txt"
  process_pr "$number" "$title" "$url" "${tmp_dir}/body-${num}.md"
done < <(jq -r '.[].number' "$prs_json")

if [[ "$fatal" -ne 0 ]]; then
  exit 1
fi
exit 0
