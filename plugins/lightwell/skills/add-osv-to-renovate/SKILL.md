---
name: add-osv-to-renovate
description: >-
  Find open Renovate pull requests, look up Lightwell remediated OSV advisories
  for Maven dependency bumps, and comment an OSV summary when matches exist.
  Use when the user asks to add OSV comments to Renovate PRs, annotate Renovate
  dependency updates with CVEs, or mentions add-osv-to-renovate.
---

# Add OSV to Renovate

Comment Lightwell remediated OSV advisory summaries onto open Renovate PRs that
bump Maven dependencies (especially `.rhlw-*` remediations).

OSV helpers: [packages-redhat.md](../lightwell-shared/packages-redhat.md).
Creds / do-not-debug: [upgrade-common.md](../lightwell-shared/upgrade-common.md).

Prefer `scripts/process-renovate-prs.sh` (`--dry-run`, `--pr N`, `-v`). Status
lines (`COMMENTED`, `SKIP_*`, `ERROR_*`) are authoritative. Needs `gh`, `jq`,
and Lightwell creds. Optional consumer CI: run on Renovate `pull_request`
events when the author is `renovate[bot]`.

```
Progress:
- [ ] 1. List open Renovate PRs
- [ ] 2. Extract Maven bumps + query OSV
- [ ] 3. Comment matches (skip duplicates)
- [ ] 4. Summarize
```

```bash
helper="$SKILL/scripts/process-renovate-prs.sh"
"$helper"              # all open Renovate PRs
"$helper" --dry-run    # parse + OSV; print comment body; do not post
"$helper" --pr 6       # single PR
"$helper" -v           # progress on stderr
```

The script lists open `app/renovate` PRs, skips those already marked
`<!-- lightwell-osv-summary -->`, parses Maven `g:a` bumps, keeps `.rhlw-*`
rows, queries `fetch_osv.py`, and comments on matches.

| Token | Meaning |
|-------|---------|
| `COMMENTED` | Posted OSV summary (`N` advisory lines) |
| `DRY_RUN_WOULD_COMMENT` | Matches found; body printed; not posted |
| `SKIP_ALREADY_COMMENTED` | Marker already present |
| `SKIP_NO_MAVEN_BUMPS` | No parseable Maven table rows |
| `SKIP_NO_RHLW` | Maven bumps present but none remediated |
| `SKIP_NO_OSV_MATCH` | Queried; no advisories for the bump |
| `ERROR_*` | `gh` / creds / OSV failure |

Manual fallback (only if the orchestrator cannot run):

```bash
python3 "$SKILL/scripts/parse-renovate-bumps.py" < body.md
python3 "$SHARED/fetch_osv.py" <g> <a> <from> <to>
```

## Do not

- Comment when there are no OSV matches, or re-comment when the marker exists
- Query OSV for non-Maven Renovate updates
- Invent CVEs or print `LIGHTWELL_*`
