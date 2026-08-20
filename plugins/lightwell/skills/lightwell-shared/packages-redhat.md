---
name: packages-redhat-reference
---

# packages.redhat.com / Lightwell reference

Shared helpers and conventions for
[upgrade-directs](../upgrade-directs/SKILL.md),
[upgrade-transitives](../upgrade-transitives/SKILL.md),
[verify-attestations](../verify-attestations/SKILL.md),
[add-osv-to-renovate](../add-osv-to-renovate/SKILL.md).

Workflows live in those skills (plan → collect → apply → summary for upgrades).
Shared **agent contract** for both upgrade skills:
[upgrade-common.md](upgrade-common.md).
This doc is the **shared API**: creds, URLs, caches, script entrypoints.

Scripts live next to this file under `scripts/`. From a skill, set
`SHARED="$SKILL/../lightwell-shared/scripts"` and use `"$SHARED/…"` below.

## What Lightwell is

[Lightwell demo](https://console.redhat.com/lightwell/demo) on
[packages.redhat.com](https://packages.redhat.com/) supplies remediated /
validated packages via the public demo content root
`/api/pulp-content/public-lightwell-demo/`. Resolved via the consumer repo's
`.m2/settings.xml` with `LIGHTWELL_USERNAME` / `LIGHTWELL_TOKEN`. Lightwell
often **backports**
fixes onto a pinned upstream line (`.rhlw-*`) instead of forcing a disruptive
upgrade.

Override content root (optional): `LIGHTWELL_CONTENT_ROOT`.

## Credentials

```bash
source "$SHARED/_load-creds.sh" || exit 1
echo "CREDS_OK"
```

- **Local:** from the **consumer** Maven repo, loads gitignored
  `scripts/_creds.sh` (never Read/print secrets). Not from this plugin tree.
- **CI (this plugin repo):** unit tests do not need Lightwell secrets. Live
  catalog tests use `LIGHTWELL_USERNAME` / `LIGHTWELL_TOKEN` from Actions
  secrets.
- **CI (consumer Maven repo):** exported `LIGHTWELL_USERNAME` /
  `LIGHTWELL_TOKEN` from Actions secrets.
- Never print `LIGHTWELL_*` or run `set -x` with secrets in the environment.
- **HTTP 401/403:** stop immediately. Tell the user to validate `LIGHTWELL_TOKEN`
  (do not treat as MISSING / continue Collect → Apply → Summary). Helpers print
  `AUTH_FAILED: HTTP … — validate LIGHTWELL_TOKEN`.

## Runtime

**Bash 5+**, **Python 3.14+** (CLIs exit 2 if older; same pin as plugin CI),
**jq**. Transitive plan + apply need **Maven**.
Attestations need **cosign**. Access: content URLs + disk cache — not pulp-cli /
Pulp admin APIs. HTTPS via `http_pool.py` (metadata, OSV, provenance download)
with `Cache-Control: no-cache` / `Pragma: no-cache`.

## Catalogs

| Catalog | Maven path | `Source:` URL | Settings id |
|---------|------------|---------------|-------------|
| Remediated | `api/pulp-content/public-lightwell-demo/java/remediated` | `https://packages.redhat.com/api/pulp-content/public-lightwell-demo/java/remediated/` | `lightwell-remediated` |
| Validated | `api/pulp-content/public-lightwell-demo/java/validated` | `https://packages.redhat.com/api/pulp-content/public-lightwell-demo/java/validated/` | `lightwell-validated` |

Do not open `.m2/settings.xml`.

Metadata:

```text
https://packages.redhat.com/api/pulp-content/public-lightwell-demo/java/{remediated|validated}/{groupPath}/{artifactId}/maven-metadata.xml
```

`groupPath` = `groupId` with `.` → `/`.

Catalog inference: `Source:` URL → version `*.rhlw-*` → else probe **remediated
same-base first**, then validated latest. Same-base matching uses SemVer
major.minor.patch equality (e.g. `20220320` ↔ `20220320.0.0.rhlw-*`). Upgrade
skills never downgrade; same major.minor.patch (incl. `.rhlw-*`) auto-applies;
major / minor / unsure → `ASK`.

Canonical URL helpers: `lightwell_urls.py`.

## Shared scripts (`lightwell-shared/scripts/`)

Python library package: `lightwell_shared/` (import as `lightwell_shared.*`).
Thin CLI shims at this directory set `sys.path` and call `main()`.
Plan / collect / apply JSON includes `schemaVersion` (currently `1`).

| Script / package | Role |
|------------------|------|
| `_load-creds.sh` | Export Lightwell creds |
| `_repo.sh` | Consumer repo root (creds file lookup) |
| `lightwell_shared/` | Library: URLs, http_pool, metadata, OSV, pom, apply/summary, attest |
| `resolve_metadata.py` | Metadata fetch/cache CLI shim |
| `fetch_osv.py` | Remediated OSV fetch CLI shim (http_pool) |
| `download_http.py` | Authenticated file / provenance download CLI shim |
| `format-osv-table.py` | Markdown table / PR comment from OSV lines |
| `verify-attestations.sh` | Creds + `verify_attestations.py` (cosign SLSA) |
| `coords_from_apply.py` | Apply JSON → attest stdin lines |
| `coords_from_pom.py` | Lightwell pom deps → attest stdin lines |

Skill scripts put this directory on `sys.path`, then `from lightwell_shared…`.

Low-level metadata CLI (prefer Collect scripts for upgrades):

```bash
source "$SHARED/_load-creds.sh" || exit 1
python3 "$SHARED/resolve_metadata.py" \
  --latest --batch <<'EOF'
remediated commons-io commons-io
validated com.fasterxml.jackson.dataformat jackson-dataformat-yaml
EOF
python3 "$SHARED/resolve_metadata.py" \
  --same-base --batch <<'EOF'
remediated org.json json 20220320
EOF
```

## Caching

Default root: `${XDG_CACHE_HOME:-$HOME/.cache}`. Never store credentials. Never
use HTTP `Expires` / `Cache-Control` for disk-cache decisions.

| Cache | Path | Notes |
|-------|------|-------|
| Metadata | `lightwell-metadata/` | TTL default **3600** + ETag; negatives; same-base; memo; pooled HTTPS |
| Natural trees | `lightwell-natural/` | TTL default **3600**; one Maven tree for all miss parents |
| OSV | `lightwell-osv/` | Manifest TTL default **3600** + advisory checksums |
| Provenance | `lightwell-provenance/` | Reuse bundle if present |

Cold metadata Collect uses keep-alive pools + in-flight GET coalescing
(`LIGHTWELL_HTTP_POOL_SIZE`, default 8) and `LIGHTWELL_METADATA_JOBS` (default
**16**).

Overrides: `LIGHTWELL_*_CACHE_DIR`, `LIGHTWELL_*_CACHE_TTL`,
`LIGHTWELL_METADATA_NEGATIVE_TTL`, `LIGHTWELL_HTTP_POOL_SIZE`,
`LIGHTWELL_MVN`, `LIGHTWELL_*_NO_CACHE=1`.

## Maven

Always: `--batch-mode --no-transfer-progress --settings=.m2/settings.xml`.
Prefer **Maven Daemon** (`mvnd`) when available; override with `LIGHTWELL_MVN`.
Load creds before Maven. After Lightwell bumps, expect
`Downloaded from lightwell-remediated:` / `lightwell-validated:` (central-only =
failed bump).

Plan reuses `<output>.tree.txt` when the pom SHA-256 matches (sidecar
`.tree.txt.pomsha`); Collect natural DROP checks use a single temp pom with all
cache-miss parents.

## Attestations

From apply JSON (preferred after upgrade Apply):

```bash
python3 "$SHARED/coords_from_apply.py" \
  --from-apply /tmp/direct-apply.json \
| bash "$SHARED/verify-attestations.sh" --batch
```

Or stdin coordinates directly:

```bash
bash "$SHARED/verify-attestations.sh" --batch
```

Provenance URL:

```text
…/api/pulp-content/public-lightwell-demo/java/{catalog}/{groupPath}/{artifactId}/{version}/{artifactId}-{version}.provenance.sigstore.json
```

Use `cosign verify-blob-attestation` (not `verify-blob`). See
[verify-attestations](../verify-attestations/SKILL.md).

## OSV

```bash
source "$SHARED/_load-creds.sh" || exit 1
python3 "$SHARED/fetch_osv.py" <g> <a> <from> <to> …
# format for comments/summaries:
…/format-osv-table.py --comment < osv-lines
```

Stdout: `g:a|CVE-…|summary|fixed=<to>|osv=<url>`. Do not invent CVEs.

## Promoted transitives

`<!-- Transitive of g:a -->` + remediated `Source:` + exclusions on introducers.
Details: [upgrade-transitives](../upgrade-transitives/SKILL.md).

## Renovate

Preserve `Source:`, `Transitive of`, exclusions, and `.rhlw-*` shapes. OSV
comments: [add-osv-to-renovate](../add-osv-to-renovate/SKILL.md).
