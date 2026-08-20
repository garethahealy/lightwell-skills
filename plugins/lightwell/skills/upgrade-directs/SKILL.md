---
name: upgrade-directs
description: >-
  Upgrade direct Maven dependencies in pom.xml with preference for Red Hat
  Lightwell packages (java/remediated and java/validated). Workflow: plan,
  collect, apply, summary. Use when the user asks to upgrade directs, bump
  versions, or mentions upgrade-directs / Lightwell directs.
---

# Upgrade Directs

Upgrade **direct** Maven dependencies in `pom.xml`. Prefer Red Hat Lightwell
artifacts from the [Lightwell demo](https://console.redhat.com/lightwell/demo)
catalogs on [packages.redhat.com](https://packages.redhat.com/).

**Scope:** direct deps only. For transitives use
[upgrade-transitives](../upgrade-transitives/SKILL.md).
For cosign provenance use [verify-attestations](../verify-attestations/SKILL.md).

**Agent contract (read first):**
[upgrade-common.md](../lightwell-shared/upgrade-common.md)
(paths, consumer CI, POM limits, execution mode, SemVer, creds).

Shared API: [packages-redhat.md](../lightwell-shared/packages-redhat.md).

Scripts: `scripts/plan.py`, `collect.py`, `apply.py`, `summary.py`.

```
Progress:
- [ ] 1. Plan
- [ ] 2. Collect
- [ ] 3. Apply
- [ ] 4. Summary
```

### 1. Plan

```bash
python3 "$SKILL/scripts/plan.py" \
  --pom pom.xml -o /tmp/direct-plan.json
```

Local parse only. Output: `{ pom, dependencies[], promotedSkipped[] }`.

### 2. Collect

```bash
source "$SHARED/_load-creds.sh" || exit 1
python3 "$SKILL/scripts/collect.py" \
  --from-plan /tmp/direct-plan.json -o /tmp/direct-collect.json
```

Output: `{ pom, results[] }` with `UPGRADE` | `ASK` | `KEEP` | `MISSING`.

- **remediated:** same SemVer base highest `.rhlw-*` → `UPGRADE`
- **validated:** catalog `latest`; SemVer gate (never downgrade)
- Unknown catalog: remediated same-base first, then validated latest
- **Primary miss:** catalog `latest` → `ASK` `suggested-catalog-latest` (never
  auto-`UPGRADE`, even with `--take-latest`). Still nothing → `MISSING`
- `--take-latest` only after the user approved those bumps

**Gate:** If any result is `ASK`, **stop** after Collect. Then Apply with
`--include-ask` (or re-Collect with `--take-latest`). Do not edit `pom.xml` here.

### 3. Apply

```bash
python3 "$SKILL/scripts/apply.py" \
  --from-collect /tmp/direct-collect.json -o /tmp/direct-apply.json
```

| Flag | Meaning |
|------|---------|
| `--include-ask` | Also apply `ASK` rows (recorded as `UPGRADE`) |
| `--dry-run` | Show planned bumps; no pom write / build |
| `--skip-build` | Edit pom only |

Applies `UPGRADE` (and approved `ASK`), refreshes `Source:` comments, runs
`mvn clean install`. Build failure → leave pom, exit non-zero → **stop**.

Then [post-Apply attestations](../lightwell-shared/upgrade-common.md#post-apply-attestations)
with `/tmp/direct-apply.json`.

### 4. Summary

```bash
source "$SHARED/_load-creds.sh" || exit 1
python3 "$SKILL/scripts/summary.py" \
  --from-collect /tmp/direct-collect.json \
  --from-apply /tmp/direct-apply.json -o /tmp/direct-summary.md
```

`--from-apply` is **required**. OSV `AUTH_FAILED` → **stop**. Do not invent CVEs.

## Skill-specific Do not

- Touch transitive promotions / exclusions (other skill)
- Replace `.rhlw-*` with Central without approval
