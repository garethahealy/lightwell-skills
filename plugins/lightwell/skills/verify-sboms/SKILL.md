---
name: verify-sboms
description: >-
  Verify Lightwell Maven SHA-256 hashes from CycloneDX SBOMs on
  packages.redhat.com against the local Maven repository. Use when the user
  asks to verify SBOMs, CycloneDX, cyclonedx.json, or verify-sboms.
---

# Verify SBOMs

Verify **SHA-256** hashes in sibling `{artifactId}-{version}.cyclonedx.json`
CycloneDX SBOMs against files in the local Maven repo. Does not edit `pom.xml`.

The [upgrade-directs](../upgrade-directs/SKILL.md) Plan is the list of packages
to consider (`dependencies[]` from `pom.xml`). A hash check runs only when
that `groupId:artifactId:version` is also a main JAR (no classifier) in the
SBOM. An SBOM component that is not in the plan is skipped. A plan package
that is not in the SBOM is skipped. Run Plan on the current pom, including
after Apply, and pass it with `--from-plan`. If `--from-plan` is omitted, the
script builds the same plan from `--pom`.

A JAR that is not in the local repo is skipped. A component with no SHA-256 is
skipped. The only package failure is Status `mismatch`.

Pair with [upgrade-directs](../upgrade-directs/SKILL.md) /
[upgrade-transitives](../upgrade-transitives/SKILL.md) after a successful
`mvn … clean install`.

Implementation:
[verify-sboms.sh](../lightwell-shared/scripts/verify-sboms.sh).
Contract: [upgrade-common.md](../lightwell-shared/upgrade-common.md)
(execution mode, creds, AUTH_FAILED). API:
[packages-redhat.md](../lightwell-shared/packages-redhat.md).

Requires `mvn`/`mvnd` (`LIGHTWELL_MVN` to override). SBOMs are cached under
`lightwell-sbom/`.

```
Progress:
- [ ] 1. Plan (upgrade-directs plan.py)
- [ ] 2. Download CycloneDX SBOMs for Lightwell GAVs
- [ ] 3. SHA-256 check packages that are in both the plan and the SBOM
- [ ] 4. Report the table
```

From pom.xml (standalone / consumer CI):

```bash
python3 "$SKILL/../upgrade-directs/scripts/plan.py" \
  --pom pom.xml -o /tmp/direct-plan.json
source "$SHARED/_load-creds.sh" || exit 1
python3 "$SHARED/coords_from_pom.py" --pom pom.xml \
| bash "$SHARED/verify-sboms.sh" --batch --from-plan /tmp/direct-plan.json
```

From an upgrade apply JSON (preferred after Apply). Re-run Plan so versions
match the updated pom:

```bash
python3 "$SKILL/../upgrade-directs/scripts/plan.py" \
  --pom pom.xml -o /tmp/direct-plan.json
source "$SHARED/_load-creds.sh" || exit 1
python3 "$SHARED/coords_from_apply.py" \
  --from-apply /tmp/direct-apply.json \
| bash "$SHARED/verify-sboms.sh" --batch --from-plan /tmp/direct-plan.json
```

Stdout is a markdown table. Report it as-is. `No packages checked.` when
nothing was hashed.

| Status | SBOM | Package | SBOM SHA-256 | Local SHA-256 |
| ------ | ---- | ------- | ------------ | ------------- |
| OK | remediated org.json:json:1.0.0.rhlw-00001 | org.json:json:1.0.0.rhlw-00001 | `<sha256>` | `<sha256>` |
| mismatch | remediated org.json:json:1.0.0.rhlw-00001 | commons-io:commons-io:2.11.0 | `<sbom sha256>` | `<local sha256>` |

`Status` is `OK`, `mismatch`, or an SBOM failure (`sbom-download`,
`sbom-parse`, `not-cyclonedx`, `bad-catalog`). Workers:
`LIGHTWELL_SBOM_JOBS` (default 8).

## Do not

- Diagnose why a SHA-256 mismatched
- Hash an SBOM component that is not in the directs plan
- Fail when a JAR is missing from the local repo
- Download jars that are not already in the local repo
- Compare any hash other than SHA-256
- Read Maven `.sha1` / `.sha256` sidecars
- Continue after `AUTH_FAILED` / HTTP 403
