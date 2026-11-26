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

Check every Lightwell package in `pom.xml`: remediated directs and promoted
dependencies whose version is `.rhlw-*`, and validated dependencies that carry
a Lightwell source URL. Promoted transitives are included. Each of those
packages gets its own CycloneDX SBOM. A hash check also covers any other main
JAR (no classifier) in that SBOM whose version is `.rhlw-*`.

A JAR that is not in the local repo is skipped. A component with no SHA-256 is
skipped. Status `mismatch` and SBOM failures (`sbom-download`, `sbom-parse`,
`not-cyclonedx`, `bad-catalog`) make the command exit non-zero. `sbom-download`
includes the HTTP status. HTTP 404 means that build has no CycloneDX file.

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
- [ ] 1. Read Lightwell packages from pom.xml (directs and promoted)
- [ ] 2. Download each package's CycloneDX SBOM
- [ ] 3. SHA-256 check those packages, plus other `.rhlw-*` JARs in the SBOMs
- [ ] 4. Report the markdown table
```

```bash
source "$SHARED/_load-creds.sh" || exit 1
bash "$SHARED/verify-sboms.sh" --pom pom.xml
```

Stdout is a markdown table, same shape as the upgrade summaries. Paste that
stdout as markdown. Do not wrap it in a code fence. Leave the blank line
before the heading. `No packages checked.` when nothing was hashed. When the
SBOM and local SHA-256 match, the hash is printed once. A mismatch prints
both. A download failure prints the HTTP status instead of a hash.

## SBOM SHA-256

| Status | Package | Catalog | Detail |
|------|------|------|------|
| OK | `org.json:json:20220320.0.0.rhlw-00003` | remediated | `sha256` |
| sbom-download | `commons-io:commons-io:2.11.0.rhlw-00011` | remediated | HTTP 404 |
| mismatch | `commons-io:commons-io:2.11.0` | remediated | SBOM `sbom-sha256` / local `local-sha256` |

`Status` is `OK`, `mismatch`, or an SBOM failure (`sbom-download`,
`sbom-parse`, `not-cyclonedx`, `bad-catalog`). Workers:
`LIGHTWELL_SBOM_JOBS` (default 8).

## Do not

- Diagnose why a SHA-256 mismatched
- Skip a promoted `.rhlw-*` dependency
- Hash a component that is neither a `.rhlw-*` build nor one of the pom's Lightwell packages
- Fail when a JAR is missing from the local repo
- Download jars that are not already in the local repo
- Compare any hash other than SHA-256
- Read Maven `.sha1` / `.sha256` sidecars
- Continue after `AUTH_FAILED` / HTTP 401 or 403 — repository download; validate
  `LIGHTWELL_TOKEN`
