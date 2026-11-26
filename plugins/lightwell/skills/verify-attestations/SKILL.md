---
name: verify-attestations
description: >-
  Verify Lightwell Maven jars in the local repo against SLSA provenance
  Sigstore bundles from packages.redhat.com using cosign. Use when the user
  asks to verify attestations, provenance, or cosign Lightwell jars.
---

# Verify Attestations

Verify **local Maven repo jars** against sibling `.provenance.sigstore.json`
bundles via `cosign verify-blob-attestation` and the shipped PNC key
[pnc-provenance-signing-key-1.pub](../lightwell-shared/pnc-provenance-signing-key-1.pub).
Does not edit `pom.xml`.

Pair with [upgrade-directs](../upgrade-directs/SKILL.md) /
[upgrade-transitives](../upgrade-transitives/SKILL.md) after a successful
`mvn … clean install`.

Implementation:
[verify-attestations.sh](../lightwell-shared/scripts/verify-attestations.sh).
Contract: [upgrade-common.md](../lightwell-shared/upgrade-common.md)
(execution mode, creds, AUTH_FAILED). API:
[packages-redhat.md](../lightwell-shared/packages-redhat.md).

Requires `cosign` and `mvn`/`mvnd` (`LIGHTWELL_MVN` to override). Provenance
is cached under `lightwell-provenance/`.

```
Progress:
- [ ] 1. Ensure jars exist (build already ran)
- [ ] 2. Batch-verify bumped Lightwell GAVs
- [ ] 3. Report the markdown table
```

From pom.xml (standalone / consumer CI):

```bash
source "$SHARED/_load-creds.sh" || exit 1
python3 "$SHARED/coords_from_pom.py" --pom pom.xml \
| bash "$SHARED/verify-attestations.sh" --batch
```

From an upgrade apply JSON (preferred after Apply):

```bash
source "$SHARED/_load-creds.sh" || exit 1
python3 "$SHARED/coords_from_apply.py" \
  --from-apply /tmp/direct-apply.json \
| bash "$SHARED/verify-attestations.sh" --batch
```

Stdout is a markdown table, same shape as the upgrade summaries and the SBOM
report. Paste that stdout as markdown. Do not wrap it in a code fence. Leave
the blank line before the heading. Workers: `LIGHTWELL_ATTEST_JOBS` (default 8).

## Provenance

| Status | Package | Catalog | Detail |
|------|------|------|------|
| OK | `org.json:json:20220320.0.0.rhlw-00003` | remediated | verified |
| FAIL | `commons-io:commons-io:2.11.0.rhlw-00011` | remediated | HTTP 404 |
| FAIL | `com.fasterxml.woodstox:woodstox-core:6.0.3.rhlw-00001` | remediated | jar-missing |

## Do not

- Diagnose why a jar is missing or why cosign failed
- Extract a public key from the bundle or use any key other than
  `pnc-provenance-signing-key-1.pub`
- Use `cosign verify-blob` instead of `verify-blob-attestation`
- Continue after `AUTH_FAILED` / HTTP 401 or 403 — repository download; validate
  `LIGHTWELL_TOKEN`
