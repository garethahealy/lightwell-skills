---
name: verify-attestations
description: >-
  Verify Lightwell Maven jars in the local repo against SLSA provenance
  Sigstore bundles from packages.redhat.com using cosign. Use when the user
  asks to verify attestations, provenance, or cosign Lightwell jars.
---

# Verify Attestations

Verify **local Maven repo jars** against sibling `.provenance.sigstore.json`
bundles via `cosign verify-blob-attestation`. Does not edit `pom.xml`.

Pair with [upgrade-directs](../upgrade-directs/SKILL.md) /
[upgrade-transitives](../upgrade-transitives/SKILL.md) after a successful
`mvn … clean install`.

Implementation:
[verify-attestations.sh](../lightwell-shared/scripts/verify-attestations.sh).
Contract: [upgrade-common.md](../lightwell-shared/upgrade-common.md)
(execution mode, creds, AUTH_FAILED). API:
[packages-redhat.md](../lightwell-shared/packages-redhat.md).

Requires `cosign` and `mvn`/`mvnd` (`LIGHTWELL_MVN` to override). Provenance
is cached under `lightwell-provenance/`. Demo catalog does not publish bundles
yet.

```
Progress:
- [ ] 1. Ensure jars exist (build already ran)
- [ ] 2. Batch-verify bumped Lightwell GAVs
- [ ] 3. Report OK / FAIL
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

Stdout: `OK catalog g:a:v` or `FAIL catalog g:a:v reason=…`. Report those
lines as-is. Workers: `LIGHTWELL_ATTEST_JOBS` (default 8).

## Do not

- Diagnose why a jar is missing or why cosign failed
- Invent public keys (helper extracts from Rekor in the bundle)
- Use `cosign verify-blob` instead of `verify-blob-attestation`
- Continue after `AUTH_FAILED` / HTTP 403
