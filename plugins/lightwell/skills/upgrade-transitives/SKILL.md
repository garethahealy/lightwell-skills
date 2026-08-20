---
name: upgrade-transitives
description: >-
  Promote or update transitive Maven dependencies that have Lightwell remediated
  .rhlw-* fixes (exclude from parents + explicit declare). Workflow: plan,
  collect, apply, summary. Use when the user asks about transitive Lightwell
  fixes, Transitive of markers, or upgrade-transitives.
---

# Upgrade Transitives

Find transitive deps with Lightwell **remediated** `.rhlw-*` fixes and
**promote** them: exclude from introducing directs + declare explicitly with
`<!-- Transitive of … -->`.

**Scope:** remediated transitives only. Direct bumps:
[upgrade-directs](../upgrade-directs/SKILL.md).
Provenance: [verify-attestations](../verify-attestations/SKILL.md).

Run **after** directs are applied/built so `dependency:tree` matches the target
graph.

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
  --pom pom.xml --settings=.m2/settings.xml -o /tmp/transitive-plan.json
```

One `dependency:tree` + pom parse. With `-o`, also writes `.tree.txt` and
reuses it when the pom fingerprint matches (`--force-tree` to refresh).

### 2. Collect

```bash
source "$SHARED/_load-creds.sh" || exit 1
python3 "$SKILL/scripts/collect.py" \
  --from-plan /tmp/transitive-plan.json -o /tmp/transitive-collect.json
```

Output: `{ pom, results[] }` with `PROMOTE` | `UPDATE` | `ASK` | `KEEP` | `DROP`.

Flags: `--skip-natural`, `--take-latest` (after user approval). Do not edit
`pom.xml` here.

**Gate:** If any result is `ASK`, **stop** after Collect. Then Apply with
`--include-ask`.

### 3. Apply

```bash
python3 "$SKILL/scripts/apply.py" \
  --from-collect /tmp/transitive-collect.json -o /tmp/transitive-apply.json
```

| Action | Pom changes |
|--------|-------------|
| `PROMOTE` | exclusions on via parents + `Transitive of` declare + remediated `Source:` |
| `UPDATE` | bump version; refresh via/exclusions |
| `ASK` | not applied unless `--include-ask` |
| `KEEP` | refresh via/exclusions if needed |
| `DROP` | remove declare + matching exclusions |

Flags: `--include-ask`, `--dry-run`, `--skip-build`. Build failure → leave pom,
exit non-zero → **stop**.

Then [post-Apply attestations](../lightwell-shared/upgrade-common.md#post-apply-attestations)
with `/tmp/transitive-apply.json`.

### 4. Summary

```bash
source "$SHARED/_load-creds.sh" || exit 1
python3 "$SKILL/scripts/summary.py" \
  --from-collect /tmp/transitive-collect.json \
  --from-apply /tmp/transitive-apply.json -o /tmp/transitive-summary.md
```

`--from-apply` is **required**. OSV for applied `PROMOTE` / `UPDATE`.

## Skill-specific Do not

- Upgrade directs (other skill)
- Promote validated-only transitives
- Leave orphan exclusions / strip `Transitive of` without DROP cleanup
