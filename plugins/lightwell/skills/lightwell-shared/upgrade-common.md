---
name: upgrade-common
---

# Upgrade skills — shared agent contract

Shared rules for [upgrade-directs](../upgrade-directs/SKILL.md) and
[upgrade-transitives](../upgrade-transitives/SKILL.md). Skill SKILL.md files
keep phase commands and action semantics only.

API/creds/URLs: [packages-redhat.md](packages-redhat.md).

## Paths

These skills ship in the **lightwell** Cursor plugin (this repository). They
are not project skills under `.cursor/skills/`. Run from the consumer Maven
repo (this plugin repo has no application `pom.xml`). `SKILL` is the
directory that contains the skill's `SKILL.md`;
`SHARED="$SKILL/../lightwell-shared/scripts"`.

## Consumer CI (optional)

This plugin repository has no application `pom.xml`. GitHub Actions for
upgrades belong in the **consumer** Maven repo: vendor or check out these
scripts, then Plan → Collect → Apply (`--include-ask`) → Summary, then
[verify-attestations](../verify-attestations/SKILL.md). Use
`LIGHTWELL_USERNAME` / `LIGHTWELL_TOKEN` secrets. Do not commit from CI unless
asked.

## POM coverage

Plan/Apply read **one** `pom.xml` (regex, comment-preserving). They do not
follow `<parent>`, BOMs, profiles, or `<modules>`. `dependencyManagement`
entries currently look like extra directs. Multi-module: run the skill in the
module you want to change.

## Execution mode (deterministic)

These skills are **scripted pipelines**. Run them; do not investigate them.

- Run the phase commands **exactly** as written, in order. Prefer the phase
  scripts over any ad-hoc approach.
- Treat script stdout / JSON as authoritative. Report results; do not
  reinterpret, second-guess, or “improve” them.
- Documented stops only: **ASK** gate after Collect (SemVer); **AUTH_FAILED** /
  HTTP 401/403 (metadata or OSV). Otherwise, if a phase exits non-zero:
  **stop**, show the relevant stderr/stdout, and wait for the user.
- Do **not** use git history (`git log`, `git show`, `git blame`, historical
  `git diff`) to explain outcomes.
- Do **not** diagnose why Collect returned empty/`KEEP`/`MISSING`/`DROP`, why
  the build failed, why attestations failed, or why OSV is empty.

- Do **not** open, debug, or edit skill / `lightwell-shared` scripts unless the
  user explicitly asks to fix the tooling.
- Do **not** call lower-level helpers as workarounds (`resolve_metadata.py`,
  `--no-cache`, ad-hoc Maven, manual pom edits, HTML scraping).
- Do **not** invent retries with different flags or alternate catalogs.

## SemVer policy

Lightwell moves use Semantic Versioning (**major.minor.patch**). Collect
enforces this in scripts — do not improvise comparisons.

| Situation | Action |
|-----------|--------|
| Candidate SemVer **lower** than current | `KEEP` / skip — **never downgrade** |
| Major differs | `ASK` |
| Minor differs | `ASK` |
| Same major+minor+patch (incl. same-base `.rhlw-*`) | auto apply (`UPGRADE` / `PROMOTE` / `UPDATE`) |
| SemVer unparsable / incomparable | `ASK` (unsure) |
| Same major+minor, **higher** patch | auto apply (`UPGRADE` / `PROMOTE` / `UPDATE`) |

ASK reasons: `semver-major` / `semver-minor` / `semver-unsure` /
`suggested-catalog-latest` (directs Collect MISSING fallback: G:A catalog
`latest` when primary resolve misses).

`--take-latest` / Apply `--include-ask` only after the user approves ASK rows.
Do not Apply `ASK` rows on your own. `suggested-catalog-latest` is never
auto-applied by `--take-latest`.

## Constraints

- Do **not** read `.gitignore` / `.cursorignore` paths (creds, `.m2/`). Skill and
  `lightwell-shared` scripts are allowed (to **run**, not to debug).
- Load secrets via `_load-creds.sh` only — never Read/print `LIGHTWELL_*`.
- If packages.redhat.com returns **HTTP 403** (or 401), **stop**. Tell the user
  to validate `LIGHTWELL_TOKEN`. Do not continue or treat as `MISSING`.
- Always `--batch-mode --no-transfer-progress --settings=.m2/settings.xml`.
  Prefers `mvnd` when on `PATH` (`LIGHTWELL_MVN` to override).
- Do not commit unless asked.
- Prefer **batch** helpers. Disk + in-process metadata cache on by default
  (TTL **3600s**).
- Never invent `.rhlw-*`. Do not scrape packages.redhat.com HTML.
- Run phases **in order**: Plan → Collect → Apply → Summary. Do not start phase
  N until phase N−1 JSON exists and looks valid.

## Credentials

See [Credentials](packages-redhat.md#credentials).

```bash
source "$SHARED/_load-creds.sh" || exit 1
echo "CREDS_OK"
```

Collect and Summary (OSV) need creds. Apply uses Maven settings (no
`LIGHTWELL_*` in the Python process); still source creds before Summary.

## Post-Apply attestations

After Apply success (build ok), verify bumped GAVs (report OK/FAIL lines; do
not dig into why). Never revert `pom.xml` on attestation FAIL /
`PROVENANCE_MISSING` or on Maven build failure — leave the pom for the user to
debug; build failure → exit non-zero → **stop** (skip attestations / Summary).


```bash
python3 "$SHARED/coords_from_apply.py" \
  --from-apply /tmp/<skill>-apply.json \
| bash "$SHARED/verify-attestations.sh" --batch
```

## Shared Do not

- Downgrade a dependency when moving to Lightwell
- Look at git history or reason about *why* a phase failed / returned empty
- Debug or bypass the phase scripts; invent workarounds
- Skip Plan/Collect and edit the pom from guesses
- Continue after `AUTH_FAILED` / HTTP 403 — stop and ask the user to validate
  `LIGHTWELL_TOKEN`
- Print secrets; invent `.rhlw-*` / CVEs; scrape packages.redhat.com HTML
