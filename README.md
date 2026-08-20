# lightwell-skills

Shareable **Cursor plugin** (team marketplace / local install) for [Red Hat
Lightwell](https://console.redhat.com/lightwell/demo) Maven work. It is not a
Maven application and not a project skill you get by cloning this repo into a
workspace.

Install the **lightwell** plugin, open a Maven repo, then invoke skills with
`/upgrade-directs` and so on.

Shared helpers (not a skill): [`lightwell-shared`](plugins/lightwell/skills/lightwell-shared/packages-redhat.md).

| Skill | What it does |
|-------|----------------|
| [`upgrade-directs`](plugins/lightwell/skills/upgrade-directs) | Bump direct `pom.xml` deps (plan → collect → apply → summary) |
| [`upgrade-transitives`](plugins/lightwell/skills/upgrade-transitives) | Promote remediated transitive fixes (plan → collect → apply → summary) |
| [`verify-attestations`](plugins/lightwell/skills/verify-attestations) | Cosign provenance check for Lightwell jars |
| [`add-osv-to-renovate`](plugins/lightwell/skills/add-osv-to-renovate) | Comment OSV data on Renovate PRs |

## Install locally (this clone)

Load the plugin from disk while you develop it:

```bash
mkdir -p ~/.cursor/plugins/local
ln -sfn "$(pwd)/plugins/lightwell" ~/.cursor/plugins/local/lightwell
```

Then **Developer: Reload Window**. Open **Customize → Skills** and confirm
`/upgrade-directs`, `/upgrade-transitives`, `/verify-attestations`, and
`/add-osv-to-renovate` are listed. Type `/upgrade-directs` in Agent chat to
run one.

The symlink is user-scoped. Skills always run against the **consumer** Maven
workspace you have open (`pom.xml`), not against this plugin repository.
Lightwell creds come from that consumer repo (`scripts/_creds.sh`) or from
exported `LIGHTWELL_USERNAME` / `LIGHTWELL_TOKEN`.

## Install for a team

On a Cursor Teams/Enterprise plan, import this GitHub repo as a [team
marketplace](https://cursor.com/docs/plugins.md#team-marketplaces):

1. Open **Dashboard → Plugins → Add Marketplace**.
2. **Import from Repo** and use `https://github.com/garethahealy/lightwell-skills`.
   The marketplace manifest is [`.cursor-plugin/marketplace.json`](.cursor-plugin/marketplace.json).
3. Add the **lightwell** plugin and set the install mode (**Default Off**,
   **Default On**, or **Required**).
4. Teammates open **Customize**, find **lightwell**, and **Install** (project
   or user scope) unless the mode already installed it.

Without a team marketplace, each person uses the local symlink above (or
copies `plugins/lightwell` and symlinks that).

## Plugin vs consumer repo

| | This repo (`lightwell-skills`) | Consumer Maven repo |
|--|-------------------------------|---------------------|
| What it is | Cursor plugin source + marketplace manifest | App with `pom.xml` |
| How skills load | Install the **lightwell** plugin | Plugin already installed; cwd is the app |
| CI | Unit + live catalog tests | Optional: vendor/run skill scripts |
| Creds | Not stored here | `scripts/_creds.sh` or `LIGHTWELL_*` |

Project **rules** in [`.cursor/rules/`](.cursor/rules) apply only when this
plugin repo is the open workspace (plugin development). They do not ship with
the plugin package.

## Limitations

Skills parse a **single** `pom.xml` with regex (comments and indent preserved).
They do not resolve parent POMs, BOMs / `dependencyManagement` as Maven does,
profiles, or a multi-module reactor. `dependencyManagement` `<dependency>`
blocks are currently treated like directs. Demo catalog:
`public-lightwell-demo` on packages.redhat.com. Provenance bundles are not
published there yet (live cosign tests are skipped).

**Runtime:** Python **3.14+** (CLIs exit 2 if older), Bash 5+, `jq`. Transitive
plan/apply need Maven (`mvnd` or `mvn`). Attestations need `cosign`.
Add-osv needs `gh`.

**Demo GAV** used by live tests: `org.json:json` at base `20220320` on
`java/remediated`.

## Tests

Python tests live in [`tests/`](tests/), outside `plugins/lightwell`, so they
are not packaged with the plugin. They use [pytest](https://docs.pytest.org/).
`make` defaults to **unit** tests.

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements-dev.txt   # pytest, ruff, mypy
make lint
make test-unit
make test-live   # demo catalog; needs LIGHTWELL_* or scripts/_creds.sh
make test        # unit + live
```

Live catalog tests (`@pytest.mark.live`) hit packages.redhat.com and need
`LIGHTWELL_USERNAME` / `LIGHTWELL_TOKEN` (or `scripts/_creds.sh` via
`_load-creds.sh`), network, and `mvn` on `PATH`. Plugin CI runs unit and live
tests on every push. Provenance/cosign cases stay in the live module but are
skipped until the demo catalog publishes bundles.

Local **pre-commit** includes `rh-pre-commit`, which needs Red Hat VPN / login
the first time. CI strips that hook. Ruff runs in both.
