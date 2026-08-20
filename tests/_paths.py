"""Locate plugin script dirs. Tests live outside ``plugins/lightwell``."""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PLUGIN_ROOT = REPO_ROOT / "plugins" / "lightwell"
SKILLS = PLUGIN_ROOT / "skills"
SHARED_SCRIPTS = SKILLS / "lightwell-shared" / "scripts"
UPGRADE_DIRECTS_SCRIPTS = SKILLS / "upgrade-directs" / "scripts"
UPGRADE_TRANSITIVES_SCRIPTS = SKILLS / "upgrade-transitives" / "scripts"
ADD_OSV_SCRIPTS = SKILLS / "add-osv-to-renovate" / "scripts"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
