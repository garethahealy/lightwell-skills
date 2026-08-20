"""Plan phase: transitive inventory from dependency:tree + pom."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path

from lightwell_shared.mvn_run import repo_root_for, run_dependency_tree
from lightwell_shared.pom_lib import SKIP_SCOPES, parse_pom, parse_tree
from lightwell_shared.runtime import preflight, print_preflight_errors, require_python
from lightwell_shared.schema import stamp

DEFAULT_SETTINGS = ".m2/settings.xml"


def pom_fingerprint(pom_text: str) -> str:
    return hashlib.sha256(pom_text.encode("utf-8")).hexdigest()


def try_reuse_tree(
    tree_path: Path,
    pom_sha: str,
    *,
    force: bool,
) -> str | None:
    """Return tree text if tree_path + sibling .pomsha match pom_sha."""
    if force or not tree_path.is_file() or tree_path.stat().st_size == 0:
        return None
    sha_path = Path(str(tree_path) + ".pomsha")
    if not sha_path.is_file():
        return None
    try:
        stored = sha_path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if stored != pom_sha:
        return None
    return tree_path.read_text(encoding="utf-8")


def save_tree_with_fingerprint(tree_path: Path, tree_text: str, pom_sha: str) -> None:
    tree_path.write_text(tree_text, encoding="utf-8")
    Path(str(tree_path) + ".pomsha").write_text(pom_sha + "\n", encoding="utf-8")


def build_inventory(pom_text: str, tree_text: str) -> dict:
    pom = parse_pom(pom_text)
    directs = set(pom["directsMap"].keys())
    promoted_gas = {p["ga"] for p in pom["promoted"]}
    nodes = parse_tree(tree_text)

    candidates: dict[str, dict] = {}
    for n in nodes:
        if n["scope"] in SKIP_SCOPES:
            continue
        if n["depth"] < 2:
            continue
        intro = n["via_direct"]
        if intro not in directs:
            continue
        if n["ga"] in directs or n["ga"] in promoted_gas:
            continue
        entry = candidates.setdefault(
            n["ga"],
            {
                "ga": n["ga"],
                "groupId": n["ga"].split(":", 1)[0],
                "artifactId": n["ga"].split(":", 1)[1],
                "treeVersion": n["version"],
                "viaParents": set(),
                "alreadyPromoted": False,
            },
        )
        entry["viaParents"].add(intro)

    cand_list = []
    for c in sorted(candidates.values(), key=lambda x: x["ga"]):
        cand_list.append(
            {
                "ga": c["ga"],
                "groupId": c["groupId"],
                "artifactId": c["artifactId"],
                "treeVersion": c["treeVersion"],
                "viaParents": sorted(c["viaParents"]),
                "alreadyPromoted": False,
            }
        )

    promoted = []
    for p in pom["promoted"]:
        promoted.append(
            {
                "ga": p["ga"],
                "groupId": p["groupId"],
                "artifactId": p["artifactId"],
                "treeVersion": p["version"],
                "viaParents": list(p["via"]),
                "alreadyPromoted": True,
            }
        )

    return {
        "directs": pom["directsMap"],
        "exclusions": pom["exclusions"],
        "candidates": cand_list,
        "promoted": promoted,
    }


def main() -> int:
    require_python()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "pom_positional",
        nargs="?",
        default="",
        help="Path to pom.xml (default: pom.xml)",
    )
    parser.add_argument("--pom", default="", help="Path to pom.xml")
    parser.add_argument(
        "--settings",
        default=DEFAULT_SETTINGS,
        help=f"Maven settings path relative to repo root (default: {DEFAULT_SETTINGS})",
    )
    parser.add_argument("-o", "--output", default="")
    parser.add_argument(
        "--tree-file",
        default="",
        help="Reuse an existing dependency:tree text file (skip mvn)",
    )
    parser.add_argument(
        "--save-tree",
        default="",
        help="Write dependency:tree text here (default: <output>.tree.txt when -o set)",
    )
    parser.add_argument(
        "--force-tree",
        action="store_true",
        help="Ignore cached tree even when pom fingerprint matches",
    )
    args = parser.parse_args()

    pom_path = Path(args.pom or args.pom_positional or "pom.xml").resolve()
    if not pom_path.is_file():
        print(f"error: pom not found: {pom_path}", file=sys.stderr)
        return 2

    root = repo_root_for(pom_path)
    settings_rel = args.settings
    if Path(settings_rel).is_absolute():
        settings_path = Path(settings_rel)
        try:
            settings_rel = str(settings_path.relative_to(root))
        except ValueError:
            settings_rel = str(settings_path)
    else:
        settings_path = root / settings_rel
    if not settings_path.is_file():
        print(f"error: Maven settings not found: {settings_path}", file=sys.stderr)
        return 2

    pom_text = pom_path.read_text(encoding="utf-8")
    pom_sha = pom_fingerprint(pom_text)

    save_tree = args.save_tree
    if not save_tree and args.output:
        save_tree = str(Path(args.output).with_suffix(".tree.txt"))

    tree_text = ""
    tree_saved = ""
    reused = False

    if args.tree_file:
        tree_text = Path(args.tree_file).read_text(encoding="utf-8")
        tree_saved = str(Path(args.tree_file).resolve())
    else:
        # Auto-reuse previous -o sibling tree when pom unchanged
        if save_tree and not args.force_tree:
            reused_text = try_reuse_tree(Path(save_tree), pom_sha, force=False)
            if reused_text is not None:
                tree_text = reused_text
                tree_saved = str(Path(save_tree).resolve())
                reused = True
                print(f"TREE_REUSED {tree_saved}", file=sys.stderr)

        if not tree_text:
            missing = preflight(maven=True)
            if missing:
                print_preflight_errors(missing)
                return 2
            try:
                pom_arg = str(pom_path.relative_to(root))
            except ValueError:
                pom_arg = str(pom_path)
            with tempfile.TemporaryDirectory(prefix="lw-plan-t-") as tmp:
                tree_path = Path(tmp) / "tree.txt"
                proc = run_dependency_tree(
                    repo_root=root,
                    settings=settings_rel,
                    pom=pom_arg,
                    output_file=tree_path,
                )
                if proc.returncode != 0 or not tree_path.is_file() or tree_path.stat().st_size == 0:
                    if proc.stderr:
                        print(proc.stderr, file=sys.stderr)
                    print("DEPENDENCY_TREE_FAILED", file=sys.stderr)
                    return 1
                tree_text = tree_path.read_text(encoding="utf-8")

    if save_tree and not reused:
        save_tree_with_fingerprint(Path(save_tree), tree_text, pom_sha)
        tree_saved = str(Path(save_tree).resolve())
    elif save_tree and reused:
        tree_saved = str(Path(save_tree).resolve())

    inventory = build_inventory(pom_text, tree_text)
    inventory["pom"] = str(pom_path)
    inventory["repoRoot"] = str(root)
    inventory["settings"] = settings_rel
    inventory["pomSha"] = pom_sha
    if tree_saved:
        inventory["treeFile"] = tree_saved
        inventory["treeReused"] = reused
    inventory = stamp(inventory)
    text = json.dumps(inventory, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
