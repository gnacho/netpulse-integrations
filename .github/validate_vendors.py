#!/usr/bin/env python3
"""Validate vendors.json against the repository reality.

vendors.json is the machine-readable vendor catalog consumed by NetPulse
(GET /api/integrations/vendors). This script is the drift guard: it exits
non-zero with a clear message whenever the catalog and the repository
disagree.

Checks:

Schema
  - vendors.json is valid JSON with a non-empty "vendors" array
  - every entry carries id, mode, arches, tagPrefix, binary, target and
    description, and none of them is empty
  - mode is "local" or "ssh" (server semantics, fixed by the schema)
  - arches is a non-empty list of known Go arches without duplicates
  - ids are unique, lowercase, and entries are sorted by id

Repository reality
  - every entry has a vendor directory named after its lowercase id with a
    README.md
  - every top-level directory with a README.md (a vendor) has an entry
  - every target path exists (<target>/main.go)

Release workflow
  - every tagPrefix has a matching "tags:" pattern and case block in
    .github/workflows/release.yml, and that case block builds the declared
    binary from the declared target for exactly the declared arches
  - every release.yml tag pattern and case block has a catalog entry

Standard library only, so CI needs no extra dependencies.
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CATALOG = ROOT / "vendors.json"
RELEASE = ROOT / ".github" / "workflows" / "release.yml"

KNOWN_MODES = ("local", "ssh")
KNOWN_ARCHES = ("amd64", "arm64", "arm", "386")
REQUIRED_FIELDS = ("id", "mode", "arches", "tagPrefix", "binary", "target", "description")


def parse_release():
    """Return (tag_prefixes, builds) parsed textually from release.yml."""
    text = RELEASE.read_text(encoding="utf-8")
    tag_prefixes = set(re.findall(r"^\s*-\s+'([^'/]+)/v\*'\s*$", text, re.M))

    case = re.search(r'case "\$TAG" in\n(.*?)^\s*esac', text, re.S | re.M)
    if case is None:
        raise SystemExit("release.yml: cannot find the TAG case block")

    def grab(block, field):
        m = re.search(rf'^\s*{field}=(?:"([^"]*)"|(\S+))\s*$', block, re.M)
        if m is None:
            return None
        return m.group(1) if m.group(1) is not None else m.group(2)

    builds = {}
    for block in re.split(r"^\s*;;\s*$", case.group(1), flags=re.M):
        head = re.match(r"^\s*(\S+/v\*)\)\s*$", block, re.M)
        if head is None:  # the *) default case and stray lines
            continue
        prefix = head.group(1)[: -len("/v*")]
        builds[prefix] = {
            "binary": grab(block, "binary"),
            "target": grab(block, "target"),
            "arches": (grab(block, "arches") or "").split(),
        }
    return tag_prefixes, builds


def norm_target(value):
    """Normalize a target path so "./x" and "x" compare equal."""
    return str(Path(value)) if isinstance(value, str) else value


def sorted_arches(value):
    """Sorted arch list, or None when the value is not a list of strings."""
    if isinstance(value, list) and all(isinstance(a, str) for a in value):
        return sorted(value)
    return None


def main():
    errors = []

    def fail(message):
        errors.append(message)

    # Schema: JSON parse and per-entry validation.
    try:
        data = json.loads(CATALOG.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"vendors.json: cannot read or parse: {exc}")
        return 1
    if not isinstance(data, dict) or not isinstance(data.get("vendors"), list) or not data["vendors"]:
        print('vendors.json: expected a top-level object with a non-empty "vendors" array')
        return 1

    entries = {}
    for pos, entry in enumerate(data["vendors"]):
        if not isinstance(entry, dict):
            fail(f"vendors.json: vendors[{pos}] must be an object")
            continue
        for field in REQUIRED_FIELDS:
            if not entry.get(field):
                fail(f'vendors.json: vendors[{pos}] is missing field "{field}"')

        vid = entry.get("id")
        if isinstance(vid, str) and re.fullmatch(r"[a-z0-9-]+", vid):
            label = f'vendors.json: vendor "{vid}"'
            if vid in entries:
                fail(f'{label}: duplicate id (already at vendors[{entries[vid]}])')
            entries[vid] = pos
        else:
            label = f"vendors.json: vendors[{pos}]"
            fail(f"{label}: id must be a lowercase [a-z0-9-] string, got {vid!r}")

        if entry.get("mode") not in KNOWN_MODES:
            fail(f'{label}: mode must be one of {list(KNOWN_MODES)}, got {entry.get("mode")!r}')

        arches = entry.get("arches")
        if not isinstance(arches, list) or not arches:
            fail(f"{label}: arches must be a non-empty array")
        else:
            for arch in arches:
                if arch not in KNOWN_ARCHES:
                    fail(f"{label}: unknown arch {arch!r} (known: {list(KNOWN_ARCHES)})")
            if len(set(arches)) != len(arches):
                fail(f"{label}: duplicate entries in arches {arches}")

        for field in ("tagPrefix", "binary", "target", "description"):
            if field in entry and not isinstance(entry[field], str):
                fail(f'{label}: field "{field}" must be a string')

        prefix = entry.get("tagPrefix")
        if isinstance(prefix, str) and not prefix.endswith("/v"):
            fail(f'{label}: tagPrefix must look like "<vendor>/v", got {prefix!r}')

    if list(entries) != sorted(entries):
        fail(f"vendors.json: entries must be sorted by id, got {list(entries)}")

    # Repository reality: directories, READMEs and target paths.
    vendor_dirs = {
        p.parent.name
        for p in ROOT.glob("*/README.md")
        if not p.parent.name.startswith(".")
    }
    for vid, pos in entries.items():
        entry = data["vendors"][pos]
        label = f'vendors.json: vendor "{vid}"'
        directory = ROOT / vid
        if not directory.is_dir():
            fail(f'{label}: vendor directory "{vid}/" does not exist')
        elif not (directory / "README.md").is_file():
            fail(f'{label}: vendor directory "{vid}/" has no README.md')

        target = entry.get("target")
        if isinstance(target, str) and target:
            parts = Path(target).parts
            if Path(target).is_absolute() or ".." in parts:
                fail(f'{label}: target must be a repository-relative path, got {target!r}')
            elif not (ROOT / target / "main.go").is_file():
                fail(f'{label}: target "{target}/main.go" does not exist')
    for name in sorted(vendor_dirs - set(entries)):
        fail(f'vendors.json: vendor directory "{name}/" has no catalog entry')

    # Release workflow: tag patterns and case block consistency.
    tag_prefixes, builds = parse_release()
    entry_prefixes = {
        entry["tagPrefix"][: -len("/v")]
        for entry in data["vendors"]
        if isinstance(entry, dict)
        and isinstance(entry.get("tagPrefix"), str)
        and entry["tagPrefix"].endswith("/v")
    }
    for vid, pos in entries.items():
        entry = data["vendors"][pos]
        prefix = entry.get("tagPrefix")
        if not isinstance(prefix, str) or not prefix.endswith("/v"):
            continue  # already reported by the schema checks
        prefix = prefix[: -len("/v")]
        label = f'vendors.json: vendor "{vid}"'
        if prefix not in tag_prefixes:
            fail(f'{label}: tagPrefix "{prefix}" has no "<prefix>/v*" pattern in the release.yml tags list')
        build = builds.get(prefix)
        if build is None:
            fail(f'{label}: release.yml has no case block for "{prefix}/v*"')
            continue
        if entry.get("binary") != build["binary"]:
            fail(f'{label}: binary is {entry.get("binary")!r} but release.yml builds {build["binary"]!r} for "{prefix}/v*"')
        if norm_target(entry.get("target")) != norm_target(build["target"]):
            fail(f'{label}: target is {entry.get("target")!r} but release.yml builds {build["target"]!r} for "{prefix}/v*"')
        if sorted_arches(entry.get("arches")) != sorted(build["arches"]):
            fail(f'{label}: arches are {entry.get("arches")} but release.yml builds {build["arches"]} for "{prefix}/v*"')
    for prefix in sorted(set(builds) - entry_prefixes):
        fail(f'release.yml: case block for "{prefix}/v*" has no catalog entry')
    for prefix in sorted(tag_prefixes - set(builds)):
        fail(f'release.yml: tag pattern "{prefix}/v*" has no case block')

    if errors:
        print("vendor catalog drift detected:")
        for message in errors:
            print(f"  - {message}")
        return 1
    print(f"vendors.json OK: {len(entries)} vendors match directories and release.yml")
    return 0


if __name__ == "__main__":
    sys.exit(main())
