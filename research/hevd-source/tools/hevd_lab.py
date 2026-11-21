#!/usr/bin/env python3
"""Safe helper for the NetTruder HEVD source-study lab.

This tool reads local JSON catalogs and a masked Code Audit bridge file. It
prints study guides and finding summaries. It never builds, loads, signs or
executes any driver code, and it never sends a device request.
"""

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path


LAB_DIR = Path(__file__).resolve().parent.parent
RESEARCH_DIR = LAB_DIR.parent
CATALOG = RESEARCH_DIR / "hevd-catalog.json"
SCENARIOS = RESEARCH_DIR / "hevd-scenarios.json"
DEFAULT_FINDINGS = Path(os.environ.get("LOCALAPPDATA", "")) / "NetTruder" / "hevd-source-findings.json"

SAFETY = (
    "Scope: source-only defensive study. No build, no driver load, no IOCTL, "
    "no payload, no bypass, no service or startup change."
)


def load_json(path):
    with path.open("r", encoding="ascii") as handle:
        return json.load(handle)


def require_keys(obj, keys, label):
    missing = [key for key in keys if key not in obj]
    if missing:
        raise ValueError(label + " missing keys: " + ", ".join(missing))


def check():
    catalog = load_json(CATALOG)
    scenarios = load_json(SCENARIOS)
    require_keys(catalog, ["version", "scope", "techniques"], "hevd-catalog.json")
    require_keys(scenarios, ["version", "scope", "beginner", "advanced"], "hevd-scenarios.json")

    entries = catalog["techniques"]
    if not isinstance(entries, list) or not entries:
        raise ValueError("hevd-catalog.json has no techniques")

    required_entry = ["id", "name", "host", "group", "method", "abuse", "detection", "hardening", "fix"]
    for index, entry in enumerate(entries):
        require_keys(entry, required_entry, "catalog entry " + str(index))

    for level in ("beginner", "advanced"):
        rows = scenarios[level]
        if not isinstance(rows, list) or not rows:
            raise ValueError("hevd-scenarios.json has no " + level + " exercises")
        required_row = ["id", "title", "objective", "steps", "evidence", "mitigation"]
        for index, row in enumerate(rows):
            require_keys(row, required_row, level + " exercise " + str(index))

    levels = Counter(entry.get("method", "?") for entry in entries)
    print("CHECK OK")
    print("catalog=" + str(CATALOG))
    print("entries=" + str(len(entries)))
    print("methods=" + ", ".join(sorted(levels.keys())))
    print("beginner=" + str(len(scenarios["beginner"])))
    print("advanced=" + str(len(scenarios["advanced"])))
    print(SAFETY)
    return 0


def render_exercises(rows, heading):
    out = ["## " + heading, ""]
    for row in rows:
        out.append("### " + str(row.get("id", "")) + " - " + str(row.get("title", "")))
        out.append("")
        out.append("**Objective.** " + str(row.get("objective", "")))
        out.append("")
        for step in row.get("steps", []):
            out.append("- " + str(step))
        out.append("")
        out.append("**Evidence to record.** " + str(row.get("evidence", "")))
        out.append("")
        out.append("**Defensive takeaway.** " + str(row.get("mitigation", "")))
        out.append("")
    return out


def guide(level):
    scenarios = load_json(SCENARIOS)
    catalog = load_json(CATALOG)

    out = ["# HEVD Source Study Guide", "", SAFETY, ""]
    out.append("Source folder: `" + str(LAB_DIR) + "`")
    out.append("")
    out.append("Catalog version: " + str(catalog.get("version", "?")))
    out.append("Scenario version: " + str(scenarios.get("version", "?")))
    out.append("")

    if level in ("beginner", "all"):
        out.extend(render_exercises(scenarios["beginner"], "Beginner track"))
    if level in ("advanced", "all"):
        out.extend(render_exercises(scenarios["advanced"], "Advanced track"))

    out.extend(["## Catalog index", ""])
    for entry in catalog.get("techniques", []):
        out.append("- **" + str(entry.get("id", "")) + "** " + str(entry.get("name", ""))
                   + " - " + str(entry.get("method", "")))
    out.append("")
    sys.stdout.write("\n".join(out))
    return 0


def review():
    """Print one layered guide: plain language first, deep dive second."""
    scenarios = load_json(SCENARIOS)
    catalog = load_json(CATALOG)

    out = ["# HEVD Layered Kernel Source Review", "", SAFETY, ""]
    out.extend([
        "## Beginner layer - plain language",
        "",
        "A driver is kernel code, so a bug in it can affect the whole machine.",
        "This lab reads the source as text only. It never builds or loads it.",
        "",
        "When a copy moves data into a buffer, the destination size must be",
        "known and the source length must never exceed it. A Code Audit hit",
        "means 'review this line'. It does not prove exploitability and it",
        "never gives a trigger step.",
        "",
        "For each finding, read the masked line, the STATE label, and the",
        "safe verification checklist. The fix describes the secure pattern.",
        ""
    ])

    out.extend(["### Beginner exercises", ""])
    for row in scenarios.get("beginner", []):
        out.append("- " + str(row.get("id", "")) + " " + str(row.get("title", ""))
                   + ": " + str(row.get("objective", "")))
    out.append("")

    out.extend([
        "## Advanced layer - source evidence only",
        "",
        "1. Boundary: name the dispatch entry and the function handling the",
        "   caller-controlled buffer. Record both as file:line.",
        "2. Flow: trace each length or size value to the copy, allocation or",
        "   dereference. Note casts, truncation and arithmetic.",
        "3. Capacity: compare destination size with the maximum source length",
        "   on every path, not just one convenient path.",
        "4. Lifetime: map allocate, reference, free and pointer-clear lines.",
        "5. User pointers: confirm probe, single copy into kernel memory, and",
        "   validation order before use.",
        "6. Evidence: record call chain, preconditions, documented fix and",
        "   explicit limits. Static evidence is never runtime proof.",
        ""
    ])

    out.extend(["### Advanced exercises", ""])
    for row in scenarios.get("advanced", []):
        out.append("- " + str(row.get("id", "")) + " " + str(row.get("title", ""))
                   + ": " + str(row.get("objective", "")))
    out.append("")

    out.extend(["## Reading order by catalog entry", ""])
    for entry in catalog.get("techniques", []):
        out.append("- " + str(entry.get("id", "")) + " " + str(entry.get("name", ""))
                   + ". Read DETECTION, HARDENING and EVENT CHAIN, then compare"
                   + " with masked Code Audit evidence.")
    out.extend([
        "",
        "No build, sign, install, load, IOCTL, payload, bypass or exploit step",
        "is part of this review. Keep all security controls enabled.",
        ""
    ])
    sys.stdout.write("\n".join(out))
    return 0


def findings(path, out_path):
    source = Path(path)
    if not source.is_file():
        print("No bridge file found: " + str(source))
        print("Run Code Audit on the HEVD source, then press SEND TO RESEARCH in NetTruder.")
        return 1

    doc = load_json(source)
    rows = doc.get("findings", [])
    if not isinstance(rows, list):
        raise ValueError("bridge findings field is not a list")

    by_sev = Counter(str(row.get("severity", "?")) for row in rows)
    by_ctrl = Counter(str(row.get("control", "?")) for row in rows)

    out = ["# HEVD Code Audit Bridge Summary", "", SAFETY, ""]
    out.append("Generated: " + str(doc.get("generated", "?")))
    out.append("Source: " + str(doc.get("source", "?")))
    out.append("Findings: " + str(len(rows)))
    out.append("")
    out.append("## Severity")
    out.append("")
    for key in sorted(by_sev):
        out.append("- " + key + ": " + str(by_sev[key]))
    out.append("")
    out.append("## Controls")
    out.append("")
    for key in sorted(by_ctrl):
        out.append("- " + key + ": " + str(by_ctrl[key]))
    out.append("")

    out.extend(["## Findings", ""])
    shown = rows[:40]
    for row in shown:
        where = str(row.get("file", "?")) + ":" + str(row.get("line", "?"))
        out.append("### " + str(row.get("id", "?")) + " - " + str(row.get("title", "?")))
        out.append("")
        out.append("Location: `" + where + "`")
        out.append("")
        out.append(str(row.get("detail", "")))
        out.append("")
        out.append("State: " + str(row.get("verdict", "STATIC LEAD / NOT RUNTIME VERIFIED")))
        out.append("Evidence: " + str(row.get("evidence", "-")))
        out.append("Reach: " + str(row.get("reach", "-")))
        checks = row.get("check", [])
        if isinstance(checks, str):
            checks = [checks]
        if checks:
            out.extend(["Verify: " + str(item) for item in checks])
        fixes = row.get("fix", [])
        if isinstance(fixes, str):
            fixes = [fixes]
        for fix in fixes:
            out.append("- " + str(fix))
        out.append("")
    if len(rows) > len(shown):
        out.append("_First " + str(len(shown)) + " of " + str(len(rows)) + " findings shown._")
        out.append("")

    text = "\n".join(out)
    sys.stdout.write(text)
    if out_path:
        target = Path(out_path)
        target.write_text(text, encoding="ascii", errors="replace")
        print("")
        print("Wrote: " + str(target))
    return 0


def paths():
    print("lab=" + str(LAB_DIR))
    print("research=" + str(RESEARCH_DIR))
    print("catalog=" + str(CATALOG))
    print("scenarios=" + str(SCENARIOS))
    print("findings=" + str(DEFAULT_FINDINGS))
    print("venv=" + str(LAB_DIR / ".venv"))
    print(SAFETY)
    return 0


def main():
    parser = argparse.ArgumentParser(description="NetTruder HEVD source-study helper")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("check", help="validate the local catalogs")
    sub.add_parser("paths", help="print lab paths")
    sub.add_parser("review", help="print a layered beginner and advanced review")

    p_guide = sub.add_parser("guide", help="print a beginner or advanced study guide")
    p_guide.add_argument("--level", choices=["beginner", "advanced", "all"], default="all")

    p_findings = sub.add_parser("findings", help="summarize a Code Audit bridge file")
    p_findings.add_argument("--input", default=str(DEFAULT_FINDINGS))
    p_findings.add_argument("--out", default="")

    args = parser.parse_args()
    if args.command == "check":
        return check()
    if args.command == "paths":
        return paths()
    if args.command == "review":
        return review()
    if args.command == "guide":
        return guide(args.level)
    if args.command == "findings":
        return findings(args.input, args.out)
    parser.print_help()
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print("ERROR: " + str(exc))
        sys.exit(2)
