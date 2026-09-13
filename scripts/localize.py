#!/usr/bin/env python3
"""Localize region-prefixed entries of the built blocklists.

Usage:
    python scripts/localize.py --region <cc> [--out <dir>]

Reads the six built files from lists/ and rewrites entries whose first
hostname label is a known source region label to the target region,
preserving each line's format (plain / "0.0.0.0 name" / "||name^").
Output goes to lists-regions/<cc>/ by default; lists/ is never modified.

Region detection is an explicit label set, NOT a generic two-letter-prefix
regex: ad., su., am., ig. are recon-verified false positives. When src/
gains a new region-prefixed entry, add its label to SOURCE_REGION_LABELS.
"""
import argparse
import hashlib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LISTS = ROOT / "lists"
REGIONS_FILE = ROOT / "src" / "regions.txt"
DEFAULT_OUT_ROOT = ROOT / "lists-regions"

# Fallback for a checkout with no src/regions.txt: the two labels the audit
# observed directly. Kept as a literal so localize.py still works standalone.
FALLBACK_REGION_LABELS = ("de", "us")


def source_region_labels() -> tuple[str, ...]:
    """Every country code the built lists may carry, from src/regions.txt.

    Read from regions.txt rather than hardcoded: build.py generates an entry
    per code there, so a stale literal here would silently leave most regions
    un-rewritten and emit a list mixing 40+ foreign endpoints into a
    single-country file.

    Region detection stays an explicit label set, never a two-letter-prefix
    regex: ad., su., am., ig. are recon-verified false positives (an ad host,
    the OTA server, two unknown services) and must never be rewritten.
    """
    if not REGIONS_FILE.is_file():
        return FALLBACK_REGION_LABELS
    codes = []
    for raw in REGIONS_FILE.read_text(encoding="utf-8").splitlines():
        code = raw.split("#", 1)[0].strip().lower()
        if REGION_RE.match(code):
            codes.append(code)
    return tuple(codes) or FALLBACK_REGION_LABELS


REGION_RE = re.compile(r"^[a-z]{2}$")
SOURCE_REGION_LABELS = source_region_labels()
EXPECTED_FILES = (
    "safe-adblock.txt",
    "safe-domains.txt",
    "safe-hosts.txt",
    "strict-adblock.txt",
    "strict-domains.txt",
    "strict-hosts.txt",
)
HOSTS_PREFIX = "0.0.0.0 "
LOCALIZED_MARKER = ("# Localized: {region} — regional endpoints are NOT audited "
                    "for this region; verify before use.")


def rewrite_entry(line: str, region: str) -> str:
    """Rewrite one entry line's region label, preserving its format."""
    if line.startswith(HOSTS_PREFIX):
        prefix, host, suffix = HOSTS_PREFIX, line[len(HOSTS_PREFIX):], ""
    elif line.startswith("||") and line.endswith("^"):
        prefix, host, suffix = "||", line[2:-1], "^"
    else:
        prefix, host, suffix = "", line, ""
    first, dot, rest = host.partition(".")
    if dot and first in SOURCE_REGION_LABELS:
        host = f"{region}.{rest}"
    return f"{prefix}{host}{suffix}"


def rewrite_content(text: str, region: str) -> tuple[str, int]:
    """Return (localized text, number of entry lines actually changed).

    Entries that collide after rewriting are de-duplicated (first occurrence
    wins): the built lists contain no duplicates by construction (build.py
    rejects them), so collisions only come from rewrites onto an existing
    name - e.g. a native target-region twin or two foreign twins rewriting
    to the same target name.
    """
    lines = text.splitlines()
    if not lines:
        return text, 0
    out: list[str] = []
    seen: set[str] = set()
    rewritten = 0
    marker_added = False
    for line in lines:
        if line.startswith("#"):
            out.append(line)
            continue
        if not marker_added:
            out.append(LOCALIZED_MARKER.format(region=region))
            marker_added = True
        if not line.strip():
            out.append(line)
            continue
        new_line = rewrite_entry(line, region)
        # Siblings of different source regions (de./us.) collapse onto the same
        # target name; emit it once instead of duplicating the entry.
        if new_line in seen:
            continue
        seen.add(new_line)
        if new_line != line:
            rewritten += 1
        out.append(new_line)
    if not marker_added:  # header-only content
        out.append(LOCALIZED_MARKER.format(region=region))
    # Header fixups. The source header describes the all-region build, so after
    # collapsing every country code onto one its entry count is far too high
    # (349 vs 61 for a single country) and its generated-endpoint note counts
    # families this file no longer contains. Correct the count, drop the note.
    out = [line for line in out if not line.startswith("# Note:")]
    out = [f"# Entries: {len(seen)}" if line.startswith("# Entries:") else line
           for line in out]
    return "\n".join(out) + "\n", rewritten


def localize(lists_dir: Path, out_dir: Path, region: str) -> dict[str, int]:
    """Rewrite the six built lists into out_dir; return per-file change counts."""
    if lists_dir.resolve() in (out_dir.resolve(), *out_dir.resolve().parents):
        raise ValueError(f"refusing to write inside the source lists directory: {lists_dir}")
    if not lists_dir.is_dir():
        raise FileNotFoundError(
            f"lists directory not found: {lists_dir} (run python scripts/build.py build first)")
    missing = [name for name in EXPECTED_FILES if not (lists_dir / name).is_file()]
    if missing:
        raise FileNotFoundError(
            f"missing built list files in {lists_dir}: {', '.join(missing)}")
    if out_dir.exists() and not out_dir.is_dir():
        raise ValueError(f"output path exists and is not a directory: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    counts: dict[str, int] = {}
    for name in EXPECTED_FILES:
        text = (lists_dir / name).read_text(encoding="utf-8")
        localized, rewritten = rewrite_content(text, region)
        (out_dir / name).write_text(localized, encoding="utf-8", newline="\n")
        counts[name] = rewritten
    checksums = []
    for name in sorted(counts):
        digest = hashlib.sha256((out_dir / name).read_bytes()).hexdigest()
        checksums.append(f"{digest}  {name}")
    (out_dir / "SHA256SUMS").write_text(
        "\n".join(checksums) + "\n", encoding="utf-8", newline="\n")
    return counts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Localize region-prefixed entries of the built blocklists")
    parser.add_argument("--region", required=True,
                        help="target two-letter region code, e.g. us")
    parser.add_argument("--out", type=Path, default=None,
                        help="output directory (default: lists-regions/<region>)")
    args = parser.parse_args(argv)
    if not REGION_RE.match(args.region):
        print(f"ERROR: --region must be two lowercase letters (got {args.region!r})",
              file=sys.stderr)
        return 2
    out_dir = args.out if args.out is not None else DEFAULT_OUT_ROOT / args.region
    try:
        counts = localize(LISTS, out_dir, args.region)
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    for name in sorted(counts):
        print(f"{name}: {counts[name]} entries rewritten")
    return 0


if __name__ == "__main__":
    sys.exit(main())
