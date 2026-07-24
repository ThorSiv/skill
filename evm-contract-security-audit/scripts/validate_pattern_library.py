#!/usr/bin/env python3
"""Validate the detection-only EVM vulnerability pattern library."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


FAMILY_FILES = (
    "access-proxy.md",
    "reentrancy-order.md",
    "accounting-precision.md",
    "oracle-market.md",
    "signatures-aa.md",
    "bridges-cross-chain.md",
    "token-nft.md",
    "lending-liquidation.md",
    "amm-vault-staking.md",
    "dos-arrays-gas.md",
    "low-level-evm.md",
    "governance-economic.md",
)
ALLOWED_FAMILIES = {name.removesuffix(".md") for name in FAMILY_FILES} | {
    "unclassified"
}
REQUIRED_FIELDS = ("Smell", "Invariant", "Test", "Source")
PATTERN_HEADING = re.compile(r"^### ([A-Z][A-Z0-9]*-\d{3}):\s+.+$", re.MULTILINE)
COUNT_LINE = re.compile(
    r"^Total:\s*(\d+)\s*·\s*Mapped:\s*(\d+)\s*·\s*Unclassified:\s*(\d+)\b",
    re.MULTILINE,
)
INDEX_ROW = re.compile(r"^\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|", re.MULTILINE)
FORBIDDEN_MARKERS = {
    "attackFunction": re.compile(r"\battackFunction\b", re.IGNORECASE),
    "vm.deal": re.compile(r"\bvm\.deal\s*\(", re.IGNORECASE),
    "vm.store": re.compile(r"\bvm\.store\s*\(", re.IGNORECASE),
    "createSelectFork": re.compile(r"\bcreateSelectFork\b", re.IGNORECASE),
    "broadcast": re.compile(r"\b(?:start|stop)?broadcast\s*\(", re.IGNORECASE),
    "private key": re.compile(r"\bprivate[ _-]?key\b", re.IGNORECASE),
    "seed phrase": re.compile(r"\bseed[ _-]?phrase\b", re.IGNORECASE),
}


def _pattern_blocks(text: str) -> list[tuple[str, str]]:
    matches = list(PATTERN_HEADING.finditer(text))
    blocks = []
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        blocks.append((match.group(1), text[match.end() : end]))
    return blocks


def _validate_pattern_files(root: Path) -> list[str]:
    errors: list[str] = []
    pattern_dir = root / "references" / "patterns"
    actual = (
        {path.name for path in pattern_dir.glob("*.md")}
        if pattern_dir.is_dir()
        else set()
    )
    required = set(FAMILY_FILES)
    for name in sorted(required - actual):
        errors.append(f"missing required pattern file: {name}")
    for name in sorted(actual - required):
        errors.append(f"unexpected pattern file: {name}")

    seen_ids: dict[str, str] = {}
    for name in FAMILY_FILES:
        path = pattern_dir / name
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        blocks = _pattern_blocks(text)
        if not blocks:
            errors.append(f"{name}: no FAMILY-NNN pattern headings")
        for pattern_id, body in blocks:
            if pattern_id in seen_ids:
                errors.append(
                    f"duplicate pattern ID {pattern_id}: {seen_ids[pattern_id]} and {name}"
                )
            else:
                seen_ids[pattern_id] = name
            fields = {
                match.group(1): match.group(2).strip()
                for match in re.finditer(
                    r"^- (Smell|Invariant|Test|Source):\s*(.*)$",
                    body,
                    re.MULTILINE,
                )
            }
            for field in REQUIRED_FIELDS:
                if not fields.get(field):
                    errors.append(f"{name} {pattern_id}: missing {field} field")
            source = fields.get("Source", "")
            if "https://github.com/sanbir/evm-hack-registry" not in source:
                errors.append(f"{name} {pattern_id}: Source must use sanbir/evm-hack-registry")
            if not re.search(r"\bsearch\s+`[^`]+`", source):
                errors.append(f"{name} {pattern_id}: Source must include a search hook")

        for label, marker in FORBIDDEN_MARKERS.items():
            if marker.search(text):
                errors.append(f"{name}: forbidden marker {label}")
    return errors


def _validate_source_index(root: Path) -> list[str]:
    path = root / "references" / "source-index.md"
    if not path.is_file():
        return ["missing source index: references/source-index.md"]
    text = path.read_text(encoding="utf-8")
    if "https://github.com/sanbir/evm-hack-registry" not in text:
        return ["source index must use sanbir/evm-hack-registry provenance"]

    rows = [
        (source.strip(), families.strip())
        for source, families in INDEX_ROW.findall(text)
        if source.strip() not in {"Source entry", "---"}
    ]
    errors: list[str] = []
    count_match = COUNT_LINE.search(text)
    if count_match is None:
        errors.append("source index is missing declared Total/Mapped/Unclassified counts")
    elif int(count_match.group(1)) != len(rows):
        errors.append(
            f"source index declares Total {count_match.group(1)} but contains {len(rows)} data rows"
        )

    mapped_count = sum(families != "unclassified" for _, families in rows)
    unclassified_count = sum(families == "unclassified" for _, families in rows)
    if count_match is not None and int(count_match.group(2)) != mapped_count:
        errors.append(
            f"source index declares Mapped {count_match.group(2)} but contains {mapped_count}"
        )
    if count_match is not None and int(count_match.group(3)) != unclassified_count:
        errors.append(
            "source index declares Unclassified "
            f"{count_match.group(3)} but contains {unclassified_count}"
        )

    seen: set[str] = set()
    for source, families_cell in rows:
        if source in seen:
            errors.append(f"duplicate source-index entry: {source}")
        seen.add(source)
        families = [family.strip() for family in families_cell.split(",")]
        for family in families:
            if family not in ALLOWED_FAMILIES:
                errors.append(f"unknown source-index family {family}: {source}")
    return errors


def validate_library(root: Path) -> list[str]:
    """Return deterministic validation errors for one Skill directory."""

    root = Path(root)
    errors = _validate_pattern_files(root) + _validate_source_index(root)
    skill_path = root / "SKILL.md"
    if skill_path.is_file():
        skill_text = skill_path.read_text(encoding="utf-8")
        for label, marker in FORBIDDEN_MARKERS.items():
            if marker.search(skill_text):
                errors.append(f"SKILL.md: forbidden marker {label}")
    return sorted(errors)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "skill_root",
        nargs="?",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="path to the evm-contract-security-audit Skill",
    )
    args = parser.parse_args()
    errors = validate_library(args.skill_root)
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    print("Pattern library valid: 12 families, unique IDs, complete source index.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
