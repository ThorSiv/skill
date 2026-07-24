#!/usr/bin/env python3
"""Build a detection-family index for the public EVM hack registry."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


REGISTRY_URL = "https://github.com/sanbir/evm-hack-registry"

FAMILY_RULES = {
    "access-proxy": (
        r"\baccess[- ]?control\b",
        r"\bauthori[sz]",
        r"\bowner(?:ship)?\b",
        r"\binitiali[sz]",
        r"\bproxy\b",
        r"\bstorage[- ]?(?:layout|collision)\b",
        r"\bupgrade",
    ),
    "reentrancy-order": (
        r"\bre-?entran",
        r"\bcallback\b",
        r"\bchecks?[- ]effects?[- ]interactions?\b",
        r"\bexecution[- ]order\b",
    ),
    "accounting-precision": (
        r"\baccounting\b",
        r"\bbalance[- ]tracking\b",
        r"\binsolvenc",
        r"\bprecision\b",
        r"\bround(?:ing|ed)\b",
        r"\bshares?\b",
        r"\btotal[- ]?supply\b",
    ),
    "oracle-market": (
        r"\boracle\b",
        r"\bflash[- ]?loan\b",
        r"\bprice[- ]manipulat",
        r"\bspot[- ]price\b",
        r"\btwap\b",
    ),
    "signatures-aa": (
        r"\baccount[- ]abstraction\b",
        r"\beip[- ]?712\b",
        r"\bnonce\b",
        r"\bpermit\b",
        r"\breplay\b",
        r"\bsignature\b",
    ),
    "bridges-cross-chain": (
        r"\bbridge\b",
        r"\bcross[- ]?chain\b",
        r"\b(?:l1|l2)[- ]?(?:message|messenger)\b",
        r"\bmessage[- ]?(?:receiver|relayer|validation)\b",
    ),
    "token-nft": (
        r"\berc[- ]?(?:20|721|777|1155)\b",
        r"\bfee[- ]on[- ]transfer\b",
        r"\bnft\b",
        r"\brebas",
        r"\bsafe[- ]transfer\b",
        r"\btoken\b",
    ),
    "lending-liquidation": (
        r"\bauction\b",
        r"\bbad[- ]debt\b",
        r"\bborrow",
        r"\bcollateral\b",
        r"\blending\b",
        r"\bliquidat",
        r"\brepay",
    ),
    "amm-vault-staking": (
        r"\bamm\b",
        r"\bliquidity\b",
        r"\bpool\b",
        r"\breserves?\b",
        r"\brewards?\b",
        r"\bstak",
        r"\bswap\b",
        r"\bvault\b",
    ),
    "dos-arrays-gas": (
        r"\barray\b",
        r"\bdenial[- ]of[- ]service\b",
        r"\bdos\b",
        r"\bgas[- ]grief",
        r"\bloop\b",
        r"\bout[- ]of[- ]gas\b",
    ),
    "low-level-evm": (
        r"\bassembly\b",
        r"\bcallcode\b",
        r"\bdelegatecall\b",
        r"\bevm\b",
        r"\blow[- ]level[- ]call\b",
        r"\breturndata\b",
        r"\bselfdestruct\b",
    ),
    "governance-economic": (
        r"\beconomic\b",
        r"\bgovernance\b",
        r"\bprivileged\b",
        r"\bproposal\b",
        r"\btimelock\b",
        r"\bvot(?:e|ing)\b",
    ),
}

_ARCHIVE_SUFFIX = re.compile(r"_exp\d*$", re.IGNORECASE)
_FILE_SUFFIXES = (
    ".t.sol",
    ".tar.gz",
    ".sol",
    ".md",
    ".json",
    ".txt",
    ".zip",
)
_SOURCE_ENTRY = re.compile(r"^\d")


def normalize_entry(path: str) -> str:
    """Return the canonical title for a registry entry path."""

    entry = path.strip().strip("/").split("/", 1)[0]
    lowered = entry.casefold()
    for suffix in _FILE_SUFFIXES:
        if lowered.endswith(suffix):
            entry = entry[: -len(suffix)]
            break
    return _ARCHIVE_SUFFIX.sub("", entry)


def classify(title: str) -> list[str]:
    """Map a finding title to all matching detection pattern families."""

    searchable = re.sub(r"[_/]+", " ", title).casefold()
    families = [
        family
        for family, rules in FAMILY_RULES.items()
        if any(re.search(rule, searchable) for rule in rules)
    ]
    return sorted(families) or ["unclassified"]


def fetch_tree(ref: str = "main") -> list[str]:
    """Fetch unique registry entry names using GitHub's recursive-tree API."""

    api_url = (
        "https://api.github.com/repos/sanbir/evm-hack-registry/git/trees/"
        f"{quote(ref, safe='')}?recursive=1"
    )
    request = Request(
        api_url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "evm-contract-security-audit-indexer",
        },
    )
    try:
        with urlopen(request, timeout=60) as response:
            payload = json.load(response)
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as error:
        raise RuntimeError(f"unable to fetch registry tree: {error}") from error

    if payload.get("truncated"):
        raise RuntimeError("GitHub returned a truncated registry tree")

    entries = set()
    for item in payload.get("tree", []):
        path = item.get("path", "").strip("/")
        if not path:
            continue

        top_level = path.split("/", 1)[0]
        if not _SOURCE_ENTRY.match(top_level):
            continue

        # Recursive results contain both entry directories and their files.
        # The first component also identifies a stand-alone, file-style entry.
        canonical = normalize_entry(top_level)
        if canonical:
            entries.add(canonical)

    return sorted(entries)


def render_index(entries: list[str]) -> str:
    """Render one deterministic source-to-family row per canonical entry."""

    canonical_entries = sorted({normalize_entry(entry) for entry in entries})
    lines = [
        "# EVM Hack Registry Source Index",
        "",
        "| Source entry | Pattern families |",
        "| --- | --- |",
    ]
    for source in canonical_entries:
        lines.append(f"| {source} | {', '.join(classify(source))} |")
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ref", default="main", help="registry Git reference")
    parser.add_argument("--output", type=Path, required=True, help="index path")
    args = parser.parse_args()

    entries = fetch_tree(args.ref)
    rendered = render_index(entries)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(rendered, encoding="utf-8")

    unclassified = sum(classify(entry) == ["unclassified"] for entry in entries)
    print(
        f"sources={len(entries)} mapped={len(entries) - unclassified} "
        f"unclassified={unclassified}"
    )


if __name__ == "__main__":
    main()
