#!/usr/bin/env python3
"""Build a detection-family index for the public EVM hack registry."""

from __future__ import annotations

import argparse
import json
import re
from collections.abc import Mapping
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


REGISTRY_URL = "https://github.com/sanbir/evm-hack-registry"
API_TREE_URL = "https://api.github.com/repos/sanbir/evm-hack-registry/git/trees"

FAMILY_RULES = {
    "access-proxy": (
        r"\baccess[- ]?control\b", r"\bauthori[sz]", r"\bowner(?:ship)?\b",
        r"\binitiali[sz]", r"\bproxy\b", r"\bstorage[- ]?(?:layout|collision)\b",
        r"\bupgrade",
    ),
    "reentrancy-order": (
        r"\bre-?entran", r"\bcallback\b",
        r"\bchecks?[- ]effects?[- ]interactions?\b", r"\bexecution[- ]order\b",
    ),
    "accounting-precision": (
        r"\baccounting\b", r"\bbalance[- ]tracking\b", r"\binsolvenc",
        r"\bprecision\b", r"\bround(?:ing|ed)\b", r"\bshares?\b",
        r"\btotal[- ]?supply\b",
    ),
    "oracle-market": (
        r"\boracle\b", r"\bflash[- ]?loan\b", r"\bprice[- ]manipulat",
        r"\bspot[- ]price\b", r"\btwap\b",
    ),
    "signatures-aa": (
        r"\baccount[- ]abstraction\b", r"\beip[- ]?712\b", r"\bnonce\b",
        r"\bpermit\b", r"\breplay\b", r"\bsignature\b",
    ),
    "bridges-cross-chain": (
        r"\bbridge\b", r"\bcross[- ]?chain\b",
        r"\b(?:l1|l2)[- ]?(?:message|messenger)\b",
        r"\bmessage[- ]?(?:receiver|relayer|validation)\b",
    ),
    "token-nft": (
        r"\berc[- ]?(?:20|721|777|1155)\b", r"\bfee[- ]on[- ]transfer\b",
        r"\bnft\b", r"\brebas", r"\bsafe[- ]transfer\b", r"\btoken\b",
    ),
    "lending-liquidation": (
        r"\bauction\b", r"\bbad[- ]debt\b", r"\bborrow", r"\bcollateral\b",
        r"\blending\b", r"\bliquidat", r"\brepay",
    ),
    "amm-vault-staking": (
        r"\bamm\b", r"\bliquidity\b", r"\bpool\b", r"\breserves?\b",
        r"\brewards?\b", r"\bstak", r"\bswap\b", r"\bvault\b",
    ),
    "dos-arrays-gas": (
        r"\barray\b", r"\bdenial[- ]of[- ]service\b", r"\bdos\b",
        r"\bgas[- ]grief", r"\bloop\b", r"\bout[- ]of[- ]gas\b",
    ),
    "low-level-evm": (
        r"\bassembly\b", r"\bcallcode\b", r"\bdelegatecall\b", r"\bevm\b",
        r"\blow[- ]level[- ]call\b", r"\breturndata\b", r"\bselfdestruct\b",
    ),
    "governance-economic": (
        r"\beconomic\b", r"\bgovernance\b", r"\bprivileged\b",
        r"\bproposal\b", r"\btimelock\b", r"\bvot(?:e|ing)\b",
    ),
}

_ARCHIVE_SUFFIX = re.compile(r"_exp\d*$", re.IGNORECASE)
_FILE_SUFFIXES = (".t.sol", ".tar.gz", ".sol", ".md", ".json", ".txt", ".zip")
_SOURCE_ENTRY = re.compile(r"^\d")


class TreeFetchError(RuntimeError):
    """A transient transport failure while requesting a GitHub tree."""


def normalize_entry(path: str) -> str:
    """Return the classification/search title for a registry entry path."""

    entry = path.strip().strip("/").rsplit("/", 1)[-1]
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
        family for family, rules in FAMILY_RULES.items()
        if any(re.search(rule, searchable) for rule in rules)
    ]
    return sorted(families) or ["unclassified"]


def _load_tree(treeish: str, *, recursive: bool) -> Mapping:
    suffix = "?recursive=1" if recursive else ""
    request = Request(
        f"{API_TREE_URL}/{quote(treeish, safe='')}{suffix}",
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "evm-contract-security-audit-indexer",
        },
    )
    try:
        with urlopen(request, timeout=60) as response:
            payload = json.load(response)
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as error:
        raise TreeFetchError(f"unable to fetch registry tree: {error}") from error
    if not isinstance(payload, Mapping):
        raise RuntimeError("malformed GitHub tree payload")
    tree = payload.get("tree")
    if not isinstance(tree, list):
        raise RuntimeError("missing or malformed tree list")
    for item in tree:
        if not isinstance(item, Mapping) or not isinstance(item.get("path"), str):
            raise RuntimeError("malformed tree entry")
        if not item["path"].strip("/"):
            raise RuntimeError("malformed tree entry")
    return payload


def _source_entries(payload: Mapping) -> set[str]:
    entries = set()
    for item in payload["tree"]:
        parts = item["path"].strip("/").split("/")
        for index, part in enumerate(parts):
            if _SOURCE_ENTRY.match(part):
                entries.add("/".join(parts[: index + 1]))
                break
    return entries


def _walk_non_source_subtrees(payload: Mapping) -> set[str]:
    """Deterministically inspect grouping directories after a truncated query."""

    entries = _source_entries(payload)
    pending = sorted(
        (
            item["path"].strip("/"), item.get("sha")
        )
        for item in payload["tree"]
        if item.get("type") == "tree"
        and not _SOURCE_ENTRY.match(item["path"].strip("/"))
        and isinstance(item.get("sha"), str)
    )
    while pending:
        prefix, sha = pending.pop(0)
        child = _load_tree(sha, recursive=False)
        if child.get("truncated"):
            raise RuntimeError(f"GitHub returned a truncated tree for {prefix}")
        for item in sorted(child["tree"], key=lambda value: value["path"]):
            path = f"{prefix}/{item['path'].strip('/')}"
            leaf = item["path"].strip("/").split("/", 1)[0]
            if _SOURCE_ENTRY.match(leaf):
                entries.add(path)
            elif item.get("type") == "tree" and isinstance(item.get("sha"), str):
                pending.append((path, item["sha"]))
        pending.sort()
    return entries


def fetch_tree(ref: str = "main") -> list[str]:
    """Fetch exact registry source identifiers without accepting partial trees."""

    try:
        recursive_payload = _load_tree(ref, recursive=True)
    except TreeFetchError:
        recursive_payload = None
    if recursive_payload is not None and not recursive_payload.get("truncated"):
        return sorted(_source_entries(recursive_payload))

    # GitHub may truncate or time out on large recursive trees. A shallow root
    # tree contains every top-level registry finding; non-source grouping trees
    # are then traversed by SHA in stable order.
    root_payload = _load_tree(ref, recursive=False)
    if root_payload.get("truncated"):
        raise RuntimeError("GitHub returned a truncated registry root tree")
    return sorted(_walk_non_source_subtrees(root_payload))


def _escape_markdown_cell(value: str) -> str:
    return (value.replace("\\", "\\\\").replace("|", "\\|")
            .replace("\r\n", "<br>").replace("\r", "<br>").replace("\n", "<br>"))


def _row(source: str) -> str:
    title = normalize_entry(source)
    source_url = f"{REGISTRY_URL}/tree/main/{quote(source, safe='')}"
    search_url = f"{REGISTRY_URL}/search?q={quote(title, safe='')}&type=code"
    source_cell = _escape_markdown_cell(source)
    families_cell = _escape_markdown_cell(", ".join(classify(title)))
    registry_cell = f"[source]({source_url}) · [search]({search_url})"
    return f"| {source_cell} | {families_cell} | {registry_cell} |"


def render_index(entries: list[str]) -> str:
    """Render exactly one deterministic source-to-family row per exact entry."""

    exact_entries = sorted(set(entry.strip().strip("/") for entry in entries if entry.strip("/")))
    mapped = [entry for entry in exact_entries if classify(normalize_entry(entry)) != ["unclassified"]]
    unclassified = [entry for entry in exact_entries if classify(normalize_entry(entry)) == ["unclassified"]]
    lines = [
        "# EVM Hack Registry Source Index", "",
        f"Source: [{REGISTRY_URL}]({REGISTRY_URL})", "",
        f"Total: {len(exact_entries)} · Mapped: {len(mapped)} · Unclassified: {len(unclassified)}", "",
        "This generated index is provenance for detection research, not proof of exploitability.", "",
        "## Mapped sources", "",
        "| Source entry | Pattern families | Registry |", "| --- | --- | --- |",
    ]
    lines.extend(_row(source) for source in mapped)
    lines.extend([
        "", "## Unclassified sources", "",
        "These entries remain explicit so coverage gaps cannot be silently dropped.", "",
        "| Source entry | Pattern families | Registry |", "| --- | --- | --- |",
    ])
    lines.extend(_row(source) for source in unclassified)
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
    unclassified = sum(classify(normalize_entry(entry)) == ["unclassified"] for entry in entries)
    print(f"sources={len(entries)} mapped={len(entries) - unclassified} unclassified={unclassified}")


if __name__ == "__main__":
    main()
