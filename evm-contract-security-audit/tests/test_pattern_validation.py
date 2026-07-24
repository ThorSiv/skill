import sys
import tempfile
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
from validate_pattern_library import validate_library


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


def pattern(pattern_id="ACCESS-001", source=None):
    source = source or (
        "https://github.com/sanbir/evm-hack-registry — search `access control`"
    )
    return (
        f"# Family\n\n### {pattern_id}: Example\n"
        "- Smell: Signal.\n"
        "- Invariant: Property.\n"
        "- Test: Detection check.\n"
        f"- Source: {source}\n"
    )


def index(rows=None, total=None):
    rows = rows or [("100-example_exp", "access-proxy")]
    total = len(rows) if total is None else total
    mapped_rows = [row for row in rows if row[1] != "unclassified"]
    unclassified_rows = [row for row in rows if row[1] == "unclassified"]

    def render(selected):
        return "\n".join(
            "| "
            f"{entry} | {family} | "
            "[source](https://github.com/sanbir/evm-hack-registry/tree/main/"
            f"{entry}) |"
            for entry, family in selected
        )

    return (
        "# Index\n\n"
        "Source: [registry](https://github.com/sanbir/evm-hack-registry)\n\n"
        f"Total: {total} · Mapped: {len(mapped_rows)} · Unclassified: {len(unclassified_rows)}\n\n"
        "## Mapped sources\n\n"
        "| Source entry | Pattern families | Registry |\n"
        "| --- | --- | --- |\n"
        f"{render(mapped_rows)}\n\n"
        "## Unclassified sources\n\n"
        "| Source entry | Pattern families | Registry |\n"
        "| --- | --- | --- |\n"
        f"{render(unclassified_rows)}\n"
    )


class PatternValidationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        patterns = self.root / "references" / "patterns"
        patterns.mkdir(parents=True)
        for number, filename in enumerate(FAMILY_FILES, start=1):
            prefix = filename.split("-", 1)[0].upper()
            (patterns / filename).write_text(
                pattern(f"{prefix}-{number:03d}"), encoding="utf-8"
            )
        (self.root / "references" / "source-index.md").write_text(
            index(), encoding="utf-8"
        )

    def tearDown(self):
        self.temp.cleanup()

    def errors(self):
        return validate_library(self.root)

    def test_valid_library_has_no_errors(self):
        self.assertEqual(self.errors(), [])

    def test_requires_exact_family_file_set(self):
        (self.root / "references" / "patterns" / FAMILY_FILES[0]).unlink()
        (self.root / "references" / "patterns" / "extra.md").write_text(
            pattern("EXTRA-001"), encoding="utf-8"
        )
        errors = "\n".join(self.errors())
        self.assertIn("missing required pattern file", errors)
        self.assertIn("unexpected pattern file", errors)

    def test_rejects_duplicate_ids_and_missing_fields(self):
        patterns = self.root / "references" / "patterns"
        (patterns / FAMILY_FILES[0]).write_text(pattern("DUP-001"), encoding="utf-8")
        (patterns / FAMILY_FILES[1]).write_text(
            pattern("DUP-001").replace("- Test: Detection check.\n", ""),
            encoding="utf-8",
        )
        errors = "\n".join(self.errors())
        self.assertIn("duplicate pattern ID DUP-001", errors)
        self.assertIn("missing Test field", errors)

    def test_requires_registry_provenance_and_search_hook(self):
        target = self.root / "references" / "patterns" / FAMILY_FILES[0]
        target.write_text(
            pattern("ACCESS-001", "https://example.com/reference"), encoding="utf-8"
        )
        errors = "\n".join(self.errors())
        self.assertIn("sanbir/evm-hack-registry", errors)
        self.assertIn("search hook", errors)

    def test_rejects_duplicate_rows_bad_count_and_unknown_family(self):
        target = self.root / "references" / "source-index.md"
        target.write_text(
            index(
                [("100-example_exp", "access-proxy"), ("100-example_exp", "mystery")],
                total=3,
            ),
            encoding="utf-8",
        )
        errors = "\n".join(self.errors())
        self.assertIn("duplicate source-index entry", errors)
        self.assertIn("declares Total 3 but contains 2 data rows", errors)
        self.assertIn("unknown source-index family mystery", errors)

    def test_allows_explicit_unclassified_family(self):
        target = self.root / "references" / "source-index.md"
        target.write_text(
            index([("100-example_exp", "unclassified")]), encoding="utf-8"
        )
        self.assertEqual(self.errors(), [])

    def test_rejects_inconsistent_mapped_and_unclassified_counts(self):
        target = self.root / "references" / "source-index.md"
        text = index([("100-example_exp", "unclassified")])
        target.write_text(
            text.replace("Mapped: 0 · Unclassified: 1", "Mapped: 1 · Unclassified: 0"),
            encoding="utf-8",
        )
        errors = "\n".join(self.errors())
        self.assertIn("declares Mapped 1 but contains 0", errors)
        self.assertIn("declares Unclassified 0 but contains 1", errors)

    def test_rejects_forbidden_exploit_and_secret_markers(self):
        target = self.root / "references" / "patterns" / FAMILY_FILES[0]
        target.write_text(
            pattern() + "\n`vm.store(target, slot, value)`\n", encoding="utf-8"
        )
        errors = "\n".join(self.errors())
        self.assertIn("forbidden marker vm.store", errors)

    def test_rejects_foundry_broadcast_method_variants(self):
        target = self.root / "references" / "patterns" / FAMILY_FILES[0]
        for method in (
            "vm.broadcast()",
            "vm.startBroadcast()",
            "startBroadcast()",
            "vm.stopBroadcast()",
            "stopBroadcast()",
            "VM.STARTBROADCAST()",
        ):
            with self.subTest(method=method):
                target.write_text(pattern() + f"\n`{method}`\n", encoding="utf-8")
                self.assertIn("forbidden marker broadcast", "\n".join(self.errors()))


if __name__ == "__main__":
    unittest.main()
