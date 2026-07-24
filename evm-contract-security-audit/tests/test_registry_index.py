import io
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
from build_registry_index import classify, fetch_tree, normalize_entry, render_index


def fetch_from_payload(payload):
    response = io.StringIO(json.dumps(payload))
    with patch("build_registry_index.urlopen", return_value=response):
        return fetch_tree()


class RegistryIndexTests(unittest.TestCase):
    def test_normalize_entry_removes_exploit_suffix(self):
        self.assertEqual(
            normalize_entry("17095-origin-marketplace-repeated-withdraw_exp"),
            "17095-origin-marketplace-repeated-withdraw",
        )

    def test_bridge_message_title_is_cross_chain(self):
        self.assertIn(
            "bridges-cross-chain",
            classify("Bridge message replay allows duplicate withdrawal"),
        )

    def test_vault_share_rounding_has_accounting_and_vault_families(self):
        families = classify("Vault share rounding manipulation")

        self.assertIn("accounting-precision", families)
        self.assertIn("amm-vault-staking", families)

    def test_unknown_title_is_unclassified(self):
        self.assertEqual(classify("Zibble quux phenomenon"), ["unclassified"])

    def test_render_index_preserves_every_supplied_source(self):
        entries = [
            "100-alpha-bridge-message-replay",
            "200-beta-vault-share-rounding",
            "300-opaque-zibble-quux",
        ]

        rendered = render_index(entries)

        for source in entries:
            self.assertIn(source, rendered)

    def test_fetch_tree_handles_directory_and_file_style_entries(self):
        payload = {
            "truncated": False,
            "tree": [
                {"path": "100-directory-entry_exp", "type": "tree"},
                {
                    "path": "100-directory-entry_exp/src/Test.sol",
                    "type": "blob",
                },
                {"path": "200-file-entry_exp.sol", "type": "blob"},
                {"path": "README.md", "type": "blob"},
            ],
        }

        self.assertEqual(
            fetch_from_payload(payload),
            ["100-directory-entry", "200-file-entry"],
        )

    def test_fetch_tree_rejects_non_mapping_payload(self):
        with self.assertRaisesRegex(RuntimeError, "malformed GitHub tree payload"):
            fetch_from_payload([])

    def test_fetch_tree_rejects_missing_tree(self):
        with self.assertRaisesRegex(RuntimeError, "missing or malformed tree list"):
            fetch_from_payload({"truncated": False})

    def test_fetch_tree_rejects_malformed_tree(self):
        with self.assertRaisesRegex(RuntimeError, "missing or malformed tree list"):
            fetch_from_payload({"truncated": False, "tree": {}})

    def test_fetch_tree_rejects_malformed_tree_entries(self):
        for item in (None, {}, {"path": 7}):
            with self.subTest(item=item):
                with self.assertRaisesRegex(RuntimeError, "malformed tree entry"):
                    fetch_from_payload({"truncated": False, "tree": [item]})

    def test_fetch_tree_rejects_truncated_response(self):
        with self.assertRaisesRegex(RuntimeError, "truncated registry tree"):
            fetch_from_payload({"truncated": True, "tree": []})

    def test_render_index_escapes_markdown_table_cells(self):
        rendered = render_index(["100-zeta|line\nbreak\\vault"])

        self.assertEqual(
            rendered.splitlines()[-1],
            "| 100-zeta\\|line<br>break\\\\vault | amm-vault-staking |",
        )

    def test_render_index_is_sorted_and_deduplicated(self):
        rendered = render_index(
            ["200-zeta_exp", "100-alpha_exp", "200-zeta"]
        )

        self.assertEqual(
            rendered,
            "# EVM Hack Registry Source Index\n"
            "\n"
            "| Source entry | Pattern families |\n"
            "| --- | --- |\n"
            "| 100-alpha | unclassified |\n"
            "| 200-zeta | unclassified |\n",
        )


if __name__ == "__main__":
    unittest.main()
