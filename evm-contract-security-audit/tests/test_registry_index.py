import io
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
from build_registry_index import classify, fetch_tree, normalize_entry, render_index


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
        response = io.StringIO(
            json.dumps(
                {
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
            )
        )

        with patch("build_registry_index.urlopen", return_value=response):
            self.assertEqual(
                fetch_tree(), ["100-directory-entry", "200-file-entry"]
            )


if __name__ == "__main__":
    unittest.main()
