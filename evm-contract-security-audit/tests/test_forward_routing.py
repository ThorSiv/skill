import unittest
from pathlib import Path


SKILL_ROOT = Path(__file__).parents[1]


class ForwardRoutingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8").lower()
        cls.patterns = {
            path.name: path.read_text(encoding="utf-8").lower()
            for path in (SKILL_ROOT / "references" / "patterns").glob("*.md")
        }

    def assert_pattern_covers(self, filename, pattern_id, *signals):
        text = self.patterns[filename]
        self.assertIn(pattern_id.lower(), text)
        for signal in signals:
            self.assertIn(signal.lower(), text, f"{filename} misses detection signal {signal!r}")

    def test_duplicate_multiset_counting_routes_to_accounting(self):
        self.assertIn("duplicates or missing identities", self.skill)
        self.assertIn("a[x] * e[x]", self.skill)
        self.assert_pattern_covers(
            "accounting-precision.md", "ACCOUNTING-003", "repeated identifiers", "deduplication"
        )

    def test_proxy_initialization_and_access_are_covered(self):
        self.assert_pattern_covers("access-proxy.md", "ACCESS-001", "authorization")
        self.assert_pattern_covers("access-proxy.md", "ACCESS-002", "initializer", "implementation")

    def test_read_only_and_cross_function_reentrancy_are_covered(self):
        self.assert_pattern_covers(
            "reentrancy-order.md", "REENTRANCY-002", "read-only", "cross-function", "stale"
        )

    def test_vault_rounding_donation_and_share_inflation_are_covered(self):
        self.assert_pattern_covers(
            "accounting-precision.md", "ACCOUNTING-001", "donation", "share"
        )
        self.assert_pattern_covers("accounting-precision.md", "ACCOUNTING-002", "rounding")

    def test_stale_and_manipulable_oracles_are_covered(self):
        self.assert_pattern_covers("oracle-market.md", "ORACLE-001", "manipulable")
        self.assert_pattern_covers("oracle-market.md", "ORACLE-002", "stale", "freshness")

    def test_signature_replay_and_domain_binding_are_covered(self):
        self.assert_pattern_covers(
            "signatures-aa.md", "SIGNATURE-001", "replay", "chain", "verifying contract"
        )

    def test_bridge_message_replay_and_binding_are_covered(self):
        self.assert_pattern_covers("bridges-cross-chain.md", "BRIDGE-001", "source chain", "sender")
        self.assert_pattern_covers("bridges-cross-chain.md", "BRIDGE-002", "replay")

    def test_nonstandard_token_accounting_is_covered(self):
        self.assert_pattern_covers("token-nft.md", "TOKEN-001", "transfer-fee", "balance change")
        self.assert_pattern_covers("token-nft.md", "TOKEN-002", "rebas")

    def test_liquidation_and_bad_debt_are_covered(self):
        self.assert_pattern_covers("lending-liquidation.md", "LENDING-002", "liquidation")
        self.assert_pattern_covers("lending-liquidation.md", "LENDING-004", "bad-debt", "insolvent")

    def test_amm_reserve_accounting_is_covered(self):
        self.assert_pattern_covers("amm-vault-staking.md", "AMM-001", "cached reserves", "actual balances")

    def test_array_and_gas_dos_are_covered(self):
        self.assert_pattern_covers("dos-arrays-gas.md", "DOS-001", "user-growable", "critical")
        self.assert_pattern_covers("dos-arrays-gas.md", "DOS-004", "gas")

    def test_delegatecall_storage_and_returndata_are_covered(self):
        self.assert_pattern_covers("low-level-evm.md", "EVM-002", "return bytes", "length")
        self.assert_pattern_covers("low-level-evm.md", "EVM-003", "delegated", "storage")

    def test_flash_loan_governance_and_economic_capture_are_covered(self):
        self.assert_pattern_covers("governance-economic.md", "GOVERNANCE-001", "same-block", "voting")
        self.assert_pattern_covers("governance-economic.md", "GOVERNANCE-004", "cyclic", "payout")


if __name__ == "__main__":
    unittest.main()
