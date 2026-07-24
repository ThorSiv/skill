import re
import unittest
from dataclasses import asdict, dataclass
from pathlib import Path


ROOT = Path(__file__).parents[1]


@dataclass(frozen=True)
class Finding:
    pattern_id: str
    code_evidence: str
    invariant_violated: str
    asset_exposure: str
    confidence: str
    registry_search_hook: str
    direct_source_link: str | None
    direct_source_absence: str | None


# This is deliberately a small forward-test oracle, not a production scanner. Rules
# consume raw observable Solidity/audit text and resolve IDs by searching the library.
RULES = (
    (r"exchangeEquivalentBonds|matchCount\s*\+\+", "ACCOUNTING-003", "duplicate identity count", "unbacked bond claims", ("count", "pair")),
    (r"initializer|delegatecall.*initialize", "ACCESS-002", "externally reachable initializer", "upgradeable contract control", ("initial",)),
    (r"function setOwner\([^)]*\) external\s*\{", "ACCESS-001", "privileged setter has no caller constraint", "contract administration and assets", ("access", "owner")),
    (r"callback.*(?:preview|price)|staticcall.*callback", "REENTRANCY-002", "transient read during callback", "mispriced shares or collateral", ("read-only-reentrancy",)),
    (r"totalAssets\(\).*balanceOf|donat(?:e|ion).*convertToShares", "ACCOUNTING-001", "unaccounted donation changes share rate", "vault deposits", ("vault", "share")),
    (r"assets \* totalSupply / totalAssets", "ACCOUNTING-002", "deposit conversion rounds value without directional protection", "vault deposit value", ("rounding", "share")),
    (r"(?:latestRoundData.*updatedAt|updatedAt.*latestRoundData)|reserve0.*price", "ORACLE-002", "price accepted without freshness", "oracle-valued collateral", ("oracle",)),
    (r"getReserves\(\).*mint", "ORACLE-001", "instantaneous pool reserves determine mint value", "protocol reserves and minted claims", ("flashloan", "manipulat")),
    (r"ecrecover.*nonce|DOMAIN_SEPARATOR.*chainid", "SIGNATURE-001", "signature domain or nonce not consumed", "signed permissions", ("signature-replay",)),
    (r"processMessage.*messageId|sourceChain.*sourceSender", "BRIDGE-002", "message identity not consumed before effects", "bridged escrow or minted supply", ("bridge",)),
    (r"onlyRelayer.*payload", "BRIDGE-001", "relayer check omits source chain and sender binding", "bridged escrow or minted supply", ("cross-chain", "bridge")),
    (r"transferFrom\([^;]+amount\).*credit\[[^]]+\]\s*\+=\s*amount", "TOKEN-001", "credit exceeds received balance delta", "depositor and pool tokens", ("erc20",)),
    (r"balanceOf\(.*\)\s*==\s*internalBalance", "TOKEN-002", "fixed ledger assumes balances cannot rebase", "rebasing token deposits", ("rebas",)),
    (r"liquidate.*badDebt|collateralValue\s*<\s*debt", "LENDING-004", "uncovered debt is not reconciled", "lenders and reserves", ("debt", "liquid")),
    (r"seize\s*=\s*repay \* bonus", "LENDING-002", "liquidation seizure lacks collateral and rounding bounds", "borrower collateral and protocol solvency", ("liquidat",)),
    (r"reserve0.*balanceOf|balanceOf.*reserve0", "AMM-001", "cached reserve diverges from balance", "AMM liquidity", ("pool",)),
    (r"for\s*\([^)]*users\.length|for\s*\([^)]*positions\.length", "DOS-001", "critical transition requires unbounded iteration", "withdrawal or settlement liveness", ("array", "loop")),
    (r"delegatecall.*returndata|returndatacopy.*delegatecall", "EVM-003", "delegated code controls caller storage", "contract state and held assets", ("delegatecall",)),
    (r"call\(data\).*abi.decode\(returndata", "EVM-002", "return bytes are decoded without a length check", "state authorized by call result", ("return", "call")),
    (r"flashLoan.*vote|vote.*getVotes\(msg\.sender\)", "GOVERNANCE-001", "same-block voting power is accepted", "governance-controlled treasury", ("proposal", "voting")),
    (r"claimReward\(\).*deposit\(reward\)", "GOVERNANCE-004", "cyclic reward compounding can exceed committed capital", "reward reserves and other stakers", ("reward", "incentive")),
)


class ForwardHarness:
    def __init__(self, root=ROOT):
        self.patterns = {}
        for path in (root / "references" / "patterns").glob("*.md"):
            text = path.read_text(encoding="utf-8")
            for match in re.finditer(r"^### ([A-Z][A-Z0-9]*-\d{3}):.*?(?=^### |\Z)", text, re.M | re.S):
                self.patterns[match.group(1)] = (path.name, match.group(0))
        self.index = (root / "references" / "source-index.md").read_text(encoding="utf-8")

    def _direct_source(self, family, keywords):
        rows = re.findall(r"^\| ([^|]+) \| ([^|]+) \| \[source\]\(([^)]+)\)", self.index, re.M)
        candidates = [(entry, url) for entry, families, url in rows if family in families]
        for entry, url in candidates:
            if any(keyword in entry.lower() for keyword in keywords):
                return url
        return None

    def audit(self, code):
        findings = []
        for expression, pattern_id, invariant, exposure, keywords in RULES:
            match = re.search(expression, code, re.I | re.S)
            if not match:
                continue
            filename, block = self.patterns[pattern_id]  # resolve family; test never supplies a file
            family = filename.removesuffix(".md")
            hook = re.search(r"^- Source: (.+search `[^`]+`)$", block, re.M).group(1)
            direct = self._direct_source(family, keywords)
            findings.append(Finding(
                pattern_id, match.group(0)[:160], invariant, exposure, "high",
                hook, direct, None if direct else "No sufficiently relevant direct source-index row selected.",
            ))
        return findings


SCENARIOS = {
    "bondmaker_duplicate_multiset": ("ACCOUNTING-003", """
        function exchangeEquivalentBonds(bytes32[] supplied) external {
          bytes32[] required = [A, B]; // required exception IDs are [A,B]
          uint matchCount;
          for (uint i; i < supplied.length; i++)
            for (uint j; j < required.length; j++)
              if (supplied[i] == required[j]) matchCount++;
          require(matchCount == required.length);
          // supplied [A,A] omits B yet passes: a[A]*e[A]+a[B]*e[B]=2*1+0*1=2.
          // Count equality holds, but multiset equality supplied == required does not.
        }
    """),
    "proxy_initializer": ("ACCESS-002", "function initialize(address owner) external initializer { _owner=owner; }"),
    "missing_access": ("ACCESS-001", "function setOwner(address next) external { owner = next; }"),
    "read_only_reentrancy": ("REENTRANCY-002", "function callback() external { uint quote = vault.previewRedeem(shares); }"),
    "vault_donation": ("ACCOUNTING-001", "totalAssets() returns asset.balanceOf(address(this)); donate(); convertToShares(1);"),
    "vault_rounding": ("ACCOUNTING-002", "shares = assets * totalSupply / totalAssets; // floors deposit conversion"),
    "stale_oracle": ("ORACLE-002", "(,int answer,,uint updatedAt,) = feed.latestRoundData(); return answer;"),
    "spot_oracle": ("ORACLE-001", "(reserve0,reserve1)=pool.getReserves(); mint(user, reserve1/reserve0);"),
    "signature_replay": ("SIGNATURE-001", "address signer=ecrecover(hash,v,r,s); require(nonce[user] >= 0);"),
    "bridge_replay": ("BRIDGE-002", "function processMessage(bytes32 messageId, uint sourceChain, address sourceSender) external { token.transfer(user, amount); }"),
    "bridge_underbinding": ("BRIDGE-001", "function receive(bytes payload) external onlyRelayer { release(payload); }"),
    "fee_token": ("TOKEN-001", "token.transferFrom(msg.sender,address(this),amount); credit[msg.sender] += amount;"),
    "rebasing_token": ("TOKEN-002", "require(token.balanceOf(address(this)) == internalBalance);"),
    "bad_debt": ("LENDING-004", "function liquidate() external { if (collateralValue < debt) closePosition(); /* badDebt omitted */ }"),
    "liquidation_bounds": ("LENDING-002", "uint seize = repay * bonus / 1e18; collateral[user] -= seize;"),
    "amm_reserves": ("AMM-001", "uint reserve0; function quote() view returns(uint){ return token.balanceOf(address(this))/reserve0; }"),
    "array_dos": ("DOS-001", "for (uint i=0; i < users.length; i++) { settle(users[i]); }"),
    "delegate_storage": ("EVM-003", "(bool ok, bytes memory returndata)=plugin.delegatecall(data); assembly { returndatacopy(0,0,returndatasize()) }"),
    "returndata_length": ("EVM-002", "(bool ok,bytes memory returndata)=target.call(data); bool accepted=abi.decode(returndata,(bool));"),
    "flash_governance": ("GOVERNANCE-001", "flashLoan(amount); governance.vote(id, getVotes(msg.sender));"),
    "economic_cycle": ("GOVERNANCE-004", "while(active){ claimReward(); deposit(reward); }"),
}


class ForwardRoutingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.harness = ForwardHarness()

    def test_scenarios_route_from_observable_surfaces_and_emit_complete_findings(self):
        for name, (expected_id, raw_code) in SCENARIOS.items():
            with self.subTest(name=name):
                matches = {finding.pattern_id: finding for finding in self.harness.audit(raw_code)}
                self.assertIn(expected_id, matches)
                record = asdict(matches[expected_id])
                for field in ("pattern_id", "code_evidence", "invariant_violated", "asset_exposure", "confidence", "registry_search_hook"):
                    self.assertTrue(record[field], f"{name} missing {field}")
                self.assertIn("sanbir/evm-hack-registry", record["registry_search_hook"])
                self.assertNotEqual(bool(record["direct_source_link"]), bool(record["direct_source_absence"]))

    def test_bondmaker_counterexample_is_explicit_and_detected(self):
        raw = SCENARIOS["bondmaker_duplicate_multiset"][1]
        for fact in ("exchangeEquivalentBonds", "[A, B]", "[A,A]", "omits B", "2*1+0*1=2", "multiset equality"):
            self.assertIn(fact, raw)
        finding = self.harness.audit(raw)[0]
        self.assertEqual(finding.pattern_id, "ACCOUNTING-003")
        self.assertIn("unbacked bond claims", finding.asset_exposure)


if __name__ == "__main__":
    unittest.main()
