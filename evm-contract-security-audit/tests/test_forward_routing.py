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


# Every rule requires independent observable indicators. It is a test oracle, not a scanner.
RULES = (
    ("ACCOUNTING-003", (r"exchangeEquivalentBonds", r"matchCount\s*\+\+", r"require\(matchCount\s*==", r"\[A,A\].*omits B"), ("count", "pair")),
    ("ACCESS-002", (r"function initialize", r"external initializer", r"implementation remains initializable"), ("initial",)),
    ("ACCESS-001", (r"function setOwner", r"external\s*\{", r"owner\s*=", r"missing caller check"), ("access", "owner")),
    ("ACCESS-003", (r"proxy slots: owner@0", r"implementation slots: totalSupply@0", r"delegatecall"), ("storage", "collision")),
    ("REENTRANCY-002", (r"function callback", r"previewRedeem", r"transient vault state"), ("read-only-reentrancy",)),
    ("ACCOUNTING-001", (r"totalAssets\(\).*balanceOf", r"donate", r"convertToShares"), ("vault", "share")),
    ("ACCOUNTING-002", (r"assets \* totalSupply / totalAssets", r"floors deposit conversion"), ("rounding", "share")),
    ("ORACLE-002", (r"latestRoundData", r"updatedAt", r"freshness check omitted"), ("oracle",)),
    ("ORACLE-001", (r"getReserves\(\)", r"mint\(", r"same-transaction spot price"), ("flashloan", "manipulat")),
    ("SIGNATURE-001", (r"ecrecover", r"nonce", r"nonce is not consumed"), ("signature-replay",)),
    ("BRIDGE-002", (r"processMessage", r"messageId", r"processed-message check omitted"), ("bridge",)),
    ("BRIDGE-001", (r"onlyRelayer", r"release\(payload\)", r"source binding omitted"), ("cross-chain", "bridge")),
    ("TOKEN-001", (r"transferFrom", r"credit\[[^]]+\]\s*\+=\s*amount", r"balance delta not measured"), ("erc20",)),
    ("TOKEN-002", (r"balanceOf\(.*\)\s*==\s*internalBalance", r"rebasing token"), ("rebas",)),
    ("LENDING-004", (r"collateralValue\s*<\s*debt", r"closePosition", r"badDebt omitted"), ("debt", "liquid")),
    ("LENDING-002", (r"seize\s*=\s*repay \* bonus", r"collateral\[user\]\s*-=", r"bounds omitted"), ("liquidat",)),
    ("AMM-001", (r"reserve0", r"balanceOf", r"cached versus live"), ("pool",)),
    ("DOS-001", (r"for\s*\([^)]*users\.length", r"settle\(users\[i\]\)", r"user-growable"), ("array", "loop")),
    ("EVM-003", (r"plugin\.delegatecall", r"returndatacopy", r"target is user-selected"), ("delegatecall",)),
    ("EVM-002", (r"target\.call", r"abi.decode\(returndata", r"length check omitted"), ("return", "call")),
    ("GOVERNANCE-001", (r"flashLoan", r"governance\.vote", r"getVotes\(msg\.sender\)"), ("proposal", "voting")),
    ("GOVERNANCE-004", (r"claimReward\(\)", r"deposit\(reward\)", r"repeatable cycle"), ("reward", "incentive")),
)

ASSET_SURFACES = (
    (r"bond|claim", "bond collateral and unbacked claims"),
    (r"owner|initialize|proxy|delegatecall", "contract control, storage, and held assets"),
    (r"vault|shares|totalAssets", "vault deposits and share value"),
    (r"oracle|latestRoundData|getReserves|reserve0", "oracle-valued collateral and pool reserves"),
    (r"ecrecover|nonce", "signature-authorized permissions and transfers"),
    (r"messageId|onlyRelayer|release\(payload", "bridged escrow or minted supply"),
    (r"token|balanceOf|transferFrom", "token deposits and pool balances"),
    (r"debt|liquidate|collateral", "borrower collateral, lender funds, and reserves"),
    (r"users\.length|settle", "settlement and withdrawal liveness"),
    (r"governance|vote|claimReward", "governance treasury or reward reserves"),
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
        for entry, families, url in rows:
            if family in families and any(word in entry.lower() for word in keywords):
                return url
        return None

    @staticmethod
    def _asset_exposure(code):
        matches = [label for expression, label in ASSET_SURFACES if re.search(expression, code, re.I | re.S)]
        if not matches:
            raise ValueError("scenario lacks an observable asset surface")
        return matches[0]

    def audit(self, code):
        findings = []
        for pattern_id, indicators, keywords in RULES:
            evidence = [re.search(indicator, code, re.I | re.S) for indicator in indicators]
            if not all(evidence):
                continue
            filename, block = self.patterns[pattern_id]
            invariant = re.search(r"^- Invariant: (.+)$", block, re.M).group(1)
            source = re.search(r"^- Source: (.+search `[^`]+`)$", block, re.M).group(1)
            direct = self._direct_source(filename.removesuffix(".md"), keywords)
            confidence = "high" if len(evidence) >= 3 else "medium"
            findings.append(Finding(
                pattern_id, " | ".join(match.group(0)[:80] for match in evidence),
                invariant, self._asset_exposure(code), confidence, source, direct,
                None if direct else "No sufficiently relevant direct source-index row selected.",
            ))
        return findings


SCENARIOS = {
    "bondmaker": ("ACCOUNTING-003", "function exchangeEquivalentBonds(){ required=[A, B]; supplied=[A,A]; for supplied for required if(eq) matchCount++; require(matchCount == required.length); /* supplied [A,A] omits B; 2*1+0*1=2; count equality passes but multiset equality fails; unbacked bond claim */ }"),
    "initializer": ("ACCESS-002", "function initialize(address owner) external initializer { owner=owner; } proxy implementation remains initializable"),
    "access": ("ACCESS-001", "function setOwner(address next) external { owner=next; } // missing caller check"),
    "storage_collision": ("ACCESS-003", "proxy slots: owner@0; implementation slots: totalSupply@0; delegatecall changes proxy storage"),
    "read_only": ("REENTRANCY-002", "function callback(){ vault.previewRedeem(shares); } // observes transient vault state"),
    "donation": ("ACCOUNTING-001", "vault totalAssets() uses token.balanceOf(this); donate(); convertToShares(1);"),
    "rounding": ("ACCOUNTING-002", "vault shares = assets * totalSupply / totalAssets; // floors deposit conversion"),
    "stale_oracle": ("ORACLE-002", "oracle latestRoundData returns updatedAt; freshness check omitted; debt collateral"),
    "spot_oracle": ("ORACLE-001", "pool.getReserves(); mint(user,value); // same-transaction spot price oracle"),
    "signature": ("SIGNATURE-001", "ecrecover(hash,v,r,s); nonce[user]; // nonce is not consumed before token transfer"),
    "bridge_replay": ("BRIDGE-002", "processMessage(messageId); token.transfer(user,amount); // processed-message check omitted"),
    "bridge_binding": ("BRIDGE-001", "onlyRelayer release(payload); // source binding omitted for bridge"),
    "fee_token": ("TOKEN-001", "token.transferFrom(user,this,amount); credit[user] += amount; // balance delta not measured"),
    "rebase": ("TOKEN-002", "rebasing token: token.balanceOf(this) == internalBalance"),
    "bad_debt": ("LENDING-004", "if(collateralValue < debt) closePosition(); // badDebt omitted during liquidate"),
    "liquidation": ("LENDING-002", "liquidate: seize = repay * bonus / 1e18; collateral[user] -= seize; // bounds omitted"),
    "amm": ("AMM-001", "pool reserve0; token.balanceOf(this); // cached versus live reserve accounting"),
    "dos": ("DOS-001", "for(i=0;i<users.length;i++) settle(users[i]); // user-growable array"),
    "delegate": ("EVM-003", "plugin.delegatecall(data); returndatacopy(0,0,size); // target is user-selected; proxy assets"),
    "returndata": ("EVM-002", "token target.call(data); abi.decode(returndata,(bool)); // length check omitted"),
    "flash_vote": ("GOVERNANCE-001", "flashLoan(amount); governance.vote(id,getVotes(msg.sender));"),
    "economic": ("GOVERNANCE-004", "claimReward(); deposit(reward); // repeatable cycle drains governance reward reserve"),
}

SAFE_LOOKALIKES = (
    "function exchangeEquivalentBonds(){ require(unique(supplied)); requireSameMultiset(supplied,required); } bond claim",
    "function initialize(address owner) external initializer onlyFactory { owner=owner; } proxy",
    "function setOwner(address next) external onlyOwner { owner=next; }",
    "function withdraw(){ balance[msg.sender]=0; token.transfer(msg.sender,amount); }",
    "oracle latestRoundData returns updatedAt; require(block.timestamp-updatedAt<MAX_AGE); debt collateral",
    "ecrecover(hash,v,r,s); require(nonce[user]++ == signedNonce); DOMAIN_SEPARATOR chainid token",
    "processMessage(messageId); require(!processed[messageId]); processed[messageId]=true; token.transfer(user,amount);",
)


class ForwardRoutingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.harness = ForwardHarness()

    def test_raw_scenarios_route_and_emit_library_backed_findings(self):
        for name, (expected_id, code) in SCENARIOS.items():
            with self.subTest(name=name):
                findings = {item.pattern_id: item for item in self.harness.audit(code)}
                self.assertIn(expected_id, findings)
                finding = findings[expected_id]
                record = asdict(finding)
                for field in ("code_evidence", "invariant_violated", "asset_exposure", "confidence", "registry_search_hook"):
                    self.assertTrue(record[field])
                library_block = self.harness.patterns[expected_id][1]
                self.assertEqual(finding.invariant_violated, re.search(r"^- Invariant: (.+)$", library_block, re.M).group(1))
                self.assertIn("sanbir/evm-hack-registry", finding.registry_search_hook)
                self.assertNotEqual(bool(finding.direct_source_link), bool(finding.direct_source_absence))

    def test_bondmaker_requires_the_complete_counterexample(self):
        code = SCENARIOS["bondmaker"][1]
        for fact in ("exchangeEquivalentBonds", "[A, B]", "[A,A]", "omits B", "2*1+0*1=2", "multiset equality"):
            self.assertIn(fact, code)
        self.assertIn("ACCOUNTING-003", {finding.pattern_id for finding in self.harness.audit(code)})

    def test_safe_lookalikes_do_not_trigger_findings(self):
        for code in SAFE_LOOKALIKES:
            with self.subTest(code=code):
                self.assertEqual(self.harness.audit(code), [])

    def test_confidence_uses_indicator_count_and_assets_use_surface_mapping(self):
        storage = next(item for item in self.harness.audit(SCENARIOS["storage_collision"][1]) if item.pattern_id == "ACCESS-003")
        initializer = next(item for item in self.harness.audit(SCENARIOS["initializer"][1]) if item.pattern_id == "ACCESS-002")
        rounding = next(item for item in self.harness.audit(SCENARIOS["rounding"][1]) if item.pattern_id == "ACCOUNTING-002")
        self.assertEqual(storage.confidence, "high")
        self.assertEqual(initializer.confidence, "high")
        self.assertEqual(rounding.confidence, "medium")
        self.assertEqual(storage.asset_exposure, "contract control, storage, and held assets")


if __name__ == "__main__":
    unittest.main()
