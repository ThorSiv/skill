# Governance and Economic Security

### GOVERNANCE-001: Flash-acquired voting power
- Smell: Voting weight uses a current balance or same-block snapshot without holding-period or historical checkpoints.
- Invariant: Temporary capital cannot determine governance outcomes disproportionate to durable economic exposure.
- Test: Acquire, delegate, vote, execute, and dispose of voting assets around proposal snapshot boundaries.
- Source: https://github.com/sanbir/evm-hack-registry — search `flash loan governance`

### GOVERNANCE-002: Proposal execution scope gap
- Smell: Governance execution permits arbitrary targets, selectors, values, or reentrant proposal state changes beyond declared policy.
- Invariant: A passed proposal can execute only its committed actions once and within governance authority.
- Test: Mutate target sets, duplicate execution, invoke callbacks, and attempt actions outside configured governance scope.
- Source: https://github.com/sanbir/evm-hack-registry — search `governance execution`

### GOVERNANCE-003: Quorum and snapshot inconsistency
- Smell: Quorum, supply, delegation, and vote weight are read at different blocks or can change after outcome calculation.
- Invariant: Proposal eligibility and outcome derive from one immutable, internally consistent voting state.
- Test: Change supply and delegation around creation, snapshot, voting, queueing, and execution boundaries.
- Source: https://github.com/sanbir/evm-hack-registry — search `governance snapshot quorum`

### GOVERNANCE-004: Incentive-driven insolvency
- Smell: Fees, emissions, discounts, or redemption rules permit cyclic actions whose payout exceeds net capital committed.
- Invariant: No closed sequence of allowed actions creates unbacked protocol liabilities or drains shared reserves.
- Test: Search repeated deposit, borrow, trade, stake, claim, redeem, and exit cycles across boundary amounts and roles.
- Source: https://github.com/sanbir/evm-hack-registry — search `economic exploit`
