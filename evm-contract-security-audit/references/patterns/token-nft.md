# Tokens and NFTs

### TOKEN-001: Transfer-delta accounting mismatch
- Smell: Protocol credits the requested token amount without measuring the actual balance change.
- Invariant: Internal credit never exceeds assets actually received, and debit reflects assets actually sent.
- Test: Exercise deposits and withdrawals with transfer-fee, burn-on-transfer, and partial-transfer token behaviors.
- Source: https://github.com/sanbir/evm-hack-registry — search `fee on transfer token`

### TOKEN-002: Rebasing balance drift
- Smell: Fixed internal balances assume token balances remain constant between transfers despite supply rebases.
- Invariant: User claims and protocol liabilities remain reconciled after positive and negative external balance changes.
- Test: Apply rebases between deposit, transfer, claim, and withdrawal operations and compare aggregate entitlements.
- Source: https://github.com/sanbir/evm-hack-registry — search `rebasing token accounting`

### TOKEN-003: Unsafe token return handling
- Smell: Token calls ignore failure, decode optional return data rigidly, or treat malformed responses as success.
- Invariant: Internal state changes only when the intended token operation demonstrably succeeds.
- Test: Use tokens that return true, false, no data, malformed data, or revert and compare state transitions.
- Source: https://github.com/sanbir/evm-hack-registry — search `erc20 return value`

### TOKEN-004: NFT callback and ownership mismatch
- Smell: NFT deposits trust callback parameters, fail to bind collection and token ID, or update ownership around unsafe callbacks.
- Invariant: Exactly one authenticated NFT maps to exactly one claimable depositor position.
- Test: Trigger direct callbacks, duplicate deposits, hostile receivers, batch edge cases, and ownership changes during callbacks.
- Source: https://github.com/sanbir/evm-hack-registry — search `nft callback ownership`
