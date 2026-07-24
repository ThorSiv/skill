# AMMs, Vaults, and Staking

### AMM-001: Reserve-balance divergence
- Smell: Pricing uses cached reserves while swaps, transfers, donations, or sync operations can change actual balances independently.
- Invariant: No caller can profit from a temporary mismatch between pricing reserves and spendable token balances.
- Test: Interleave direct transfers, synchronization, liquidity changes, and swaps while tracking the constant-product or pool invariant.
- Source: https://github.com/sanbir/evm-hack-registry — search `amm reserve manipulation`

### AMM-002: Vault conversion inconsistency
- Smell: Preview, deposit, mint, withdraw, and redeem paths use different totals, rounding, fees, or update ordering.
- Invariant: All asset-share conversions are mutually consistent, monotonic, and conservatively rounded.
- Test: Cross-compose every conversion path at zero supply, low liquidity, fee boundaries, and after gains or losses.
- Source: https://github.com/sanbir/evm-hack-registry — search `vault share accounting`

### AMM-003: Reward index overclaim
- Smell: Reward debt or global index updates occur after balance changes, omit a path, or mishandle zero total stake.
- Invariant: Aggregate claimed plus pending rewards never exceeds funded rewards under any stake-transfer ordering.
- Test: Interleave stake, unstake, transfer, claim, reward funding, and zero-stake intervals across multiple users.
- Source: https://github.com/sanbir/evm-hack-registry — search `staking reward accounting`

### AMM-004: Single-block liquidity entitlement
- Smell: Fee or reward entitlement depends on instantaneous stake or liquidity without a duration or checkpoint requirement.
- Invariant: Temporary capital cannot capture rewards generated outside its participation interval.
- Test: Add and remove liquidity around fee, reward, or snapshot events and compare time-weighted contribution.
- Source: https://github.com/sanbir/evm-hack-registry — search `flash loan staking rewards`
