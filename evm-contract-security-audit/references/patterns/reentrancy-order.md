# Reentrancy and Ordering

### REENTRANCY-001: External call before state settlement
- Smell: Token, native-asset, or arbitrary external calls occur before balances, debts, or one-time flags are finalized.
- Invariant: Reentrant observation cannot see spendable state that the outer operation has already consumed.
- Test: Reenter the same function from each external-call boundary and compare total claims before and after settlement.
- Source: https://github.com/sanbir/evm-hack-registry — search `reentrancy checks effects interactions`

### REENTRANCY-002: Cross-function and read-only stale state
- Smell: One guarded function exposes an external call while another function reads or mutates the same accounting without the same guard; read-only quote or valuation functions can observe that transient state.
- Invariant: Shared accounting and every externally observable derived value remain internally consistent across every callable path during an in-progress operation.
- Test: At each callback, inspect read-only prices and previews, then invoke sibling deposit, withdraw, borrow, repay, claim, and transfer paths that share state.
- Source: https://github.com/sanbir/evm-hack-registry — search `cross function read only reentrancy`

### REENTRANCY-003: Callback authenticity gap
- Smell: Swap, flash-loan, token-receiver, or hook callbacks trust parameters without binding the caller to an expected pool or token.
- Invariant: A callback can settle obligations only for the exact authenticated operation that created it.
- Test: Call callbacks directly and through lookalike contracts while varying initiator, asset, amount, and operation identifier.
- Source: https://github.com/sanbir/evm-hack-registry — search `callback validation`

### REENTRANCY-004: Transaction-order state capture
- Smell: Quotes, rewards, or permissions are computed from mutable state without deadlines, bounds, or same-operation commitments.
- Invariant: Reordering adjacent transactions cannot transfer value beyond the user's declared tolerance.
- Test: Permute attacker and victim actions around state-changing operations and assert bounded value differences.
- Source: https://github.com/sanbir/evm-hack-registry — search `transaction ordering`
