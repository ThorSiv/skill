# Accounting and Precision

### ACCOUNTING-001: Share inflation from donation
- Smell: Share conversion uses live asset balance and permits assets to arrive without minting corresponding shares.
- Invariant: Unsolicited balance changes cannot let an existing holder capture later depositors' principal.
- Test: Compare mint and redeem outcomes when a minimal first deposit is followed by direct asset transfers and victim deposits.
- Source: https://github.com/sanbir/evm-hack-registry — search `donation share inflation`

### ACCOUNTING-002: Directional rounding value leak
- Smell: Asset-share or debt conversions round in the same beneficiary direction for mint, redeem, borrow, and repay paths.
- Invariant: Rounding loss is bounded and never systematically favors the caller over the protocol or other users.
- Test: Sweep boundary amounts around each division and compose repeated small operations to measure cumulative drift.
- Source: https://github.com/sanbir/evm-hack-registry — search `rounding precision loss`

### ACCOUNTING-003: Duplicate component counting
- Smell: Aggregate value sums overlapping positions, repeated identifiers, or both sides of an equivalent pair without deduplication.
- Invariant: Each unit of collateral, debt, or claim contributes exactly once to solvency and withdrawal limits.
- Test: Supply duplicated and aliased component sets, then compare aggregate value with the union of unique underlying claims.
- Source: https://github.com/sanbir/evm-hack-registry — search `double counting collateral`

### ACCOUNTING-004: Cached total desynchronization
- Smell: Cached assets, supply, debt, or rewards are updated on some paths but not on transfers, fees, losses, or callbacks.
- Invariant: Cached totals reconcile with independently derived balances and liabilities after every state transition.
- Test: Compose all balance-changing paths in varied order and assert cached, token, and per-user totals reconcile.
- Source: https://github.com/sanbir/evm-hack-registry — search `accounting mismatch`
