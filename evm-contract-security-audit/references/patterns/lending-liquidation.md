# Lending and Liquidation

### LENDING-001: Solvency component omission
- Smell: Health calculations omit accrued interest, fees, pending losses, decimal scaling, or one class of liability.
- Invariant: A borrower's recognized collateral minus all current liabilities never overstates withdrawable value.
- Test: Reconcile health across interest accrual, fee realization, multiple assets, decimal extremes, and loss events.
- Source: https://github.com/sanbir/evm-hack-registry — search `lending health factor`

### LENDING-002: Liquidation incentive inversion
- Smell: Close factor, bonus, seizure rounding, or repay limits can make liquidation over-seize or leave profitable bad debt.
- Invariant: Liquidation improves system solvency while respecting configured repayment and seizure bounds.
- Test: Sweep positions around eligibility thresholds and partial-liquidation sizes under price and interest changes.
- Source: https://github.com/sanbir/evm-hack-registry — search `liquidation calculation`

### LENDING-003: Interest index desynchronization
- Smell: User principal is read or changed before global and per-user indexes accrue to the same timestamp.
- Invariant: Equivalent borrow and repay histories produce consistent debt independent of unrelated transaction timing.
- Test: Interleave accrual, borrow, repay, transfer, and liquidation at long and zero-duration intervals.
- Source: https://github.com/sanbir/evm-hack-registry — search `interest accrual index`

### LENDING-004: Bad-debt socialization gap
- Smell: Insolvent positions can be closed or collateral removed without recording uncovered debt against reserves or suppliers.
- Invariant: Every liability is assigned to a borrower, reserve, insurer, or explicit loss-accounting mechanism.
- Test: Drive positions through insolvency, liquidation exhaustion, write-off, and market closure while reconciling total debt.
- Source: https://github.com/sanbir/evm-hack-registry — search `bad debt accounting`
