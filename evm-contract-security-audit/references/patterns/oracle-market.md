# Oracles and Markets

### ORACLE-001: Spot-price dependency
- Smell: Solvency, minting, or settlement uses a manipulable pool reserve or instantaneous exchange rate.
- Invariant: A transient trade cannot materially change protocol-recognized value without sustained external price evidence.
- Test: Perturb the referenced market immediately before valuation and restore it afterward while measuring extractable accounting change.
- Source: https://github.com/sanbir/evm-hack-registry — search `spot price manipulation`

### ORACLE-002: Stale or incomplete feed acceptance
- Smell: Feed reads omit freshness, positivity, round-completeness, or sequencer-health checks.
- Invariant: State-changing valuation accepts only complete, recent, valid observations for the intended market.
- Test: Inject zero, negative, stale, future-dated, incomplete-round, and sequencer-outage observations.
- Source: https://github.com/sanbir/evm-hack-registry — search `stale oracle`

### ORACLE-003: Decimal and quote mismatch
- Smell: Oracle answers, token units, and quote directions are combined without explicit decimal normalization or inversion handling.
- Invariant: Equivalent economic values produce equivalent normalized prices across all supported decimal and quote configurations.
- Test: Evaluate identical values using tokens and feeds with varied decimals and reciprocal quote orientations.
- Source: https://github.com/sanbir/evm-hack-registry — search `oracle decimals`

### ORACLE-004: Thin-market reference
- Smell: A price adapter trusts a single low-liquidity route, user-selected pool, or observation window with weak cardinality.
- Invariant: Users cannot choose or cheaply dominate the market data that determines their own solvency or payout.
- Test: Substitute shallow and adversarial pools, vary observation history, and verify liquidity and provenance constraints.
- Source: https://github.com/sanbir/evm-hack-registry — search `oracle low liquidity`
