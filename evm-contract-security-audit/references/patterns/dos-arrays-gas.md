# Denial of Service, Arrays, and Gas

### DOS-001: Unbounded mandatory iteration
- Smell: A critical state transition loops over user-growable storage without pagination or resumable progress.
- Invariant: One adversarial user cannot make withdrawals, settlement, or governance permanently exceed available gas.
- Test: Grow the collection to realistic and adversarial sizes, then measure whether critical operations remain callable.
- Source: https://github.com/sanbir/evm-hack-registry — search `unbounded loop denial of service`

### DOS-002: Push-payment batch blockage
- Smell: A batch reverts entirely when any recipient call or token transfer fails.
- Invariant: One failing recipient cannot indefinitely block unrelated users' funds or protocol progress.
- Test: Include reverting, gas-consuming, and incompatible recipients at different batch positions.
- Source: https://github.com/sanbir/evm-hack-registry — search `failed transfer denial of service`

### DOS-003: Array mutation index corruption
- Smell: Swap-and-pop, parallel arrays, or cached indexes are updated incompletely during removal and reordering.
- Invariant: Every live element has one correct index and removal cannot orphan, duplicate, or redirect another user's state.
- Test: Remove first, middle, last, repeated, and nonexistent elements while checking membership and index bijection.
- Source: https://github.com/sanbir/evm-hack-registry — search `array index swap pop`

### DOS-004: Gas forwarding assumption
- Smell: Correctness depends on a fixed stipend, unrestricted forwarded gas, or a callee completing within an assumed budget.
- Invariant: Gas behavior cannot silently skip required state changes or permanently block recovery paths.
- Test: Vary callee gas consumption and return behavior at each external-call boundary and verify explicit outcomes.
- Source: https://github.com/sanbir/evm-hack-registry — search `gas griefing`
