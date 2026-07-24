# Low-Level EVM Behavior

### EVM-001: Unchecked low-level call result
- Smell: Low-level call success or returned bytes are ignored before state is finalized.
- Invariant: State records an external effect only after both call status and expected response semantics are verified.
- Test: Exercise successful, reverting, empty, malformed, and semantically false responses from the target.
- Source: https://github.com/sanbir/evm-hack-registry — search `unchecked low level call`

### EVM-002: Returndata confusion
- Smell: Assembly copies or decodes return bytes without length checks, clearing memory, or binding data to the current call.
- Invariant: A caller consumes only well-formed response data produced by the intended immediate callee.
- Test: Return zero-length, short, oversized, trailing, and differently typed bytes across consecutive calls.
- Source: https://github.com/sanbir/evm-hack-registry — search `returndata length`

### EVM-003: Delegate context corruption
- Smell: User-influenced code executes with delegated storage context or delegated targets are weakly validated.
- Invariant: Delegated execution cannot modify state outside an explicitly compatible and authorized implementation layout.
- Test: Substitute targets with incompatible layouts and exercise fallback selectors, value, sender, and nested delegation contexts.
- Source: https://github.com/sanbir/evm-hack-registry — search `delegatecall storage`

### EVM-004: Forced native balance assumption
- Smell: Logic treats contract balance as equal to accounted deposits or requires exact balance equality for progress.
- Invariant: Unsolicited native value cannot create claims, alter pricing, or block state transitions.
- Test: Introduce native balance outside normal deposit paths and verify accounting and liveness remain unchanged.
- Source: https://github.com/sanbir/evm-hack-registry — search `forced ether balance`
