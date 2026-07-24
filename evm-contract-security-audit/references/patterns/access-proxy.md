# Access Control and Proxies

### ACCESS-001: Missing authorization boundary
- Smell: Asset-moving or configuration functions are public and lack a role, ownership, or caller constraint.
- Invariant: Only explicitly authorized actors may move protocol assets or change security-critical state.
- Test: Call every privileged-looking entry point from an untrusted actor before and after normal initialization.
- Source: https://github.com/sanbir/evm-hack-registry — search `access control`

### ACCESS-002: Reinitialization takeover
- Smell: Initializers are externally reachable more than once or implementation contracts remain initializable.
- Invariant: Administrative authority and dependency addresses can be initialized exactly once in the intended context.
- Test: Invoke initialization through proxy and implementation contexts, including after upgrades and partial setup.
- Source: https://github.com/sanbir/evm-hack-registry — search `uninitialized proxy`

### ACCESS-003: Proxy storage collision
- Smell: Upgrade layouts reorder fields, reuse slots, or mix incompatible proxy and implementation storage conventions.
- Invariant: An upgrade preserves every live value and cannot reinterpret data as authority or balances.
- Test: Seed sentinel values in all slots, upgrade across candidate layouts, and compare decoded state and permissions.
- Source: https://github.com/sanbir/evm-hack-registry — search `storage collision`

### ACCESS-004: Upgrade authority bypass
- Smell: Upgrade, beacon, or implementation setters validate the wrong caller or accept unchecked targets.
- Invariant: Only the designated governance path can install code, and installed code satisfies required compatibility checks.
- Test: Exercise direct, proxied, delegated, and fallback calls from every role against malformed implementation targets.
- Source: https://github.com/sanbir/evm-hack-registry — search `upgrade authorization`
