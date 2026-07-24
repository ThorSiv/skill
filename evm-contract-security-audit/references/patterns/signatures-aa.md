# Signatures and Account Abstraction

### SIGNATURE-001: Missing replay domain
- Smell: Signed payloads omit chain, verifying contract, nonce, deadline, or operation-specific domain data.
- Invariant: One authorization is consumable once, by one contract, on one chain, for one intended action.
- Test: Reuse a valid signature across chains, deployments, users, nonces, deadlines, and semantically different entry points.
- Source: https://github.com/sanbir/evm-hack-registry — search `signature replay`

### SIGNATURE-002: Ambiguous message encoding
- Smell: Hashes use packed variable-length fields or omit type and length boundaries.
- Invariant: Distinct authorized messages cannot serialize to the same signed digest.
- Test: Generate boundary-shifted strings, bytes, and arrays that concatenate identically and compare digests.
- Source: https://github.com/sanbir/evm-hack-registry — search `abi encode packed collision`

### SIGNATURE-003: Signer recovery edge case
- Smell: Raw recovery accepts malleable signatures, invalid recovery identifiers, zero addresses, or incompatible contract signers.
- Invariant: Authorization succeeds only for one canonical signature from the configured signer type.
- Test: Vary signature canonicality, length, recovery identifier, zero recovery, and contract-based validation responses.
- Source: https://github.com/sanbir/evm-hack-registry — search `ecrecover malleability`

### SIGNATURE-004: User-operation field underbinding
- Smell: Account-abstraction validation hashes only a subset of call, fee, nonce, paymaster, or deployment fields.
- Invariant: Validation commits to every field that can alter execution target, cost payer, authority, or replay scope.
- Test: Hold the signature fixed while mutating each operation field independently and require validation failure.
- Source: https://github.com/sanbir/evm-hack-registry — search `account abstraction validation`
