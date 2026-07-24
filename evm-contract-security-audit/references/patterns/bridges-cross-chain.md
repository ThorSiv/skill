# Bridges and Cross-Chain Messaging

### BRIDGE-001: Message origin underbinding
- Smell: A receiver checks a relayer but not source chain, source sender, destination, or application domain.
- Invariant: Only the intended remote application on the intended chain can authorize local state changes.
- Test: Deliver structurally valid messages while varying source chain, sender, relayer, destination, and application identifier.
- Source: https://github.com/sanbir/evm-hack-registry — search `cross chain message validation`

### BRIDGE-002: Cross-chain replay
- Smell: Processed-message state uses incomplete identifiers or marks completion after external effects.
- Invariant: Each canonical cross-chain message can produce local effects at most once.
- Test: Redeliver the same payload through alternate relayers, encodings, routes, and ordering around the completion write.
- Source: https://github.com/sanbir/evm-hack-registry — search `bridge replay`

### BRIDGE-003: Mint-release conservation gap
- Smell: Remote minting or local release is not reconciled against locked, burned, rate-limited, and pending amounts.
- Invariant: Bridged liabilities never exceed canonical backing after fees, retries, cancellation, and partial execution.
- Test: Model concurrent deposits, withdrawals, failures, retries, and refunds while reconciling supply across domains.
- Source: https://github.com/sanbir/evm-hack-registry — search `bridge mint backing`

### BRIDGE-004: Proof context omission
- Smell: A proof verifies inclusion but does not bind block finality, root authority, event signature, token, recipient, or amount.
- Invariant: An accepted proof establishes the complete intended transfer under an authorized finalized root.
- Test: Reuse a valid proof with altered leaf interpretation, root source, event fields, or finality state.
- Source: https://github.com/sanbir/evm-hack-registry — search `bridge proof verification`
