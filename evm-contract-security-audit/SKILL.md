---
name: evm-contract-security-audit
description: Use when analyzing, auditing, reviewing, or investigating any EVM smart contract, deployed address, Solidity/Vyper source, bytecode, transaction, protocol, token approval, exploitability, or risk of theft, draining, freezing, dilution, unauthorized minting, or loss of user assets. Trigger on requests such as “is this contract safe,” “will it be attacked,” “can it take user funds,” and Chinese equivalents including “检测合约”“是否会被攻击”“获取用户资产”“盗币”“漏洞”.
---

# EVM Contract Security Audit

## Core rule

Do not equate a familiar contract shape, verified source, audit report, empty current balance, or successful final `require` with safety. Prove or refute asset-loss paths using adversarial inputs and protocol invariants.

This Skill is detection-only. Analyze reachable paths, invariants, and asset impact; do not generate or execute exploit code, fork attacks, broadcasts, credential use, or asset-moving transactions. A pattern match is a review lead, not confirmed exploitability.

## Required workflow

1. Resolve the chain, runtime bytecode, verified source, proxy implementation, immutable dependencies, privileged roles, deployment history, and current balances. Treat current state and code safety as separate conclusions.
2. Map assets and authority: user-wallet assets, approvals, protocol-held collateral, minted claims, oracle influence, factories, callbacks, and upgrade keys.
3. Enumerate every externally reachable state-changing entry point. Trace checks, state writes, external calls, mint/burn operations, and asset exits.
4. State each intended invariant in plain language and algebra. Test whether the code enforces the invariant per identity or merely in aggregate.
5. Reason through a complete adversarial transaction sequence without executing it. Show prerequisites, input cost, skipped debit/burn, created credit/mint, conversion into transferable value, victim asset source, and net profit.
6. Verify live exploitability separately from structural vulnerability. A zero balance means little current profit, not safe code.
7. Report evidence and uncertainty. Say “not found in reviewed scope,” never “safe,” unless a formal proof supports it.

## Pattern routing

Always check the baseline families: [access/proxy](references/patterns/access-proxy.md), [reentrancy/order](references/patterns/reentrancy-order.md), [accounting/precision](references/patterns/accounting-precision.md), and [low-level EVM](references/patterns/low-level-evm.md). Load only the additional family references indicated by the contract's reachable surface:

| Contract surface | Additional reference |
| --- | --- |
| Prices, feeds, swaps used for valuation, market manipulation | [oracle/market](references/patterns/oracle-market.md) |
| Signatures, permits, nonces, EIP-712, smart accounts | [signatures/account abstraction](references/patterns/signatures-aa.md) |
| Relayers, proofs, messages, remote mint/release | [bridges/cross-chain](references/patterns/bridges-cross-chain.md) |
| ERC-20/721/777/1155 hooks, rebasing, transfer fees | [token/NFT](references/patterns/token-nft.md) |
| Borrowing, collateral, interest, auctions, liquidation | [lending/liquidation](references/patterns/lending-liquidation.md) |
| AMMs, vault shares, staking, rewards, liquidity | [AMM/vault/staking](references/patterns/amm-vault-staking.md) |
| User-growable collections, batches, mandatory loops, gas-sensitive calls | [DoS/arrays/gas](references/patterns/dos-arrays-gas.md) |
| Voting, proposals, timelocks, emissions, cyclic incentives | [governance/economic](references/patterns/governance-economic.md) |

For each applicable pattern, compare its Smell to the code, state whether its Invariant holds, and perform its detection Test by source reasoning or non-destructive analysis. Report matched `FAMILY-NNN` IDs with code evidence, reachable-path reasoning, affected assets, confidence, and current versus structural exposure. Do not label a match exploitable until the path and asset impact are established.

Use [references/source-index.md](references/source-index.md) to find related registry cases by family or keyword. Follow its `source` or `search` links to [sanbir/evm-hack-registry](https://github.com/sanbir/evm-hack-registry) only when deeper source analysis is useful; treat those files as research provenance and do not run their exploit or replay artifacts.

## Mandatory collection and counting tests

For every array, set, batch, allowlist, exception list, signature list, token list, route, or group:

- Test empty, singleton, duplicate, missing, extra, reordered, aliased, and zero-value elements.
- Test duplicates independently in every participating array, including protocol-created arrays.
- Reject aggregate-match reasoning such as `count == array.length` unless uniqueness and one-to-one consumption are independently enforced.
- Rewrite nested-loop counts using multiplicities. For identity `x`, a nested comparison counts `a[x] * e[x]`, not membership. Check whether:

  `sum(a[x] * e[x]) == sum(e[x])`

  can hold while some `e[x] > 0` has `a[x] == 0`.
- Track each element with a consumed bitmap/map or prove all relevant arrays contain unique IDs. A final counter returning to zero does not establish bijection.
- Run `scripts/check_match_count.py` when code uses nested equality loops plus a shared counter.

Read [references/business-logic-patterns.md](references/business-logic-patterns.md) whenever the contract batches identities, mints/burns claims, exchanges groups, or validates exceptions.

## Completion gate

Before concluding, explicitly answer:

- Can it move ordinary wallet assets through approvals or arbitrary calls?
- Can it drain or strand protocol-held assets?
- Can it mint claims without equivalent debit, dilute holders, or corrupt accounting?
- Do duplicates or missing identities pass any aggregate counter/checksum?
- Can the primitive flaw be composed into a complete profitable path?
- What value is at risk now, and what would be at risk after future deposits?

Classify structural severity independently from current TVL. Include a minimal counterexample for every high/critical business-logic finding.
