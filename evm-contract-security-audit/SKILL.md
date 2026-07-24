---
name: evm-contract-security-audit
description: Use when analyzing, auditing, reviewing, or investigating any EVM smart contract, deployed address, Solidity/Vyper source, bytecode, transaction, protocol, token approval, exploitability, or risk of theft, draining, freezing, dilution, unauthorized minting, or loss of user assets. Trigger on requests such as “is this contract safe,” “will it be attacked,” “can it take user funds,” and Chinese equivalents including “检测合约”“是否会被攻击”“获取用户资产”“盗币”“漏洞”.
---

# EVM Contract Security Audit

## Core rule

Do not equate a familiar contract shape, verified source, audit report, empty current balance, or successful final `require` with safety. Prove or refute asset-loss paths using adversarial inputs and protocol invariants.

## Required workflow

1. Resolve the chain, runtime bytecode, verified source, proxy implementation, immutable dependencies, privileged roles, deployment history, and current balances. Treat current state and code safety as separate conclusions.
2. Map assets and authority: user-wallet assets, approvals, protocol-held collateral, minted claims, oracle influence, factories, callbacks, and upgrade keys.
3. Enumerate every externally reachable state-changing entry point. Trace checks, state writes, external calls, mint/burn operations, and asset exits.
4. State each intended invariant in plain language and algebra. Test whether the code enforces the invariant per identity or merely in aggregate.
5. Construct a complete adversarial transaction sequence. Show prerequisites, input cost, skipped debit/burn, created credit/mint, conversion into transferable value, victim asset source, and net profit.
6. Verify live exploitability separately from structural vulnerability. A zero balance means little current profit, not safe code.
7. Report evidence and uncertainty. Say “not found in reviewed scope,” never “safe,” unless a formal proof supports it.

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
