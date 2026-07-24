# EVM business-logic attack patterns

Use this reference to challenge protocol invariants, not as a finite vulnerability checklist.

## Match-pair counting mistaken for membership

Vulnerable shape:

```solidity
for (uint i; i < group.length; i++) {
    for (uint j; j < exceptions.length; j++) {
        if (group[i] == exceptions[j]) count++;
    }
}
require(count == exceptions.length);
```

Let `a[x]` and `e[x]` be multiplicities. The code checks:

```text
Σ a[x]e[x] = Σ e[x]
```

It does not check `e[x] > 0 => a[x] > 0`. A repeated present ID can compensate for an absent ID.

Example:

```text
group      = [S, S, L]
exceptions = [S, L, X]
matches    = 2 + 1 + 0 = 3
```

The length check passes although `X` is absent. If matching elements skip burns, all shown group elements may avoid debit. If a second loop decrements the same counter, repeated output IDs can return it to zero while unrelated output IDs are minted.

Do not stop after demonstrating a free mint. Determine whether an attacker can construct economically valid groups, repeat exchanges to assemble a redeemable group, and withdraw shared collateral.

## Related mandatory probes

- Duplicate IDs in registered groups, even when caller-supplied exceptions are unique.
- Duplicate signatures counted toward quorum without unique signers.
- Duplicate assets counted toward collateral or withdrawal totals.
- Missing IDs offset by repeated matches, positive/negative deltas, or repeated callbacks.
- Parallel arrays with unequal lengths, aliasing, reordered identities, or default zero entries.
- Batch operations where validation aggregates amounts but execution applies per occurrence.
- Mint-before-debit, burn-after-transfer, callback reentrancy, and rollback assumptions across external calls.
- Rounding or decimal gaps that become profitable through repetition.
- Oracle identifiers, timestamps, hints, and stale values supplied by attackers.

## Safer invariants

Enforce the intended relation directly:

- Require uniqueness for every array whose elements represent identities.
- Mark each expected identity consumed exactly once and reject second consumption.
- Verify both inclusion directions when equality of sets is required.
- Bind amounts, identities, chain ID, caller, nonce, and destination in signed data.
- Test conservation: assets out plus remaining liabilities must not exceed assets in plus explicit yield.
