#!/usr/bin/env python3
"""Find aggregate nested-loop counts that pass despite missing identities."""

import argparse
from collections import Counter


def parse_ids(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def match_pairs(left: list[str], expected: list[str]) -> int:
    left_counts = Counter(left)
    expected_counts = Counter(expected)
    return sum(left_counts[item] * count for item, count in expected_counts.items())


def missing(left: list[str], expected: list[str]) -> list[str]:
    present = set(left)
    return sorted({item for item in expected if item not in present})


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check whether aggregate match counting accepts missing identities."
    )
    parser.add_argument("--input", required=True, help="Comma-separated input IDs")
    parser.add_argument("--exceptions", required=True, help="Comma-separated expected IDs")
    parser.add_argument("--output", help="Optional comma-separated output IDs")
    args = parser.parse_args()

    inputs = parse_ids(args.input)
    exceptions = parse_ids(args.exceptions)
    input_pairs = match_pairs(inputs, exceptions)
    input_missing = missing(inputs, exceptions)
    input_passes = input_pairs == len(exceptions)

    print(f"input match-pairs: {input_pairs}; expected length: {len(exceptions)}")
    print(f"input aggregate check passes: {str(input_passes).lower()}")
    print(f"exceptions missing from input: {','.join(input_missing) or '-'}")

    vulnerable = input_passes and bool(input_missing)
    if args.output is not None:
        outputs = parse_ids(args.output)
        output_pairs = match_pairs(outputs, exceptions)
        output_missing = missing(outputs, exceptions)
        print(f"output match-pairs: {output_pairs}; starting counter: {input_pairs}")
        print(f"shared counter returns to zero: {str(output_pairs == input_pairs).lower()}")
        print(f"exceptions missing from output: {','.join(output_missing) or '-'}")
        vulnerable = vulnerable or (input_passes and output_pairs == input_pairs and bool(output_missing))

    print(f"aggregate-count bypass found: {str(vulnerable).lower()}")
    return 2 if vulnerable else 0


if __name__ == "__main__":
    raise SystemExit(main())
