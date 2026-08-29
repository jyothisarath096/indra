#!/usr/bin/env python3
"""Exact/high-precision symbolic models for the INDRA Bitcoin entropy audit.

No live Bitcoin economic inputs are used. Decimal arithmetic is used only to
render formulas whose inputs are explicit rational model parameters.
"""

from __future__ import annotations

import csv
from decimal import Decimal, getcontext
from pathlib import Path

getcontext().prec = 100
OUT = Path(__file__).with_name("attack_model_results.csv")


def d(n: int, den: int = 1) -> Decimal:
    return Decimal(n) / Decimal(den)


def gambler_ruin(q: Decimal, z: int) -> Decimal:
    """Eventual catch-up probability from an exact z-block deficit."""
    if q >= d(1, 2):
        return Decimal(1)
    return (q / (1 - q)) ** z


def nakamoto_poisson(q: Decimal, z: int) -> Decimal:
    """Bitcoin-paper Poisson approximation after z honest confirmations."""
    if q >= d(1, 2):
        return Decimal(1)
    p = 1 - q
    lam = Decimal(z) * q / p
    total = Decimal(0)
    poisson = (-lam).exp()
    for k in range(z + 1):
        if k:
            poisson *= lam / Decimal(k)
        catch = Decimal(1) if k >= z else (q / p) ** (z - k)
        total += poisson * (1 - catch)
    return 1 - total


def main() -> None:
    rows: list[dict[str, str | int]] = []
    for q_num in (10, 20, 30, 40, 49, 50):
        q = d(q_num, 100)
        for z in (1, 6, 20, 50, 100):
            rows.append({
                "model": "reorg",
                "q": str(q),
                "z_or_bits": z,
                "eventual_catchup_probability": str(gambler_ruin(q, z)),
                "nakamoto_poisson_probability": str(nakamoto_poisson(q, z)),
                "replacement_blocks_for_strictly_more_work_equal_difficulty": z + 1,
                "attacker_expected_baseline_block_intervals_for_z_plus_1_blocks": str(Decimal(z + 1) / q),
                "expected_valid_finds": "",
                "expected_discarded_valid_blocks": "",
                "race_win_probability": "",
            })
    for q_num in (10, 20, 30, 40, 50):
        q = d(q_num, 100)
        for bits in (1, 2, 4, 8):
            attempts = 1 << bits
            race = q / (Decimal(attempts) * (1 - q) + q)
            rows.append({
                "model": "target_block_grinding",
                "q": str(q),
                "z_or_bits": bits,
                "eventual_catchup_probability": "",
                "nakamoto_poisson_probability": "",
                "replacement_blocks_for_strictly_more_work_equal_difficulty": "",
                "attacker_expected_baseline_block_intervals_for_z_plus_1_blocks": str(Decimal(attempts) / q),
                "expected_valid_finds": attempts,
                "expected_discarded_valid_blocks": attempts - 1,
                "race_win_probability": str(race),
            })
    with OUT.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print(f"wrote {len(rows)} rows to {OUT}")


if __name__ == "__main__":
    main()
