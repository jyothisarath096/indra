#!/usr/bin/env python3
"""Exact/high-precision correlated-topology model for INDRA at mainnet f=3/8."""

from __future__ import annotations

import csv
import json
from decimal import Decimal, getcontext
from pathlib import Path

getcontext().prec = 100
D = Decimal
ROOT = Path(__file__).resolve().parent
F = D(3) / D(8)
ONE_THIRD = D(1) / D(3)


def dpow(base: D, exponent: D) -> D:
    return (exponent * base.ln()).exp() if exponent else D(1)


def eligible(stake_fraction: D) -> D:
    return D(1) - dpow(D(1) - F, stake_fraction)


def fmt(value: D) -> str:
    return format(value, ".42g")


rows: list[dict[str, str]] = []


def emit(category: str, scenario: str, stake: D, metric: str, value: object,
         *, role: str = "", rounds: str = "", identities: str = "") -> None:
    rows.append({
        "category": category,
        "scenario": scenario,
        "role": role,
        "stake_fraction": fmt(stake),
        "identities": identities,
        "rounds": rounds,
        "metric": metric,
        "value": fmt(value) if isinstance(value, D) else str(value).lower(),
        "method": "analytic-decimal-100-digit",
    })


def outage(category: str, label: str, failed: D) -> None:
    online = D(1) - failed
    p_online = eligible(online)
    q_online = D(1) - p_online
    qc = online * D(3) > D(2)
    emit(category, label, failed, "honest_online_stake", online)
    emit(category, label, failed, "qc_possible_without_failed_stake", qc)
    emit(category, label, failed, "p_online_honest_proposer", p_online)
    emit(category, label, failed, "expected_rounds_to_online_honest_proposer", D(1) / p_online)
    for n in (5, 10, 20):
        emit(category, label, failed, "p_no_online_honest_proposer", q_online ** n,
             rounds=str(n))


OUTAGES = [D("0.05"), D("0.10"), D("0.20"), D("0.25"), D("0.30"),
           ONE_THIRD, D("0.40"), D("0.50")]
for fraction in OUTAGES:
    outage("correlated_failure", "deterministic_stake_outage", fraction)

for fraction in map(D, ["0.05", "0.10", "0.20", "0.25", "0.30"]):
    outage("operator_offline", "largest_operator_offline", fraction)

for dimension, values in {
    "provider": ["0.10", "0.20", "0.30", "0.40", "0.50"],
    "region": ["0.10", "0.20", "0.30", "0.40"],
    "asn": ["0.10", "0.20", "0.30", "0.40", "0.50"],
}.items():
    for text in values:
        outage("infrastructure_outage", f"{dimension}_outage", D(text))


def byzantine(label: str, beta: D) -> None:
    honest = D(1) - beta
    p_b = eligible(beta)
    p_h = eligible(honest)
    q_h = D(1) - p_h
    p_only_b = p_b * q_h
    qc_without_b = honest * D(3) > D(2)
    emit("operator_byzantine", label, beta, "honest_online_stake", honest)
    emit("operator_byzantine", label, beta, "qc_possible_if_coalition_withholds", qc_without_b)
    emit("operator_byzantine", label, beta, "p_coalition_eligible", p_b)
    emit("operator_byzantine", label, beta, "p_no_honest_proposer", q_h)
    emit("operator_byzantine", label, beta, "p_only_byzantine_proposer", p_only_b)
    emit("operator_byzantine", label, beta, "expected_rounds_to_honest_proposer", D(1) / p_h)
    emit("operator_byzantine", label, beta, "qc_blocking_capability", not qc_without_b)
    # Phase-6/7 upper-bound publish/withhold strategy.
    favorable = p_only_b * p_b
    race = favorable / (p_h + favorable)
    biased = p_b + (D(1) - p_b) * race
    emit("operator_byzantine", label, beta, "gr01_baseline_next_eligibility", p_b)
    emit("operator_byzantine", label, beta, "gr01_biased_next_eligibility", biased)
    emit("operator_byzantine", label, beta, "gr01_absolute_bias", biased - p_b)


for beta in map(D, ["0.05", "0.10", "0.20", "0.25", "0.30"]):
    byzantine("largest_operator_byzantine", beta)
for beta in map(D, ["0.20", "0.25", "0.30", "0.32"]):
    byzantine("correlated_byzantine_coalition", beta)

# Common-control identity splitting: P(any) is conserved, while multiple
# independently keyed outputs become possible. Equal splits are illustrative.
for beta in map(D, ["0.20", "0.25", "0.30", "0.32"]):
    for k in (1, 5, 20, 100, 200):
        p_each = eligible(beta / D(k))
        p_none = dpow(D(1) - p_each, D(k))
        p_one = D(k) * p_each * dpow(D(1) - p_each, D(k - 1))
        emit("identity_split", "equal_split_common_control", beta, "p_any", D(1) - p_none,
             identities=str(k))
        emit("identity_split", "equal_split_common_control", beta, "p_multiple",
             D(1) - p_none - p_one, identities=str(k))

# Deterministic network partitions. Each side gets a separate row and can elect
# proposers independently; strict-QC formation is possible only above 2/3.
for left_text, right_text in [("0.70", "0.30"), ("0.67", "0.33"),
                              ("0.66", "0.34"), ("0.60", "0.40"),
                              ("0.50", "0.50")]:
    label = f"{left_text}/{right_text}"
    for role, text in (("left", left_text), ("right", right_text)):
        stake = D(text)
        emit("network_partition", label, stake, "qc_possible", stake * D(3) > D(2), role=role)
        emit("network_partition", label, stake, "can_elect_proposer", stake > 0, role=role)
        emit("network_partition", label, stake, "p_side_proposer", eligible(stake), role=role)
        emit("network_partition", label, stake, "expected_rounds_to_side_proposer",
             D(1) / eligible(stake), role=role)

# Identity count is intentionally irrelevant to aggregate outage math.
for identities in (10, 100):
    stake = D("0.35")
    emit("identity_vs_infrastructure", "provider_controls_35pct", stake,
         "p_aggregate_provider_proposer", eligible(stake), identities=str(identities))
    emit("identity_vs_infrastructure", "provider_controls_35pct", stake,
         "qc_blocking_if_provider_offline", (D(1) - stake) * D(3) <= D(2),
         identities=str(identities))

fields = ["category", "scenario", "role", "stake_fraction", "identities",
          "rounds", "metric", "value", "method"]
with (ROOT / "topology_results.csv").open("w", newline="") as handle:
    writer = csv.DictWriter(handle, fieldnames=fields)
    writer.writeheader()
    writer.writerows(rows)

print(json.dumps({"rows": len(rows), "f": "3/8", "precision": 100}, indent=2))
