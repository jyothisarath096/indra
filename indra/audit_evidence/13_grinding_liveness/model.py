#!/usr/bin/env python3
"""Exact/high-precision analytic model for INDRA proposer sortition.

No production implementation is imported. Decimal arithmetic is used for
fractional powers; all probabilities are analytic (there is no Monte Carlo).
"""

from __future__ import annotations

import csv
import json
from decimal import Decimal, getcontext
from pathlib import Path

getcontext().prec = 100
D = Decimal
ROOT = Path(__file__).resolve().parent
OUT = ROOT / "results.csv"

F_VALUES = [
    ("min", D(1) / D(2) ** 64),
    ("f_0.01", D("0.01")),
    ("f_0.05", D("0.05")),
    ("f_0.10", D("0.10")),
    ("f_0.20", D("0.20")),
    ("current_example", D("0.5")),
]


def pow_decimal(base: Decimal, exponent: Decimal) -> Decimal:
    if exponent == 0:
        return D(1)
    return (exponent * base.ln()).exp()


def eligibility(f: Decimal, stake_fraction: Decimal) -> Decimal:
    return D(1) - pow_decimal(D(1) - f, stake_fraction)


def poisson_binomial(ps: list[Decimal]) -> list[Decimal]:
    dist = [D(1)]
    for p in ps:
        nxt = [D(0)] * (len(dist) + 1)
        for j, probability in enumerate(dist):
            nxt[j] += probability * (D(1) - p)
            nxt[j + 1] += probability * p
        dist = nxt
    return dist


def proposer_stats(f: Decimal, weights: list[Decimal]) -> dict[str, Decimal]:
    total = sum(weights, D(0))
    ps = [eligibility(f, w / total) for w in weights]
    dist = poisson_binomial(ps)
    mean = sum((D(i) * p for i, p in enumerate(dist)), D(0))
    variance = sum((p * (D(i) - mean) ** 2 for i, p in enumerate(dist)), D(0))
    return {
        "p0": dist[0],
        "p1": dist[1] if len(dist) > 1 else D(0),
        "p_ge_2": sum(dist[2:], D(0)),
        "mean": mean,
        "variance": variance,
    }


def fmt(value: Decimal) -> str:
    return format(value, ".40g")


rows: list[dict[str, str]] = []


def emit(category: str, scenario: str, metric: str, value: Decimal, **fields: object) -> None:
    row = {
        "category": category,
        "scenario": scenario,
        "f": "",
        "validator_count": "",
        "stake_fraction": "",
        "offline_fraction": "",
        "coalition_keys": "",
        "rounds": "",
        "metric": metric,
        "value": fmt(value),
        "method": "analytic-decimal-100-digit",
    }
    row.update({k: str(v) for k, v in fields.items()})
    rows.append(row)


distributions = {
    "equal_1": [D(1)],
    "equal_4_current_manifest": [D(1)] * 4,
    "equal_10": [D(1)] * 10,
    "equal_200": [D(1)] * 200,
    "moderate_20_top4_10pct": [D("0.10")] * 4 + [D("0.0375")] * 16,
    "high_20_top1_40pct_next4_10pct": [D("0.40")] + [D("0.10")] * 4 + [D("0.20") / D(15)] * 15,
}

for f_name, f in F_VALUES:
    for name, weights in distributions.items():
        stats = proposer_stats(f, weights)
        for metric, value in stats.items():
            emit("proposer_distribution", name, metric, value, f=f_name, validator_count=len(weights))

# Deterministic unavailable-stake scenarios. The remaining online stake is
# treated as one aggregate because the no-online-eligible probability is split
# invariant in the ideal Praos model.
for _, f in F_VALUES[1:]:
    for offline in map(D, ["0", "0.05", "0.10", "0.20", "0.33", "0.40"]):
        online = D(1) - offline
        p_progress = eligibility(f, online)
        no_progress = D(1) - p_progress
        emit("correlated_outage", "deterministic_stake_group", "p_no_online_eligible", no_progress, f=fmt(f), offline_fraction=offline)
        emit("correlated_outage", "deterministic_stake_group", "p_online_progress", p_progress, f=fmt(f), offline_fraction=offline)
        emit("correlated_outage", "deterministic_stake_group", "expected_rounds", D(1) / p_progress, f=fmt(f), offline_fraction=offline)
        for n_rounds in [1, 2, 5, 10, 20]:
            emit("correlated_outage", "deterministic_stake_group", "p_no_progress_ge_n", no_progress ** n_rounds, f=fmt(f), offline_fraction=offline, rounds=n_rounds)

# Independent per-validator outage differs from a fixed correlated stake loss.
for f in [D("0.1"), D("0.5")]:
    for n in [4, 20, 200]:
        p = eligibility(f, D(1) / D(n))
        for d in map(D, ["0.05", "0.10", "0.20", "0.33"]):
            p_no_online = (D(1) - (D(1) - d) * p) ** n
            emit("independent_outage", "equal_stake", "p_no_online_eligible", p_no_online, f=fmt(f), validator_count=n, offline_fraction=d)

# Byzantine withholding. Progress is guaranteed only by at least one honest
# online eligible proposer. "only Byzantine" excludes empty rounds.
for f in [D("0.01"), D("0.05"), D("0.1"), D("0.2"), D("0.5")]:
    for beta in map(D, ["0.05", "0.10", "0.20", "0.33"]):
        honest = D(1) - beta
        p_h = eligibility(f, honest)
        p_b = eligibility(f, beta)
        p_no_h = D(1) - p_h
        p_only_b = p_b * p_no_h
        emit("byzantine_withholding", "all_byzantine_proposals_withheld", "p_no_honest_eligible", p_no_h, f=fmt(f), stake_fraction=beta)
        emit("byzantine_withholding", "all_byzantine_proposals_withheld", "p_at_least_one_honest", p_h, f=fmt(f), stake_fraction=beta)
        emit("byzantine_withholding", "all_byzantine_proposals_withheld", "p_only_byzantine", p_only_b, f=fmt(f), stake_fraction=beta)
        emit("byzantine_withholding", "all_byzantine_proposals_withheld", "expected_rounds", D(1) / p_h, f=fmt(f), stake_fraction=beta)
        for n_rounds in [2, 5, 10, 20]:
            emit("byzantine_withholding", "all_byzantine_proposals_withheld", "p_no_progress_ge_n", p_no_h ** n_rounds, f=fmt(f), stake_fraction=beta, rounds=n_rounds)

# Adaptive two-height grinding: in an adversary-only eligible round, publish
# iff the candidate next seed makes the coalition eligible at the next height.
# Honest eligibility terminates the current-height race. This is an upper-bound
# model favorable to the attacker: network priority and honest competing values
# cannot reduce its chance once it is the sole eligible coalition.
for f in [D("0.01"), D("0.05"), D("0.1"), D("0.2"), D("0.5")]:
    for beta in map(D, ["0.05", "0.10", "0.20", "0.33"]):
        p_b = eligibility(f, beta)
        p_h = eligibility(f, D(1) - beta)
        p_only_b = p_b * (D(1) - p_h)
        target = p_b
        favorable_solo = p_only_b * target
        race_win = favorable_solo / (p_h + favorable_solo)
        biased_target = target + (D(1) - target) * race_win
        emit("adaptive_grinding", "publish_solo_only_if_next_coalition_eligible", "baseline_next_coalition_eligibility", target, f=fmt(f), stake_fraction=beta)
        emit("adaptive_grinding", "publish_solo_only_if_next_coalition_eligible", "biased_next_coalition_eligibility", biased_target, f=fmt(f), stake_fraction=beta)
        emit("adaptive_grinding", "publish_solo_only_if_next_coalition_eligible", "absolute_bias", biased_target - target, f=fmt(f), stake_fraction=beta)
        emit("adaptive_grinding", "publish_solo_only_if_next_coalition_eligible", "relative_advantage", biased_target / target - D(1), f=fmt(f), stake_fraction=beta)
        emit("adaptive_grinding", "publish_solo_only_if_next_coalition_eligible", "effective_grinding_bits", (biased_target / target).ln() / D(2).ln(), f=fmt(f), stake_fraction=beta)
        emit("adaptive_grinding", "publish_solo_only_if_next_coalition_eligible", "expected_rounds_to_terminal", D(1) / (p_h + favorable_solo), f=fmt(f), stake_fraction=beta)

# A generic balanced predicate gives a lower bound on full-distribution total
# variation: the attacker publishes a solo candidate only when predicate=1.
for f in [D("0.1"), D("0.5")]:
    for beta in map(D, ["0.10", "0.20", "0.33"]):
        p_b = eligibility(f, beta)
        p_h = eligibility(f, D(1) - beta)
        a = p_b * (D(1) - p_h)
        race = (a / D(2)) / (p_h + a / D(2))
        final = D("0.5") + D("0.5") * race
        emit("adaptive_grinding", "balanced_seed_predicate", "tv_lower_bound", final - D("0.5"), f=fmt(f), stake_fraction=beta)

# Stake splitting conserves P(any) but increases P(multiple controlled outputs).
for f in [D("0.1"), D("0.5")]:
    for beta in map(D, ["0.10", "0.20", "0.33"]):
        for k in [1, 2, 5, 10, 50, 200]:
            p_each = eligibility(f, beta / D(k))
            dist = poisson_binomial([p_each] * k)
            p_any = D(1) - dist[0]
            p_multi = sum(dist[2:], D(0))
            conditional_multi = p_multi / p_any if p_any else D(0)
            emit("coalition_split", "equal_split", "p_any", p_any, f=fmt(f), stake_fraction=beta, coalition_keys=k)
            emit("coalition_split", "equal_split", "p_multiple", p_multi, f=fmt(f), stake_fraction=beta, coalition_keys=k)
            emit("coalition_split", "equal_split", "p_multiple_given_any", conditional_multi, f=fmt(f), stake_fraction=beta, coalition_keys=k)

# Bitcoin catch-up probability for a biased random walk after z confirmations.
# This is a probability bound, not an economic-cost estimate.
for q in map(D, ["0.10", "0.20", "0.30", "0.40", "0.49", "0.50"]):
    z = 100
    catchup = D(1) if q >= D("0.5") else (q / (D(1) - q)) ** z
    emit("genesis_entropy", "bitcoin_100_confirmation_catchup", "eventual_catchup_probability", catchup, stake_fraction=q, rounds=z)

fieldnames = [
    "category", "scenario", "f", "validator_count", "stake_fraction",
    "offline_fraction", "coalition_keys", "rounds", "metric", "value", "method",
]
with OUT.open("w", newline="") as handle:
    writer = csv.DictWriter(handle, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)

summary = {
    "rows": len(rows),
    "arithmetic": "Python Decimal, 100 significant decimal digits",
    "monte_carlo_cases": 0,
    "analytic_cases_only": True,
}
print(json.dumps(summary, indent=2))
