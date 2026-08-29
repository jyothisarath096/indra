#!/usr/bin/env python3
"""Deterministic analytic calibration for INDRA's active-slot coefficient."""

from __future__ import annotations

import csv
import json
from decimal import Decimal, getcontext
from fractions import Fraction
from pathlib import Path

getcontext().prec = 100
D = Decimal
ROOT = Path(__file__).resolve().parent
OUT = ROOT / "calibration_results.csv"
TWO64 = 1 << 64

CANDIDATES = [
    "0.01", "0.025", "0.05", "0.075", "0.10", "0.15", "0.20",
    "0.25", "0.30", "0.32", "0.33", "0.34", "0.35", "0.36",
    "0.375", "0.38", "0.39", "0.40", "0.41", "0.42", "0.45", "0.50",
]
BETAS = ["0.10", "0.20", str(D(1) / D(3))]
UNAVAILABLE = ["0", "0.10", "0.20"]  # fraction of total stake, known honest but offline
SPLITS = [1, 2, 5, 10, 50, 200]


def dpow(base: D, exponent: D) -> D:
    return (exponent * base.ln()).exp() if exponent else D(1)


def eligible(f: D, alpha: D) -> D:
    return D(1) - dpow(D(1) - f, alpha)


def poisson_binomial(ps: list[D]) -> list[D]:
    dist = [D(1)]
    for p in ps:
        nxt = [D(0)] * (len(dist) + 1)
        for i, old in enumerate(dist):
            nxt[i] += old * (D(1) - p)
            nxt[i + 1] += old * p
        dist = nxt
    return dist


def quantize_half_up(text: str) -> int:
    x = Fraction(text)
    q, r = divmod(x.numerator * TWO64, x.denominator)
    return q + (1 if 2 * r >= x.denominator else 0)


def fmt(x: D) -> str:
    return format(x, ".42g")


rows: list[dict[str, str]] = []


def emit(f_text: str, category: str, scenario: str, metric: str, value: D, **extra: object) -> None:
    row = {
        "f_requested": f_text,
        "F_nearest_half_up": str(quantize_half_up(f_text)),
        "f_effective": fmt(D(quantize_half_up(f_text)) / D(TWO64)),
        "category": category,
        "scenario": scenario,
        "beta": "",
        "unavailable_honest_total_fraction": "",
        "validator_count": "",
        "coalition_keys": "",
        "rounds": "",
        "network_delta_seconds": "",
        "metric": metric,
        "value": fmt(value),
        "method": "analytic-decimal-100-digit",
    }
    row.update({key: str(value) for key, value in extra.items()})
    rows.append(row)


for f_text in CANDIDATES:
    f = D(f_text)

    # Whole-set proposer multiplicity. Equal stake maximizes the Bernoulli
    # trial count and approaches the Poisson limit at the validator cap.
    for n in [1, 4, 20, 200]:
        p = eligible(f, D(1) / D(n))
        dist = poisson_binomial([p] * n)
        emit(f_text, "proposer_count", "equal_stake", "p_zero", dist[0], validator_count=n)
        emit(f_text, "proposer_count", "equal_stake", "p_one", dist[1], validator_count=n)
        emit(f_text, "proposer_count", "equal_stake", "p_multiple", sum(dist[2:], D(0)), validator_count=n)
        emit(f_text, "proposer_count", "equal_stake", "expected_count", D(n) * p, validator_count=n)

    for beta_text in BETAS:
        beta = D(beta_text)
        p_b = eligible(f, beta)

        for unavailable_text in UNAVAILABLE:
            unavailable = D(unavailable_text)
            honest_online = D(1) - beta - unavailable
            if honest_online <= 0:
                continue
            p_h = eligible(f, honest_online)
            q_h = D(1) - p_h
            emit(f_text, "liveness", "byzantine_plus_offline", "honest_online_stake", honest_online, beta=beta_text, unavailable_honest_total_fraction=unavailable_text)
            emit(f_text, "liveness", "byzantine_plus_offline", "p_honest_proposer", p_h, beta=beta_text, unavailable_honest_total_fraction=unavailable_text)
            emit(f_text, "liveness", "byzantine_plus_offline", "p_no_honest_proposer", q_h, beta=beta_text, unavailable_honest_total_fraction=unavailable_text)
            emit(f_text, "liveness", "byzantine_plus_offline", "expected_rounds", D(1) / p_h, beta=beta_text, unavailable_honest_total_fraction=unavailable_text)
            emit(f_text, "liveness", "byzantine_plus_offline", "p_only_byzantine", p_b * q_h, beta=beta_text, unavailable_honest_total_fraction=unavailable_text)
            for rounds in [5, 10, 20]:
                emit(f_text, "liveness", "byzantine_plus_offline", "p_no_honest_for_n_rounds", q_h ** rounds, beta=beta_text, unavailable_honest_total_fraction=unavailable_text, rounds=rounds)
                emit(f_text, "timing", "empty_proposer_tail", "minimum_tail_seconds", D(14 * rounds), beta=beta_text, unavailable_honest_total_fraction=unavailable_text, rounds=rounds)
            # Successful round = fixed proposal-selection window + two network
            # delays. Each prior absent-proposer round consumes 8+3+3 seconds.
            for delta in [D("0.5"), D("1"), D("2")]:
                successful = D(8) + D(2) * delta
                expected_seconds = (q_h / p_h) * D(14) + successful
                emit(f_text, "timing", "geometric_absent_rounds", "expected_seconds", expected_seconds, beta=beta_text, unavailable_honest_total_fraction=unavailable_text, network_delta_seconds=delta)

        # Adaptive publish/withhold strategy from Phase 6, with all honest stake
        # online. Mixed honest/adversarial rounds are awarded to honest progress.
        p_h = eligible(f, D(1) - beta)
        p_only_b = p_b * (D(1) - p_h)
        target = p_b
        favorable = p_only_b * target
        race = favorable / (p_h + favorable)
        biased = target + (D(1) - target) * race
        generic_race = (p_only_b / D(2)) / (p_h + p_only_b / D(2))
        tv = generic_race / D(2)
        emit(f_text, "adaptive_grinding", "next_coalition_eligibility", "baseline", target, beta=beta_text)
        emit(f_text, "adaptive_grinding", "next_coalition_eligibility", "biased", biased, beta=beta_text)
        emit(f_text, "adaptive_grinding", "next_coalition_eligibility", "absolute_bias", biased - target, beta=beta_text)
        emit(f_text, "adaptive_grinding", "next_coalition_eligibility", "relative_advantage", biased / target - D(1), beta=beta_text)
        emit(f_text, "adaptive_grinding", "next_coalition_eligibility", "effective_grinding_bits", (biased / target).ln() / D(2).ln(), beta=beta_text)
        emit(f_text, "adaptive_grinding", "balanced_predicate", "tv_lower_bound", tv, beta=beta_text)

    beta = D(1) / D(3)
    for k in SPLITS:
        p_each = eligible(f, beta / D(k))
        dist = poisson_binomial([p_each] * k)
        p_any = D(1) - dist[0]
        p_multiple = sum(dist[2:], D(0))
        emit(f_text, "stake_splitting", "beta_one_third_equal_split", "p_any", p_any, beta=str(beta), coalition_keys=k)
        emit(f_text, "stake_splitting", "beta_one_third_equal_split", "p_multiple", p_multiple, beta=str(beta), coalition_keys=k)
        emit(f_text, "stake_splitting", "beta_one_third_equal_split", "p_multiple_given_any", p_multiple / p_any, beta=str(beta), coalition_keys=k)

fields = [
    "f_requested", "F_nearest_half_up", "f_effective", "category", "scenario",
    "beta", "unavailable_honest_total_fraction", "validator_count", "coalition_keys",
    "rounds", "network_delta_seconds", "metric", "value", "method",
]
with OUT.open("w", newline="") as handle:
    writer = csv.DictWriter(handle, fieldnames=fields)
    writer.writeheader()
    writer.writerows(rows)

print(json.dumps({"rows": len(rows), "candidate_f_values": len(CANDIDATES)}, indent=2))
