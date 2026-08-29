#!/usr/bin/env python3
"""Dandelion++ simulation v2: small-N any-authenticated relay eligibility.

This follow-up deliberately imports the frozen v1 evidence model rather than
editing it. Policy B changes only relay eligibility at N <= 9: every authenticated
connection is eligible, regardless of which endpoint initiated it. At larger N,
the policy is outbound-only and therefore identical to Policy A.

Outputs contain new Policy-B cells plus exact Policy-A 30-second reference rows
copied from simulation_results.csv for direct comparison. No production INDRA
module is imported.
"""

from __future__ import annotations

import argparse
import csv
import importlib.util
import json
import math
import random
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
V1_MODEL_PATH = ROOT / "dandelion_topology_model.py"
V1_RESULTS_PATH = ROOT / "simulation_results.csv"
CSV_OUT = ROOT / "simulation_results_v2.csv"
JSON_OUT = ROOT / "simulation_metadata_v2.json"

MIN_ROUND_TIME_MS = 3_000
ROUND_SECONDS = MIN_ROUND_TIME_MS / 1_000
FLAT_EMBARGO_SECONDS = (5, 10, 15, 20, 30)
ROUND_MULTIPLIERS = (1, 2, 3, 4, 5, 10)
ROUND_EMBARGO_SECONDS = tuple(int(k * ROUND_SECONDS) for k in ROUND_MULTIPLIERS)
EMBARGO_SECONDS = tuple(sorted(set(FLAT_EMBARGO_SECONDS) | set(ROUND_EMBARGO_SECONDS)))
VALIDATOR_COUNTS = (4, 8)
ADVERSARY_FRACTIONS = (0.05, 0.10, 0.20, 0.33)
Q = 0.20
RELAY_COUNT = 1
MODEL_SEED_V2 = 0x1D4A_2026_0830_0002
DEFAULT_TRANSACTIONS_PER_CELL = 1_000


def load_v1_model():
    spec = importlib.util.spec_from_file_location("indra_dandelion_model_v1", V1_MODEL_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load frozen v1 model")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


V1 = load_v1_model()


def policy_b_topology(topology):
    """At small N, make every authenticated neighbor relay-eligible."""
    if topology.n > V1.TARGET_OUTBOUND_PEERS + 1:
        return topology
    return V1.Topology(
        n=topology.n,
        edges=topology.edges,
        outbound=topology.neighbors,
        neighbors=topology.neighbors,
        inbound_counts=topology.inbound_counts,
    )


def framing_fields(seconds: int) -> dict[str, object]:
    multiplier = seconds / ROUND_SECONDS
    exact_multiplier = int(multiplier) if multiplier.is_integer() and int(multiplier) in ROUND_MULTIPLIERS else ""
    return {
        "flat_sweep_member": seconds in FLAT_EMBARGO_SECONDS,
        "round_relative_sweep_member": seconds in ROUND_EMBARGO_SECONDS,
        "round_multiplier": exact_multiplier,
    }


def run_policy_b_cell(
    n: int,
    adversary_fraction: float,
    embargo_base: int,
    transactions: int,
) -> dict[str, object]:
    cell_rng = random.Random(V1.stable_seed(
        MODEL_SEED_V2, n, adversary_fraction, Q, RELAY_COUNT, embargo_base
    ))
    adversary_count = V1.coalition_size(n, adversary_fraction)
    outcomes = []
    topology_edges = []
    topology_degrees = []
    topology_zero_eligible = []
    honest_exposed_eligible = []
    per_epoch = math.ceil(transactions / V1.TOPOLOGY_EPOCHS_PER_CELL)

    for _epoch in range(V1.TOPOLOGY_EPOCHS_PER_CELL):
        topology_rng = random.Random(cell_rng.getrandbits(64))
        physical = V1.build_topology(n, topology_rng)
        topology = policy_b_topology(physical)
        relays = V1.choose_epoch_relays(topology, RELAY_COUNT, topology_rng)
        adversaries = set(topology_rng.sample(range(n), adversary_count))
        honest = set(range(n)) - adversaries

        topology_edges.append(len(topology.edges))
        topology_degrees.append(statistics.mean(len(v) for v in topology.neighbors))
        topology_zero_eligible.append(sum(not v for v in topology.outbound) / n)
        honest_exposed_eligible.append(
            sum(any(peer in adversaries for peer in topology.outbound[node]) for node in honest)
            / len(honest)
        )

        for _ in range(per_epoch):
            if len(outcomes) >= transactions:
                break
            source = topology_rng.choice(sorted(honest))
            outcomes.append(V1.simulate_transaction(
                topology, relays, source, adversaries, Q, RELAY_COUNT,
                float(embargo_base), topology_rng,
            ))

    honest_sources = {outcome.source for outcome in outcomes}
    metrics = V1.aggregate_outcomes(outcomes, honest_sources)
    return {
        "evidence_source": "v2-simulated",
        "relay_eligibility_policy": "B_any_authenticated_at_n_le_9",
        "validator_count": n,
        "requested_adversary_fraction": adversary_fraction,
        "adversary_count": adversary_count,
        "realized_adversary_fraction": adversary_count / n,
        "fluff_probability": Q,
        "relay_count": RELAY_COUNT,
        "embargo_base_seconds": embargo_base,
        **framing_fields(embargo_base),
        "transactions": len(outcomes),
        "topology_epochs": V1.TOPOLOGY_EPOCHS_PER_CELL,
        "mean_edges": statistics.mean(topology_edges),
        "mean_degree": statistics.mean(topology_degrees),
        "mean_zero_eligible_node_fraction": statistics.mean(topology_zero_eligible),
        "honest_nodes_with_adversarial_eligible_peer_fraction": statistics.mean(honest_exposed_eligible),
        **metrics,
    }


def load_policy_a_reference_rows() -> list[dict[str, object]]:
    """Copy exact q=.20/one-relay/30s Policy-A evidence from frozen v1 CSV."""
    rows: list[dict[str, object]] = []
    with V1_RESULTS_PATH.open(newline="") as handle:
        for old in csv.DictReader(handle):
            if (
                int(old["validator_count"]) not in VALIDATOR_COUNTS
                or float(old["fluff_probability"]) != Q
                or int(old["relay_count"]) != RELAY_COUNT
                or int(old["embargo_base_seconds"]) != 30
            ):
                continue
            row: dict[str, object] = {
                "evidence_source": "v1-copied-reference",
                "relay_eligibility_policy": "A_outbound_only",
                "validator_count": int(old["validator_count"]),
                "requested_adversary_fraction": float(old["requested_adversary_fraction"]),
                "adversary_count": int(old["adversary_count"]),
                "realized_adversary_fraction": float(old["realized_adversary_fraction"]),
                "fluff_probability": Q,
                "relay_count": RELAY_COUNT,
                "embargo_base_seconds": 30,
                **framing_fields(30),
                "transactions": int(old["transactions"]),
                "topology_epochs": int(old["topology_epochs"]),
                "mean_edges": float(old["mean_edges"]),
                "mean_degree": float(old["mean_degree"]),
                "mean_zero_eligible_node_fraction": float(old["mean_zero_outbound_node_fraction"]),
                "honest_nodes_with_adversarial_eligible_peer_fraction": float(old["honest_nodes_with_adversarial_outbound_fraction"]),
            }
            for key in (
                "first_spy_precision", "first_spy_precision_macro", "first_spy_recall",
                "first_spy_observation_rate", "embargo_fluff_fraction",
                "loop_transaction_rate", "duplicate_stem_rate",
                "mean_propagation_coverage", "full_coverage_fraction",
                "bounded_full_coverage_fraction", "added_latency_p50_seconds",
                "added_latency_p95_seconds", "added_latency_p99_seconds",
                "zero_outbound_tx_fraction", "zero_outbound_events_per_tx",
                "reconnect_substitution_tx_fraction",
            ):
                row[key] = float(old[key])
            rows.append(row)
    if len(rows) != 8:
        raise RuntimeError(f"expected 8 Policy-A reference rows, got {len(rows)}")
    return rows


def run(transactions: int) -> list[dict[str, object]]:
    rows = load_policy_a_reference_rows()
    total = len(VALIDATOR_COUNTS) * len(ADVERSARY_FRACTIONS) * len(EMBARGO_SECONDS)
    index = 0
    for n in VALIDATOR_COUNTS:
        for adversary_fraction in ADVERSARY_FRACTIONS:
            for embargo_base in EMBARGO_SECONDS:
                index += 1
                rows.append(run_policy_b_cell(n, adversary_fraction, embargo_base, transactions))
                if index % 12 == 0:
                    print(f"completed {index}/{total} Policy-B cells", flush=True)
    return rows


def write_outputs(rows: list[dict[str, object]], transactions: int) -> None:
    fields = list(rows[0].keys())
    with CSV_OUT.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    metadata = {
        "model": "INDRA Dandelion++ small-N relay eligibility and embargo sweep v2",
        "seed": MODEL_SEED_V2,
        "policy_a_reference_rows": 8,
        "policy_b_cells": len(rows) - 8,
        "transactions_per_new_cell": transactions,
        "new_transactions": (len(rows) - 8) * transactions,
        "v1_artifacts_modified": False,
        "min_round_time_ms": MIN_ROUND_TIME_MS,
        "target_outbound_peers": V1.TARGET_OUTBOUND_PEERS,
        "small_n_policy_threshold": V1.TARGET_OUTBOUND_PEERS + 1,
        "flat_embargo_seconds": FLAT_EMBARGO_SECONDS,
        "round_multipliers": ROUND_MULTIPLIERS,
        "round_embargo_seconds": ROUND_EMBARGO_SECONDS,
        "deduplicated_embargo_seconds": EMBARGO_SECONDS,
        "validator_counts": VALIDATOR_COUNTS,
        "adversary_fractions": ADVERSARY_FRACTIONS,
        "q": Q,
        "relay_count": RELAY_COUNT,
        "policy_b": "any authenticated connection at N<=9; outbound-only at N>9",
        "inherited_v1_assumptions": "See simulation_metadata.json and imported v1 model",
    }
    JSON_OUT.write_text(json.dumps(metadata, indent=2) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--transactions-per-cell", type=int,
        default=DEFAULT_TRANSACTIONS_PER_CELL,
    )
    args = parser.parse_args()
    if args.transactions_per_cell < 100:
        raise SystemExit("transactions-per-cell must be at least 100")
    rows = run(args.transactions_per_cell)
    write_outputs(rows, args.transactions_per_cell)
    print(json.dumps({
        "rows": len(rows),
        "policy_b_cells": len(rows) - 8,
        "new_transactions": (len(rows) - 8) * args.transactions_per_cell,
        "csv": str(CSV_OUT),
        "metadata": str(JSON_OUT),
    }, indent=2))


if __name__ == "__main__":
    main()
