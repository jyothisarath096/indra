#!/usr/bin/env python3
"""INDRA-specific Monte Carlo model for Dandelion++ parameter selection.

This is audit evidence, not production code. It models authenticated validator
identities, INDRA's directed connection ownership, bounded connection caps,
colluding first-spy validators, adversarial stem black holes, randomized embargo
fallback, transient link churn, loops, diffusion coverage, and latency relative
to the current immediate-flood behavior.

The output is deterministic for MODEL_SEED. No INDRA production module is
imported; constants are repeated below and checked by the report against source.
"""

from __future__ import annotations

import argparse
import csv
import heapq
import json
import math
import random
import statistics
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parent
CSV_OUT = ROOT / "simulation_results.csv"
JSON_OUT = ROOT / "simulation_metadata.json"

# Current INDRA constants at the audited snapshot.
TARGET_OUTBOUND_PEERS = 8
MAX_INBOUND_PEERS = 64
MAX_PEERS = 80
MIN_ACTIVE_VALIDATORS = 4

VALIDATOR_COUNTS = (4, 8, 20, 50, 100, 200)
ADVERSARY_FRACTIONS = (0.05, 0.10, 0.20, 0.33)
FLUFF_PROBABILITIES = (0.10, 0.15, 0.20)
RELAY_COUNTS = (1, 2)
EMBARGO_BASES_SECONDS = (30, 60, 120)

MODEL_SEED = 0x1D4A_2026_0830
DEFAULT_TRANSACTIONS_PER_CELL = 1_000
TOPOLOGY_EPOCHS_PER_CELL = 10
TRANSIENT_EDGE_DOWN_PROBABILITY = 0.02
ACTIVE_RECONNECT_DELAY_SECONDS = 2.0
ZERO_OUTBOUND_WINDOW_SECONDS = 3.0
PROPAGATION_BOUND_SECONDS = 180.0
LINK_LATENCY_MEDIAN_SECONDS = 0.080
LINK_LATENCY_LOG_SIGMA = 0.35


@dataclass(frozen=True)
class Topology:
    n: int
    edges: tuple[tuple[int, int], ...]  # directed by connection initiator
    outbound: tuple[tuple[int, ...], ...]
    neighbors: tuple[tuple[int, ...], ...]
    inbound_counts: tuple[int, ...]


@dataclass
class TxOutcome:
    source: int
    guess: int | None
    observed: bool
    correct: bool
    embargo_fluff: bool
    looped: bool
    duplicate_stem_receipts: int
    stem_transmissions: int
    coverage_fraction: float
    full_coverage: bool
    bounded_full_coverage: bool
    added_latency_seconds: float
    zero_outbound_events: int
    reconnect_substitutions: int


def stable_seed(*values: object) -> int:
    """Stable non-cryptographic seed combiner independent of hash randomization."""
    state = MODEL_SEED
    for value in values:
        data = str(value).encode()
        for byte in data:
            state ^= byte
            state = (state * 0x100000001B3) & ((1 << 64) - 1)
    return state


def build_topology(n: int, rng: random.Random) -> Topology:
    """Build an INDRA-cap-bounded directed connection graph.

    At N<=TARGET_OUTBOUND_PEERS+1, all pairs connect. Duplicate simultaneous
    connection resolution keeps the lower validator-id endpoint as initiator,
    mirroring tie_break_keep_new's identity ordering. At larger N, validators
    dial shuffled candidates until their outbound target is met, subject to the
    remote inbound cap and both endpoints' total MAX_PEERS cap.
    """
    if n < MIN_ACTIVE_VALIDATORS:
        raise ValueError("validator count is below INDRA's minimum")

    edges: set[tuple[int, int]] = set()
    undirected: set[tuple[int, int]] = set()
    outbound_count = [0] * n
    inbound_count = [0] * n
    degree = [0] * n

    def add_edge(src: int, dst: int) -> bool:
        pair = (min(src, dst), max(src, dst))
        if src == dst or pair in undirected:
            return False
        if outbound_count[src] >= TARGET_OUTBOUND_PEERS:
            return False
        if inbound_count[dst] >= MAX_INBOUND_PEERS:
            return False
        if degree[src] >= MAX_PEERS or degree[dst] >= MAX_PEERS:
            return False
        edges.add((src, dst))
        undirected.add(pair)
        outbound_count[src] += 1
        inbound_count[dst] += 1
        degree[src] += 1
        degree[dst] += 1
        return True

    if n <= TARGET_OUTBOUND_PEERS + 1:
        for low in range(n):
            for high in range(low + 1, n):
                add_edge(low, high)
    else:
        # Randomized dial order approximates peer discovery. Repeated passes let
        # nodes rejected by an already-existing pair try other candidates.
        for _ in range(4):
            order = list(range(n))
            rng.shuffle(order)
            progress = False
            for src in order:
                candidates = [dst for dst in range(n) if dst != src]
                rng.shuffle(candidates)
                for dst in candidates:
                    if outbound_count[src] >= TARGET_OUTBOUND_PEERS:
                        break
                    progress |= add_edge(src, dst)
            if not progress or all(c >= TARGET_OUTBOUND_PEERS for c in outbound_count):
                break

    outbound = [[] for _ in range(n)]
    neighbors = [[] for _ in range(n)]
    for src, dst in sorted(edges):
        outbound[src].append(dst)
        neighbors[src].append(dst)
        neighbors[dst].append(src)
    return Topology(
        n=n,
        edges=tuple(sorted(edges)),
        outbound=tuple(tuple(v) for v in outbound),
        neighbors=tuple(tuple(sorted(v)) for v in neighbors),
        inbound_counts=tuple(inbound_count),
    )


def coalition_size(n: int, requested_fraction: float) -> int:
    # Nearest representable identity count, half upward, with at least one spy.
    return max(1, min(n - 1, int(math.floor(n * requested_fraction + 0.5))))


def edge_key(a: int, b: int) -> tuple[int, int]:
    return (min(a, b), max(a, b))


def quantile(values: list[float], p: float) -> float:
    if not values:
        return math.nan
    ordered = sorted(values)
    position = (len(ordered) - 1) * p
    low = int(math.floor(position))
    high = int(math.ceil(position))
    if low == high:
        return ordered[low]
    return ordered[low] * (high - position) + ordered[high] * (position - low)


def shortest_diffusion(
    topology: Topology,
    start: int,
    start_time: float,
    active_edges: set[tuple[int, int]],
    latencies: dict[tuple[int, int], float],
    adversaries: set[int],
) -> dict[int, float]:
    """Shortest arrival times; adversaries receive but refuse to forward."""
    arrivals = {start: start_time}
    heap = [(start_time, start)]
    while heap:
        time, node = heapq.heappop(heap)
        if time != arrivals[node]:
            continue
        if node in adversaries and node != start:
            continue
        for peer in topology.neighbors[node]:
            key = edge_key(node, peer)
            if key not in active_edges:
                continue
            candidate = time + latencies[key]
            if candidate < arrivals.get(peer, math.inf):
                arrivals[peer] = candidate
                heapq.heappush(heap, (candidate, peer))
    return arrivals


def choose_epoch_relays(topology: Topology, relay_count: int, rng: random.Random) -> tuple[tuple[int, ...], ...]:
    selected: list[tuple[int, ...]] = []
    for node in range(topology.n):
        candidates = list(topology.outbound[node])
        rng.shuffle(candidates)
        selected.append(tuple(candidates[:relay_count]))
    return tuple(selected)


def simulate_transaction(
    topology: Topology,
    relays: tuple[tuple[int, ...], ...],
    source: int,
    adversaries: set[int],
    q: float,
    relay_count: int,
    embargo_base: float,
    rng: random.Random,
) -> TxOutcome:
    all_edge_keys = {edge_key(a, b) for a, b in topology.edges}
    active_edges = {
        key for key in all_edge_keys if rng.random() >= TRANSIENT_EDGE_DOWN_PROBABILITY
    }
    latencies = {
        key: rng.lognormvariate(math.log(LINK_LATENCY_MEDIAN_SECONDS), LINK_LATENCY_LOG_SIGMA)
        for key in all_edge_keys
    }

    baseline = shortest_diffusion(topology, source, 0.0, active_edges, latencies, adversaries)
    baseline_completion = max(baseline.values()) if len(baseline) == topology.n else PROPAGATION_BOUND_SECONDS

    # Epoch-selected stems plus active-reconnect substitution from any currently
    # live outbound connection if a selected relay is unavailable.
    zero_outbound_events = 0
    reconnect_substitutions = 0
    seen_stem: set[int] = {source}
    stem_transmissions = 0
    duplicate_stem_receipts = 0
    looped = False
    first_spy_time = math.inf
    first_spy_predecessor: int | None = None
    fluffed = False
    fluff_time = math.inf
    fluff_node: int | None = None
    embargo_fluff = False
    event_counter = 0
    events: list[tuple[float, int, str, int, int | None]] = []

    def schedule(time: float, kind: str, node: int, sender: int | None = None) -> None:
        nonlocal event_counter
        event_counter += 1
        heapq.heappush(events, (time, event_counter, kind, node, sender))

    def set_fluff(time: float, node: int, via_embargo: bool) -> None:
        nonlocal fluffed, fluff_time, fluff_node, embargo_fluff
        if not fluffed or time < fluff_time:
            fluffed = True
            fluff_time = time
            fluff_node = node
            embargo_fluff = via_embargo

    def forward_stem(node: int, now: float) -> None:
        nonlocal stem_transmissions, zero_outbound_events, reconnect_substitutions
        chosen = [peer for peer in relays[node] if edge_key(node, peer) in active_edges]
        delay = 0.0
        if len(chosen) < min(relay_count, len(topology.outbound[node])):
            substitutes = [
                peer for peer in topology.outbound[node]
                if edge_key(node, peer) in active_edges and peer not in chosen
            ]
            rng.shuffle(substitutes)
            needed = relay_count - len(chosen)
            added = substitutes[:needed]
            if added:
                reconnect_substitutions += 1
                chosen.extend(added)
                delay = ACTIVE_RECONNECT_DELAY_SECONDS
        if not chosen:
            zero_outbound_events += 1
            schedule(now + ZERO_OUTBOUND_WINDOW_SECONDS, "zero_fluff", node)
            return
        for peer in chosen[:relay_count]:
            stem_transmissions += 1
            schedule(now + delay + latencies[edge_key(node, peer)], "stem", peer, node)

    # Every honest stem holder, including the origin, has an independent
    # exponential embargo. Local origins always stem and never take the q coin.
    schedule(rng.expovariate(1.0 / embargo_base), "embargo", source)
    forward_stem(source, 0.0)

    while events:
        now, _, kind, node, sender = heapq.heappop(events)
        if now > PROPAGATION_BOUND_SECONDS:
            break
        if kind == "embargo":
            if not fluffed:
                set_fluff(now, node, True)
                break
            continue
        if kind == "zero_fluff":
            if not fluffed:
                set_fluff(now, node, False)
                break
            continue
        if kind != "stem" or sender is None:
            continue
        if node in adversaries:
            if now < first_spy_time:
                first_spy_time = now
                first_spy_predecessor = sender
            # Worst-case colluding validator black-holes stem traffic.
            continue
        if node in seen_stem:
            duplicate_stem_receipts += 1
            looped = True
            set_fluff(now, node, False)
            break
        seen_stem.add(node)
        schedule(now + rng.expovariate(1.0 / embargo_base), "embargo", node)
        if rng.random() < q:
            set_fluff(now, node, False)
            break
        forward_stem(node, now)

    if not fluffed:
        # The bounded simulation horizon is also a fail-closed coverage bound.
        set_fluff(PROPAGATION_BOUND_SECONDS, source, True)

    assert fluff_node is not None
    arrivals = shortest_diffusion(
        topology, fluff_node, fluff_time, active_edges, latencies, adversaries
    )
    for adversary in adversaries:
        if adversary in arrivals:
            # First-spy records the honest predecessor on the shortest diffusion
            # path only if no stem observation arrived earlier.
            arrival = arrivals[adversary]
            if arrival < first_spy_time:
                predecessor = min(
                    (
                        peer for peer in topology.neighbors[adversary]
                        if peer in arrivals
                        and peer not in adversaries
                        and abs(arrivals[peer] + latencies[edge_key(peer, adversary)] - arrival) < 1e-9
                    ),
                    default=fluff_node,
                )
                first_spy_time = arrival
                first_spy_predecessor = predecessor

    completion = max(arrivals.values()) if len(arrivals) == topology.n else PROPAGATION_BOUND_SECONDS
    coverage = len(arrivals) / topology.n
    return TxOutcome(
        source=source,
        guess=first_spy_predecessor,
        observed=first_spy_predecessor is not None,
        correct=first_spy_predecessor == source,
        embargo_fluff=embargo_fluff,
        looped=looped,
        duplicate_stem_receipts=duplicate_stem_receipts,
        stem_transmissions=stem_transmissions,
        coverage_fraction=coverage,
        full_coverage=len(arrivals) == topology.n,
        bounded_full_coverage=len(arrivals) == topology.n and completion <= PROPAGATION_BOUND_SECONDS,
        added_latency_seconds=max(0.0, completion - baseline_completion),
        zero_outbound_events=zero_outbound_events,
        reconnect_substitutions=reconnect_substitutions,
    )


def aggregate_outcomes(outcomes: list[TxOutcome], honest_nodes: set[int]) -> dict[str, float]:
    observed = [outcome for outcome in outcomes if outcome.observed]
    correct = [outcome for outcome in observed if outcome.correct]

    # Paper-style first-spy metrics. Micro precision is literally the fraction
    # of adversarial guesses that are correct. Macro recall averages, over honest
    # sources, the fraction of each source's transactions correctly identified.
    precision = len(correct) / len(observed) if observed else 0.0
    by_source_total: dict[int, int] = defaultdict(int)
    by_source_correct: dict[int, int] = defaultdict(int)
    by_guess_total: dict[int, int] = defaultdict(int)
    by_guess_correct: dict[int, int] = defaultdict(int)
    for outcome in outcomes:
        by_source_total[outcome.source] += 1
        if outcome.correct:
            by_source_correct[outcome.source] += 1
        if outcome.guess is not None:
            by_guess_total[outcome.guess] += 1
            if outcome.correct:
                by_guess_correct[outcome.guess] += 1
    recall_macro = statistics.mean(
        by_source_correct[node] / by_source_total[node]
        for node in honest_nodes if by_source_total[node]
    )
    precision_macro = statistics.mean(
        by_guess_correct[node] / by_guess_total[node]
        for node in honest_nodes if by_guess_total[node]
    ) if by_guess_total else 0.0

    latencies = [outcome.added_latency_seconds for outcome in outcomes]
    stem_tx = sum(outcome.stem_transmissions for outcome in outcomes)
    dup = sum(outcome.duplicate_stem_receipts for outcome in outcomes)
    return {
        "first_spy_precision": precision,
        "first_spy_precision_macro": precision_macro,
        "first_spy_recall": recall_macro,
        "first_spy_observation_rate": len(observed) / len(outcomes),
        "embargo_fluff_fraction": sum(o.embargo_fluff for o in outcomes) / len(outcomes),
        "loop_transaction_rate": sum(o.looped for o in outcomes) / len(outcomes),
        "duplicate_stem_rate": dup / stem_tx if stem_tx else 0.0,
        "mean_propagation_coverage": statistics.mean(o.coverage_fraction for o in outcomes),
        "full_coverage_fraction": sum(o.full_coverage for o in outcomes) / len(outcomes),
        "bounded_full_coverage_fraction": sum(o.bounded_full_coverage for o in outcomes) / len(outcomes),
        "added_latency_p50_seconds": quantile(latencies, 0.50),
        "added_latency_p95_seconds": quantile(latencies, 0.95),
        "added_latency_p99_seconds": quantile(latencies, 0.99),
        "zero_outbound_tx_fraction": sum(o.zero_outbound_events > 0 for o in outcomes) / len(outcomes),
        "zero_outbound_events_per_tx": sum(o.zero_outbound_events for o in outcomes) / len(outcomes),
        "reconnect_substitution_tx_fraction": sum(o.reconnect_substitutions > 0 for o in outcomes) / len(outcomes),
    }


def run_cell(
    n: int,
    adversary_fraction: float,
    q: float,
    relay_count: int,
    embargo_base: int,
    transactions: int,
) -> dict[str, object]:
    cell_rng = random.Random(stable_seed(n, adversary_fraction, q, relay_count, embargo_base))
    adversary_count = coalition_size(n, adversary_fraction)
    outcomes: list[TxOutcome] = []
    topology_degrees: list[float] = []
    topology_outbound_zero: list[float] = []
    topology_edges: list[int] = []
    honest_exposed_outbound: list[float] = []
    honest_exposed_inbound: list[float] = []

    per_epoch = math.ceil(transactions / TOPOLOGY_EPOCHS_PER_CELL)
    for epoch in range(TOPOLOGY_EPOCHS_PER_CELL):
        topology_rng = random.Random(cell_rng.getrandbits(64))
        topology = build_topology(n, topology_rng)
        relays = choose_epoch_relays(topology, relay_count, topology_rng)

        # Sample colluders independently per epoch. In a directed topology they
        # can appear on either inbound or outbound edges of honest validators.
        adversaries = set(topology_rng.sample(range(n), adversary_count))
        honest = set(range(n)) - adversaries
        inbound_from: list[list[int]] = [[] for _ in range(n)]
        for initiator, responder in topology.edges:
            inbound_from[responder].append(initiator)
        topology_degrees.append(statistics.mean(len(v) for v in topology.neighbors))
        topology_outbound_zero.append(sum(not v for v in topology.outbound) / n)
        topology_edges.append(len(topology.edges))
        honest_exposed_outbound.append(
            sum(any(peer in adversaries for peer in topology.outbound[node]) for node in honest)
            / len(honest)
        )
        honest_exposed_inbound.append(
            sum(any(peer in adversaries for peer in inbound_from[node]) for node in honest)
            / len(honest)
        )

        for _ in range(per_epoch):
            if len(outcomes) >= transactions:
                break
            source = topology_rng.choice(sorted(honest))
            outcomes.append(simulate_transaction(
                topology, relays, source, adversaries, q, relay_count,
                float(embargo_base), topology_rng,
            ))

    # Recall must be aggregated across all honest identities appearing in the
    # epoch samples; every outcome source is honest by construction.
    honest_sources = {outcome.source for outcome in outcomes}
    metrics = aggregate_outcomes(outcomes, honest_sources)
    row: dict[str, object] = {
        "validator_count": n,
        "requested_adversary_fraction": adversary_fraction,
        "adversary_count": adversary_count,
        "realized_adversary_fraction": adversary_count / n,
        "fluff_probability": q,
        "relay_count": relay_count,
        "embargo_base_seconds": embargo_base,
        "transactions": len(outcomes),
        "topology_epochs": TOPOLOGY_EPOCHS_PER_CELL,
        "mean_edges": statistics.mean(topology_edges),
        "mean_degree": statistics.mean(topology_degrees),
        "mean_zero_outbound_node_fraction": statistics.mean(topology_outbound_zero),
        "honest_nodes_with_adversarial_outbound_fraction": statistics.mean(honest_exposed_outbound),
        "honest_nodes_with_adversarial_inbound_fraction": statistics.mean(honest_exposed_inbound),
        **metrics,
    }
    return row


def run(transactions: int) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    total = (
        len(VALIDATOR_COUNTS) * len(ADVERSARY_FRACTIONS)
        * len(FLUFF_PROBABILITIES) * len(RELAY_COUNTS)
        * len(EMBARGO_BASES_SECONDS)
    )
    index = 0
    for n in VALIDATOR_COUNTS:
        for adversary_fraction in ADVERSARY_FRACTIONS:
            for q in FLUFF_PROBABILITIES:
                for relay_count in RELAY_COUNTS:
                    for embargo_base in EMBARGO_BASES_SECONDS:
                        index += 1
                        rows.append(run_cell(
                            n, adversary_fraction, q, relay_count,
                            embargo_base, transactions,
                        ))
                        if index % 24 == 0:
                            print(f"completed {index}/{total} cells", flush=True)
    return rows


def write_outputs(rows: list[dict[str, object]], transactions: int) -> None:
    with CSV_OUT.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    metadata = {
        "model": "INDRA Dandelion++ validator-topology Monte Carlo",
        "seed": MODEL_SEED,
        "cells": len(rows),
        "transactions_per_cell": transactions,
        "total_transactions": len(rows) * transactions,
        "topology_epochs_per_cell": TOPOLOGY_EPOCHS_PER_CELL,
        "constants": {
            "target_outbound_peers": TARGET_OUTBOUND_PEERS,
            "max_inbound_peers": MAX_INBOUND_PEERS,
            "max_peers": MAX_PEERS,
            "min_active_validators": MIN_ACTIVE_VALIDATORS,
        },
        "sweep": {
            "validator_counts": VALIDATOR_COUNTS,
            "adversary_fractions": ADVERSARY_FRACTIONS,
            "fluff_probabilities": FLUFF_PROBABILITIES,
            "relay_counts": RELAY_COUNTS,
            "embargo_base_seconds": EMBARGO_BASES_SECONDS,
        },
        "assumptions": {
            "colluding_stem_behavior": "observe first predecessor then black-hole",
            "transient_edge_down_probability_per_transaction": TRANSIENT_EDGE_DOWN_PROBABILITY,
            "active_reconnect_delay_seconds": ACTIVE_RECONNECT_DELAY_SECONDS,
            "zero_outbound_window_seconds": ZERO_OUTBOUND_WINDOW_SECONDS,
            "propagation_bound_seconds": PROPAGATION_BOUND_SECONDS,
            "link_latency_distribution": "independent lognormal per edge/transaction",
            "link_latency_median_seconds": LINK_LATENCY_MEDIAN_SECONDS,
            "link_latency_log_sigma": LINK_LATENCY_LOG_SIGMA,
            "embargo_distribution": "independent exponential with named mean/base",
            "adversarial_diffusion_behavior": "receive but do not forward",
            "small_n_topology": "complete; lower identity initiates duplicate-resolved edge",
        },
        "metric_definitions": {
            "first_spy_precision": "correct adversarial source guesses / all adversarial guesses",
            "first_spy_recall": "macro-average across honest sources of correctly guessed transactions / transactions originated",
            "duplicate_stem_rate": "duplicate honest stem receipts / stem transmissions",
            "added_latency": "Dandelion completion minus immediate-flood completion on the same active graph and edge latencies",
        },
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
        "transactions": len(rows) * args.transactions_per_cell,
        "csv": str(CSV_OUT),
        "metadata": str(JSON_OUT),
    }, indent=2))


if __name__ == "__main__":
    main()
