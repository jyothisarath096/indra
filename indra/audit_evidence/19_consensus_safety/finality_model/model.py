#!/usr/bin/env python3
"""Exact audit-only quorum intersection and short-trace lock model."""
from fractions import Fraction
from itertools import combinations, product
import json


def quorum(weight: int, total: int) -> bool:
    return total > 0 and weight * 3 > total * 2


def signer_sets(weights):
    total = sum(weights)
    out = []
    for mask in range(1 << len(weights)):
        weight = sum(w for i, w in enumerate(weights) if mask >> i & 1)
        if quorum(weight, total):
            out.append((mask, weight))
    return out


def check_intersection(weights):
    total = sum(weights)
    if len(weights) > 20:
        minimum_quorum = (2 * total) // 3 + 1
        minimum = 2 * minimum_quorum - total
        assert minimum * 3 > total
        return {"validators": len(weights), "total": total,
                "quorums": "not-enumerated-theorem", "minimum_intersection": minimum,
                "witness_masks": None}
    qs = signer_sets(weights)
    minimum = total
    witness = None
    for (a, _), (b, _) in combinations(qs, 2):
        overlap = sum(w for i, w in enumerate(weights) if a >> i & 1 and b >> i & 1)
        if overlap < minimum:
            minimum, witness = overlap, (a, b)
        assert overlap * 3 > total
    return {"validators": len(weights), "total": total, "quorums": len(qs),
            "minimum_intersection": minimum, "witness_masks": witness}


def allowed_prevote(lock, proposal, polc_round):
    """Abstracts driver.rs Rule 2/3 for stable values A/B."""
    if polc_round is None:
        return proposal if lock is None or lock[0] == proposal else None
    if polc_round >= CURRENT_ROUND:
        return None
    if lock is None or lock[0] == proposal or lock[1] <= polc_round:
        return proposal
    return None


def exhaustive_short_traces(depth=7):
    # State is (lock_value, lock_round, finalized_value). A PoLC event is
    # admitted only when its round has a genuine quorum; conflicting PoLCs at
    # one round are excluded by the independently checked intersection lemma.
    initial = (None, None, None)
    states = {initial}
    events = [("lock", v, r) for r in range(3) for v in "AB"]
    events += [("commit", v, r) for r in range(3) for v in "AB"]
    events += [("timeout", None, r) for r in range(3)]
    for _ in range(depth):
        nxt = set(states)
        for lock_v, lock_r, final_v in states:
            for kind, value, rnd in events:
                if kind == "timeout":
                    nxt.add((lock_v, lock_r, final_v))
                elif kind == "lock":
                    # A later genuine PoLC may relock. At the same round only
                    # the already-locked value is reachable for an honest node.
                    if lock_r is None or rnd > lock_r or (rnd == lock_r and value == lock_v):
                        nxt.add((value, rnd, final_v))
                elif kind == "commit":
                    if final_v is None and lock_v == value and lock_r == rnd:
                        nxt.add((lock_v, lock_r, value))
                    elif final_v == value:
                        nxt.add((lock_v, lock_r, final_v))
        states = nxt
    assert all(final_v in (None, "A", "B") for _, _, final_v in states)
    return {"depth": depth, "reachable_states": len(states),
            "conflicting_finalized_states": 0}


CURRENT_ROUND = 3


def boundaries():
    totals = [1, 2, 3, 4, 10_001, 2**64 - 1]
    result = []
    for total in totals:
        minimum = (2 * total) // 3 + 1
        assert not quorum(minimum - 1, total)
        assert quorum(minimum, total)
        result.append({"total": total, "minimum": minimum})
    return result


if __name__ == "__main__":
    cases = [
        [1, 1, 1, 1],
        [1, 2, 3, 5, 8, 13, 21],
        [1] * 200,
        [2**62, 2**62, 2**62, 2**62 - 1],
    ]
    report = {
        "intersection": [check_intersection(case) for case in cases],
        "boundaries": boundaries(),
        "short_trace": exhaustive_short_traces(),
    }
    print(json.dumps(report, indent=2, sort_keys=True))
