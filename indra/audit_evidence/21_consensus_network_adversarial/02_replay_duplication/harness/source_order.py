from pathlib import Path

driver = Path("indra-node/src/driver.rs").read_text()

proposal_boundary = driver[driver.index("fn process_proposal("):driver.index("fn process_proposal_internal(")]
required = [
    "block.header.height != next_height",
    "block.header.block_hash()",
    "pending_blocks.contains_key",
    "process_proposal_internal",
]
positions = [proposal_boundary.index(token) for token in required]
assert positions == sorted(positions), (required, positions)

proposal_admission = driver[driver.index("fn process_proposal_internal("):driver.index("fn process_vote(")]
required = [
    "snapshot_for_consensus_height",
    "verify_proposal(",
    "verify_network_block_qc(",
    "project_block_for_roots(",
]
positions = [proposal_admission.index(token) for token in required]
assert positions == sorted(positions), (required, positions)

vote = driver[driver.index("fn process_vote("):driver.index("fn maybe_advance_to_certified_round(")]
required = [
    "let slot_key =",
    "let replay_identity = AcceptedVoteIdentity",
    "seen_round_votes",
    "snapshot_for_consensus_height",
    "verify_vote_authority(",
    "slash_detector.observe_vote",
]
positions = [vote.index(token) for token in required]
assert positions == sorted(positions), (required, positions)

print("PASS: L3-NET-05 and L3-NET-06 trusted replay guards precede expensive admission")
