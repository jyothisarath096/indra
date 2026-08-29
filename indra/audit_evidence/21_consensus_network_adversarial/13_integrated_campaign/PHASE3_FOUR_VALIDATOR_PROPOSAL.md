# Four-validator production proposal distribution

Implemented `audit_harness_four_validators_accept_one_production_proposal`.
The test uses `shared_four_validator_fixture()`, obtains the production
proposer election for height 1/round 0, selects the legitimately eligible
validator, builds one proposal through `NodeEngine::propose`, and routes the
exact envelope through `DriverEvent::InboundBlock` to all four drivers.

All four stage the same block hash/value hash/proposer identity; committed
height remains zero. Exact replay to the receiver is not separately expanded
here because this pass is limited to proposal distribution. No votes, QC, or
finalization were performed.

The test now records the complete eligible proposer set, selects deterministically
from that production-derived set, replays the exact proposal through the inbound
path, verifies proposal-admission metrics are unchanged, and removes all four
fixture directories during cleanup.
