# Phase 3 Step 20B — deterministic GST delayed delivery

`audit_harness_four_validator_gst_delayed_delivery_recovers` uses a deterministic
VecDeque scheduler: one proposal is withheld, remaining deliveries are released
in order, and post-release production vote/QC paths finalize height 1. All four
validators converge on identical canonical roots and production QC verification
passes. This models bounded deterministic delivery only; it makes no claim about
arbitrary real-world latency or permanent asynchrony.

Step 20B.1 withholds the proposal from two validators, advances two complete
pre-GST rounds through production timeout paths, releases the delayed message
after round advancement, and searches production rounds for a genuinely
eligible recovery proposer. Recovery uses the same four drivers and production
vote/QC/finalization paths without reset or recreation.

Step 20B.5 routes every proposer-search nil prevote and nil precommit through
the same bounded logical scheduler. Recovery proposal, prevote, and precommit
broadcasts are each counted as emitted and delivered, and the test asserts
one-to-one broadcast accounting with no post-GST drops.
