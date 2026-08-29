# Phase 3 Step 19E — post-finalization conflict safety

`audit_harness_post_finalization_stale_and_conflicting_traffic_is_safe` finalized one height-1 production proposal with A/B/C precommits (3/4). It then replayed the finalized proposal, valid stale prevote and precommit, and a cryptographically valid conflicting D precommit. A's height, committed tip, QC bytes/height, round, phase, and QC-formation count remained identical; no height-1 pending proposal remained. The conflicting stale vote was handled by the production inbound gate without affecting committed state.

Validation: focused Step 19E test PASS; Step 19D finalization test PASS; workspace no-run PASS; `git diff --check` PASS. No production code was changed.

Step 19E.1 also constructs a second production-signed height-1 proposal before
commit (different timestamp and hash), then delivers it after finalization; the
full baseline remains unchanged and the alternate proposal is not pending.
The existing production regression `set_last_qc_bytes_if_newer_height_ordering`
was rerun and confirms a genuine conflicting same-height QC returns `Err` while
the cached QC remains unchanged.
