# L3-NET-10 Remediation

## Root cause

The sync loop accepted a `QCResponse` whenever a provisional block existed and the response height matched. The response was not correlated with the authenticated validator/socket that supplied the provisional block and received the `RequestQC`.

## Fix

`ProvisionalSyncBlock` already retained `source_validator_id` and `source`. A new `SyncState::accept_provisional_qc_response` performs the cheap binding check before `verify_network_direct_provisional_qc`: provisional state must exist, transport validator ID and socket must match, and response height must match. Wrong-peer, wrong-height, absent, timed-out, disconnected, or replaced provisional state is rejected without consuming the request or invoking QC verification.

The existing cryptographic verifier, rate limits, framing, and BlockResponse correlation are unchanged. L3-NET-10 remains **OPEN, pending independent review**.

## Tests and validation

Added `provisional_qc_response_requires_selected_peer_and_height`, covering wrong peer, wrong height, correct peer/height, and post-clear rejection. Existing BlockResponse binding, timeout, disconnect, QC validation, deduplication, and rate-limit tests remain passing. Full node/network/consensus tests, workspace no-run, formatting, and `git diff --check` passed.

Evidence-completion rerun: `cargo test -p indra-node provisional_qc_response_requires_selected_peer_and_height -- --nocapture` passed; `cargo test -p indra-node` passed; `git diff --check` passed. The complete regression test is present in `indra-node/src/sync.rs` at approximately line 2275 and is reproduced in the focused diff without placeholders.
