# Request/Response Abuse & Amplification Audit

## Final disposition

**PASS WITH NON-CRITICAL FINDINGS**. No HIGH/CRITICAL request amplification or unbounded outstanding-state defect was reproduced. One bounded medium finding (L3-NET-10) is recorded.

## Request/response matrix

| Family | Auth | Rate key | Byte budget | Max response | Correlation | Unsolicited behavior |
|---|---|---|---|---|---|---|
| RequestBlocks | authenticated validator; observers use separate 2-burst limiter | validator ID | request count bucket; responses charged to sender's response bucket and bytes | 50 blocks, `MAX_MSG_BYTES` frame cap | serving path has no request token, but range is clamped to 50 and block store bounds | bounded response generation |
| BlockResponse | authenticated validator | validator ID | per-validator bytes + global large-payload bucket | 50 blocks, `MAX_MSG_BYTES` | exact selected peer, requested range, contiguous heights, one outstanding sync request | rejected before expensive state verification |
| RequestQC | authenticated validator | validator ID | count bucket | one QC response, frame cap | response path is point-to-point | missing QC returns no response |
| QCResponse | authenticated validator | validator ID; global frame cap | per-validator bytes | `MAX_MSG_BYTES`; QC decoder also enforces protocol signer/size bounds | height/pending-provisional check; selected-peer correlation absent in sync provisional branch | matching-height unsolicited responses can reach bounded QC verification (L3-NET-10) |

## Bounds and amplification

`RequestBlocks` payload is 16 bytes (21 bytes including discriminator and length
prefix in the canonical wire object); the serving helper clamps each response to
`SYNC_BATCH_SIZE = 50` contiguous blocks and the transport caps a complete message
at `MAX_MSG_BYTES = 14,680,064`. `RequestQC` payload is 8 bytes (13-byte wire
object); a QC response is transport-capped and QC decoding enforces
`MAX_QC_SIGNERS = 200` plus the core QC size bound. These are large but finite
protocol amplifications, and authenticated request count buckets run before the
storage-serving branches.

## Outstanding-state and response handling

Sync keeps one `OutstandingSyncRequest` (selected validator, selected socket,
height range, issue time) with timeout cleanup. `accept_response` requires exact
validator/socket, range, and contiguous heights before consuming it. Disconnect and
timeout clear the binding. Duplicate/unsolicited BlockResponses therefore do not
reach projection or storage commit.

QC responses have a bounded node-wide wire-hash dedup cache (2,048 entries/TTL)
before actor delivery. In the sync provisional-QC branch, however, the node checks
only that a provisional block exists and that the response height matches before
`verify_network_direct_provisional_qc`; it does not compare the sender with the
peer that received `RequestQC`. This permits bounded cross-peer duplicate/invalid
verification and is L3-NET-10.

## L3-NET-10 — unbound provisional-QC response peer correlation

- Severity: **MEDIUM**
- Production reachable: **Yes**, while a provisional sync block exists.
- Reproducer: send an authenticated `QCResponse` for the provisional block height
  from a validator other than the selected/requested peer; the node reaches the
  provisional QC verification branch. Repeat with distinct QC byte strings to avoid
  the 2,048-entry wire-hash cache.
- Effective bound: authenticated validator QCResponse bucket (5 burst, 5/sec),
  per-validator byte bucket, frame cap, and bounded provisional state.
- Impact: bounded extra QC decode/verification work and peer-attribution ambiguity;
  no unrequested state commit was reproduced because the QC must still verify and
  match the provisional block. No consensus safety mutation or unbounded load.
- Recommended next action: independently review whether provisional QC responses
  should require the outstanding request's selected validator/socket. No remediation
  was performed here.

## Validation

Passed relevant network message framing and rate-limit tests, observer request
limiting tests, sync response-binding tests (`response_binding_rejects_unsolicited_wrong_peer_and_out_of_range`), timeout/disconnect cleanup tests, QC response valid/invalid/wrong-height tests, and workspace validation previously run on this tree. Formatting and `git diff --check` pass.

Request-family evidence does not audit outbound/sync cooldown cardinality or generic
connection races, per scope.
