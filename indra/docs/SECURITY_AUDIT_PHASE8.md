# INDRA Security Audit — Phase 8: RPC and API Security

## Summary Table

| ID | Component | Finding | Severity | Status |
|----|-----------|---------|----------|--------|
| API-01 | RPC input | RPC parameter/method and staking admission validation hardened | MEDIUM | FIXED |
| API-02 | RPC input | Transaction submission uses validated mempool admission | SAFE | VERIFIED |
| API-03 | RPC input | Governance op admission uses full validation | SAFE | VERIFIED |
| API-04 | Info leak | No RPC endpoint exposes private keys or raw secret material | SAFE | VERIFIED |
| API-05 | Info leak | Public UTXO/address scans superseded by authorized legacy scan RPC | MEDIUM | FIXED |
| API-06 | Info leak | Public peer endpoint exposes validator peer topology/IPs | HIGH | FIXED |
| API-07 | Resource | No RPC rate limiting or connection concurrency limit | HIGH | FIXED |
| API-08 | Resource | Oversized bodies, non-POST methods, and batch requests rejected | MEDIUM | FIXED |
| API-09 | Resource | RPC handlers run under consensus driver lock and can delay consensus | HIGH | FIXED |
| API-10 | FFI | Caller-provided C strings now use bounded NUL scan | LOW | FIXED |
| API-11 | FFI | FFI key-material handling documented and local copies zeroized where feasible | MEDIUM | FIXED |
| API-12 | FFI | FFI panic safety is consistently guarded with `catch_unwind` | SAFE | VERIFIED |
| API-13 | CLI | CLI exposes key material via argv and writes plaintext `keys.json` with default permissions | HIGH | FIXED |
| API-14 | CLI | RPC enablement/config binding and exposure warnings added | MEDIUM | FIXED |
| API-15 | CLI | No shell-command construction found in CLI paths | SAFE | VERIFIED |
| API-16 | Cross-cutting | Wildcard CORS removed; allowlist-based origin reflection added | MEDIUM | FIXED |

Severity: CRITICAL / HIGH / MEDIUM / LOW / INFO / SAFE

## Detailed Findings

### API-01 — RPC parameter validation completeness

**Status:** FIXED  
**Severity:** MEDIUM

The RPC layer performs some important validation, but it was not uniform across endpoints. Hex transaction/governance/staking payloads were decoded before reaching application logic, and transaction/governance admissions already routed through validated paths. The remaining gaps were:

- The hand-written JSON-RPC parser in `indra-rpc/src/types.rs` accepts missing or non-`2.0` `jsonrpc` values and does not implement a strict JSON parser.
- Invalid address lengths for the legacy address-scan methods returned zero/empty results instead of a clean invalid-parameter error.
- Staking operations admitted through RPC called `NodeEngine::add_staking_op`, which only ran `validate_structure()` plus duplicate nonce checks before adding the op to the staking mempool.
- The inline node RPC handler accepted any non-OPTIONS HTTP method with a body; it did not require POST.

**Attack scenario:** An attacker sends large volumes of structurally valid but state-invalid staking operations. They can enter the staking mempool and be selected into candidate blocks, wasting proposer/block-validation work before final rejection.

**Fix implemented:** `NodeEngine::add_staking_op` now validates staking operations against a scratch clone of current state via `apply_staking_op` before mempool insertion. The legacy address-scan challenge path now rejects malformed address parameters with JSON-RPC invalid-params errors. The live node and generic RPC handlers enforce POST/OPTIONS semantics. Regression coverage: `staking_mempool_rejects_structurally_invalid_staking_op_at_admission`, `rpc_legacy_scan_challenge_returns_error_for_invalid_address`, and `rpc_rejects_non_post_method`.

**Residual note:** The minimal hand-written JSON parser remains intentionally small; it is now bounded and stricter at the transport/method layer, but a production RPC stack should eventually use a full HTTP/JSON implementation.

### API-02 — Transaction submission validation

**Status:** VERIFIED  
**Severity:** SAFE

Transaction submission through the live node RPC path decodes `TransactionV1` and calls `mempool.submit_validated(tx.clone(), &state)` before gossiping (`indra-node/src/bin/node.rs:2765`). The trait implementation used by the generic RPC server also routes to `submit_validated` (`indra-node/src/lib.rs:140`).

This verifies signatures, UTXO existence, value arithmetic, nullifiers, and other transaction state rules added in Phase 2 before mempool admission.

**Residual note:** The RPC layer relies on the HTTP body cap for transaction size; API-08 covers the body-limit behavior.

### API-03 — Governance op admission validation

**Status:** VERIFIED  
**Severity:** SAFE

Governance submission through RPC calls `NodeEngine::add_governance_op` (`indra-node/src/bin/node.rs:2740`, `indra-node/src/lib.rs:130`). That function calls `validate_governance_op(&self.state, &op, current_epoch, &self.state.chain_id)` before inserting into the governance mempool (`indra-node/src/engine.rs:270`).

This covers signature, nonce, signer eligibility, proposal/action state, and current governance parameters.

### API-04 — Sensitive data in RPC responses

**Status:** VERIFIED  
**Severity:** SAFE

No RPC endpoint inspected returns validator private keys, VRF secret keys, BLS seeds, ML-DSA private keys, mnemonics, or raw wallet secret material. Public validator endpoints return public keys and staking metadata only.

**Residual note:** Error messages do include validation failure strings. They are useful operationally and did not expose secrets in the inspected paths, but should still be reviewed before exposing RPC to untrusted networks.

### API-05 — UTXO and transaction privacy

**Status:** FIXED; superseded by later legacy-scan authorization hardening  
**Severity:** MEDIUM

The original finding was that the RPC layer exposed address-indexed UTXO data without proving that the caller owns the address. The old `indra_getBalance`/`indra_getUtxos` methods scanned all UTXOs for any 32-byte address hash supplied by the caller. `indra_getUtxoProof` also allows generic UTXO membership probing by ID.

This does not expose blinding factors or private keys, but it weakens wallet privacy and makes balance/UTXO surveillance easy for any known address.

**Attack scenario:** An external caller who learns a validator/user address can repeatedly query address-indexed scan endpoints to track balances, UTXO churn, lock heights, and output lineage without authentication or ownership proof.

**Current fix implemented:** The old unauthenticated public scan methods have been removed from dispatch/read-only classification and replaced by `indra_getLegacyScanChallenge`, `indra_getLegacyUtxosAuthorized`, and `indra_getLegacyBalanceAuthorized`. The authorized methods require a signed ownership challenge from the address's hybrid spend key before returning address-specific UTXO/balance data. The live node keeps a separate per-IP UTXO-scan limiter (`UTXO_SCAN_RATE_PER_MIN = 10`) on the authorized scan endpoints. Regression coverage: `legacy_utxo_and_balance_scans_require_valid_ownership_auth`, `old_public_utxo_scan_methods_are_removed_from_public_rpc`, and `utxo_query_is_rate_limited_independently`.

**Residual limitation:** This is RPC-layer hardening only. OutputV1 still exposes owner/value metadata to anyone reading raw chain data or running a full node. Full node-level transaction privacy remains deferred to OutputV2 pending external post-quantum cryptography review.

### API-06 — Validator identity and topology exposure

**Status:** FIXED  
**Severity:** HIGH

`indra_getPeers` previously returned connected validator peer addresses and counts (`indra-rpc/src/handlers.rs:482`). The live node passed `gossip.connected_addrs()` into the public RPC response while holding the driver lock (`indra-node/src/bin/node.rs:2692`).

This endpoint exposes live network topology and validator IP information to anyone who can reach RPC. That materially helps eclipse, DDoS, and peer-targeting attacks identified in Phase 6.

**Attack scenario:** An attacker queries every reachable validator RPC port, builds the validator connection graph, identifies sparse or central peer links, then targets those IPs with network-level disruption.

**Fix implemented:** Public `indra_getPeers` now returns aggregate counts only (`peer_count`, `target_peers`, `discovered_count`, `observer_peer_count`) and does not include concrete peer IPs, validator IDs, or connection-direction details. Regression coverage: `get_peers_public_returns_only_count`.

**Residual note:** A future admin-only topology endpoint can be added behind a real admin token if operators need full peer details. The safe default is now no public topology disclosure.

### API-07 — RPC rate limiting

**Status:** FIXED  
**Severity:** HIGH

No per-IP, per-method, global, or expensive-endpoint rate limiter was found in the live node RPC path. The node accepted each TCP connection and spawned an unbounded OS thread (`indra-node/src/bin/node.rs:2082`). The generic `indra-rpc` server bound a listener but had no rate limiting either (`indra-rpc/src/server.rs:63`).

Expensive read endpoints include UTXO scans, delegation/staking queries, governance queries, and peer topology queries. Mutating endpoints also decode and validate user-provided payloads.

**Attack scenario:** A single client opens many concurrent RPC connections and repeatedly calls authorized legacy UTXO scans or mutation endpoints with large-but-under-limit bodies. This consumes threads, memory, validation CPU, and the consensus driver mutex.

**Fix implemented:** The live node RPC listener now enforces `MAX_RPC_CONNECTIONS = 64` with atomic connection accounting and drops excess connections before spawning handlers. A shared per-IP RPC token bucket (`RPC_RATE_LIMIT_PER_SEC = 20`, `RPC_RATE_BURST = 40`) rejects excess requests with HTTP 429. Regression coverage: `rpc_connection_limit_is_enforced` and `rpc_per_ip_rate_limit_returns_429`.

**Residual note:** This is a connection/request-level limiter, not a full per-method cost model. Expensive endpoint-specific quotas remain a recommended follow-up under API-01/API-08/API-14.

### API-08 — Request size limits

**Status:** FIXED  
**Severity:** MEDIUM

RPC body reads previously allocated `content_length.min(1_048_576)` bytes and parsed whatever was read (`indra-node/src/bin/node.rs:2675`, `indra-rpc/src/server.rs:145`, `indra-rpc/src/server.rs:242`). If `Content-Length` exceeded 1 MiB, the server read and parsed only the first 1 MiB rather than rejecting the request.

There is also no strict method enforcement beyond `OPTIONS`, and no explicit JSON-RPC batch support or batch rejection beyond parser failure.

**Attack scenario:** A client claims a very large `Content-Length`, sends a crafted first 1 MiB prefix, and leaves remaining bytes unread until connection close. Combined with unbounded threads, this is a low-cost resource exhaustion vector.

**Fix implemented:** Oversized request bodies are now rejected before allocation/partial parsing using `MAX_RPC_BODY_BYTES = 1_048_576` in both the generic RPC server and live node inline handler. Non-POST/non-OPTIONS methods are rejected with HTTP 405, and JSON-RPC batch request bodies are explicitly rejected as unsupported. Regression coverage: `rpc_rejects_oversized_body_before_allocation`, `rpc_rejects_non_post_method`, and `rpc_rejects_batch_requests`.

### API-09 — RPC and consensus isolation

**Status:** FIXED  
**Severity:** HIGH

The live node RPC handler previously locked the consensus driver before building `NodeState`, dispatching read handlers, decoding mutation payloads, and validating/admitting transactions/governance/staking ops (`indra-node/src/bin/node.rs:2692`). Several handlers perform full-state scans, including UTXO balance and UTXO-list queries (`indra-rpc/src/handlers.rs:429`, `indra-rpc/src/handlers.rs:447`).

Because the same driver lock is used by consensus processing, a slow or repeated RPC query can delay consensus progress.

**Attack scenario:** A public client repeatedly calls full-UTXO-scan endpoints while consensus needs the driver lock for propose/vote/commit processing. Even if each request eventually completes, aggregate contention can cause missed timeouts, delayed votes, and liveness degradation.

**Fix implemented:** The live node now builds a detached `RpcSnapshot` under a brief driver lock, then releases the lock before dispatching read-only RPC handlers. Mutation payloads are decoded before acquiring the driver lock; transaction gossip is broadcast after the mempool admission lock is released. Regression coverage: `rpc_read_state_is_consistent_snapshot`.

### API-10 — FFI input validation and memory safety

**Status:** FIXED  
**Severity:** LOW

The FFI layer is generally well hardened:

- Fixed-size byte inputs check null pointers before `from_raw_parts`.
- Transaction and operation outputs are bounded by constants such as `MAX_TX_BYTES`, `MAX_UTXO_COUNT`, and `INDRA_OP_HEX_MAX_BYTES` (`indra-ffi/src/lib.rs:43`, `indra-ffi/src/lib.rs:53`, `indra-ffi/src/lib.rs:55`).
- Functions are marked `unsafe extern "C"` where appropriate.

The remaining issue is C string handling: mnemonic, chain ID, governance title/description/action JSON, and similar strings use `CStr::from_ptr` (`indra-ffi/src/lib.rs:246`, `indra-ffi/src/staking.rs:54`, `indra-ffi/src/governance.rs:66`, `indra-ffi/src/governance.rs:232`). That requires the caller to provide a valid NUL-terminated string; there is no bounded `(ptr, len)` variant for these inputs.

**Attack scenario:** A buggy or malicious mobile caller passes a non-NUL-terminated pointer. Rust will scan until a NUL byte is found, which can read beyond the intended buffer. This is inside an unsafe FFI contract, so it is not a remote node exploit, but it is still wallet API hardening debt.

**Fix implemented:** All production `CStr::from_ptr` uses for caller-provided FFI inputs were replaced with a bounded C-string scanner (`MAX_CSTR_LEN = 4096`). Strings without a NUL byte within the limit are rejected cleanly instead of scanning unbounded memory. This preserves the existing Swift-facing ABI while adding a bounded read. Regression coverage: `ffi_bounded_cstr_rejects_string_without_nul_in_limit` and `ffi_bounded_cstr_accepts_valid_short_string`.

### API-11 — Key material handling in FFI

**Status:** FIXED  
**Severity:** MEDIUM

The FFI keygen API returns private key material in `IndraKeyPair`, including classical seed, PQ private key, BLS seed, and VRF seed (`indra-ffi/src/lib.rs:67`). Phase 1 added explicit zeroizers (`indra_zeroize_keypair`, `indra_zeroize_tx_result`) at `indra-ffi/src/lib.rs:148` and `indra-ffi/src/lib.rs:161`, and tests verify they clear sensitive fields.

However, zeroization is caller-driven. If the iOS/Mac caller forgets to call the zeroizer, key material remains in app memory. Some local copies inside FFI helper functions are ordinary stack arrays and are not consistently zeroized after use.

**Attack scenario:** A wallet crash dump or memory disclosure bug in the host app recovers `IndraKeyPair` or transaction-building seed buffers after the app finished using them.

**Fix implemented:** The public C header now marks `IndraKeyPair` secret fields as private key material and documents `indra_zeroize_keypair()` as mandatory. Local FFI copies of wallet seed/PQ secret material are zeroed after use where feasible, including keygen/transaction/staking helper paths. Existing zeroizer coverage remains in place. Regression coverage: `keypair_zeroize_clears_private_fields`, `ffi_intermediate_key_buffers_are_zeroized`.

**Remaining mainnet work:** Opaque key handles are the default signing API, but raw private-key crossing has not been eliminated repository-wide. The optional `legacy_raw_keys` feature still compiles classical/PQ/VRF raw-key APIs, and the default payment API can still return an encoded private payment keypair. Treat complete removal or an explicit disposition of those surfaces as Phase 5 work; the existence of the handle API alone does not close this item.

### API-12 — FFI panic safety

**Status:** VERIFIED  
**Severity:** SAFE

The FFI crate denies `unwrap`, `expect`, and `panic` via crate-level lints (`indra-ffi/src/lib.rs:14`). Exported functions inspected use `catch_unwind` around Rust logic before returning integer error codes, e.g. keygen, mnemonic, transaction, staking, and governance builders (`indra-ffi/src/lib.rs:183`, `indra-ffi/src/staking.rs:106`, `indra-ffi/src/governance.rs:167`).

No panic-across-FFI path was found in the inspected exported functions.

### API-13 — CLI key material

**Status:** FIXED  
**Severity:** HIGH

The CLI previously exposed sensitive key material through several channels:

- `indra-keygen --recover <phrase>` and `--passphrase <phrase>` read secrets from command-line arguments (`indra-cli/src/bin/keygen.rs:10`, `indra-cli/src/bin/keygen.rs:14`). These can appear in shell history and process listings.
- `keys.json` stores private seeds and the ML-DSA private key in plaintext (`indra-cli/src/keygen.rs:90`).
- `indra-keygen` writes `keys.json` via `std::fs::write` without setting restrictive permissions (`indra-cli/src/bin/keygen.rs:60`).
- `generate_from_passphrase` is explicitly documented as not cryptographically secure and derives keys from a passphrase using domain-separated SHA-256, not a password KDF (`indra-cli/src/keygen.rs:254`).

Printing a newly generated mnemonic once is intentional recovery UX and includes clear warnings (`indra-cli/src/bin/keygen.rs:65`), but recovery and passphrase input via argv are unsafe.

**Attack scenario:** On a shared validator host, another local user or monitoring agent reads process arguments while `indra-keygen --recover` is running, or reads a world/group-readable `keys.json` created under a permissive umask.

**Fix implemented:** `indra-keygen` now rejects `--recover <phrase>` and `--passphrase <phrase>` secret values in argv. The flags are retained only as prompt triggers, and secrets are read from stdin with terminal echo disabled on Unix. `keys.json` is written through a secure helper that sets mode `0600`, and key-file reads warn if an existing file is group/other-readable. Passphrase-derived keygen now emits a clear warning that it is not suitable for mainnet/production. Regression coverage: `keygen_does_not_accept_mnemonic_as_argv`, `passphrase_secret_value_in_argv_is_detected`, and `keys_json_written_with_mode_0600`.

**Residual note:** `keys.json` remains plaintext by design. File permissions and safer input close the confirmed leak paths; encrypted key storage remains a future wallet/validator UX improvement.

### API-14 — CLI to RPC authentication

**Status:** FIXED  
**Severity:** MEDIUM

The node defaults RPC to `127.0.0.1:8545` in the live startup path (`indra-node/src/bin/node.rs:2079`), and CLI tools default to `http://127.0.0.1:8545`. That is a good default. However:

- No RPC authentication token, mTLS, or admin/public separation exists.
- If operators bind `--rpc-addr` to a public interface, read and mutation endpoints are reachable without authentication.
- The config parser supports `[rpc].addr` and `[rpc].enabled` (`indra-node/src/config_file.rs:54`), and `init-config` writes those fields, but the live node RPC thread uses only the CLI `--rpc-addr` or hardcoded default (`indra-node/src/bin/node.rs:2079`). `rpc.enabled` does not appear to gate the live RPC server.

Mutation endpoints still require signed transactions/governance/staking ops, so this is not direct fund theft. The risk is unauthenticated resource abuse, topology leakage, and operator surprise when config claims RPC is disabled.

**Fix implemented:** The live node now honors `rpc.enabled` and `rpc.addr` from config, prints a loud warning when RPC binds to a non-loopback address, and parses `rpc.admin_token` / `rpc.cors_origins` config fields for explicit operator control. Public topology details were already removed under API-06; no full-topology admin endpoint is exposed when no token is configured. Regression coverage: `rpc_server_does_not_start_when_disabled_in_config`, `rpc_warns_on_non_loopback_binding`, and config parsing coverage for `rpc.admin_token` / `rpc.cors_origins`.

**Admin policy follow-up implemented:** `rpc.admin_token` is now wired to explicit admin-only RPC methods through the `X-Admin-Token` header. The first admin-gated endpoint is `indra_getPeerTopology`, which restores full peer topology visibility only for local/operator diagnostics; the public `indra_getPeers` endpoint remains aggregate-only. `indra_getRpcPolicy` reports listener mode and whether an admin token is configured without ever returning the token value. Empty or unset `rpc.admin_token` disables admin endpoints fail-closed.

**Design note:** Mutation endpoints remain available on the full local listener and remain protected by signed transaction/staking/governance payload validation, not by the admin token. This is intentional: payload signatures are the decentralized authority model for submissions, and admin RPC authentication must not become a centralized gate for ordinary network participation.

### API-15 — CLI command injection

**Status:** VERIFIED  
**Severity:** SAFE

No CLI path inspected constructs shell commands or invokes external programs from user-provided input. Search found no `std::process::Command` usage in the CLI. User-provided paths are used for file reads/writes, which can still overwrite files chosen by the user, but this is normal CLI behavior and not shell-command injection.

**Recommended hardening:** Continue avoiding shell invocation. Where files contain secrets, combine this with the API-13 permission checks.

### API-16 — RPC replay / CSRF / origin validation

**Status:** FIXED  
**Severity:** MEDIUM

Both the generic RPC server and inline node RPC server emit wildcard CORS headers:

- `Access-Control-Allow-Origin: *`
- `Access-Control-Allow-Methods: POST, OPTIONS`
- `Access-Control-Allow-Headers: Content-Type`

Locations: `indra-rpc/src/server.rs:84`, `indra-rpc/src/server.rs:87`, and `indra-node/src/bin/node.rs:2656`.

There is no origin allowlist, CSRF token, request authentication, or replay nonce at the RPC transport layer. Application payloads such as transactions and governance ops are signed and nonce-protected, which prevents a browser from forging funds-moving operations without key material. But public read endpoints, topology endpoints, and submission of already-signed payloads remain cross-origin reachable.

**Attack scenario:** A malicious website visited by an operator’s browser sends cross-origin POSTs to `http://127.0.0.1:8545`, querying peer topology/balances or submitting signed payloads the page obtained from another local compromise.

**Fix implemented:** Wildcard CORS was removed from both generic and inline RPC paths. CORS is restrictive by default: an empty `rpc.cors_origins` allowlist emits no cross-origin browser headers. When an origin is configured and matches the request `Origin`, the response reflects only that specific origin and includes `X-Admin-Token` in allowed headers for future admin endpoints. Regression coverage: `rpc_cors_default_is_restrictive` and `rpc_cors_reflects_allowlisted_origin`.

**Residual note:** This closes browser-origin exposure by default. It does not add CSRF tokens because browser-accessible RPC is now opt-in via explicit CORS origins.

## Proof-of-Concept Tests

The original Phase 8 audit was audit-only, but follow-up fix tasks added regression coverage for the exploitable/high-impact paths and the remaining hardening gaps:

1. **API-06 topology leak**
   - Start a node with mock connected validator addresses.
   - Call `indra_getPeers` over unauthenticated RPC.
   - Assert current behavior returns concrete peer addresses.
   - Fix expectation: unauthenticated public RPC returns only aggregate counts or an authorization error.

2. **API-07 unbounded RPC threads**
   - Open many concurrent TCP connections to the RPC port and send slow/valid requests.
   - Observe unbounded OS thread creation and absence of rate-limit errors.
   - Fix expectation: requests beyond configured concurrency/rate are rejected or queued with bounded resources.

3. **API-09 consensus-lock contention**
   - Populate state with many UTXOs.
   - Repeatedly call `indra_getLegacyUtxosAuthorized` while measuring time to acquire the consensus driver lock for a local consensus action.
   - Fix expectation: read-only RPC does not hold the consensus driver lock across full-state scans.

4. **API-13 CLI argv leakage**
   - Invoke `indra-keygen --recover "<mnemonic>"`.
   - Inspect process arguments from another local process.
   - Fix expectation: recovery secret is read through no-echo stdin and never appears in argv.

5. **API-01/API-08 RPC validation**
   - Invalid staking ops are rejected before staking mempool admission.
   - Invalid address params return JSON-RPC errors instead of zero/empty responses.
   - Non-POST methods, oversized bodies, and batch requests are rejected explicitly.

6. **API-05 UTXO scan privacy/rate limit**
   - Legacy address-indexed UTXO/balance scans require valid ownership authorization.
   - Authorized UTXO scan endpoints are independently per-IP rate-limited.

7. **API-10/API-11 FFI hardening**
   - Bounded C strings reject non-NUL-terminated buffers within `MAX_CSTR_LEN`.
   - FFI keypair zeroizers and intermediate key-buffer zeroization behavior are tested.

8. **API-14/API-16 exposure controls**
   - `rpc.enabled = false` suppresses RPC startup.
   - Non-loopback RPC binding emits an operator warning.
   - CORS is restrictive by default and reflects only allowlisted origins.

## Findings NOT Present

- Transaction RPC admission uses `submit_validated`, not raw mempool insertion.
- Governance RPC admission uses `validate_governance_op` before mempool insertion.
- RPC does not expose private validator keys, VRF secret keys, BLS seeds, ML-DSA private keys, or mnemonics.
- FFI exported functions are consistently wrapped with `catch_unwind`, and the crate denies common panic/unwrap patterns.
- FFI includes explicit zeroizers for keypair and transaction-result structures.
- FFI caller-provided C strings are bounded to `MAX_CSTR_LEN` before UTF-8 decoding.
- No shell command injection path was found in CLI tooling.
- CLI/RPC defaults use localhost, reducing—but not eliminating—the risk of unauthenticated public exposure.
- RPC no longer emits wildcard CORS headers by default.

## Recommended Fix Order

All Phase 8 findings are now either FIXED or VERIFIED. Remaining mainnet design follow-ups, in priority order:

1. **Wallet privacy redesign.** Decide whether address-indexed UTXO/balance queries should require view keys or signed ownership challenges instead of being public chain-data RPC.
2. **Opaque FFI key handles.** Replace raw private-key return structs with opaque handles for production wallet integrations.
3. **Full RPC stack hardening.** The explicit public/admin RPC policy has been implemented for admin-only diagnostics. Replacing the hand-written HTTP/JSON transport with a mature bounded HTTP implementation remains deliberately deferred architectural debt, not an active security gap under the current hardened transport envelope (body size limits, connection limits, per-IP rate limiting, batch rejection, method enforcement, and fail-closed read-only dispatch).
4. **Encrypted key storage.** `keys.json` remains plaintext with mode `0600`; encrypted validator key storage remains a future operator UX/security improvement.
