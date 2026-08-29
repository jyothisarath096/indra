# L3-NET-04 — undersized hybrid signatures pass framing decode

Construct a canonical `VoteV1` but set the Ed25519 `VariableBytes<64>` length to 0 or 63 and/or the ML-DSA-87 `VariableBytes<4627>` length to 0 or 4626. Encode normally.

Production decoder: `Message::decode_wire` → `VoteV1::decode_exact` → `HybridSignature::decode`.

Expected: signature framing rejects any length other than exactly 64 and 4627.

Actual: decoding accepts all lengths at or below the maxima. `HybridSignature::to_crypto_sig` then rejects wrong lengths before cryptographic verification. In the peer manager, relay verification fails, but the decoded event is still delivered to the node; the node performs height checks and snapshot lookup before authoritative vote verification rejects it. No vote collector or consensus state mutation occurs.

Reachability/consequence: yes. This is cheap malformed input admitted one layer farther than necessary; it is not an authentication bypass. Oversized lengths and truncation are rejected during decode before allocation/copy.

Run the audit harness command documented in L3-NET-01.

