# L3-NET-01 — ignored inner message length

Constructor: take canonical `Message::Ping(7).encode_wire()`, retain bytes 4 onward, and prepend either `00 00 00 00` or `ff ff ff ff`. The authenticated frame plaintext therefore differs only in the inner length prefix.

Production decoder: `FrameReader::read_frame` → `peer_manager` read task → `payload = &plaintext[4..]` → `Message::decode_wire(payload)`.

Expected: the inner length must equal the bytes following it, or the field must not exist.

Actual: both variants are accepted as `Ping(7)`. The enclosing AEAD frame remains bounded and authenticated, so this does not enable allocation bypass or cross-node interpretation divergence.

Reachability/consequence: yes, from any authenticated validator connection. The bytes collapse before message classification; rate limiting uses actual plaintext size and consensus relay/dedup keys re-encode canonical bytes. No authentication or authorization bypass was found.

Run: `cargo run --offline --manifest-path audit_evidence/21_consensus_network_adversarial/01_message_canonicality/harness/Cargo.toml`.

