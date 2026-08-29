# L3-NET-02 — trailing bytes accepted by five application decoders

Construct canonical `Ping`, `Pong`, `RequestBlocks`, `RequestQC`, or `QCResponse` wire bytes and append one or more arbitrary bytes while increasing no inner field. Send the result as one authenticated AEAD plaintext frame.

Production decoder: `peer_manager` read task → `Message::decode_wire` → the relevant custom decoder.

Expected: reject because accepted wire representations must be exact.

Actual: all five decoders read their required prefix and return success without checking the remainder. For `QCResponse`, bytes after the declared `qc_bytes` length are discarded; the retained QC is still passed through `QuorumCertificateV1::decode_exact` before verification/mutation.

Reachability/consequence: yes. Distinct wire bytes become the same logical object. Rate limiting charges the original plaintext size; relay/dedup hashes use canonical re-encoding, and no consensus authentication bypass was reproduced. Potentially affected downstream keys are QC-response coalescing and any future raw-wire accounting, although current coalescing intentionally collapses these variants.

Run the audit harness command documented in L3-NET-01.

