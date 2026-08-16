#![no_main]

use indra_core::{
    codec::Decode,
    types::governance::{GovernanceOpV2, GovernancePayload},
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&selector, encoded)) = data.split_first() else {
        return;
    };
    match selector & 1 {
        0 => {
            // Payload tags cover proposal creation, commit, reveal, and cancel,
            // including their cold-authorized forms.
            let _ = GovernancePayload::decode_exact(encoded);
        }
        _ => {
            if let Ok(operation) = GovernanceOpV2::decode_exact(encoded) {
                let _ = operation.validate_structure();
                let _ = operation.cold_authorization_signing_bytes("indra-fuzz-chain");
            }
        }
    }
});
