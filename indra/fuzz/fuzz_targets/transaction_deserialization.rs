#![no_main]

use indra_core::{codec::Decode, types::transaction::TransactionV1};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(transaction) = TransactionV1::decode_exact(data) {
        let _ = transaction.validate_structure();
        let _ = transaction.signing_bytes("indra-fuzz-chain");
    }
});
