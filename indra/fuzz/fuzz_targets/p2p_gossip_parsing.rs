#![no_main]

use indra_network::Message;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // This is the actual first-ingress decoder after the transport's bounded
    // four-byte frame length. It dispatches transactions, staking/governance
    // operations, votes, proposals/blocks, QC responses, and control messages.
    let _ = Message::decode_wire(data);
});
