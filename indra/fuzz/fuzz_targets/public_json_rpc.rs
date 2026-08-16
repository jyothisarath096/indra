#![no_main]

use indra_rpc::{
    dispatch_with_mode,
    handlers::{RpcMethodAccess, RPC_METHODS},
    types::parse_request,
    NodeState, RpcMode,
};
use indra_state::ChainState;
use libfuzzer_sys::fuzz_target;
use serde_json::Value;
use std::sync::LazyLock;

static STATE: LazyLock<ChainState> = LazyLock::new(ChainState::new_genesis);

fuzz_target!(|data: &[u8]| {
    // Exercise the real JSON-RPC envelope parser whenever the bytes are UTF-8.
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = parse_request(text);
    }

    let Some((&selector, parameter_bytes)) = data.split_first() else {
        return;
    };
    let public_methods = RPC_METHODS
        .iter()
        .filter(|(_, access)| *access == RpcMethodAccess::ReadOnly)
        .collect::<Vec<_>>();
    let method = public_methods[usize::from(selector) % public_methods.len()].0;

    // Handler parameters are raw JSON values in the production dispatcher.
    // A JSON array preserves that boundary; non-arrays and invalid JSON become
    // one adversarial raw parameter instead of being discarded.
    let params = match serde_json::from_slice::<Value>(parameter_bytes) {
        Ok(Value::Array(values)) => values.into_iter().map(|value| value.to_string()).collect(),
        _ => vec![String::from_utf8_lossy(parameter_bytes).into_owned()],
    };
    let state = NodeState::read_only(&*STATE);
    let _ = dispatch_with_mode(method, &params, &state, RpcMode::ReadOnly);
});
