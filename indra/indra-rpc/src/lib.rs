//! # indra-rpc
//!
//! JSON-RPC 2.0 API for the INDRA v2 node.
//!
//! ## Endpoints
//!
//! | Method                    | Description                                    |
//! |---------------------------|------------------------------------------------|
//! | `indra_getHeight`         | Current chain height                           |
//! | `indra_getBlock`          | Block by height                                |
//! | `indra_getTip`            | Current tip hash and height                    |
//! | `indra_getBalance`        | UTXO balance for a public key                  |
//! | `indra_getMempoolSize`    | Number of pending transactions                 |
//! | `indra_sendTransaction`   | Submit a signed transaction                    |
//! | `indra_getTransaction`    | Look up a transaction by ID                    |
//! | `indra_getValidator`      | Validator info by ID                           |
//! | `indra_getChainInfo`      | Chain summary (height, supply, base fee, etc.) |
//! | `indra_getValidatorSet`   | All active validators and their stakes         |
//!
//! ## Wire format
//!
//! Standard JSON-RPC 2.0 over HTTP POST to `/`.
//!
//! Request:
//! ```json
//! {"jsonrpc":"2.0","method":"indra_getHeight","params":[],"id":1}
//! ```
//!
//! Response:
//! ```json
//! {"jsonrpc":"2.0","result":{"height":42},"id":1}
//! ```
//!
//! Error:
//! ```json
//! {"jsonrpc":"2.0","error":{"code":-32601,"message":"Method not found"},"id":1}
//! ```
//!
//! ## No external dependencies
//!
//! The HTTP server and JSON codec use only the Rust standard library.
//! This keeps the binary small and the dependency tree auditable.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

pub mod error;
pub mod handlers;
pub mod server;
pub mod types;

pub use error::{RpcError, RpcResult};
pub use handlers::{dispatch, DispatchResult, NetworkContext, NodeState};
pub use server::{RpcRateLimiter, RpcServer, MAX_RPC_CONNECTIONS, RPC_REQUEST_TIMEOUT};
pub use types::{RpcErrorBody, RpcRequest, RpcResponse};
