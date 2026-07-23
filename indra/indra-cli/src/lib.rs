//! # indra-cli
//!
//! Command-line tools for the INDRA v2 protocol.
//!
//! ## Commands
//!
//! ### `keygen`
//! Generate a complete validator keypair set:
//! - Ed25519 + ML-DSA-87 hybrid keypair (for signing transactions and votes)
//! - Legacy BLS12-381 keypair metadata (retained for backward compatibility)
//! - VRF keypair (for proposer election)
//!
//! Output: an encrypted `keys.json` by default, with legacy plaintext available
//! only through an explicit unsafe opt-out for test/dev use.
//!
//! ### `genesis`
//! Build a `genesis.toml` from a list of validator public keys and stake amounts.
//! Used by the testnet coordinator to produce the agreed-upon genesis block.
//!
//! ### `send-tx`
//! Build and submit a transaction to a running node via JSON-RPC.
//!
//! ### `stake`
//! Build and submit validator and delegation staking operations.
//!
//! ### `query`
//! Query chain state from a running node:
//! - `query height`
//! - `query chain-info`
//! - `query validator <id>`
//! - `query mempool-size`

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

pub mod error;
pub mod genesis_cmd;
pub mod keygen;
pub mod legacy_scan_auth;
pub mod query;
pub mod staking;
pub mod tx_builder;
pub mod wallet;

pub use error::{CliError, CliResult};
pub use genesis_cmd::{build_genesis_config, GenesisConfig, GenesisEntry};
pub use keygen::{
    decrypt_encrypted_keys, encrypt_plaintext_keys, encrypt_plaintext_keys_replace,
    generate_from_new_mnemonic, generate_from_passphrase, generate_keypairs,
    has_secret_value_in_argv, inspect_public_metadata, load_keys_for_cli,
    password_source_from_args, recover_from_mnemonic, warn_if_key_file_permissive,
    write_keys_file_secure, KeysFile, PasswordSource, ValidatorKeys,
};
pub use legacy_scan_auth::{
    build_legacy_scan_auth_proof, fetch_legacy_scan_challenge, json_string, rpc_call_raw_params,
    ScanAuthFileV1,
};
pub use query::{rpc_call, QueryResult};
pub use staking::{
    build_claim_rewards_op, build_delegate_op, build_register_validator_op,
    build_set_auto_delegate_op, build_set_commission_op, build_undelegate_op,
    build_update_network_address_op, fetch_chain_id, fetch_staking_nonce, reconstruct_keypair,
    submit_staking_op,
};
pub use tx_builder::{
    build_register_payment_key_op, build_transaction, BuiltStakingOp, BuiltTransaction, TxParams,
};
pub use wallet::{PendingChange, Wallet, WalletEntry};
