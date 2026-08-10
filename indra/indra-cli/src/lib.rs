//! # indra-cli
//!
//! Command-line tools for the INDRA v2 protocol.
//!
//! ## Commands
//!
//! ### `keygen`
//! Generate a complete validator keypair set:
//! - Ed25519 + ML-DSA-87 hybrid keypair (for signing transactions and votes)
//! - VRF keypair (for proposer election)
//!
//! Output: an encrypted `keys.json`.
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

pub mod amount;
pub mod canonical_scan;
pub mod error;
pub mod genesis_cmd;
pub mod keygen;
pub mod legacy_scan_auth;
pub mod query;
pub mod staking;
pub mod tx_builder;
pub mod wallet;

pub use amount::{parse_indra_amount_to_spark, SPARK_PER_INDRA};
pub use canonical_scan::{scan_canonical_block, scan_canonical_blocks};
pub use error::{CliError, CliResult};
pub use genesis_cmd::{
    build_genesis_config, entry_from_keys, entry_from_public_keys, with_cold_file,
    with_cold_manifest, GenesisConfig, GenesisEntry,
};
pub use keygen::{
    encrypt_cold_keys, encrypt_keys, generate_cold_keys_file, generate_cold_share_ceremony,
    generate_from_master_seed, generate_from_new_mnemonic, generate_from_passphrase,
    has_secret_value_in_argv, inspect_key_file_public_metadata, inspect_public_metadata,
    load_cold_keys, load_keys_for_cli, password_source_from_args, read_cold_share,
    reconstruct_cold_shares, recover_from_mnemonic, validate_cold_share_manifest,
    warn_if_key_file_permissive, write_cold_share_secure, write_keys_file_secure, ColdKeysFile,
    ColdShareCeremony, ColdShareFile, ColdShareManifest, KeyFilePublicMetadata, KeysFile,
    PasswordSource, ValidatorKeys,
};
pub use legacy_scan_auth::{
    build_legacy_scan_auth_proof, fetch_legacy_scan_challenge, json_string, rpc_call_raw_params,
    ScanAuthFileV1,
};
pub use query::{rpc_call, QueryResult};
pub use staking::{
    build_claim_rewards_op, build_delegate_op, build_exit_stake_position_op,
    build_register_validator_op, build_register_validator_op_with_cold, build_set_auto_delegate_op,
    build_set_commission_op, build_update_network_address_op, fetch_chain_id, fetch_staking_nonce,
    fetch_validator_cold_replay, reconstruct_keypair, submit_staking_op, StakePositionExitSigner,
};
pub use tx_builder::{build_transaction, BuiltStakingOp, BuiltTransaction, TxParams};
pub use wallet::{PendingChange, Wallet, WalletEntry};
