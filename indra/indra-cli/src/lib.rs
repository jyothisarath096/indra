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
#![deny(unused_must_use)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable, clippy::todo, clippy::unimplemented)]
#![deny(clippy::indexing_slicing)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented
    )
)]

pub mod amount;
pub mod canonical_scan;
pub mod error;
pub mod genesis_cmd;
pub mod keygen;
pub mod query;
pub mod rpc_client;
pub mod scan_auth;
pub mod staking;
pub mod tx_builder;
pub mod wallet;

pub use amount::{parse_indra_amount_to_spark, SPARK_PER_INDRA};
pub use canonical_scan::{
    scan_canonical_block, scan_canonical_blocks, scan_canonical_blocks_authorized,
};
pub use error::{CliError, CliResult};
pub use genesis_cmd::{
    build_genesis_config, entry_from_keys, entry_from_public_keys, holds_at_least_one_third,
    stake_share_bps, GenesisConfig, GenesisEntry,
};
pub use keygen::{
    cold_hot_pairing_message, cold_hybrid_pubkey, cold_password_source_from_args,
    encrypt_cold_keys, encrypt_keys, generate_cold_keys_file, generate_cold_share_ceremony,
    generate_from_master_seed, generate_from_new_mnemonic, generate_from_passphrase,
    has_secret_value_in_argv, inspect_key_file_public_metadata, inspect_public_metadata,
    load_cold_keys, load_keys, load_keys_for_cli, password_source_from_args,
    public_export_from_cold_key_file, public_export_from_key_file, read_cold_share,
    reconstruct_cold_shares, recover_from_mnemonic, validate_cold_hot_pairing,
    validate_cold_share_manifest, validate_public_export, verify_cold_share,
    warn_if_key_file_permissive, write_cold_share_secure, write_keys_file_secure, ColdKeysFile,
    ColdShareCeremony, ColdShareFile, ColdShareManifest, ExpectedColdPublicKey,
    KeyFilePublicMetadata, KeysFile, PasswordSource, PublicKeyExport, ValidatorKeys,
};
pub use query::{rpc_call, QueryResult};
pub use scan_auth::{
    build_scan_authorization, fetch_scan_challenge, json_string, rpc_call_raw_params,
    ScanAuthorization,
};
pub use staking::{
    build_claim_rewards_op, build_cold_authorized_staking_op, build_delegate_op,
    build_exit_stake_position_op, build_register_validator_op_with_cold,
    build_update_network_address_op, fetch_base_fee, fetch_chain_id, fetch_staking_nonce,
    fetch_validator_cold_replay, reconstruct_keypair, submit_staking_op,
    ColdAuthorizedStakingAction, StakePositionExitSigner,
};
pub use tx_builder::{
    build_cold_transaction, build_cold_transaction_with_fee_policy, build_transaction,
    build_transaction_with_fee_policy, default_fee_for_base_fee, required_fee_for_transaction,
    BuiltStakingOp, BuiltTransaction, ColdTxParams, TxParams, FEE_SAFETY_MARGIN,
};
pub use wallet::{seed_wallet_from_genesis, PendingChange, Wallet, WalletEntry};

/// Exact error emitted when a command requires an explicit chain ID.
pub const MISSING_CHAIN_ID_ERROR: &str = "missing required flag --chain-id";

/// Return the explicit `--chain-id` argument required by chain-bound commands.
pub fn required_chain_id(args: &[String]) -> Result<String, &'static str> {
    let Some(index) = args.iter().position(|arg| arg == "--chain-id") else {
        return Err(MISSING_CHAIN_ID_ERROR);
    };
    let Some(value) = args.get(index + 1) else {
        return Err(MISSING_CHAIN_ID_ERROR);
    };
    if value.is_empty() || value.starts_with("--") {
        return Err("invalid --chain-id value");
    }
    Ok(value.clone())
}

#[cfg(test)]
mod tests {
    use super::{required_chain_id, MISSING_CHAIN_ID_ERROR};

    #[test]
    fn required_chain_id_reports_missing_flag() {
        assert_eq!(required_chain_id(&[]), Err(MISSING_CHAIN_ID_ERROR));
    }

    #[test]
    fn required_chain_id_reports_flag_without_value() {
        assert_eq!(
            required_chain_id(&["--chain-id".into()]),
            Err(MISSING_CHAIN_ID_ERROR)
        );
    }

    #[test]
    fn required_chain_id_rejects_empty_value() {
        assert_eq!(
            required_chain_id(&["--chain-id".into(), "".into()]),
            Err("invalid --chain-id value")
        );
    }

    #[test]
    fn required_chain_id_rejects_flag_as_value() {
        assert_eq!(
            required_chain_id(&["--chain-id".into(), "--keys".into()]),
            Err("invalid --chain-id value")
        );
    }

    #[test]
    fn required_chain_id_accepts_explicit_value() {
        assert_eq!(
            required_chain_id(&["--chain-id".into(), "indra-mainnet".into()]),
            Ok("indra-mainnet".into())
        );
    }
}
