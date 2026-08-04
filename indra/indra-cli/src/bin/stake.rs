//! `indra-stake` — build and submit staking operations.

use indra_cli::{
    fetch_chain_id, fetch_staking_nonce, fetch_validator_cold_replay, load_cold_keys,
    password_source_from_args, reconstruct_keypair, submit_staking_op, BuiltStakingOp, CliError,
    CliResult, KeysFile, PasswordSource, StakePositionExitSigner, Wallet, WalletEntry,
};
use indra_core::types::{
    primitives::Bytes32, stake_position::PositionCustodyV1, staking::StakeDepositProof,
};
#[cfg(test)]
use indra_core::{
    codec::{Decode, Encode},
    types::{crypto::HybridPubKey, primitives::VariableBytes},
};

const DEFAULT_NODE: &str = "http://127.0.0.1:8545";
const DEFAULT_KEYS: &str = "keys.json";
const DEFAULT_WALLET: &str = "wallet.json";

fn main() {
    if let Err(e) = run(std::env::args().collect()) {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

fn run(args: Vec<String>) -> CliResult<()> {
    let subcommand = args.get(1).map(String::as_str).unwrap_or("help");
    match subcommand {
        "register" => run_register(&args),
        "self-stake" => run_self_stake(&args),
        "self-unstake" => run_self_unstake(&args),
        "delegate" => run_delegate(&args),
        "undelegate" => run_undelegate(&args),
        "claim-rewards" => run_claim_rewards(&args),
        "set-commission" => run_set_commission(&args),
        "auto-delegate" => run_auto_delegate(&args),
        "update-network-address" => run_update_network_address(&args),
        "nonce" => run_nonce(&args),
        "help" | "--help" | "-h" => {
            print_help();
            Ok(())
        }
        _ => {
            print_help();
            Ok(())
        }
    }
}

fn run_register(args: &[String]) -> CliResult<()> {
    if has_help(args) {
        print_register_help();
        return Ok(());
    }
    let keys = load_keys(args)?;
    let keypair = reconstruct_keypair(&keys)?;
    let cold_path = get(args, "--cold-keys")
        .ok_or_else(|| CliError::Transaction("register requires --cold-keys <path>".into()))?;
    let cold_keys = load_cold_keys(&cold_path, password_source_from_args(args))
        .map_err(|e| CliError::Keystore(e.to_string()))?;
    let cold_keypair = cold_keys
        .reconstruct()
        .map_err(|e| CliError::Keystore(e.to_string()))?;
    let commission_bps = parse_commission(args)?;
    let deposit_utxo_id = parse_required_bytes32(args, "--utxo")?;
    let wallet_path = get(args, "--wallet").unwrap_or_else(|| DEFAULT_WALLET.to_string());
    let deposit_proof = stake_deposit_proof_from_wallet(&wallet_path, &deposit_utxo_id)?;
    let signer_id = staking_signer_id(&keys)?;
    let node_url = get(args, "--node").unwrap_or_else(|| DEFAULT_NODE.to_string());
    let chain_id = fetch_chain_id(&node_url)?;
    let nonce = fetch_next_nonce(&node_url, &signer_id)?;
    let built = indra_cli::tx_builder::build_register_validator_op_with_cold(
        commission_bps,
        deposit_utxo_id,
        deposit_proof,
        &keypair,
        &cold_keypair,
        keys.public.vrf_pk,
        nonce,
        &chain_id,
    )?;
    finish_op(
        args,
        "register",
        &built,
        &signer_id,
        nonce,
        &node_url,
        &[
            ("Commission", format!("{} bps", commission_bps)),
            ("Bond UTXO", hex::encode(deposit_utxo_id.0)),
        ],
        Some((&wallet_path, deposit_utxo_id)),
    )
}

fn run_self_stake(args: &[String]) -> CliResult<()> {
    if has_help(args) {
        print_self_stake_help();
        return Ok(());
    }
    let keys = load_keys(args)?;
    let keypair = reconstruct_keypair(&keys)?;
    let deposit_utxo_id = parse_required_bytes32(args, "--utxo")?;
    let wallet_path = get(args, "--wallet").unwrap_or_else(|| DEFAULT_WALLET.to_string());
    let deposit_proof = stake_deposit_proof_from_wallet(&wallet_path, &deposit_utxo_id)?;
    let signer_id = staking_signer_id(&keys)?;
    let node_url = get(args, "--node").unwrap_or_else(|| DEFAULT_NODE.to_string());
    let chain_id = fetch_chain_id(&node_url)?;
    let nonce = fetch_next_nonce(&node_url, &signer_id)?;
    let built = indra_cli::tx_builder::build_self_stake_op(
        deposit_utxo_id,
        deposit_proof,
        &keypair,
        nonce,
        &chain_id,
    )?;
    finish_op(
        args,
        "self-stake",
        &built,
        &signer_id,
        nonce,
        &node_url,
        &[("Bond UTXO", hex::encode(deposit_utxo_id.0))],
        Some((&wallet_path, deposit_utxo_id)),
    )
}

fn run_self_unstake(args: &[String]) -> CliResult<()> {
    if has_help(args) {
        print_self_unstake_help();
        return Ok(());
    }
    let keys = load_keys(args)?;
    let position_id = parse_required_bytes32(args, "--position-id")?;
    let amount_spark = parse_exit_amount(args)?;
    let signer_id = staking_signer_id(&keys)?;
    let cold_path = get(args, "--cold-keys")
        .ok_or_else(|| CliError::MissingArgument("missing required flag: --cold-keys".into()))?;
    let cold_password_path = get(args, "--cold-keys-password-file");
    let cold_password = if let Some(path) = cold_password_path.as_deref() {
        PasswordSource::File {
            path: std::path::Path::new(path),
            reject_permissive: false,
        }
    } else {
        PasswordSource::Prompt
    };
    let cold_keys =
        load_cold_keys(&cold_path, cold_password).map_err(|e| CliError::Keystore(e.to_string()))?;
    let cold_keypair = cold_keys
        .reconstruct()
        .map_err(|e| CliError::Keystore(e.to_string()))?;
    let node_url = get(args, "--node").unwrap_or_else(|| DEFAULT_NODE.to_string());
    let chain_id = fetch_chain_id(&node_url)?;
    let (cold_key_version, cold_nonce) =
        fetch_validator_cold_replay(&node_url, &hex::encode(signer_id.0))?;
    let built = indra_cli::tx_builder::build_exit_stake_position_op(
        position_id,
        amount_spark,
        PositionCustodyV1::ValidatorColdIdentity {
            validator_id: signer_id,
        },
        StakePositionExitSigner::ValidatorCold {
            keypair: &cold_keypair,
            cold_key_version,
            cold_nonce,
        },
        &chain_id,
    )?;
    finish_op(
        args,
        "self-unstake",
        &built,
        &signer_id,
        cold_nonce,
        &node_url,
        &[(
            "Note",
            "UTXO returns after 60 epochs (approximately 30 days)".to_string(),
        )],
        None,
    )
}

fn run_delegate(args: &[String]) -> CliResult<()> {
    if has_help(args) {
        print_delegate_help();
        return Ok(());
    }
    let keys = load_keys(args)?;
    let keypair = reconstruct_keypair(&keys)?;
    let deposit_utxo_id = parse_required_bytes32(args, "--utxo")?;
    let validator_id = parse_required_bytes32(args, "--validator")?;
    let wallet_path = get(args, "--wallet").unwrap_or_else(|| DEFAULT_WALLET.to_string());
    let deposit_proof = stake_deposit_proof_from_wallet(&wallet_path, &deposit_utxo_id)?;
    let signer_id = staking_signer_id(&keys)?;
    let node_url = get(args, "--node").unwrap_or_else(|| DEFAULT_NODE.to_string());
    let chain_id = fetch_chain_id(&node_url)?;
    let nonce = fetch_next_nonce(&node_url, &signer_id)?;
    let built = indra_cli::tx_builder::build_delegate_op(
        validator_id,
        deposit_utxo_id,
        deposit_proof,
        &keypair,
        nonce,
        &chain_id,
    )?;
    finish_op(
        args,
        "delegate",
        &built,
        &signer_id,
        nonce,
        &node_url,
        &[
            ("Validator", hex::encode(validator_id.0)),
            ("Bond UTXO", hex::encode(deposit_utxo_id.0)),
        ],
        Some((&wallet_path, deposit_utxo_id)),
    )
}

fn run_undelegate(args: &[String]) -> CliResult<()> {
    if has_help(args) {
        print_undelegate_help();
        return Ok(());
    }
    let keys = load_keys(args)?;
    let keypair = reconstruct_keypair(&keys)?;
    let position_id = parse_required_bytes32(args, "--position-id")?;
    let amount_spark = parse_exit_amount(args)?;
    let signer_id = staking_signer_id(&keys)?;
    let node_url = get(args, "--node").unwrap_or_else(|| DEFAULT_NODE.to_string());
    let chain_id = fetch_chain_id(&node_url)?;
    let nonce = fetch_next_nonce(&node_url, &signer_id)?;
    let built = indra_cli::tx_builder::build_exit_stake_position_op(
        position_id,
        amount_spark,
        PositionCustodyV1::DelegatorIdentity {
            delegator_id: signer_id,
        },
        StakePositionExitSigner::Delegator {
            keypair: &keypair,
            nonce,
        },
        &chain_id,
    )?;
    finish_op(
        args,
        "undelegate",
        &built,
        &signer_id,
        nonce,
        &node_url,
        &[
            ("Position", hex::encode(position_id.0)),
            (
                "Note",
                "UTXO returns after 60 epochs (approximately 30 days)".to_string(),
            ),
        ],
        None,
    )
}

fn run_claim_rewards(args: &[String]) -> CliResult<()> {
    if has_help(args) {
        print_claim_rewards_help();
        return Ok(());
    }
    let keys = load_keys(args)?;
    let keypair = reconstruct_keypair(&keys)?;
    let validator_id = parse_required_bytes32(args, "--validator")?;
    let signer_id = staking_signer_id(&keys)?;
    let node_url = get(args, "--node").unwrap_or_else(|| DEFAULT_NODE.to_string());
    let chain_id = fetch_chain_id(&node_url)?;
    let nonce = fetch_next_nonce(&node_url, &signer_id)?;
    let built =
        indra_cli::tx_builder::build_claim_rewards_op(validator_id, &keypair, nonce, &chain_id)?;
    finish_op(
        args,
        "claim-rewards",
        &built,
        &signer_id,
        nonce,
        &node_url,
        &[
            ("Validator", hex::encode(validator_id.0)),
            (
                "Note",
                "Use indra-wallet-scan to discover and add the reward UTXO to your wallet"
                    .to_string(),
            ),
        ],
        None,
    )
}

fn run_set_commission(args: &[String]) -> CliResult<()> {
    if has_help(args) {
        print_set_commission_help();
        return Ok(());
    }
    let keys = load_keys(args)?;
    let keypair = reconstruct_keypair(&keys)?;
    let commission_bps = parse_commission(args)?;
    let validator_id = validator_id_from_keys(&keys);
    let node_url = get(args, "--node").unwrap_or_else(|| DEFAULT_NODE.to_string());
    let chain_id = fetch_chain_id(&node_url)?;
    let nonce = fetch_next_nonce(&node_url, &validator_id)?;
    let built = indra_cli::tx_builder::build_set_commission_op(
        validator_id,
        commission_bps,
        &keypair,
        nonce,
        &chain_id,
    )?;
    finish_op(
        args,
        "set-commission",
        &built,
        &validator_id,
        nonce,
        &node_url,
        &[
            ("Commission", format!("{} bps", commission_bps)),
            (
                "Note",
                "Commission change takes effect at the next epoch boundary".to_string(),
            ),
        ],
        None,
    )
}

fn run_auto_delegate(args: &[String]) -> CliResult<()> {
    if has_help(args) {
        print_auto_delegate_help();
        return Ok(());
    }
    let clear = args.iter().any(|arg| arg == "--clear");
    if clear && get(args, "--target").is_some() {
        return Err(CliError::Parse(
            "--clear cannot be combined with --target".to_string(),
        ));
    }
    let keys = load_keys(args)?;
    let keypair = reconstruct_keypair(&keys)?;
    let validator_id = parse_required_bytes32(args, "--validator")?;
    let target_validator_id = if clear {
        Bytes32::ZERO
    } else {
        parse_required_bytes32(args, "--target")?
    };
    let node_url = get(args, "--node").unwrap_or_else(|| DEFAULT_NODE.to_string());
    let chain_id = fetch_chain_id(&node_url)?;
    let nonce = fetch_next_nonce(&node_url, &validator_id)?;
    let built = indra_cli::tx_builder::build_set_auto_delegate_op(
        validator_id,
        target_validator_id,
        &keypair,
        nonce,
        &chain_id,
    )?;
    let action = if clear {
        "clear".to_string()
    } else {
        hex::encode(target_validator_id.0)
    };
    finish_op(
        args,
        "auto-delegate",
        &built,
        &validator_id,
        nonce,
        &node_url,
        &[
            ("Validator", hex::encode(validator_id.0)),
            ("Target", action),
            (
                "Note",
                "Auto-delegation affects reward routing at epoch boundaries".to_string(),
            ),
        ],
        None,
    )
}

fn run_update_network_address(args: &[String]) -> CliResult<()> {
    if has_help(args) {
        print_update_network_address_help();
        return Ok(());
    }
    let clear = args.iter().any(|arg| arg == "--clear");
    let address = get(args, "--address");
    if clear && address.is_some() {
        return Err(CliError::Parse(
            "--clear cannot be combined with --address".to_string(),
        ));
    }
    if !clear && address.is_none() {
        return Err(CliError::MissingArgument(
            "missing required flag: --address <ip:port> or --clear".to_string(),
        ));
    }

    let keys = load_keys(args)?;
    let keypair = reconstruct_keypair(&keys)?;
    let validator_id = validator_id_from_keys(&keys);
    let node_url = get(args, "--node").unwrap_or_else(|| DEFAULT_NODE.to_string());
    let chain_id = fetch_chain_id(&node_url)?;
    let nonce = fetch_next_nonce(&node_url, &validator_id)?;
    let network_addr = if clear { None } else { address };
    let built = indra_cli::tx_builder::build_update_network_address_op(
        validator_id,
        network_addr.clone(),
        &keypair,
        nonce,
        &chain_id,
    )?;
    let action = network_addr.unwrap_or_else(|| "<clear>".to_string());
    finish_op(
        args,
        "update-network-address",
        &built,
        &validator_id,
        nonce,
        &node_url,
        &[
            ("Validator", hex::encode(validator_id.0)),
            ("Address", action),
            (
                "Note",
                "One network-address update is allowed per validator per epoch".to_string(),
            ),
        ],
        None,
    )
}

fn run_nonce(args: &[String]) -> CliResult<()> {
    if has_help(args) {
        print_nonce_help();
        return Ok(());
    }
    let keys = load_keys(args)?;
    let signer_id = staking_signer_id(&keys)?;
    let node_url = get(args, "--node").unwrap_or_else(|| DEFAULT_NODE.to_string());
    let current = fetch_staking_nonce(&node_url, &hex::encode(signer_id.0))?;
    println!("  Signer:        {}", hex::encode(signer_id.0));
    println!("  Current nonce: {}", current);
    println!("  Next op nonce: {}", current.saturating_add(1));
    Ok(())
}

fn finish_op(
    args: &[String],
    op_name: &str,
    built: &BuiltStakingOp,
    signer_id: &Bytes32,
    nonce: u64,
    node_url: &str,
    details: &[(&str, String)],
    mark_spent: Option<(&str, Bytes32)>,
) -> CliResult<()> {
    if args.iter().any(|arg| arg == "--dry-run") {
        print_confirmation(
            "INDRA STAKING OP DRY RUN - NOT SUBMITTED",
            op_name,
            built,
            signer_id,
            nonce,
            node_url,
            details,
            None,
        );
        return Ok(());
    }

    let response = submit_staking_op(node_url, &built.op_hex)?;
    if let Some((wallet_path, utxo_id)) = mark_spent {
        let mut wallet = Wallet::load(wallet_path)?;
        wallet.mark_spent(&utxo_id);
        wallet.save(wallet_path)?;
    }
    print_confirmation(
        "INDRA STAKING OP SUBMITTED",
        op_name,
        built,
        signer_id,
        nonce,
        node_url,
        details,
        Some(&response),
    );
    Ok(())
}

fn print_confirmation(
    title: &str,
    op_name: &str,
    built: &BuiltStakingOp,
    signer_id: &Bytes32,
    nonce: u64,
    node_url: &str,
    details: &[(&str, String)],
    response: Option<&str>,
) {
    println!("==========================================");
    println!("  {}", title);
    println!("==========================================");
    println!();
    println!("  Operation:  {}", op_name);
    println!("  Op ID:      {}", built.op_id);
    println!("  Signer:     {}", hex::encode(signer_id.0));
    println!("  Nonce:      {}", nonce);
    println!("  Node:       {}", node_url);
    for (label, value) in details {
        println!("  {:<11} {}", format!("{}:", label), value);
    }
    if let Some(response) = response {
        println!();
        println!("  Node response:");
        println!("  {}", response);
    } else {
        println!();
        println!("  Op hex:");
        println!("  {}", built.op_hex);
    }
    println!();
    println!("==========================================");
}

fn fetch_next_nonce(node_url: &str, signer_id: &Bytes32) -> CliResult<u64> {
    fetch_staking_nonce(node_url, &hex::encode(signer_id.0)).map(|nonce| nonce.saturating_add(1))
}

fn load_keys(args: &[String]) -> CliResult<KeysFile> {
    let path = get(args, "--keys").unwrap_or_else(|| DEFAULT_KEYS.to_string());
    indra_cli::load_keys_for_cli(&path, args)
}

fn stake_deposit_proof_from_wallet(
    wallet_path: &str,
    utxo_id: &Bytes32,
) -> CliResult<StakeDepositProof> {
    let wallet = Wallet::load(wallet_path)?;
    match wallet.get(utxo_id) {
        Some(entry) => stake_deposit_proof_from_wallet_entry(entry),
        None => Err(CliError::Transaction(format!(
            "UTXO {} not found in wallet {}; cannot construct stake-deposit proof without value and blinding factor",
            hex::encode(utxo_id.0),
            wallet_path
        ))),
    }
}

fn stake_deposit_proof_from_wallet_entry(entry: &WalletEntry) -> CliResult<StakeDepositProof> {
    if entry.spent {
        return Err(CliError::Transaction(
            "UTXO is already marked spent in wallet; refusing to build stake-deposit proof".into(),
        ));
    }
    if entry.blinding == [0u8; 32] {
        return Err(CliError::Transaction(
            "missing UTXO blinding factor; staking requires the original UTXO blinding factor"
                .into(),
        ));
    }
    Ok(StakeDepositProof {
        committed_value_spark: entry.value_spark,
        blinding_factor: Bytes32::from(entry.blinding),
    })
}

fn get(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|arg| arg == flag)
        .and_then(|idx| args.get(idx + 1))
        .cloned()
}

fn has_help(args: &[String]) -> bool {
    args.iter()
        .any(|arg| arg == "--help" || arg == "-h" || arg == "help")
}

fn parse_commission(args: &[String]) -> CliResult<u32> {
    let raw = required(args, "--commission")?;
    let commission = raw.parse::<u32>().map_err(|_| {
        CliError::Parse("commission must be between 500 and 2000 bps (5% to 20%)".into())
    })?;
    if !(500..=2_000).contains(&commission) {
        return Err(CliError::Parse(
            "commission must be between 500 and 2000 bps (5% to 20%)".into(),
        ));
    }
    Ok(commission)
}

fn parse_required_bytes32(args: &[String], flag: &str) -> CliResult<Bytes32> {
    parse_bytes32(flag, &required(args, flag)?)
}

fn parse_exit_amount(args: &[String]) -> CliResult<u64> {
    indra_cli::parse_indra_amount_to_spark(&required(args, "--amount")?, "--amount")
}

fn parse_bytes32(flag: &str, value: &str) -> CliResult<Bytes32> {
    let bytes = hex::decode(value)
        .map_err(|e| CliError::InvalidHex(format!("invalid hex for {}: {}", flag, e)))?;
    if bytes.len() != 32 {
        return Err(CliError::InvalidHex(format!(
            "invalid hex for {}: expected 32 bytes, got {}",
            flag,
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(Bytes32::from(out))
}

fn required(args: &[String], flag: &str) -> CliResult<String> {
    get(args, flag)
        .ok_or_else(|| CliError::MissingArgument(format!("missing required flag: {flag}")))
}

fn staking_signer_id(keys: &KeysFile) -> CliResult<Bytes32> {
    Ok(validator_id_from_keys(keys))
}

fn validator_id_from_keys(keys: &KeysFile) -> Bytes32 {
    Bytes32::from(keys.public.validator_id)
}

#[cfg(test)]
fn hybrid_pubkey_from_keys(keys: &KeysFile) -> CliResult<HybridPubKey> {
    Ok(HybridPubKey {
        classical_pk: Bytes32::from(keys.public.hybrid_classical_pk),
        pq_pk: VariableBytes::from_slice(&keys.public.hybrid_pq_pk)
            .map_err(|_| CliError::Parse("PQ public key too large".into()))?,
    })
}

fn print_help() {
    println!(
        "INDRA Stake CLI\nUsage: indra-stake <subcommand> [flags]\n\nSubcommands:\n  register                Register a new validator with self-stake\n  self-stake              Add a UTXO to the validator's active position\n  self-unstake            Exit principal from a validator position\n  delegate                Add a UTXO to a delegated position\n  undelegate              Exit principal from a delegated position\n  claim-rewards           Claim pending staking rewards\n  set-commission          Update validator commission rate\n  auto-delegate           Set or clear validator auto-delegation\n  update-network-address  Set or clear validator P2P address\n  nonce                   Query current staking nonce for your key\n\nCommon flags:\n  --keys <path>    Path to keys.json (default: keys.json)\n  --keys-password-file <path>  Password file for encrypted keys.json\n  --node <url>     Node RPC URL (default: http://127.0.0.1:8545)\n  --dry-run        Build and sign but do not submit\n\nRun 'indra-stake <subcommand> --help' for subcommand-specific flags."
    );
}

fn print_register_help() {
    println!("Usage: indra-stake register --commission <bps> --utxo <utxo_id_hex> [--keys keys.json] [--wallet wallet.json] [--node url] [--dry-run]");
}

fn print_self_stake_help() {
    println!("Usage: indra-stake self-stake --utxo <utxo_id_hex> [--keys keys.json] [--wallet wallet.json] [--node url] [--dry-run]");
}

fn print_self_unstake_help() {
    println!("Usage: indra-stake self-unstake --position-id <position_id_hex> --amount <indra> --cold-keys <path> [--keys keys.json] [--cold-keys-password-file path] [--node url] [--dry-run]");
}

fn print_delegate_help() {
    println!("Usage: indra-stake delegate --utxo <utxo_id_hex> --validator <validator_hex> [--keys keys.json] [--wallet wallet.json] [--node url] [--dry-run]");
}

fn print_undelegate_help() {
    println!("Usage: indra-stake undelegate --position-id <position_id_hex> --amount <indra> [--keys keys.json] [--node url] [--dry-run]");
}

fn print_claim_rewards_help() {
    println!("Usage: indra-stake claim-rewards --validator <validator_hex> [--keys keys.json] [--wallet wallet.json] [--node url] [--dry-run]");
}

fn print_set_commission_help() {
    println!("Usage: indra-stake set-commission --commission <bps> [--keys keys.json] [--node url] [--dry-run]");
}

fn print_auto_delegate_help() {
    println!("Usage: indra-stake auto-delegate --validator <validator_hex> --target <target_validator_hex> [--keys keys.json] [--node url] [--dry-run]");
    println!("       indra-stake auto-delegate --validator <validator_hex> --clear [--keys keys.json] [--node url] [--dry-run]");
}

fn print_update_network_address_help() {
    println!("Usage: indra-stake update-network-address --address <ip:port> [--keys keys.json] [--node url] [--dry-run]");
    println!("       indra-stake update-network-address --clear [--keys keys.json] [--node url] [--dry-run]");
}

fn print_nonce_help() {
    println!("Usage: indra-stake nonce [--keys keys.json] [--node url]");
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_cli::{generate_from_master_seed, ColdKeysFile};
    use indra_crypto::hybrid::ColdHybridKeypair;

    #[test]
    fn parse_bytes32_accepts_32_byte_hex() {
        let parsed = parse_bytes32("--utxo", &"11".repeat(32)).unwrap();
        assert_eq!(parsed, Bytes32::from([0x11; 32]));
    }

    #[test]
    fn parse_bytes32_rejects_bad_hex() {
        assert!(parse_bytes32("--utxo", "not-hex").is_err());
    }

    #[test]
    fn parse_commission_accepts_range() {
        let args = vec![
            "indra-stake".to_string(),
            "register".to_string(),
            "--commission".to_string(),
            "1000".to_string(),
        ];
        assert_eq!(parse_commission(&args).unwrap(), 1_000);
    }

    #[test]
    fn parse_commission_rejects_out_of_range() {
        let args = vec![
            "indra-stake".to_string(),
            "register".to_string(),
            "--commission".to_string(),
            "3000".to_string(),
        ];
        assert!(parse_commission(&args).is_err());
    }

    #[test]
    fn auto_delegate_clear_rejects_target() {
        let args = vec![
            "indra-stake".to_string(),
            "auto-delegate".to_string(),
            "--validator".to_string(),
            "11".repeat(32),
            "--target".to_string(),
            "22".repeat(32),
            "--clear".to_string(),
        ];
        assert!(run_auto_delegate(&args).is_err());
    }

    #[test]
    fn update_network_address_clear_rejects_address() {
        let args = vec![
            "indra-stake".to_string(),
            "update-network-address".to_string(),
            "--address".to_string(),
            "203.0.113.20:30303".to_string(),
            "--clear".to_string(),
        ];
        assert!(run_update_network_address(&args).is_err());
    }

    #[test]
    fn update_network_address_requires_address_or_clear() {
        let args = vec![
            "indra-stake".to_string(),
            "update-network-address".to_string(),
        ];
        assert!(run_update_network_address(&args).is_err());
    }

    #[test]
    fn validator_owned_address_update_uses_keys_json_validator_id() {
        let keys = generate_from_master_seed("validator".to_string(), [0xA1; 32]).unwrap();
        let canonical = Bytes32::from(keys.public.validator_id);
        let old_hybrid_encoding_hash = {
            let pubkey = hybrid_pubkey_from_keys(&keys).unwrap();
            Bytes32::from(indra_crypto::sha256(&pubkey.encode_to_vec()))
        };

        assert_eq!(validator_id_from_keys(&keys), canonical);
        assert_eq!(staking_signer_id(&keys).unwrap(), canonical);
        assert_eq!(
            canonical,
            Bytes32::from(indra_crypto::sha256(&keys.public.hybrid_classical_pk))
        );
        assert_ne!(
            canonical, old_hybrid_encoding_hash,
            "the old CLI derivation hashed the encoded hybrid pubkey and does not match live validator_id"
        );
    }

    #[test]
    fn claim_rewards_uses_keys_json_validator_id_for_signer() {
        let keys = generate_from_master_seed("validator".to_string(), [0xB1; 32]).unwrap();
        let keypair = reconstruct_keypair(&keys).unwrap();
        let canonical = validator_id_from_keys(&keys);
        let built = indra_cli::tx_builder::build_claim_rewards_op(
            canonical,
            &keypair,
            1,
            "indra-testnet-1",
        )
        .unwrap();
        let op_bytes = hex::decode(&built.op_hex).unwrap();
        let op = indra_core::types::staking::StakingOp::decode_exact(&op_bytes).unwrap();

        assert_eq!(staking_signer_id(&keys).unwrap(), canonical);
        assert_eq!(op.signer_id(), canonical);
    }
}
