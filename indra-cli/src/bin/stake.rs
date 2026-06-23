//! `indra-stake` — build and submit staking operations.

use indra_cli::{
    fetch_chain_id, fetch_staking_nonce, reconstruct_keypair, submit_staking_op, BuiltStakingOp,
    CliError, CliResult, KeysFile, Wallet,
};
use indra_core::{
    codec::Encode,
    types::{
        crypto::HybridPubKey,
        primitives::{Bytes32, VariableBytes},
    },
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
    let commission_bps = parse_commission(args)?;
    let signer_id = staking_signer_id(&keys)?;
    let node_url = get(args, "--node").unwrap_or_else(|| DEFAULT_NODE.to_string());
    let chain_id = fetch_chain_id(&node_url)?;
    let nonce = fetch_next_nonce(&node_url, &signer_id)?;
    let built = indra_cli::tx_builder::build_register_validator_op(
        commission_bps,
        &keypair,
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
        &[("Commission", format!("{} bps", commission_bps))],
        None,
    )
}

fn run_self_stake(args: &[String]) -> CliResult<()> {
    if has_help(args) {
        print_self_stake_help();
        return Ok(());
    }
    let keys = load_keys(args)?;
    let keypair = reconstruct_keypair(&keys)?;
    let bond_utxo_id = parse_required_bytes32(args, "--utxo")?;
    let wallet_path = get(args, "--wallet").unwrap_or_else(|| DEFAULT_WALLET.to_string());
    warn_if_wallet_utxo_unavailable(&wallet_path, &bond_utxo_id)?;
    let signer_id = staking_signer_id(&keys)?;
    let node_url = get(args, "--node").unwrap_or_else(|| DEFAULT_NODE.to_string());
    let chain_id = fetch_chain_id(&node_url)?;
    let nonce = fetch_next_nonce(&node_url, &signer_id)?;
    let built =
        indra_cli::tx_builder::build_self_stake_op(bond_utxo_id, &keypair, nonce, &chain_id)?;
    finish_op(
        args,
        "self-stake",
        &built,
        &signer_id,
        nonce,
        &node_url,
        &[("Bond UTXO", hex::encode(bond_utxo_id.0))],
        Some((&wallet_path, bond_utxo_id)),
    )
}

fn run_self_unstake(args: &[String]) -> CliResult<()> {
    if has_help(args) {
        print_self_unstake_help();
        return Ok(());
    }
    let keys = load_keys(args)?;
    let keypair = reconstruct_keypair(&keys)?;
    let bond_utxo_id = parse_required_bytes32(args, "--utxo")?;
    let signer_id = staking_signer_id(&keys)?;
    let node_url = get(args, "--node").unwrap_or_else(|| DEFAULT_NODE.to_string());
    let chain_id = fetch_chain_id(&node_url)?;
    let nonce = fetch_next_nonce(&node_url, &signer_id)?;
    let built =
        indra_cli::tx_builder::build_self_unstake_op(bond_utxo_id, &keypair, nonce, &chain_id)?;
    finish_op(
        args,
        "self-unstake",
        &built,
        &signer_id,
        nonce,
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
    let bond_utxo_id = parse_required_bytes32(args, "--utxo")?;
    let validator_id = parse_required_bytes32(args, "--validator")?;
    let wallet_path = get(args, "--wallet").unwrap_or_else(|| DEFAULT_WALLET.to_string());
    warn_if_wallet_utxo_unavailable(&wallet_path, &bond_utxo_id)?;
    let signer_id = staking_signer_id(&keys)?;
    let node_url = get(args, "--node").unwrap_or_else(|| DEFAULT_NODE.to_string());
    let chain_id = fetch_chain_id(&node_url)?;
    let nonce = fetch_next_nonce(&node_url, &signer_id)?;
    let built = indra_cli::tx_builder::build_delegate_op(
        validator_id,
        bond_utxo_id,
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
            ("Bond UTXO", hex::encode(bond_utxo_id.0)),
        ],
        Some((&wallet_path, bond_utxo_id)),
    )
}

fn run_undelegate(args: &[String]) -> CliResult<()> {
    if has_help(args) {
        print_undelegate_help();
        return Ok(());
    }
    let keys = load_keys(args)?;
    let keypair = reconstruct_keypair(&keys)?;
    let bond_utxo_id = parse_required_bytes32(args, "--utxo")?;
    let validator_id = parse_required_bytes32(args, "--validator")?;
    let signer_id = staking_signer_id(&keys)?;
    let node_url = get(args, "--node").unwrap_or_else(|| DEFAULT_NODE.to_string());
    let chain_id = fetch_chain_id(&node_url)?;
    let nonce = fetch_next_nonce(&node_url, &signer_id)?;
    let built = indra_cli::tx_builder::build_undelegate_op(
        validator_id,
        bond_utxo_id,
        &keypair,
        nonce,
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
            ("Validator", hex::encode(validator_id.0)),
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
    let validator_id = staking_signer_id(&keys)?;
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
    KeysFile::load(&path)
}

fn warn_if_wallet_utxo_unavailable(wallet_path: &str, utxo_id: &Bytes32) -> CliResult<()> {
    let wallet = Wallet::load(wallet_path)?;
    match wallet.get(utxo_id) {
        Some(entry) if entry.spent => {
            eprintln!("Warning: UTXO is already marked spent in wallet - proceeding anyway");
        }
        Some(_) => {}
        None => {
            eprintln!("Warning: UTXO not found in wallet - proceeding anyway");
        }
    }
    Ok(())
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
    let pubkey = hybrid_pubkey_from_keys(keys)?;
    Ok(Bytes32::from(indra_crypto::sha256(&pubkey.encode_to_vec())))
}

fn hybrid_pubkey_from_keys(keys: &KeysFile) -> CliResult<HybridPubKey> {
    Ok(HybridPubKey {
        classical_pk: Bytes32::from(keys.public.hybrid_classical_pk),
        pq_pk: VariableBytes::from_slice(&keys.public.hybrid_pq_pk)
            .map_err(|_| CliError::Parse("PQ public key too large".into()))?,
    })
}

fn print_help() {
    println!(
        "INDRA Stake CLI\nUsage: indra-stake <subcommand> [flags]\n\nSubcommands:\n  register         Register a new validator\n  self-stake       Bond one of your UTXOs as self-stake\n  self-unstake     Begin unbonding a self-stake bond\n  delegate         Delegate a UTXO to a validator\n  undelegate       Begin undelegating from a validator\n  claim-rewards    Claim pending staking rewards\n  set-commission   Update validator commission rate\n  auto-delegate    Set or clear validator auto-delegation\n  nonce            Query current staking nonce for your key\n\nCommon flags:\n  --keys <path>    Path to keys.json (default: keys.json)\n  --node <url>     Node RPC URL (default: http://127.0.0.1:8545)\n  --dry-run        Build and sign but do not submit\n\nRun 'indra-stake <subcommand> --help' for subcommand-specific flags."
    );
}

fn print_register_help() {
    println!("Usage: indra-stake register --commission <bps> [--keys keys.json] [--node url] [--dry-run]");
}

fn print_self_stake_help() {
    println!("Usage: indra-stake self-stake --utxo <utxo_id_hex> [--keys keys.json] [--wallet wallet.json] [--node url] [--dry-run]");
}

fn print_self_unstake_help() {
    println!("Usage: indra-stake self-unstake --utxo <utxo_id_hex> [--keys keys.json] [--node url] [--dry-run]");
}

fn print_delegate_help() {
    println!("Usage: indra-stake delegate --utxo <utxo_id_hex> --validator <validator_hex> [--keys keys.json] [--wallet wallet.json] [--node url] [--dry-run]");
}

fn print_undelegate_help() {
    println!("Usage: indra-stake undelegate --utxo <utxo_id_hex> --validator <validator_hex> [--keys keys.json] [--node url] [--dry-run]");
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

fn print_nonce_help() {
    println!("Usage: indra-stake nonce [--keys keys.json] [--node url]");
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
