use std::path::Path;

use indra_cli::{build_genesis_config, entry_from_public_keys, with_cold_file};
use indra_state::{compute_state_root, ChainState};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let result = match args.get(1).map(String::as_str) {
        Some("build") => build(&args[2..]),
        Some("validate") => validate(&args[2..]),
        Some("inspect") => inspect(&args[2..]),
        _ => {
            print_help();
            return;
        }
    };
    if let Err(error) = result {
        eprintln!("Error: {error}");
        std::process::exit(1);
    }
}

fn required(args: &[String], flag: &str) -> Result<String, String> {
    args.iter()
        .position(|arg| arg == flag)
        .and_then(|index| args.get(index + 1))
        .cloned()
        .ok_or_else(|| format!("missing required {flag}"))
}

fn repeated(args: &[String], flag: &str) -> Vec<String> {
    args.iter()
        .enumerate()
        .filter(|(_, arg)| *arg == flag)
        .filter_map(|(index, _)| args.get(index + 1).cloned())
        .collect()
}

fn build(args: &[String]) -> Result<(), String> {
    let chain_id = required(args, "--chain-id")?;
    let f_text = required(args, "--active-slot-coefficient-numerator")?;
    if f_text.is_empty()
        || !f_text.bytes().all(|byte| byte.is_ascii_digit())
        || (f_text.len() > 1 && f_text.starts_with('0'))
    {
        return Err("--active-slot-coefficient-numerator must be canonical ASCII decimal".into());
    }
    let active_slot_coefficient_numerator = f_text
        .parse::<u64>()
        .map_err(|_| "--active-slot-coefficient-numerator is outside u64")?;
    let network_genesis_hash = required(args, "--bitcoin-network-genesis-hash")?;
    let announced_height = required(args, "--bitcoin-height")?
        .parse::<u64>()
        .map_err(|_| "--bitcoin-height must be a u64")?;
    let bitcoin_pow_entropy_header = required(args, "--bitcoin-header")?;
    let minimum_confirmations = required(args, "--bitcoin-minimum-confirmations")?
        .parse::<u32>()
        .map_err(|_| "--bitcoin-minimum-confirmations must be a u32")?;
    let output = required(args, "--output")?;
    let specs = repeated(args, "--validator");
    let mut validators = Vec::with_capacity(specs.len());
    for spec in specs {
        let parts: Vec<&str> = spec.split(',').collect();
        if parts.len() != 4 {
            return Err("--validator must be NAME,STAKE_SPARK,HOT_KEYS_JSON,COLD_FILE_JSON".into());
        }
        let stake = parts[1]
            .parse::<u64>()
            .map_err(|_| format!("invalid stake in validator specification for {}", parts[0]))?;
        let hot_json = std::fs::read_to_string(parts[2])
            .map_err(|error| format!("cannot read hot public metadata {}: {error}", parts[2]))?;
        let (_, public) = indra_cli::inspect_public_metadata(&hot_json)
            .map_err(|error| format!("invalid hot keystore {}: {error}", parts[2]))?;
        let cold_json = std::fs::read_to_string(parts[3])
            .map_err(|error| format!("cannot read cold file {}: {error}", parts[3]))?;
        validators.push(
            with_cold_file(entry_from_public_keys(parts[0], &public, stake), &cold_json)
                .map_err(|error| format!("invalid cold file {}: {error}", parts[3]))?,
        );
    }
    let source = indra_node::genesis::BitcoinPowEntropySourceV1 {
        scheme: 1,
        network_genesis_hash,
        announced_height,
        header_codec: 1,
        extraction_algorithm: 1,
        minimum_confirmations,
        reorg_policy: 1,
    };
    let config = build_genesis_config(
        &chain_id,
        active_slot_coefficient_numerator,
        source,
        bitcoin_pow_entropy_header,
        validators,
    )
    .map_err(|error| error.to_string())?;
    let rendered = config.to_toml();
    indra_node::parse_genesis_manifest_str(&rendered)?;
    if Path::new(&output).exists() {
        return Err(format!("{output} already exists; refusing to overwrite"));
    }
    std::fs::write(&output, rendered).map_err(|error| format!("cannot write {output}: {error}"))?;
    println!("Canonical genesis written to {output}");
    inspect_path(&output)
}

fn validate(args: &[String]) -> Result<(), String> {
    let path = required(args, "--genesis")?;
    let manifest = indra_node::parse_genesis_manifest(&path)?;
    println!(
        "Genesis valid: chain_id={} validators={}",
        manifest.genesis.chain_id,
        manifest.validators.len()
    );
    Ok(())
}

fn inspect(args: &[String]) -> Result<(), String> {
    inspect_path(&required(args, "--genesis")?)
}

fn inspect_path(path: &str) -> Result<(), String> {
    let bytes = std::fs::read(path).map_err(|error| format!("cannot read {path}: {error}"))?;
    let state = indra_node::build_finalized_genesis_state(Some(path))?;
    print_artifacts(&bytes, &state)?;
    Ok(())
}

fn print_artifacts(file_bytes: &[u8], state: &ChainState) -> Result<(), String> {
    let consensus = state
        .snapshot_for_consensus_height(1)
        .map_err(|error| error.to_string())?;
    let economic = state
        .reward_economic_snapshot
        .as_ref()
        .ok_or_else(|| "finalized genesis is missing economic snapshot".to_string())?;
    let slash = state
        .slash_membership_roots
        .iter()
        .find(|record| record.activation_height == 1)
        .ok_or_else(|| "finalized genesis is missing slash-membership root".to_string())?;
    println!(
        "genesis_file_sha256={}",
        hex::encode(indra_crypto::sha256(file_bytes))
    );
    println!(
        "genesis_block_hash={}",
        indra_node::genesis::genesis_block_hash()
    );
    println!("state_root={}", compute_state_root(state));
    println!("consensus_snapshot_root={}", consensus.snapshot_root);
    println!("reward_economic_snapshot_root={}", economic.snapshot_root);
    println!("slash_membership_root={}", slash.membership_root);
    Ok(())
}

fn print_help() {
    println!(
        "Usage:\n  indra-genesis build --chain-id ID --active-slot-coefficient-numerator F \\\n+    --bitcoin-network-genesis-hash HEX32 --bitcoin-height HEIGHT \\\n+    --bitcoin-header HEX80 --bitcoin-minimum-confirmations N --output genesis.toml \\\n+    --validator NAME,STAKE_SPARK,HOT_KEYS_JSON,COLD_FILE_JSON [--validator ...]\n  indra-genesis validate --genesis genesis.toml\n  indra-genesis inspect --genesis genesis.toml"
    );
}
