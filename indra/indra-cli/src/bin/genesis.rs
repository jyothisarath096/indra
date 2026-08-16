use std::path::Path;
use std::process::Command;

use indra_cli::{build_genesis_config, entry_from_public_keys, with_cold_file};
use indra_state::{compute_state_root, ChainState};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GenesisVrfProofFile {
    vrf_possession_output: String,
    vrf_possession_proof: String,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let result = match args.get(1).map(String::as_str) {
        Some("build") => build(&args[2..]),
        Some("create-vrf-proof") => create_vrf_proof(&args[2..]),
        Some("verify-bitcoin-entropy") => verify_bitcoin_entropy_command(&args[2..]),
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

fn create_vrf_proof(args: &[String]) -> Result<(), String> {
    let chain_id = required(args, "--chain-id")?;
    let hot_keys = required(args, "--hot-keys")?;
    let output = required(args, "--output")?;
    if Path::new(&output).exists() {
        return Err(format!("{output} already exists; refusing to overwrite"));
    }
    let keys = indra_cli::load_keys_for_cli(&hot_keys, args).map_err(|error| error.to_string())?;
    let validator_id = indra_core::Bytes32::from(keys.public.validator_id);
    let vrf = indra_crypto::VrfKeypair::from_seed(&keys.vrf_seed);
    let vrf_pk = indra_core::Bytes32::from(vrf.public_key());
    let challenge = indra_core::types::staking::StakingOp::vrf_possession_challenge(
        &chain_id,
        &validator_id,
        &vrf_pk,
        0,
    )
    .map_err(|error| error.to_string())?;
    let (vrf_output, vrf_proof) = indra_crypto::vrf_prove(&vrf, &challenge);
    let json = serde_json::json!({
        "vrf_possession_output": hex::encode(vrf_output.0),
        "vrf_possession_proof": hex::encode(vrf_proof.0),
    });
    std::fs::write(&output, serde_json::to_vec_pretty(&json).unwrap())
        .map_err(|error| format!("cannot write {output}: {error}"))?;
    println!("Genesis VRF possession proof written to {output}");
    Ok(())
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
    let bitcoin_cli_path = required(args, "--bitcoin-cli")?;
    let specs = repeated(args, "--validator");
    let mut validators = Vec::with_capacity(specs.len());
    for spec in specs {
        let parts: Vec<&str> = spec.split(',').collect();
        if parts.len() != 5 {
            return Err(
                "--validator must be NAME,STAKE_SPARK,HOT_KEYS_JSON,COLD_FILE_JSON,VRF_PROOF_JSON"
                    .into(),
            );
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
        let proof_json = std::fs::read_to_string(parts[4])
            .map_err(|error| format!("cannot read VRF proof file {}: {error}", parts[4]))?;
        let proof: GenesisVrfProofFile = serde_json::from_str(&proof_json)
            .map_err(|error| format!("invalid VRF proof file {}: {error}", parts[4]))?;
        let mut entry =
            with_cold_file(entry_from_public_keys(parts[0], &public, stake), &cold_json)
                .map_err(|error| format!("invalid cold file {}: {error}", parts[3]))?;
        entry.vrf_possession_output = proof.vrf_possession_output;
        entry.vrf_possession_proof = proof.vrf_possession_proof;
        validators.push(entry);
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
    verify_bitcoin_entropy(&config, &bitcoin_cli_path)?;
    let rendered = config.to_toml();
    indra_node::parse_genesis_manifest_str(&rendered)?;
    if Path::new(&output).exists() {
        return Err(format!("{output} already exists; refusing to overwrite"));
    }
    std::fs::write(&output, rendered).map_err(|error| format!("cannot write {output}: {error}"))?;
    println!("Canonical genesis written to {output}");
    inspect_path(&output)
}

fn run_bitcoin_cli(binary: &str, arguments: &[&str]) -> Result<String, String> {
    let output = Command::new(binary)
        .args(arguments)
        .output()
        .map_err(|error| format!("cannot execute Bitcoin Core client {binary}: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "Bitcoin Core RPC command failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_string())
        .map_err(|_| "Bitcoin Core RPC returned non-UTF-8 output".into())
}

fn reverse_hex_digest(display_hex: &str, label: &str) -> Result<String, String> {
    if display_hex.len() != 64
        || !display_hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("Bitcoin Core returned noncanonical {label}"));
    }
    let mut bytes = hex::decode(display_hex).map_err(|_| format!("invalid {label}"))?;
    bytes.reverse();
    Ok(hex::encode(bytes))
}

fn verify_bitcoin_entropy(config: &indra_cli::GenesisConfig, binary: &str) -> Result<(), String> {
    let source = &config.bitcoin_pow_entropy_source;
    let height = source.announced_height.to_string();
    // `getblockhash(height)` returns the block on Bitcoin Core's active
    // most-work chain, so equality here also establishes canonical membership.
    let displayed_hash = run_bitcoin_cli(binary, &["getblockhash", &height])?;
    let actual_header = run_bitcoin_cli(binary, &["getblockheader", &displayed_hash, "false"])?;
    if actual_header != config.bitcoin_pow_entropy_header {
        return Err("claimed Bitcoin entropy header differs from the active most-work-chain block at the announced height".into());
    }
    let header_bytes = hex::decode(&actual_header)
        .map_err(|_| "Bitcoin Core returned a non-hex block header".to_string())?;
    if header_bytes.len() != 80 {
        return Err("Bitcoin Core returned a block header that is not 80 bytes".into());
    }
    let local_hash = indra_crypto::sha256(&indra_crypto::sha256(&header_bytes));
    if hex::encode(local_hash) != reverse_hex_digest(&displayed_hash, "block hash")? {
        return Err(
            "Bitcoin Core's claimed block hash does not match local double-SHA-256 of its header"
                .into(),
        );
    }
    let displayed_genesis = run_bitcoin_cli(binary, &["getblockhash", "0"])?;
    if reverse_hex_digest(&displayed_genesis, "network genesis hash")?
        != source.network_genesis_hash
    {
        return Err("Bitcoin node network genesis does not match the entropy descriptor".into());
    }
    let tip = run_bitcoin_cli(binary, &["getblockcount"])?
        .parse::<u64>()
        .map_err(|_| "Bitcoin Core returned an invalid block count".to_string())?;
    let confirmations = tip
        .checked_sub(source.announced_height)
        .and_then(|depth| depth.checked_add(1))
        .ok_or_else(|| "announced Bitcoin height is above the active-chain tip".to_string())?;
    if confirmations < u64::from(source.minimum_confirmations) {
        return Err(format!(
            "Bitcoin entropy block has {confirmations} confirmations; {} required",
            source.minimum_confirmations
        ));
    }
    Ok(())
}

fn verify_bitcoin_entropy_command(args: &[String]) -> Result<(), String> {
    let path = required(args, "--genesis")?;
    let binary = required(args, "--bitcoin-cli")?;
    let manifest = indra_node::parse_genesis_manifest(&path)?;
    let config = indra_cli::GenesisConfig {
        chain_id: manifest.genesis.chain_id,
        active_slot_coefficient_numerator: manifest.genesis.active_slot_coefficient_numerator,
        bitcoin_pow_entropy_source: manifest.genesis.bitcoin_pow_entropy_source,
        bitcoin_pow_entropy_header: manifest.genesis.bitcoin_pow_entropy_header,
        validators: Vec::new(),
    };
    verify_bitcoin_entropy(&config, &binary)?;
    println!("Bitcoin entropy source verified against the active most-work chain");
    Ok(())
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
        indra_node::genesis::genesis_block_hash(state)?
    );
    println!(
        "genesis_fingerprint={}",
        indra_node::genesis::genesis_fingerprint(state)?
    );
    println!("state_root={}", compute_state_root(state));
    println!("consensus_snapshot_root={}", consensus.snapshot_root);
    println!("reward_economic_snapshot_root={}", economic.snapshot_root);
    println!("slash_membership_root={}", slash.membership_root);
    println!(
        "lifetime_supply_cap_spark={}",
        state.monetary_ledger.lifetime_cap_spark
    );
    println!(
        "genesis_issued_spark={}",
        state.monetary_ledger.genesis_issued_spark
    );
    println!(
        "reward_budget_spark={}",
        state.monetary_ledger.reward_budget_spark
    );
    for position in state.stake_positions.values() {
        if let Some(active) = position.active {
            println!(
                "genesis_stake validator_id={} position_id={} value_spark={}",
                position.validator_id, position.position_id, active.principal_spark
            );
        }
    }
    for entry in state.utxos.all_entries() {
        println!(
            "genesis_utxo utxo_id={} value_spark={} owner_classical_pk={}",
            entry.utxo_id, entry.output.value_spark, entry.output.owner_pubkey.classical_pk
        );
    }
    Ok(())
}

fn print_help() {
    println!("Usage:");
    println!("  indra-genesis build --chain-id ID --active-slot-coefficient-numerator F");
    println!("    --bitcoin-network-genesis-hash HEX32 --bitcoin-height HEIGHT");
    println!("    --bitcoin-header HEX80 --bitcoin-minimum-confirmations N");
    println!("    --bitcoin-cli /path/to/bitcoin-cli --output genesis.toml");
    println!("    --validator NAME,STAKE_SPARK,HOT_KEYS_JSON,COLD_FILE_JSON,VRF_PROOF_JSON [--validator ...]");
    println!("  indra-genesis verify-bitcoin-entropy --genesis genesis.toml --bitcoin-cli /path/to/bitcoin-cli");
    println!("  indra-genesis create-vrf-proof --chain-id ID --hot-keys keys.json --output vrf-proof.json [password options]");
    println!("  indra-genesis validate --genesis genesis.toml");
    println!("  indra-genesis inspect --genesis genesis.toml");
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn config() -> indra_cli::GenesisConfig {
        indra_cli::GenesisConfig {
            chain_id: "test".into(),
            active_slot_coefficient_numerator: 1,
            bitcoin_pow_entropy_source: indra_node::genesis::BitcoinPowEntropySourceV1 {
                scheme: 1,
                network_genesis_hash: "11".repeat(32),
                announced_height: 50,
                header_codec: 1,
                extraction_algorithm: 1,
                minimum_confirmations: 100,
                reorg_policy: 1,
            },
            bitcoin_pow_entropy_header: "22".repeat(80),
            validators: vec![],
        }
    }

    fn mock(tip: u64, header: &str) -> std::path::PathBuf {
        let header_bytes = hex::decode(header).unwrap();
        let mut displayed_block_hash = indra_crypto::sha256(&indra_crypto::sha256(&header_bytes));
        displayed_block_hash.reverse();
        let displayed_block_hash = hex::encode(displayed_block_hash);
        let path = std::env::temp_dir().join(format!(
            "indra-bitcoin-cli-mock-{}-{tip}-{}",
            std::process::id(),
            &header[..2]
        ));
        let script = format!(
            "#!/bin/sh\ncase \"$1:$2\" in\ngetblockhash:0) echo {};;\ngetblockhash:50) echo {};;\ngetblockheader:{}) echo {header};;\ngetblockcount:) echo {tip};;\n*) exit 2;;\nesac\n",
            "11".repeat(32), displayed_block_hash, displayed_block_hash,
        );
        std::fs::write(&path, script).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    #[test]
    fn bitcoin_entropy_verifier_checks_header_active_chain_and_depth() {
        let good = mock(149, &"22".repeat(80));
        assert!(verify_bitcoin_entropy(&config(), good.to_str().unwrap()).is_ok());
        let shallow = mock(148, &"22".repeat(80));
        assert!(verify_bitcoin_entropy(&config(), shallow.to_str().unwrap()).is_err());
        let wrong = mock(149, &"33".repeat(80));
        assert!(verify_bitcoin_entropy(&config(), wrong.to_str().unwrap()).is_err());
        let _ = std::fs::remove_file(good);
        let _ = std::fs::remove_file(shallow);
        let _ = std::fs::remove_file(wrong);
    }
}
