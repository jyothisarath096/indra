#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use std::{
    fs::{File, OpenOptions},
    io::Write,
    time::{SystemTime, UNIX_EPOCH},
};

use indra_cli::{
    build_genesis_config, holds_at_least_one_third, stake_share_bps, validate_public_export,
    validate_cold_hot_pairing, GenesisEntry,
};
use indra_core::codec::Encode;
use indra_core::types::{
    crypto::HybridPubKey,
    primitives::{Bytes32, VariableBytes},
};
use indra_state::compute_state_root;

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

fn create_new_output(path: &str) -> Result<File, String> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                format!("{path} already exists; refusing to overwrite")
            } else {
                format!("cannot create {path}: {error}")
            }
        })
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let result = match args.get(1).map(String::as_str) {
        Some("create-vrf-proof") => create_vrf_proof(&args[2..]),
        Some("validator-entry") => validator_entry(&args[2..]),
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

fn create_vrf_proof(args: &[String]) -> Result<(), String> {
    let chain_id = required(args, "--chain-id")?;
    let hot_keys = required(args, "--hot-keys")?;
    let output = required(args, "--output")?;
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
    let (output_value, proof) = indra_crypto::vrf_prove(&vrf, &challenge);
    let json = serde_json::json!({
        "vrf_possession_output": hex::encode(output_value.0),
        "vrf_possession_proof": hex::encode(proof.0),
    });
    let mut file = create_new_output(&output)?;
    let encoded = serde_json::to_vec_pretty(&json)
        .map_err(|error| format!("cannot serialize VRF proof: {error}"))?;
    file.write_all(&encoded)
        .map_err(|error| format!("cannot write {output}: {error}"))?;
    println!("Genesis VRF possession proof written to {output}");
    Ok(())
}

fn validator_entry(args: &[String]) -> Result<(), String> {
    for argument in args.iter().filter(|argument| argument.starts_with("--")) {
        if !matches!(argument.as_str(), "--name" | "--stake" | "--chain-id" | "--hot-export" | "--cold-export" | "--vrf-proof" | "--output") {
            return Err(format!("unknown argument {argument}"));
        }
    }
    let name = required(args, "--name")?;
    let chain_id = required(args, "--chain-id")?;
    let stake = required(args, "--stake")?
        .parse::<u64>()
        .map_err(|_| "invalid --stake")?;
    let hot_export = required(args, "--hot-export")?;
    let cold_export = required(args, "--cold-export")?;
    let proof_file = required(args, "--vrf-proof")?;
    let output = required(args, "--output")?;
    let hot = validate_public_export(
        &std::fs::read_to_string(&hot_export).map_err(|error| error.to_string())?,
        &chain_id,
    )
    .map_err(|error| error.to_string())?;
    let cold = validate_public_export(
        &std::fs::read_to_string(&cold_export).map_err(|error| error.to_string())?,
        &chain_id,
    )
    .map_err(|error| error.to_string())?;
    if hot.kind != "hot" || cold.kind != "cold" {
        return Err("validator-entry requires a hot export followed by a cold export".into());
    }
    validate_cold_hot_pairing(&hot, &cold).map_err(|error| error.to_string())?;
    let validator_id = hot.validator_id.clone().ok_or("hot export is missing validator_id")?;
    let hot_classical = hot.hybrid_classical_pk.clone().ok_or("hot export is missing hybrid_classical_pk")?;
    let hot_pq = hot.hybrid_pq_pk.clone().ok_or("hot export is missing hybrid_pq_pk")?;
    let vrf_pk = hot.vrf_pk.clone().ok_or("hot export is missing vrf_pk")?;
    let cold_classical = cold.cold_hybrid_classical_pk.clone().ok_or("cold export is missing cold_hybrid_classical_pk")?;
    let cold_pq = cold.cold_hybrid_pq_pk.clone().ok_or("cold export is missing cold_hybrid_pq_pk")?;
    if hot_classical == cold_classical || hot_pq == cold_pq {
        return Err("hot and cold public keys must not be identical".into());
    }
    let proof: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&proof_file).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let entry_vrf_output = proof
        .get("vrf_possession_output")
        .and_then(|value| value.as_str())
        .ok_or("VRF proof file lacks vrf_possession_output")?
        .to_string();
    let entry_vrf_proof = proof
        .get("vrf_possession_proof")
        .and_then(|value| value.as_str())
        .ok_or("VRF proof file lacks vrf_possession_proof")?
        .to_string();
    let validator_id_bytes: [u8; 32] = hex::decode(&validator_id)
        .map_err(|_| "validator ID is invalid hex")?
        .try_into()
        .map_err(|_| "validator ID has wrong length")?;
    let vrf_pk_bytes: [u8; 32] = hex::decode(&vrf_pk)
        .map_err(|_| "VRF key is invalid hex")?
        .try_into()
        .map_err(|_| "VRF key has wrong length")?;
    let output_bytes: [u8; 64] = hex::decode(&entry_vrf_output)
        .map_err(|_| "VRF proof output is invalid hex")?
        .try_into()
        .map_err(|_| "VRF proof output has wrong length")?;
    let proof_bytes: [u8; 80] = hex::decode(&entry_vrf_proof)
        .map_err(|_| "VRF proof is invalid hex")?
        .try_into()
        .map_err(|_| "VRF proof has wrong length")?;
    let challenge = indra_core::types::staking::StakingOp::vrf_possession_challenge(
        &chain_id,
        &indra_core::Bytes32::from(validator_id_bytes),
        &indra_core::Bytes32::from(vrf_pk_bytes),
        0,
    )
    .map_err(|error| error.to_string())?;
    indra_crypto::vrf_verify(
        &vrf_pk_bytes,
        &challenge,
        &indra_crypto::VrfOutput(output_bytes),
        &indra_crypto::VrfProof(proof_bytes.to_vec()),
    )
    .map_err(|_| "invalid VRF proof for hot export")?;
    let output_value = serde_json::json!({
        "name": name,
        "validator_id": validator_id,
        "hybrid_classical_pk": hot_classical,
        "hybrid_pq_pk": hot_pq,
        "vrf_pk": vrf_pk,
        "vrf_possession_output": entry_vrf_output,
        "vrf_possession_proof": entry_vrf_proof,
        "cold_hybrid_classical_pk": cold_classical,
        "cold_hybrid_pq_pk": cold_pq,
        "cold_key_version": 1,
        "cold_nonce": 0,
        "stake": stake,
    });
    let mut file = create_new_output(&output)?;
    file.write_all(&serde_json::to_vec_pretty(&output_value).map_err(|error| error.to_string())?)
        .map_err(|error| format!("cannot write {output}: {error}"))?;
    Ok(())
}

fn build(args: &[String]) -> Result<(), String> {
    let chain_id = required(args, "--chain-id")?;
    let genesis_timestamp = required(args, "--genesis-timestamp")?
        .parse::<u64>()
        .map_err(|error| format!("invalid --genesis-timestamp: {error}"))?;
    let output = required(args, "--output")?;
    let entries = repeated(args, "--validator-entry")
        .into_iter()
        .map(|path| {
            serde_json::from_str::<GenesisEntry>(
                &std::fs::read_to_string(&path).map_err(|error| error.to_string())?,
            )
            .map_err(|error| format!("invalid validator entry {path}: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let config = build_genesis_config(&chain_id, genesis_timestamp, entries)
        .map_err(|error| error.to_string())?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("cannot read current Unix time: {error}"))?
        .as_secs();
    let difference = genesis_timestamp.abs_diff(now);
    if difference > 86_400 {
        println!(
            "WARNING: genesis timestamp differs from current Unix time by {difference} seconds"
        );
    }
    let mut file = create_new_output(&output)?;
    file.write_all(config.to_toml().as_bytes())
        .map_err(|error| format!("cannot write {output}: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("cannot sync {output}: {error}"))?;
    drop(file);
    match inspect_path(&output) {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = std::fs::remove_file(&output);
            Err(error)
        }
    }
}

fn validate(args: &[String]) -> Result<(), String> {
    let path = required(args, "--genesis")?;
    let state = indra_node::build_finalized_genesis_state(Some(&path))?;
    println!("chain_id={}", state.chain_id);
    println!("validator_count={}", state.validators.active_count());
    println!("fingerprint={}", state.genesis_fingerprint);
    println!(
        "genesis_block_hash={}",
        indra_node::genesis::genesis_block_hash(&state)?
    );
    Ok(())
}

fn inspect(args: &[String]) -> Result<(), String> {
    inspect_path(&required(args, "--genesis")?)
}

fn inspect_path(path: &str) -> Result<(), String> {
    let bytes = std::fs::read(path).map_err(|error| format!("cannot read {path}: {error}"))?;
    let state = indra_node::build_finalized_genesis_state(Some(path))?;
    let snapshot = state
        .snapshot_for_consensus_height(1)
        .map_err(|error| error.to_string())?;
    println!("chain_id={}", state.chain_id);
    println!("validator_count={}", state.validators.active_count());
    println!("seed={}", hex::encode(state.election_seed.0));
    println!(
        "state_root={}",
        compute_state_root(&state).map_err(|error| error.to_string())?
    );
    println!("snapshot_root={}", snapshot.snapshot_root);
    println!("fingerprint={}", state.genesis_fingerprint);
    println!(
        "genesis_block_hash={}",
        indra_node::genesis::genesis_block_hash(&state)?
    );
    println!("file_sha256={}", hex::encode(indra_crypto::sha256(&bytes)));
    let total = state.validators.total_active_stake();
    for validator in state.validators.active_validators() {
        let id_prefix = hex::encode(validator.validator_id.0)[..8].to_string();
        let share = stake_share_bps(validator.stake_spark, total);
        println!(
            "validator name={} id_prefix={} stake_spark={} share_bps={}",
            validator.name, id_prefix, validator.stake_spark, share
        );
        // Manifest validation makes these branches unreachable; return errors instead of panicking.
        let classical_pk = validator.cold_hybrid_classical_pk.ok_or_else(|| {
            format!(
                "internal error: validator {} has no cold classical key",
                validator.name
            )
        })?;
        let pq_pk = validator.cold_hybrid_pq_pk.ok_or_else(|| {
            format!(
                "internal error: validator {} has no cold PQ key",
                validator.name
            )
        })?;
        let owner = HybridPubKey {
            classical_pk: Bytes32::from(classical_pk),
            pq_pk: VariableBytes::from_slice(&pq_pk).map_err(|error| error.to_string())?,
        };
        println!("owner_pubkey_hex={}", hex::encode(owner.encode_to_vec()));
        if holds_at_least_one_third(validator.stake_spark, total) {
            println!(
                "WARNING: validator {} holds >= 1/3 of genesis stake",
                validator.name
            );
        }
    }
    Ok(())
}

fn print_help() {
    println!("Usage:");
    println!("  indra-genesis create-vrf-proof --chain-id ID --hot-keys keys.json --output proof.json [password options]");
    println!("  indra-genesis validator-entry --name NAME --stake SPARK --chain-id ID --hot-export hot.json --cold-export cold.json --vrf-proof proof.json --output entry.json");
    println!("  indra-genesis build --chain-id ID --genesis-timestamp SECONDS --validator-entry A.json --validator-entry B.json --validator-entry C.json --validator-entry D.json --output genesis.toml");
    println!("  indra-genesis validate --genesis genesis.toml");
    println!("  indra-genesis inspect --genesis genesis.toml");
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_cli::{entry_from_keys, keygen::generate_from_master_seed};
    use indra_core::types::primitives::DUST_LIMIT_SPARK;

    fn test_validators(chain_id: &str, count: usize) -> Vec<GenesisEntry> {
        (0..count)
            .map(|i| {
                let keys =
                    generate_from_master_seed(format!("validator-{i}"), [i as u8 + 1; 32]).unwrap();
                let cold_public = indra_crypto::ColdHybridKeypair::from_independent_seeds(
                    [i as u8 + 41; 32],
                    [i as u8 + 81; 32],
                )
                .unwrap()
                .public_key();
                let cold = cold_public.as_complete_hybrid();
                let mut entry =
                    entry_from_keys(&format!("validator-{i}"), &keys, DUST_LIMIT_SPARK * 10);
                entry.cold_hybrid_classical_pk = hex::encode(cold.classical.0);
                entry.cold_hybrid_pq_pk = hex::encode(cold.pq.0);
                let id = indra_core::Bytes32::from(keys.public.validator_id);
                let vrf = indra_crypto::VrfKeypair::from_seed(&keys.vrf_seed);
                let challenge = indra_core::types::staking::StakingOp::vrf_possession_challenge(
                    chain_id,
                    &id,
                    &indra_core::Bytes32::from(vrf.public_key()),
                    0,
                )
                .unwrap();
                let (output, proof) = indra_crypto::vrf_prove(&vrf, &challenge);
                entry.vrf_possession_output = hex::encode(output.0);
                entry.vrf_possession_proof = hex::encode(proof.0);
                entry
            })
            .collect()
    }

    #[test]
    fn genesis_with_4_validators() {
        let config = build_genesis_config(
            "indra-testnet-1",
            1_700_000_000,
            test_validators("indra-testnet-1", 4),
        )
        .unwrap();
        let parsed = indra_node::parse_genesis_manifest_str(&config.to_toml()).unwrap();
        assert_eq!(parsed.validators.len(), 4);
    }

    #[test]
    fn genesis_rejects_3_validators() {
        let error =
            build_genesis_config("test", 1_700_000_000, test_validators("test", 3)).unwrap_err();
        assert_eq!(
            error.to_string(),
            "genesis error: need at least 4 validators for BFT safety"
        );
    }

    #[test]
    fn stake_shares_are_integer_basis_points() {
        assert_eq!(stake_share_bps(25, 100), 2500);
        assert_eq!(stake_share_bps(10, 40), 2500);
        assert!(!holds_at_least_one_third(25, 100));
        assert!(holds_at_least_one_third(3, 6));
        assert!(holds_at_least_one_third(100, 100));
        assert!(holds_at_least_one_third(1, 3));
        assert_eq!(stake_share_bps(u64::MAX, u64::MAX), 10_000);
        assert!(holds_at_least_one_third(u64::MAX, u64::MAX));
    }

    #[test]
    fn below_dust_stake_rejected() {
        let mut validators = test_validators("dust", 4);
        validators[0].stake = 1;
        let error = build_genesis_config("dust", 1_700_000_000, validators).unwrap_err();
        assert_eq!(
            error.to_string(),
            "genesis error: genesis validator validator-0 stake is below dust"
        );
    }

    #[test]
    fn duplicate_validator_id_rejected() {
        let mut validators = test_validators("duplicate", 4);
        validators[1] = validators[0].clone();
        let error = build_genesis_config("duplicate", 1_700_000_000, validators).unwrap_err();
        assert_eq!(
            error.to_string(),
            "genesis error: duplicate genesis validator or key in validator-0"
        );
    }

    #[test]
    fn toml_output_has_all_fields() {
        let config =
            build_genesis_config("fields", 1_700_000_000, test_validators("fields", 4)).unwrap();
        let toml = config.to_toml();
        for field in [
            "chain_id",
            "validator_id",
            "hybrid_classical_pk",
            "hybrid_pq_pk",
            "vrf_pk",
            "vrf_possession_output",
            "vrf_possession_proof",
            "cold_hybrid_classical_pk",
            "cold_hybrid_pq_pk",
            "cold_key_version",
            "cold_nonce",
            "stake",
        ] {
            assert!(toml.contains(field), "missing {field}");
        }
    }

    #[test]
    fn toml_renderer_escapes_operator_text() {
        let chain_id = "indra-\"test\\chain";
        let config =
            build_genesis_config(chain_id, 1_700_000_000, test_validators(chain_id, 4)).unwrap();
        let parsed = indra_node::parse_genesis_manifest_str(&config.to_toml()).unwrap();
        assert_eq!(parsed.genesis.chain_id, chain_id);
    }
}
