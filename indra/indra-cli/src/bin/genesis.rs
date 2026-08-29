use std::path::Path;
use std::process::Command;

use indra_cli::{build_genesis_config, entry_from_public_keys, with_cold_file};
use indra_core::types::primitives::{
    Bytes32, BITCOIN_GENESIS_CONFIRMATIONS, MIN_GENESIS_PRECOMMIT_BLOCK_LEAD,
};
use indra_state::{compute_state_root, ChainState};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GenesisVrfProofFile {
    vrf_possession_output: String,
    vrf_possession_proof: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ValidatorCommitmentArtifact {
    version: u8,
    commitment: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ValidatorRevealArtifact {
    version: u8,
    commitment: String,
    validator: indra_cli::GenesisEntry,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GenesisPrecommitArtifact {
    version: u8,
    chain_id: String,
    bitcoin_descriptor: indra_node::genesis::BitcoinPowEntropySourceV1,
    validator_commitments: Vec<String>,
    canonical_bytes: String,
    precommit_hash: String,
    created_unix_seconds_informational_only: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GenesisAuthorityArtifact {
    version: u8,
    precommit_hash: String,
    vrf_suite: u8,
    activation_epoch: u64,
    validator_commitments: Vec<String>,
    validators: Vec<indra_cli::GenesisEntry>,
    canonical_bytes: String,
    authority_hash: String,
    bitcoin_tip_at_freeze_informational_only: u64,
    created_unix_seconds_informational_only: u64,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let result = match args.get(1).map(String::as_str) {
        Some("commit-validator") => commit_validator(&args[2..]),
        Some("precommit") => precommit(&args[2..]),
        Some("freeze-authority") => freeze_authority(&args[2..]),
        Some("finalize") => finalize(&args[2..]),
        Some("build") => Err("legacy one-shot genesis build is removed; use commit-validator, precommit, freeze-authority, then finalize".into()),
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

fn entry_to_validator(entry: &indra_cli::GenesisEntry) -> indra_node::GenesisValidator {
    indra_node::GenesisValidator {
        name: entry.name.clone(),
        validator_id: entry.validator_id.clone(),
        hybrid_classical_pk: entry.hybrid_classical_pk.clone(),
        hybrid_pq_pk: entry.hybrid_pq_pk.clone(),
        vrf_pk: entry.vrf_pk.clone(),
        vrf_possession_output: entry.vrf_possession_output.clone(),
        vrf_possession_proof: entry.vrf_possession_proof.clone(),
        cold_hybrid_classical_pk: entry.cold_hybrid_classical_pk.clone(),
        cold_hybrid_pq_pk: entry.cold_hybrid_pq_pk.clone(),
        cold_key_version: entry.cold_key_version,
        cold_nonce: entry.cold_nonce,
        stake: entry.stake,
        genesis_commitment_nonce: entry.genesis_commitment_nonce.clone(),
    }
}

fn write_new_json(path: &str, value: &impl Serialize) -> Result<(), String> {
    if Path::new(path).exists() {
        return Err(format!("{path} already exists; refusing to overwrite"));
    }
    let bytes = serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?;
    std::fs::write(path, bytes).map_err(|e| format!("cannot write {path}: {e}"))
}

#[cfg(unix)]
fn write_new_private_json(path: &str, value: &impl Serialize) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let path = Path::new(path);
    if path.exists() {
        return Err(format!(
            "{} already exists; refusing to overwrite",
            path.display()
        ));
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut suffix = [0u8; 16];
    OsRng.fill_bytes(&mut suffix);
    let temporary = parent.join(format!(".indra-genesis-reveal-{}.tmp", hex::encode(suffix)));
    let bytes = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|error| format!("cannot create {}: {error}", temporary.display()))?;
    if let Err(error) = file.write_all(&bytes).and_then(|()| file.sync_all()) {
        let _ = std::fs::remove_file(&temporary);
        return Err(format!("cannot write {}: {error}", temporary.display()));
    }
    std::fs::rename(&temporary, path).map_err(|error| {
        let _ = std::fs::remove_file(&temporary);
        format!("cannot install {}: {error}", path.display())
    })
}

fn commit_validator(args: &[String]) -> Result<(), String> {
    let chain_id = required(args, "--chain-id")?;
    let spec = required(args, "--validator")?;
    let commitment_output = required(args, "--commitment-output")?;
    let reveal_output = required(args, "--reveal-output")?;
    let parts: Vec<&str> = spec.split(',').collect();
    if parts.len() != 5 {
        return Err(
            "--validator must be NAME,STAKE_SPARK,HOT_KEYS_JSON,COLD_FILE_JSON,VRF_PROOF_JSON"
                .into(),
        );
    }
    let stake = parts[1]
        .parse::<u64>()
        .map_err(|_| "invalid validator stake")?;
    let hot_json = std::fs::read_to_string(parts[2]).map_err(|e| e.to_string())?;
    let (_, public) = indra_cli::inspect_public_metadata(&hot_json).map_err(|e| e.to_string())?;
    let cold_json = std::fs::read_to_string(parts[3]).map_err(|e| e.to_string())?;
    let proof: GenesisVrfProofFile =
        serde_json::from_str(&std::fs::read_to_string(parts[4]).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    let mut entry = with_cold_file(entry_from_public_keys(parts[0], &public, stake), &cold_json)
        .map_err(|e| e.to_string())?;
    entry.vrf_possession_output = proof.vrf_possession_output;
    entry.vrf_possession_proof = proof.vrf_possession_proof;
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    entry.genesis_commitment_nonce = hex::encode(nonce);
    let commitment =
        indra_node::genesis::genesis_validator_commitment(&chain_id, &entry_to_validator(&entry))?;
    let commitment = hex::encode(commitment.0);
    write_new_json(
        &commitment_output,
        &ValidatorCommitmentArtifact {
            version: 1,
            commitment: commitment.clone(),
        },
    )?;
    write_new_private_json(
        &reveal_output,
        &ValidatorRevealArtifact {
            version: 1,
            commitment,
            validator: entry,
        },
    )
}

fn bitcoin_clients(args: &[String]) -> Result<Vec<String>, String> {
    let clients = repeated(args, "--bitcoin-cli");
    if clients.len() < 2 {
        return Err(
            "at least two independently operated --bitcoin-cli clients are required".into(),
        );
    }
    Ok(clients)
}

fn parse_commitment(value: &str) -> Result<Bytes32, String> {
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("commitment must use canonical lowercase hexadecimal".into());
    }
    let bytes = hex::decode(value).map_err(|_| "invalid commitment hex".to_string())?;
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "commitment must be 32 bytes".to_string())?;
    Ok(Bytes32(array))
}

fn agreed_bitcoin_cli(clients: &[String], arguments: &[&str]) -> Result<String, String> {
    let mut agreed: Option<String> = None;
    for client in clients {
        let value = run_bitcoin_cli(client, arguments)?;
        if agreed.as_ref().is_some_and(|old| old != &value) {
            return Err(format!(
                "independent Bitcoin Core nodes disagree on {arguments:?}"
            ));
        }
        agreed = Some(value);
    }
    agreed.ok_or_else(|| "no Bitcoin Core clients".into())
}

fn precommit(args: &[String]) -> Result<(), String> {
    let chain_id = required(args, "--chain-id")?;
    let target = required(args, "--bitcoin-height")?
        .parse::<u64>()
        .map_err(|_| "invalid target height")?;
    let network_genesis_hash = required(args, "--bitcoin-network-genesis-hash")?;
    let clients = bitcoin_clients(args)?;
    let displayed_genesis = agreed_bitcoin_cli(&clients, &["getblockhash", "0"])?;
    if reverse_hex_digest(&displayed_genesis, "network genesis hash")? != network_genesis_hash {
        return Err("Bitcoin node network genesis does not match the precommit descriptor".into());
    }
    let tip = agreed_bitcoin_cli(&clients, &["getblockcount"])?
        .parse::<u64>()
        .map_err(|_| "invalid Bitcoin tip")?;
    let minimum = tip
        .checked_add(MIN_GENESIS_PRECOMMIT_BLOCK_LEAD)
        .ok_or("Bitcoin height overflow")?;
    if target < minimum {
        return Err(format!("target height must be at least current tip + {MIN_GENESIS_PRECOMMIT_BLOCK_LEAD} ({minimum})"));
    }
    let mut commitments = repeated(args, "--validator-commitment")
        .into_iter()
        .map(|path| {
            let value: ValidatorCommitmentArtifact =
                serde_json::from_str(&std::fs::read_to_string(path).map_err(|e| e.to_string())?)
                    .map_err(|e| e.to_string())?;
            if value.version != 1 {
                return Err("unsupported validator commitment version".into());
            }
            Ok(value.commitment)
        })
        .collect::<Result<Vec<String>, String>>()?;
    commitments.sort();
    if commitments.len() < 4 {
        return Err("at least four validator commitments are required".into());
    }
    let source = indra_node::genesis::BitcoinPowEntropySourceV1 {
        scheme: 1,
        network_genesis_hash,
        announced_height: target,
        header_codec: 1,
        extraction_algorithm: 1,
        minimum_confirmations: BITCOIN_GENESIS_CONFIRMATIONS,
        reorg_policy: 1,
    };
    let settings = indra_node::GenesisSettings {
        chain_id: chain_id.clone(),
        active_slot_coefficient_numerator:
            indra_core::types::primitives::MAINNET_ACTIVE_SLOT_COEFFICIENT_NUMERATOR,
        bitcoin_pow_entropy_source: source.clone(),
        bitcoin_pow_entropy_header: String::new(),
        genesis_precommit_hash: String::new(),
    };
    let hashes = commitments
        .iter()
        .map(|value| parse_commitment(value))
        .collect::<Result<Vec<_>, _>>()?;
    let canonical =
        indra_node::genesis::genesis_precommit_bytes_from_commitments(&settings, &hashes)?;
    let hash = indra_node::genesis::genesis_precommit_hash_from_commitments(&settings, &hashes)?;
    let created = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();
    let artifact = GenesisPrecommitArtifact {
        version: 1,
        chain_id,
        bitcoin_descriptor: source,
        validator_commitments: commitments,
        canonical_bytes: hex::encode(canonical),
        precommit_hash: hex::encode(hash.0),
        created_unix_seconds_informational_only: created,
    };
    write_new_json(&required(args, "--output")?, &artifact)
}

fn read_precommit(path: &str) -> Result<GenesisPrecommitArtifact, String> {
    let artifact: GenesisPrecommitArtifact =
        serde_json::from_str(&std::fs::read_to_string(path).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    if artifact.version != 1 {
        return Err("unsupported genesis precommit version".into());
    }
    if artifact
        .validator_commitments
        .windows(2)
        .any(|pair| pair[0] >= pair[1])
    {
        return Err("precommit validator commitments must be strictly ascending".into());
    }
    let settings = indra_node::GenesisSettings {
        chain_id: artifact.chain_id.clone(),
        active_slot_coefficient_numerator:
            indra_core::types::primitives::MAINNET_ACTIVE_SLOT_COEFFICIENT_NUMERATOR,
        bitcoin_pow_entropy_source: artifact.bitcoin_descriptor.clone(),
        bitcoin_pow_entropy_header: String::new(),
        genesis_precommit_hash: String::new(),
    };
    let hashes = artifact
        .validator_commitments
        .iter()
        .map(|value| parse_commitment(value))
        .collect::<Result<Vec<_>, _>>()?;
    let bytes = indra_node::genesis::genesis_precommit_bytes_from_commitments(&settings, &hashes)?;
    let hash = indra_node::genesis::genesis_precommit_hash_from_commitments(&settings, &hashes)?;
    if hex::encode(&bytes) != artifact.canonical_bytes
        || hex::encode(hash.0) != artifact.precommit_hash
    {
        return Err("precommit canonical bytes/hash mismatch".into());
    }
    Ok(artifact)
}

fn open_validator_reveals(
    artifact: &GenesisPrecommitArtifact,
    reveal_paths: Vec<String>,
) -> Result<(Vec<indra_cli::GenesisEntry>, Vec<String>), String> {
    let mut validators = Vec::new();
    let mut opened = Vec::new();
    for path in reveal_paths {
        let reveal: ValidatorRevealArtifact =
            serde_json::from_str(&std::fs::read_to_string(path).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
        if reveal.version != 1 {
            return Err("unsupported validator reveal version".into());
        }
        let commitment = indra_node::genesis::genesis_validator_commitment(
            &artifact.chain_id,
            &entry_to_validator(&reveal.validator),
        )?;
        if hex::encode(commitment.0) != reveal.commitment {
            return Err("validator reveal does not open its commitment".into());
        }
        opened.push(reveal.commitment.clone());
        validators.push(reveal.validator);
    }
    opened.sort();
    let mut expected = artifact.validator_commitments.clone();
    expected.sort();
    if opened != expected {
        return Err("validator reveal membership does not exactly match precommitment".into());
    }
    validators.sort_by(|left, right| left.validator_id.cmp(&right.validator_id));
    Ok((validators, opened))
}

fn authority_canonical_bytes(
    precommit_hash: &str,
    commitments: &[String],
    bitcoin_tip_at_freeze: u64,
) -> Result<Vec<u8>, String> {
    let precommit = parse_commitment(precommit_hash)?;
    let mut commitments = commitments
        .iter()
        .map(|value| parse_commitment(value))
        .collect::<Result<Vec<_>, _>>()?;
    commitments.sort_by_key(|value| value.0);
    if commitments.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err("duplicate frozen validator commitment".into());
    }
    let mut bytes = b"INDRA-GENESIS-AUTHORITY-FROZEN-v1".to_vec();
    bytes.push(1);
    bytes.extend_from_slice(&precommit.0);
    bytes.extend_from_slice(&bitcoin_tip_at_freeze.to_le_bytes());
    bytes.push(1); // VrfSuiteV1::EcvrfEdwards25519Sha512Ell2
    bytes.extend_from_slice(&0u64.to_le_bytes()); // genesis activation epoch
    bytes.extend_from_slice(
        &u16::try_from(commitments.len())
            .map_err(|_| "too many frozen validator commitments")?
            .to_be_bytes(),
    );
    for commitment in commitments {
        bytes.extend_from_slice(&commitment.0);
    }
    Ok(bytes)
}

fn freeze_authority(args: &[String]) -> Result<(), String> {
    let artifact = read_precommit(&required(args, "--precommit")?)?;
    let clients = bitcoin_clients(args)?;
    let tip = agreed_bitcoin_cli(&clients, &["getblockcount"])?
        .parse::<u64>()
        .map_err(|_| "invalid Bitcoin tip")?;
    if tip >= artifact.bitcoin_descriptor.announced_height {
        return Err("cannot freeze genesis authority after the Bitcoin target exists".into());
    }
    let (validators, opened) =
        open_validator_reveals(&artifact, repeated(args, "--validator-reveal"))?;

    // Independently run the complete genesis authority validator before the
    // target. The zero header is only a structurally valid placeholder; it is
    // replaced deterministically by the committed-height header at finalize.
    let provisional = build_genesis_config(
        &artifact.chain_id,
        artifact.bitcoin_descriptor.clone(),
        hex::encode([0u8; 80]),
        artifact.precommit_hash.clone(),
        validators.clone(),
    )
    .map_err(|error| error.to_string())?;
    indra_node::parse_genesis_manifest_str(&provisional.to_toml())?;

    let canonical = authority_canonical_bytes(&artifact.precommit_hash, &opened, tip)?;
    let authority_hash = indra_crypto::sha256(&canonical);
    let created = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_secs();
    let frozen = GenesisAuthorityArtifact {
        version: 1,
        precommit_hash: artifact.precommit_hash,
        vrf_suite: 1,
        activation_epoch: 0,
        validator_commitments: opened,
        validators,
        canonical_bytes: hex::encode(canonical),
        authority_hash: hex::encode(authority_hash),
        bitcoin_tip_at_freeze_informational_only: tip,
        created_unix_seconds_informational_only: created,
    };
    write_new_json(&required(args, "--output")?, &frozen)
}

fn read_frozen_authority(
    path: &str,
    precommit: &GenesisPrecommitArtifact,
) -> Result<GenesisAuthorityArtifact, String> {
    let frozen: GenesisAuthorityArtifact =
        serde_json::from_str(&std::fs::read_to_string(path).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    if frozen.version != 1 {
        return Err("unsupported frozen genesis authority version".into());
    }
    if frozen.vrf_suite != 1 || frozen.activation_epoch != 0 {
        return Err("unsupported frozen genesis VRF suite or activation epoch".into());
    }
    if frozen.precommit_hash != precommit.precommit_hash
        || frozen.validator_commitments != precommit.validator_commitments
    {
        return Err("frozen authority does not match the original precommitment".into());
    }
    if frozen.bitcoin_tip_at_freeze_informational_only
        >= precommit.bitcoin_descriptor.announced_height
    {
        return Err("frozen authority records a Bitcoin tip at or beyond the target".into());
    }
    if frozen
        .validators
        .windows(2)
        .any(|pair| pair[0].validator_id >= pair[1].validator_id)
    {
        return Err("frozen validators must be strictly ordered by validator ID".into());
    }
    let mut actual_commitments = frozen
        .validators
        .iter()
        .map(|validator| {
            indra_node::genesis::genesis_validator_commitment(
                &precommit.chain_id,
                &entry_to_validator(validator),
            )
            .map(|commitment| hex::encode(commitment.0))
        })
        .collect::<Result<Vec<_>, _>>()?;
    actual_commitments.sort();
    if actual_commitments != frozen.validator_commitments {
        return Err("frozen validator material does not open the committed set".into());
    }
    let canonical = authority_canonical_bytes(
        &frozen.precommit_hash,
        &frozen.validator_commitments,
        frozen.bitcoin_tip_at_freeze_informational_only,
    )?;
    if frozen.canonical_bytes != hex::encode(&canonical)
        || frozen.authority_hash != hex::encode(indra_crypto::sha256(&canonical))
    {
        return Err("frozen authority canonical bytes/hash mismatch".into());
    }
    if frozen.validators.len() != frozen.validator_commitments.len() {
        return Err("frozen authority membership is incomplete".into());
    }
    Ok(frozen)
}

fn finalize(args: &[String]) -> Result<(), String> {
    if args.iter().any(|argument| argument == "--validator-reveal") {
        return Err("finalize accepts no validator reveals; authority must be frozen before the Bitcoin target".into());
    }
    let artifact = read_precommit(&required(args, "--precommit")?)?;
    let frozen = read_frozen_authority(&required(args, "--authority")?, &artifact)?;
    let clients = bitcoin_clients(args)?;
    let height = artifact.bitcoin_descriptor.announced_height.to_string();
    let displayed_hash = agreed_bitcoin_cli(&clients, &["getblockhash", &height])?;
    let header = agreed_bitcoin_cli(&clients, &["getblockheader", &displayed_hash, "false"])?;
    let config = build_genesis_config(
        &artifact.chain_id,
        artifact.bitcoin_descriptor,
        header,
        artifact.precommit_hash,
        frozen.validators,
    )
    .map_err(|e| e.to_string())?;
    verify_bitcoin_entropy_multi(&config, &clients)?;
    let rendered = config.to_toml();
    indra_node::parse_genesis_manifest_str(&rendered)?;
    let output = required(args, "--output")?;
    if Path::new(&output).exists() {
        return Err(format!("{output} already exists; refusing to overwrite"));
    }
    std::fs::write(&output, rendered).map_err(|e| e.to_string())?;
    println!("Canonical committed genesis written to {output}");
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

fn verify_bitcoin_entropy_multi(
    config: &indra_cli::GenesisConfig,
    clients: &[String],
) -> Result<(), String> {
    let height = config
        .bitcoin_pow_entropy_source
        .announced_height
        .to_string();
    let displayed_hash = agreed_bitcoin_cli(clients, &["getblockhash", &height])?;
    let _ = agreed_bitcoin_cli(clients, &["getblockheader", &displayed_hash, "false"])?;
    let _ = agreed_bitcoin_cli(clients, &["getblockhash", "0"])?;
    let _ = agreed_bitcoin_cli(clients, &["getblockcount"])?;
    for client in clients {
        verify_bitcoin_entropy(config, client)?;
    }
    Ok(())
}

fn verify_bitcoin_entropy_command(args: &[String]) -> Result<(), String> {
    let path = required(args, "--genesis")?;
    let clients = bitcoin_clients(args)?;
    let manifest = indra_node::parse_genesis_manifest(&path)?;
    let config = indra_cli::GenesisConfig {
        chain_id: manifest.genesis.chain_id,
        active_slot_coefficient_numerator: manifest.genesis.active_slot_coefficient_numerator,
        bitcoin_pow_entropy_source: manifest.genesis.bitcoin_pow_entropy_source,
        bitcoin_pow_entropy_header: manifest.genesis.bitcoin_pow_entropy_header,
        genesis_precommit_hash: manifest.genesis.genesis_precommit_hash,
        validators: Vec::new(),
    };
    verify_bitcoin_entropy_multi(&config, &clients)?;
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
    println!("  indra-genesis commit-validator --chain-id ID --validator NAME,STAKE,HOT,COLD,VRF_PROOF --commitment-output public.json --reveal-output private.json");
    println!("  indra-genesis precommit --chain-id ID --bitcoin-network-genesis-hash HEX32 --bitcoin-height FUTURE_HEIGHT --bitcoin-cli NODE_A --bitcoin-cli NODE_B --validator-commitment public.json --output precommit.json");
    println!("  indra-genesis freeze-authority --precommit precommit.json --bitcoin-cli NODE_A --bitcoin-cli NODE_B --validator-reveal private.json --output authority.json");
    println!("  indra-genesis finalize --precommit precommit.json --authority authority.json --bitcoin-cli NODE_A --bitcoin-cli NODE_B --output genesis.toml");
    println!("  indra-genesis verify-bitcoin-entropy --genesis genesis.toml --bitcoin-cli NODE_A --bitcoin-cli NODE_B");
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
            active_slot_coefficient_numerator:
                indra_core::types::primitives::MAINNET_ACTIVE_SLOT_COEFFICIENT_NUMERATOR,
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
            genesis_precommit_hash: "33".repeat(32),
            validators: vec![],
        }
    }

    #[test]
    fn declared_confirmation_depth_is_exactly_100() {
        let mut cfg = config();
        cfg.bitcoin_pow_entropy_source.minimum_confirmations = 99;
        assert!(
            indra_node::genesis::derive_genesis_election_seed(&indra_node::GenesisSettings {
                chain_id: cfg.chain_id.clone(),
                active_slot_coefficient_numerator: cfg.active_slot_coefficient_numerator,
                bitcoin_pow_entropy_source: cfg.bitcoin_pow_entropy_source.clone(),
                bitcoin_pow_entropy_header: cfg.bitcoin_pow_entropy_header.clone(),
                genesis_precommit_hash: cfg.genesis_precommit_hash.clone()
            })
            .is_err()
        );
        cfg.bitcoin_pow_entropy_source.minimum_confirmations = 101;
        assert!(
            indra_node::genesis::derive_genesis_election_seed(&indra_node::GenesisSettings {
                chain_id: cfg.chain_id.clone(),
                active_slot_coefficient_numerator: cfg.active_slot_coefficient_numerator,
                bitcoin_pow_entropy_source: cfg.bitcoin_pow_entropy_source.clone(),
                bitcoin_pow_entropy_header: cfg.bitcoin_pow_entropy_header.clone(),
                genesis_precommit_hash: cfg.genesis_precommit_hash.clone()
            })
            .is_err()
        );
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
