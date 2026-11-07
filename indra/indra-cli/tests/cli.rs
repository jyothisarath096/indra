//! Integration tests for the CLI tools.

use indra_cli::{
    build_claim_rewards_op, build_cold_authorized_staking_op, build_delegate_op,
    build_exit_stake_position_op, build_register_validator_op_with_cold, generate_from_master_seed,
    generate_from_passphrase,
    genesis_cmd::{build_genesis_config, entry_from_keys},
    load_cold_keys,
    query::rpc_call,
    ColdAuthorizedStakingAction, PasswordSource, StakePositionExitSigner,
};
use indra_core::{
    codec::Decode,
    types::{
        crypto::HybridPubKey,
        primitives::{VariableBytes, DUST_LIMIT_SPARK},
        stake_position::PositionCustodyV1,
        staking::StakingOp,
    },
    Bytes32,
};
use indra_crypto::{ClassicalKeypair, HybridKeypair, PqKeypair};
use indra_node::{NodeConfig, NodeEngine};
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn genesis_entry(
    chain_id: &str,
    name: &str,
    keys: &indra_cli::KeysFile,
    stake: u64,
    tag: u8,
) -> indra_cli::GenesisEntry {
    let cold_public = indra_crypto::ColdHybridKeypair::from_independent_seeds(
        [tag; 32],
        [tag.wrapping_add(64); 32],
    )
    .unwrap()
    .public_key();
    let cold = cold_public.as_complete_hybrid();
    let mut entry = entry_from_keys(name, keys, stake);
    entry.cold_hybrid_classical_pk = hex::encode(cold.classical.0);
    entry.cold_hybrid_pq_pk = hex::encode(cold.pq.0);
    let validator_id = Bytes32::from(keys.public.validator_id);
    let vrf = indra_crypto::VrfKeypair::from_seed(&keys.vrf_seed);
    let challenge = indra_core::types::staking::StakingOp::vrf_possession_challenge(
        chain_id,
        &validator_id,
        &Bytes32::from(vrf.public_key()),
        0,
    )
    .unwrap();
    let (output, proof) = indra_crypto::vrf_prove(&vrf, &challenge);
    entry.vrf_possession_output = hex::encode(output.0);
    entry.vrf_possession_proof = hex::encode(proof.0);
    entry
}

fn temp_dir(suffix: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("indra_cli_test_{}_{}", suffix, std::process::id()));
    p
}

fn engine(suffix: &str) -> (NodeEngine, PathBuf) {
    let dir = temp_dir(suffix);
    let config = NodeConfig::local_test(dir.clone());
    (NodeEngine::init(config).unwrap(), dir)
}

fn build_test_genesis(
    chain_id: &str,
    validators: Vec<indra_cli::GenesisEntry>,
) -> indra_cli::GenesisConfig {
    build_genesis_config(chain_id, 1_700_000_000, validators).unwrap()
}

fn write_build_entries(dir: &PathBuf, chain_id: &str) -> Vec<PathBuf> {
    (0..4u8)
        .map(|i| {
            let keys = generate_from_master_seed(format!("build-{i}"), [i + 11; 32]).unwrap();
            let entry = genesis_entry(
                chain_id,
                &format!("build-v{i}"),
                &keys,
                DUST_LIMIT_SPARK * 10,
                i + 91,
            );
            let path = dir.join(format!("entry-{i}.json"));
            std::fs::write(&path, serde_json::to_vec(&entry).unwrap()).unwrap();
            path
        })
        .collect()
}

fn build_command_args(
    chain_id: &str,
    timestamp: u64,
    entries: &[PathBuf],
    output: &PathBuf,
) -> Vec<String> {
    let mut args = vec![
        "build".to_string(),
        "--chain-id".to_string(), chain_id.to_string(),
        "--genesis-timestamp".to_string(), timestamp.to_string(),
    ];
    for entry in entries {
        args.extend(["--validator-entry".to_string(), entry.to_string_lossy().into_owned()]);
    }
    args.extend(["--output".to_string(), output.to_string_lossy().into_owned()]);
    args
}

#[test]
fn genesis_cli_round_trips_and_inspects_all_canonical_roots() {
    let validators = (0..4u8)
        .map(|i| {
            let keys = generate_from_master_seed(format!("genesis-{i}"), [i + 1; 32]).unwrap();
            genesis_entry("indra-cli-roundtrip", &format!("v{i}"), &keys, DUST_LIMIT_SPARK * 10, i + 41)
        })
        .collect();
    let config = build_test_genesis("indra-cli-roundtrip", validators);
    let dir = temp_dir("genesis-roundtrip");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("genesis.toml");
    std::fs::write(&path, config.to_toml()).unwrap();
    let validate = Command::new(env!("CARGO_BIN_EXE_indra-genesis"))
        .args(["validate", "--genesis", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(validate.status.success(), "{}", String::from_utf8_lossy(&validate.stderr));
    let validate_stdout = String::from_utf8_lossy(&validate.stdout);
    assert!(validate_stdout.contains("fingerprint="));
    assert!(validate_stdout.contains("genesis_block_hash="));
    let inspect = Command::new(env!("CARGO_BIN_EXE_indra-genesis"))
        .args(["inspect", "--genesis", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(inspect.status.success(), "{}", String::from_utf8_lossy(&inspect.stderr));
    let output = String::from_utf8_lossy(&inspect.stdout);
    for field in ["chain_id", "validator_count", "seed", "state_root", "snapshot_root", "fingerprint", "genesis_block_hash", "file_sha256"] {
        assert!(output.contains(field), "inspect output missing {field}: {output}");
    }
    assert_eq!(output.matches("share_bps=2500").count(), 4);
    assert!(!output.contains("WARNING: validator"));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn genesis_cli_build_timestamp_warning_is_nonfatal_and_current_time_is_quiet() {
    let chain_id = "indra-cli-timestamp-warning";
    let dir = temp_dir("genesis-timestamp-warning");
    std::fs::create_dir_all(&dir).unwrap();
    let entries = write_build_entries(&dir, chain_id);
    let old_output = dir.join("old.toml");
    let old = Command::new(env!("CARGO_BIN_EXE_indra-genesis"))
        .args(build_command_args(chain_id, 1_700_000_000, &entries, &old_output))
        .output()
        .unwrap();
    assert!(old.status.success(), "{}", String::from_utf8_lossy(&old.stderr));
    assert!(String::from_utf8_lossy(&old.stdout).contains("WARNING: genesis timestamp"));
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let current_output = dir.join("current.toml");
    let current = Command::new(env!("CARGO_BIN_EXE_indra-genesis"))
        .args(build_command_args(chain_id, now, &entries, &current_output))
        .output()
        .unwrap();
    assert!(current.status.success(), "{}", String::from_utf8_lossy(&current.stderr));
    assert!(!String::from_utf8_lossy(&current.stdout).contains("WARNING: genesis timestamp"));
    let _ = std::fs::remove_dir_all(dir);
}

// ── Keygen tests ──────────────────────────────────────────────────────────────

#[test]
fn keygen_all_keys_present() {
    let keys = generate_from_master_seed("TestValidator".to_string(), [0x01u8; 32]).unwrap();
    assert_eq!(keys.name, "TestValidator");
    assert_eq!(keys.public.hybrid_classical_pk.len(), 32);
    assert_eq!(keys.public.vrf_pk.len(), 32);
    assert!(!keys.public.hybrid_pq_pk.is_empty());
}

#[test]
fn keygen_deterministic_from_seed() {
    let k1 = generate_from_master_seed("Deterministic".to_string(), [0xAAu8; 32]).unwrap();
    let k2 = generate_from_master_seed("Deterministic".to_string(), [0xAAu8; 32]).unwrap();
    assert_eq!(k1.public.validator_id, k2.public.validator_id);
    assert_eq!(k1.name, k2.name);
}

#[test]
fn keygen_from_passphrase() {
    let k = generate_from_passphrase("my-testnet-validator", "Alice".to_string()).unwrap();
    let k2 = generate_from_passphrase("my-testnet-validator", "Alice".to_string()).unwrap();
    assert_eq!(k.public.validator_id, k2.public.validator_id);
    assert_eq!(k.name, "Alice");
    // Different passphrase = different key
    let k3 = generate_from_passphrase("other-validator", "Bob".to_string()).unwrap();
    assert_ne!(k.public.validator_id, k3.public.validator_id);
}

#[test]
fn keys_json_is_valid_structure() {
    let keys = generate_from_master_seed("TestValidator".to_string(), [0x01u8; 32]).unwrap();
    let json = indra_cli::encrypt_keys(&keys, b"pw").unwrap();
    // All required fields present
    for field in &[
        "name",
        "validator_id",
        "hybrid_classical_pk",
        "vrf_pk",
        "crypto",
    ] {
        assert!(json.contains(field), "missing: {field}");
    }
}

#[test]
fn keygen_cold_cli_encrypts_preserves_hot_file_and_requires_force_to_overwrite() {
    let dir = temp_dir("cold-command");
    std::fs::create_dir_all(&dir).unwrap();
    let hot_path = dir.join("keys.json");
    let cold_path = dir.join("validator-cold-keys.json");
    let password_path = dir.join("cold-password.txt");
    let hot_contents = b"existing-hot-key-file-must-not-change";
    std::fs::write(&hot_path, hot_contents).unwrap();
    std::fs::write(&password_path, b"test-cold-password\n").unwrap();

    let first = Command::new(env!("CARGO_BIN_EXE_indra-keygen"))
        .args([
            "cold",
            "--output",
            cold_path.to_str().unwrap(),
            "--keys-password-file",
            password_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let stdout = String::from_utf8(first.stdout).unwrap();
    assert!(stdout.contains("Classical PK:"));
    assert!(stdout.contains("PQ PK:"));
    assert_eq!(std::fs::read(&hot_path).unwrap(), hot_contents);
    let loaded = load_cold_keys(
        cold_path.to_str().unwrap(),
        PasswordSource::File {
            path: &password_path,
            reject_permissive: false,
        },
    )
    .unwrap();

    let inspect = Command::new(env!("CARGO_BIN_EXE_indra-keygen"))
        .args(["inspect", "--keys", cold_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        inspect.status.success(),
        "{}",
        String::from_utf8_lossy(&inspect.stderr)
    );
    let inspect_stdout = String::from_utf8(inspect.stdout).unwrap();
    assert!(inspect_stdout.contains("validator cold authority"));
    assert!(inspect_stdout.contains("PQ PK bytes:"));

    assert!(stdout.contains(&hex::encode(loaded.classical_pk)));
    assert!(stdout.contains(&hex::encode(&loaded.pq_pk)));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&cold_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let before = std::fs::read(&cold_path).unwrap();
    let refused = Command::new(env!("CARGO_BIN_EXE_indra-keygen"))
        .args([
            "cold",
            "--output",
            cold_path.to_str().unwrap(),
            "--keys-password-file",
            password_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!refused.status.success());
    assert_eq!(std::fs::read(&cold_path).unwrap(), before);
    assert_eq!(std::fs::read(&hot_path).unwrap(), hot_contents);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn genesis_cli_build_refuses_to_overwrite_existing_output() {
    let chain_id = "indra-cli-build-overwrite";
    let dir = temp_dir("genesis-build-overwrite");
    std::fs::create_dir_all(&dir).unwrap();
    let output = dir.join("genesis.toml");
    let entries = write_build_entries(&dir, chain_id);
    let args = build_command_args(chain_id, 1_700_000_000, &entries, &output);
    let first = Command::new(env!("CARGO_BIN_EXE_indra-genesis")).args(&args).output().unwrap();
    assert!(first.status.success(), "{}", String::from_utf8_lossy(&first.stderr));
    let second = Command::new(env!("CARGO_BIN_EXE_indra-genesis")).args(&args).output().unwrap();
    assert!(!second.status.success());
    assert!(String::from_utf8_lossy(&second.stderr).contains("already exists; refusing to overwrite"));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn genesis_cli_validator_entry_refuses_to_overwrite_existing_output() {
    let dir = temp_dir("validator-entry-overwrite");
    std::fs::create_dir_all(&dir).unwrap();
    let hot = generate_from_master_seed("validator-entry".to_string(), [0x31; 32]).unwrap();
    let hot_path = dir.join("hot.json");
    std::fs::write(&hot_path, indra_cli::encrypt_keys(&hot, b"pw").unwrap()).unwrap();
    let cold_path = dir.join("cold.json");
    indra_cli::generate_cold_keys_file(&cold_path, b"pw", false).unwrap();
    let proof_path = dir.join("proof.json");
    std::fs::write(
        &proof_path,
        r#"{"vrf_possession_output":"00","vrf_possession_proof":"00"}"#,
    )
    .unwrap();
    let output = dir.join("entry.json");
    std::fs::write(&output, b"must remain unchanged").unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_indra-genesis"))
        .args([
            "validator-entry", "--name", "existing", "--stake", "1000000000",
            "--hot-keys", hot_path.to_str().unwrap(), "--cold-file", cold_path.to_str().unwrap(),
            "--vrf-proof", proof_path.to_str().unwrap(), "--output", output.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("already exists; refusing to overwrite"));
    assert_eq!(std::fs::read(&output).unwrap(), b"must remain unchanged");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn genesis_cli_validate_rejects_malformed_manifest() {
    let dir = temp_dir("genesis-validate-malformed");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("bad.toml");
    std::fs::write(&path, "not a genesis manifest").unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_indra-genesis"))
        .args(["validate", "--genesis", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("Error:"));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn genesis_cli_inspect_warns_for_dominant_test_support_manifest() {
    let dir = temp_dir("genesis-inspect-dominant");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("genesis.toml");
    let manifest = indra_node::genesis::test_genesis_toml(
        "indra-cli-dominant",
        &[
            ([0x11; 32], [0x21; 32], [0x31; 32]),
            ([0x12; 32], [0x22; 32], [0x32; 32]),
            ([0x13; 32], [0x23; 32], [0x33; 32]),
            ([0x14; 32], [0x24; 32], [0x34; 32]),
        ],
    )
    .replacen("stake = 1000000000000", "stake = 3000000000000", 1);
    std::fs::write(&path, manifest).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_indra-genesis"))
        .args(["inspect", "--genesis", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    assert!(String::from_utf8_lossy(&result.stdout).contains("WARNING: validator"));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn cold_share_ceremony_verifies_and_recovers_only_encrypted_keys() {
    let dir = temp_dir("cold-share-ceremony");
    let shares_dir = dir.join("shares");
    let rekey_dir = dir.join("rekeyed-shares");
    let verification_receipt = dir.join("rekey-verification.json");
    let recovered = dir.join("recovered-cold.json");
    let password_path = dir.join("cold-password.txt");
    let hot_path = dir.join("hot.json");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(&password_path, b"ceremony-password\n").unwrap();
    let hot = generate_from_master_seed("ceremony-hot".into(), [0x42; 32]).unwrap();
    std::fs::write(
        &hot_path,
        indra_cli::encrypt_keys(&hot, b"ceremony-password").unwrap(),
    )
    .unwrap();

    let generated = Command::new(env!("CARGO_BIN_EXE_indra-keygen"))
        .args([
            "cold",
            "ceremony",
            "--hot-keys",
            hot_path.to_str().unwrap(),
            "--hot-keys-password-file",
            password_path.to_str().unwrap(),
            "--threshold",
            "2",
            "--shares",
            "3",
            "--out-dir",
            shares_dir.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        generated.status.success(),
        "{}",
        String::from_utf8_lossy(&generated.stderr)
    );
    assert!(!shares_dir.join("validator-cold-keys.json").exists());

    let share_1 = shares_dir.join("share-001.json");
    let share_2 = shares_dir.join("share-002.json");
    let manifest: indra_cli::ColdShareManifest =
        serde_json::from_str(&std::fs::read_to_string(shares_dir.join("ceremony.json")).unwrap())
            .unwrap();
    let expected_classical = manifest.cold_classical_pk.clone();
    let expected_pq = manifest.cold_pq_pk.clone();
    let insufficient = Command::new(env!("CARGO_BIN_EXE_indra-keygen"))
        .args([
            "cold",
            "verify",
            "--share",
            share_1.to_str().unwrap(),
            "--hot-keys",
            hot_path.to_str().unwrap(),
            "--expected-cold-classical-pk",
            &expected_classical,
            "--expected-cold-pq-pk",
            &expected_pq,
        ])
        .output()
        .unwrap();
    assert!(!insufficient.status.success());

    let verified = Command::new(env!("CARGO_BIN_EXE_indra-keygen"))
        .args([
            "cold",
            "verify",
            "--share",
            share_1.to_str().unwrap(),
            "--share",
            share_2.to_str().unwrap(),
            "--hot-keys",
            hot_path.to_str().unwrap(),
            "--expected-cold-classical-pk",
            &expected_classical,
            "--expected-cold-pq-pk",
            &expected_pq,
        ])
        .output()
        .unwrap();
    assert!(verified.status.success());

    let rekeyed = Command::new(env!("CARGO_BIN_EXE_indra-keygen"))
        .args([
            "cold",
            "dealer-rekey",
            "--share",
            share_1.to_str().unwrap(),
            "--share",
            share_2.to_str().unwrap(),
            "--hot-keys",
            hot_path.to_str().unwrap(),
            "--hot-keys-password-file",
            password_path.to_str().unwrap(),
            "--expected-cold-classical-pk",
            &expected_classical,
            "--expected-cold-pq-pk",
            &expected_pq,
            "--threshold",
            "2",
            "--shares",
            "3",
            "--out-dir",
            rekey_dir.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        rekeyed.status.success(),
        "{}",
        String::from_utf8_lossy(&rekeyed.stderr)
    );
    assert!(rekey_dir.join("REKEY_PENDING.json").exists());
    assert!(!verification_receipt.exists());

    let rekey_verified = Command::new(env!("CARGO_BIN_EXE_indra-keygen"))
        .args([
            "cold",
            "verify",
            "--share",
            rekey_dir.join("share-001.json").to_str().unwrap(),
            "--share",
            rekey_dir.join("share-002.json").to_str().unwrap(),
            "--hot-keys",
            hot_path.to_str().unwrap(),
            "--expected-cold-classical-pk",
            &expected_classical,
            "--expected-cold-pq-pk",
            &expected_pq,
            "--verification-output",
            verification_receipt.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        rekey_verified.status.success(),
        "{}",
        String::from_utf8_lossy(&rekey_verified.stderr)
    );
    let receipt = std::fs::read_to_string(&verification_receipt).unwrap();
    assert!(receipt.contains("indra-cold-dealer-rekey-verification"));

    let no_ack = Command::new(env!("CARGO_BIN_EXE_indra-keygen"))
        .args([
            "cold",
            "recover",
            "--share",
            share_1.to_str().unwrap(),
            "--share",
            share_2.to_str().unwrap(),
            "--hot-keys",
            hot_path.to_str().unwrap(),
            "--expected-cold-classical-pk",
            &expected_classical,
            "--expected-cold-pq-pk",
            &expected_pq,
            "--output",
            recovered.to_str().unwrap(),
            "--keys-password-file",
            password_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!no_ack.status.success());
    assert!(!recovered.exists());

    let recovery = Command::new(env!("CARGO_BIN_EXE_indra-keygen"))
        .args([
            "cold",
            "recover",
            "--share",
            share_1.to_str().unwrap(),
            "--share",
            share_2.to_str().unwrap(),
            "--hot-keys",
            hot_path.to_str().unwrap(),
            "--expected-cold-classical-pk",
            &expected_classical,
            "--expected-cold-pq-pk",
            &expected_pq,
            "--output",
            recovered.to_str().unwrap(),
            "--keys-password-file",
            password_path.to_str().unwrap(),
            "--acknowledge-destroy-after-use",
        ])
        .output()
        .unwrap();
    assert!(
        recovery.status.success(),
        "{}",
        String::from_utf8_lossy(&recovery.stderr)
    );
    let json = std::fs::read_to_string(&recovered).unwrap();
    assert!(json.contains("indra-cold-keystore"));
    assert!(!json.contains("classical_seed"));
    load_cold_keys(
        recovered.to_str().unwrap(),
        PasswordSource::File {
            path: &password_path,
            reject_permissive: false,
        },
    )
    .unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for path in [share_1, share_2, recovered] {
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
    let _ = std::fs::remove_dir_all(dir);
}

// ── Query tests ───────────────────────────────────────────────────────────────

#[test]
fn query_pipeline() {
    let (e, dir) = engine("query_full");

    let height = rpc_call("indra_getHeight", &[], &e).unwrap();
    assert!(height.summary.contains("0"));

    let info = rpc_call("indra_getChainInfo", &[], &e).unwrap();
    assert!(info.summary.contains("Height:"));

    let mp = rpc_call("indra_getMempoolSize", &[], &e).unwrap();
    assert!(mp.summary.contains("0"));

    let _ = std::fs::remove_dir_all(&dir);
}

// ── End-to-end: keygen → genesis → query ─────────────────────────────────────

#[test]
fn full_testnet_setup_pipeline() {
    // Step 1: Each participant generates their keys
    let alice = generate_from_passphrase("alice-testnet-seed-v1", "alice".to_string()).unwrap();
    let bob = generate_from_passphrase("bob-testnet-seed-v1", "bob".to_string()).unwrap();
    let carol = generate_from_passphrase("carol-testnet-seed-v1", "carol".to_string()).unwrap();
    let dave = generate_from_passphrase("dave-testnet-seed-v1", "dave".to_string()).unwrap();

    // Step 2: Coordinator builds genesis
    let stake = DUST_LIMIT_SPARK * 100;
    let validators = vec![
        genesis_entry("indra-private-testnet-1", "alice", &alice, stake, 21),
        genesis_entry("indra-private-testnet-1", "bob", &bob, stake, 22),
        genesis_entry("indra-private-testnet-1", "carol", &carol, stake, 23),
        genesis_entry("indra-private-testnet-1", "dave", &dave, stake, 24),
    ];

    let config = build_test_genesis("indra-private-testnet-1", validators);

    assert_eq!(config.validators.len(), 4);

    // Step 3: Write keys.json (verify output is valid)
    let alice_json = indra_cli::encrypt_keys(&alice, b"pw").unwrap();
    assert!(alice_json.contains("\"name\": \"alice\""));
    assert!(alice_json.contains("validator_id"));
    assert!(alice_json.contains("crypto"));

    // Step 4: Write genesis.toml
    let toml = config.to_toml();
    assert!(toml.contains("alice"));
    assert!(toml.contains("bob"));
    assert!(toml.contains("carol"));
    assert!(toml.contains("dave"));
    assert!(toml.contains("indra-private-testnet-1"));

    // Step 5: Query a fresh node (verifies RPC works end-to-end)
    let (e, dir) = engine("e2e");
    let result = rpc_call("indra_getChainInfo", &[], &e).unwrap();
    assert!(result.summary.contains("Height:"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_build_and_decode_all_staking_ops() {
    let keypair = HybridKeypair::new(
        ClassicalKeypair::from_seed(&[0x90; 32]),
        PqKeypair::from_seed(&[0x90; 32]).unwrap(),
    );
    let validator_id = Bytes32::from([0xA1; 32]);
    let deposit_utxo_id = Bytes32::from([0xB2; 32]);
    let chain_id = "indra-testnet-1";
    let cold =
        indra_crypto::ColdHybridKeypair::from_independent_seeds([0x91; 32], [0x92; 32]).unwrap();
    let public = keypair.public_key();
    let validator_pubkey = HybridPubKey {
        classical_pk: Bytes32::from(public.classical.0),
        pq_pk: VariableBytes::from_slice(&public.pq.0).unwrap(),
    };
    let built = vec![
        build_register_validator_op_with_cold(
            1_000,
            deposit_utxo_id,
            &keypair,
            &cold,
            &indra_crypto::VrfKeypair::from_seed(&[0xC3; 32]),
            1,
            chain_id,
        )
        .unwrap(),
        build_cold_authorized_staking_op(
            ColdAuthorizedStakingAction::SelfStake {
                deposit_utxo_id,
                validator_pubkey,
            },
            &cold,
            1,
            2,
            chain_id,
        )
        .unwrap(),
        build_delegate_op(validator_id, deposit_utxo_id, &keypair, 4, chain_id).unwrap(),
        build_exit_stake_position_op(
            Bytes32::from([0xD4; 32]),
            500_000,
            PositionCustodyV1::DelegatorIdentity {
                delegator_id: validator_id,
            },
            StakePositionExitSigner::Delegator {
                keypair: &keypair,
                nonce: 5,
            },
            chain_id,
        )
        .unwrap(),
        build_claim_rewards_op(validator_id, &keypair, 6, chain_id).unwrap(),
        build_cold_authorized_staking_op(
            ColdAuthorizedStakingAction::SetCommission {
                validator_id,
                new_commission_bps: 1_250,
            },
            &cold,
            1,
            7,
            chain_id,
        )
        .unwrap(),
    ];

    for (idx, op) in built.iter().enumerate() {
        let bytes = hex::decode(&op.op_hex).unwrap();
        let decoded = StakingOp::decode_exact(&bytes).unwrap();
        assert_eq!(decoded.nonce, [1, 0, 4, 5, 6, 0][idx]);
        assert!(decoded
            .signature
            .classical_sig
            .as_slice()
            .iter()
            .any(|byte| *byte != 0));
        assert!(decoded
            .signature
            .pq_sig
            .as_slice()
            .iter()
            .any(|byte| *byte != 0));
    }
}
