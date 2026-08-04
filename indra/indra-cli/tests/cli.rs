//! Integration tests for the CLI tools.

use indra_cli::{
    build_claim_rewards_op, build_delegate_op, build_exit_stake_position_op,
    build_register_validator_op_with_cold, build_set_commission_op, generate_from_master_seed,
    generate_from_passphrase,
    genesis_cmd::{build_genesis_config, entry_from_keys},
    load_cold_keys,
    query::rpc_call,
    tx_builder::build_self_stake_op,
    PasswordSource, StakePositionExitSigner,
};
use indra_core::{
    codec::Decode,
    types::{
        primitives::DUST_LIMIT_SPARK,
        stake_position::PositionCustodyV1,
        staking::{StakeDepositProof, StakingOp},
    },
    Bytes32,
};
use indra_crypto::{ClassicalKeypair, HybridKeypair, PqKeypair};
use indra_node::{NodeConfig, NodeEngine};
use std::path::PathBuf;
use std::process::Command;

fn genesis_entry(
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
    let json = keys.to_json();
    // All required fields present
    for field in &[
        "name",
        "validator_id",
        "hybrid_classical_pk",
        "vrf_pk",
        "hybrid_seed",
        "WARNING",
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

    let forbidden_plaintext = dir.join("cold-plaintext.json");
    let decrypt = Command::new(env!("CARGO_BIN_EXE_indra-keygen"))
        .args([
            "decrypt",
            "--keys",
            cold_path.to_str().unwrap(),
            "--out",
            forbidden_plaintext.to_str().unwrap(),
            "--password-file",
            password_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!decrypt.status.success());
    assert!(!forbidden_plaintext.exists());
    assert!(String::from_utf8_lossy(&decrypt.stderr)
        .contains("plaintext cold-key export is prohibited"));
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
fn cold_share_ceremony_verifies_and_recovers_only_encrypted_keys() {
    let dir = temp_dir("cold-share-ceremony");
    let shares_dir = dir.join("shares");
    let recovered = dir.join("recovered-cold.json");
    let password_path = dir.join("cold-password.txt");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(&password_path, b"ceremony-password\n").unwrap();
    let validator_id = hex::encode([0x42; 32]);

    let generated = Command::new(env!("CARGO_BIN_EXE_indra-keygen"))
        .args([
            "cold",
            "ceremony",
            "--validator-id",
            &validator_id,
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
    let insufficient = Command::new(env!("CARGO_BIN_EXE_indra-keygen"))
        .args(["cold", "verify", "--share", share_1.to_str().unwrap()])
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
        ])
        .output()
        .unwrap();
    assert!(verified.status.success());

    let no_ack = Command::new(env!("CARGO_BIN_EXE_indra-keygen"))
        .args([
            "cold",
            "recover",
            "--share",
            share_1.to_str().unwrap(),
            "--share",
            share_2.to_str().unwrap(),
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

// ── Genesis tests ─────────────────────────────────────────────────────────────

#[test]
fn genesis_with_4_validators() {
    let stake = DUST_LIMIT_SPARK * 100;
    let validators: Vec<_> = (0..4u8)
        .map(|i| {
            let seed = [i + 1; 32];
            let keys = generate_from_master_seed(format!("v{i}"), seed).unwrap();
            genesis_entry(&format!("v{i}"), &keys, stake, i + 20)
        })
        .collect();

    let config = build_genesis_config("indra-testnet-1", validators).unwrap();

    assert_eq!(config.validators.len(), 4);
    let toml = config.to_toml();
    assert!(toml.contains("indra-testnet-1"));
    assert!(toml.contains("[[validators]]"));
}

#[test]
fn genesis_rejects_3_validators() {
    let stake = DUST_LIMIT_SPARK * 100;
    let validators: Vec<_> = (0..3u8)
        .map(|i| {
            let seed = [i + 1; 32];
            let keys = generate_from_master_seed(format!("v{i}"), seed).unwrap();
            genesis_entry(&format!("v{i}"), &keys, stake, i + 20)
        })
        .collect();

    assert!(build_genesis_config("test", validators).is_err());
}

#[test]
fn genesis_cli_round_trips_and_inspects_all_canonical_roots() {
    let stake = DUST_LIMIT_SPARK * 100;
    let dir = temp_dir("genesis_artifacts");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("genesis.toml");
    let mut command = Command::new(env!("CARGO_BIN_EXE_indra-genesis"));
    command.args([
        "build",
        "--chain-id",
        "indra-testnet-artifact-test",
        "--output",
        path.to_str().unwrap(),
    ]);
    let mut validator_inputs = Vec::new();
    let mut expected_cold_public = Vec::new();
    for i in 0..4u8 {
        let keys = generate_from_master_seed(format!("v{i}"), [i + 1; 32]).unwrap();
        let hot_path = dir.join(format!("hot-{i}.json"));
        std::fs::write(&hot_path, keys.to_json()).unwrap();
        let cold =
            indra_crypto::ColdHybridKeypair::from_independent_seeds([i + 20; 32], [i + 84; 32])
                .unwrap();
        let cold_public = cold.public_key();
        let cold_public = cold_public.as_complete_hybrid();
        let classical_hex = hex::encode(cold_public.classical.0);
        let pq_hex = hex::encode(cold_public.pq.0);
        expected_cold_public.push((classical_hex.clone(), pq_hex.clone()));
        let cold_path = dir.join(format!("cold-{i}.json"));
        if i < 3 {
            let cold_keys = indra_cli::ColdKeysFile {
                classical_seed: [i + 20; 32],
                pq_seed: [i + 84; 32],
                classical_pk: cold_public.classical.0,
                pq_pk: cold_public.pq.0.to_vec(),
            };
            let encrypted = indra_cli::encrypt_cold_keys(&cold_keys, b"test-password").unwrap();
            std::fs::write(&cold_path, encrypted).unwrap();

            let inspect = Command::new(env!("CARGO_BIN_EXE_indra-keygen"))
                .args(["inspect", "--keys", cold_path.to_str().unwrap()])
                .output()
                .unwrap();
            assert!(inspect.status.success());
            let inspected = String::from_utf8(inspect.stdout).unwrap();
            assert!(inspected.contains(&format!("Classical PK:   {classical_hex}")));
            assert!(inspected.contains(&format!("PQ PK:          {pq_hex}")));
        } else {
            let ceremony = indra_cli::ColdShareManifest {
                format: "indra-cold-key-share".into(),
                version: 1,
                ceremony_id: hex::encode([i + 50; 32]),
                created_unix_seconds: 1,
                validator_id: hex::encode(keys.public.validator_id),
                cold_classical_pk: classical_hex,
                cold_pq_pk: pq_hex,
                threshold: 2,
                share_count: 3,
            };
            std::fs::write(&cold_path, serde_json::to_string(&ceremony).unwrap()).unwrap();
        }
        command.arg("--validator").arg(format!(
            "v{i},{stake},{},{}",
            hot_path.display(),
            cold_path.display()
        ));
        validator_inputs.push((hot_path, cold_path));
    }
    let build = command.output().unwrap();
    assert!(
        build.status.success(),
        "{}",
        String::from_utf8_lossy(&build.stderr)
    );
    let manifest = indra_node::parse_genesis_manifest(path.to_str().unwrap()).unwrap();
    for (validator, (classical, pq)) in manifest.validators.iter().zip(&expected_cold_public) {
        assert_eq!(&validator.cold_hybrid_classical_pk, classical);
        assert_eq!(&validator.cold_hybrid_pq_pk, pq);
    }

    let malformed_path = dir.join("cold-malformed.json");
    std::fs::write(&malformed_path, r#"{"format":"not-a-cold-format"}"#).unwrap();
    let malformed_genesis = dir.join("malformed-genesis.toml");
    let mut malformed = Command::new(env!("CARGO_BIN_EXE_indra-genesis"));
    malformed.args([
        "build",
        "--chain-id",
        "indra-testnet-artifact-test",
        "--output",
        malformed_genesis.to_str().unwrap(),
    ]);
    for (index, (hot, cold)) in validator_inputs.iter().enumerate() {
        let cold = if index == 0 { &malformed_path } else { cold };
        malformed.arg("--validator").arg(format!(
            "v{index},{stake},{},{}",
            hot.display(),
            cold.display()
        ));
    }
    let malformed = malformed.output().unwrap();
    assert!(!malformed.status.success());
    assert!(!malformed_genesis.exists());
    assert!(String::from_utf8_lossy(&malformed.stderr).contains("unsupported cold-file format"));

    let validate = Command::new(env!("CARGO_BIN_EXE_indra-genesis"))
        .args(["validate", "--genesis", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        validate.status.success(),
        "{}",
        String::from_utf8_lossy(&validate.stderr)
    );

    let inspect = Command::new(env!("CARGO_BIN_EXE_indra-genesis"))
        .args(["inspect", "--genesis", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        inspect.status.success(),
        "{}",
        String::from_utf8_lossy(&inspect.stderr)
    );
    let stdout = String::from_utf8(inspect.stdout).unwrap();
    for field in [
        "genesis_file_sha256=",
        "genesis_block_hash=",
        "state_root=",
        "consensus_snapshot_root=",
        "reward_economic_snapshot_root=",
        "slash_membership_root=",
    ] {
        assert!(stdout.contains(field), "missing {field} in {stdout}");
    }
    let artifact = |name: &str| {
        stdout
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{name}=")))
            .unwrap_or_else(|| panic!("missing {name} in {stdout}"))
            .to_string()
    };
    let bytes = std::fs::read(&path).unwrap();
    let state = indra_node::build_finalized_genesis_state(Some(path.to_str().unwrap())).unwrap();
    let consensus = state.snapshot_for_consensus_height(1).unwrap();
    let economic = state.reward_economic_snapshot.as_ref().unwrap();
    let slash = state
        .slash_membership_roots
        .iter()
        .find(|record| record.activation_height == 1)
        .unwrap();
    assert_eq!(
        artifact("genesis_file_sha256"),
        hex::encode(indra_crypto::sha256(&bytes))
    );
    assert_eq!(
        artifact("genesis_block_hash"),
        indra_node::genesis::genesis_block_hash().to_string()
    );
    assert_eq!(
        artifact("state_root"),
        indra_state::compute_state_root(&state).to_string()
    );
    assert_eq!(
        artifact("consensus_snapshot_root"),
        consensus.snapshot_root.to_string()
    );
    assert_eq!(
        artifact("reward_economic_snapshot_root"),
        economic.snapshot_root.to_string()
    );
    assert_eq!(
        artifact("slash_membership_root"),
        slash.membership_root.to_string()
    );
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
        genesis_entry("alice", &alice, stake, 21),
        genesis_entry("bob", &bob, stake, 22),
        genesis_entry("carol", &carol, stake, 23),
        genesis_entry("dave", &dave, stake, 24),
    ];

    let config = build_genesis_config("indra-private-testnet-1", validators).unwrap();

    assert_eq!(config.validators.len(), 4);

    // Step 3: Write keys.json (verify output is valid)
    let alice_json = alice.to_json();
    assert!(alice_json.contains("\"name\": \"alice\""));
    assert!(alice_json.contains("validator_id"));
    assert!(alice_json.contains("WARNING"));

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
    let deposit_proof = StakeDepositProof {
        committed_value_spark: 1_000_000,
        blinding_factor: Bytes32::from([0xB2; 32]),
    };
    let chain_id = "indra-testnet-1";
    let built = vec![
        build_register_validator_op_with_cold(
            1_000,
            deposit_utxo_id,
            deposit_proof.clone(),
            &keypair,
            &indra_crypto::ColdHybridKeypair::from_independent_seeds([0x91; 32], [0x92; 32])
                .unwrap(),
            [0xC3; 32],
            1,
            chain_id,
        )
        .unwrap(),
        build_self_stake_op(
            deposit_utxo_id,
            deposit_proof.clone(),
            &keypair,
            2,
            chain_id,
        )
        .unwrap(),
        build_delegate_op(
            validator_id,
            deposit_utxo_id,
            deposit_proof,
            &keypair,
            4,
            chain_id,
        )
        .unwrap(),
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
        build_set_commission_op(validator_id, 1_250, &keypair, 7, chain_id).unwrap(),
    ];

    for (idx, op) in built.iter().enumerate() {
        let bytes = hex::decode(&op.op_hex).unwrap();
        let decoded = StakingOp::decode_exact(&bytes).unwrap();
        assert_eq!(decoded.nonce, [1, 2, 4, 5, 6, 7][idx]);
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
