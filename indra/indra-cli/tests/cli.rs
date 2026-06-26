//! Integration tests for the CLI tools.

use indra_cli::{
    build_claim_rewards_op, build_delegate_op, build_register_validator_op,
    build_set_commission_op, build_undelegate_op, generate_from_passphrase, generate_keypairs,
    genesis_cmd::{build_genesis_config, entry_from_keys},
    query::rpc_call,
    tx_builder::{build_self_stake_op, build_self_unstake_op},
};
use indra_core::{
    codec::Decode,
    types::{primitives::DUST_LIMIT_SPARK, staking::StakingOp},
    Bytes32,
};
use indra_crypto::{ClassicalKeypair, HybridKeypair, PqKeypair};
use indra_node::{NodeConfig, NodeEngine};
use std::path::PathBuf;

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
    let keys = generate_keypairs(
        "TestValidator".to_string(),
        [0x01u8; 32],
        [0x02u8; 32],
        [0x03u8; 32],
    )
    .unwrap();
    assert_eq!(keys.name, "TestValidator");
    assert_eq!(keys.public.hybrid_classical_pk.len(), 32);
    assert_eq!(keys.public.bls_pk.len(), 48);
    assert_eq!(keys.public.vrf_pk.len(), 32);
    assert!(!keys.public.hybrid_pq_pk.is_empty());
}

#[test]
fn keygen_deterministic_from_seed() {
    let k1 = generate_keypairs(
        "Deterministic".to_string(),
        [0xAAu8; 32],
        [0xBBu8; 32],
        [0xCCu8; 32],
    )
    .unwrap();
    let k2 = generate_keypairs(
        "Deterministic".to_string(),
        [0xAAu8; 32],
        [0xBBu8; 32],
        [0xCCu8; 32],
    )
    .unwrap();
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
    let keys = generate_keypairs(
        "TestValidator".to_string(),
        [0x01u8; 32],
        [0x02u8; 32],
        [0x03u8; 32],
    )
    .unwrap();
    let json = keys.to_json();
    // All required fields present
    for field in &[
        "name",
        "validator_id",
        "hybrid_classical_pk",
        "bls_pk",
        "vrf_pk",
        "hybrid_seed",
        "WARNING",
    ] {
        assert!(json.contains(field), "missing: {field}");
    }
}

// ── Genesis tests ─────────────────────────────────────────────────────────────

#[test]
fn genesis_with_4_validators() {
    let stake = DUST_LIMIT_SPARK * 100;
    let validators: Vec<_> = (0..4u8)
        .map(|i| {
            let seed = [i + 1; 32];
            let keys = generate_keypairs(format!("v{i}"), seed, seed, seed).unwrap();
            entry_from_keys(&format!("v{i}"), &keys, stake)
        })
        .collect();

    let config = build_genesis_config(
        "indra-testnet-1",
        1_700_000_000,
        1_000_000_000_000_000,
        validators,
    )
    .unwrap();

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
            let keys = generate_keypairs(format!("v{i}"), seed, seed, seed).unwrap();
            entry_from_keys(&format!("v{i}"), &keys, stake)
        })
        .collect();

    assert!(build_genesis_config("test", 0, 0, validators).is_err());
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
        entry_from_keys("alice", &alice, stake),
        entry_from_keys("bob", &bob, stake),
        entry_from_keys("carol", &carol, stake),
        entry_from_keys("dave", &dave, stake),
    ];

    let config = build_genesis_config(
        "indra-private-testnet-1",
        1_700_000_000,
        1_000_000_000_000_000,
        validators,
    )
    .unwrap();

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
    let bond_utxo_id = Bytes32::from([0xB2; 32]);
    let chain_id = "indra-testnet-1";
    let built = vec![
        build_register_validator_op(1_000, &keypair, [0xC3; 32], 1, chain_id).unwrap(),
        build_self_stake_op(bond_utxo_id, &keypair, 2, chain_id).unwrap(),
        build_self_unstake_op(bond_utxo_id, &keypair, 3, chain_id).unwrap(),
        build_delegate_op(validator_id, bond_utxo_id, &keypair, 4, chain_id).unwrap(),
        build_undelegate_op(validator_id, bond_utxo_id, &keypair, 5, chain_id).unwrap(),
        build_claim_rewards_op(validator_id, &keypair, 6, chain_id).unwrap(),
        build_set_commission_op(validator_id, 1_250, &keypair, 7, chain_id).unwrap(),
    ];

    for (idx, op) in built.iter().enumerate() {
        let bytes = hex::decode(&op.op_hex).unwrap();
        let decoded = StakingOp::decode_exact(&bytes).unwrap();
        assert_eq!(decoded.nonce, idx as u64 + 1);
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
