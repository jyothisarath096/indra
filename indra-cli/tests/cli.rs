//! Integration tests for the CLI tools.

use indra_cli::{
    generate_keypairs, generate_from_passphrase,
    genesis_cmd::{build_genesis_config, entry_from_keys},
    query::rpc_call,
};
use indra_core::types::primitives::MIN_STAKE_SPARK;
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
    let keys = generate_keypairs([0x01u8; 32], [0x02u8; 32], [0x03u8; 32]).unwrap();
    assert_eq!(keys.public.hybrid_classical_pk.len(), 32);
    assert_eq!(keys.public.bls_pk.len(), 48);
    assert_eq!(keys.public.vrf_pk.len(), 32);
    assert!(!keys.public.hybrid_pq_pk.is_empty());
}

#[test]
fn keygen_deterministic_from_seed() {
    let k1 = generate_keypairs([0xAAu8; 32], [0xBBu8; 32], [0xCCu8; 32]).unwrap();
    let k2 = generate_keypairs([0xAAu8; 32], [0xBBu8; 32], [0xCCu8; 32]).unwrap();
    assert_eq!(k1.public.validator_id, k2.public.validator_id);
}

#[test]
fn keygen_from_passphrase() {
    let k = generate_from_passphrase("my-testnet-validator").unwrap();
    let k2 = generate_from_passphrase("my-testnet-validator").unwrap();
    assert_eq!(k.public.validator_id, k2.public.validator_id);
    // Different passphrase = different key
    let k3 = generate_from_passphrase("other-validator").unwrap();
    assert_ne!(k.public.validator_id, k3.public.validator_id);
}

#[test]
fn keys_json_is_valid_structure() {
    let keys = generate_keypairs([0x01u8; 32], [0x02u8; 32], [0x03u8; 32]).unwrap();
    let json = keys.to_json();
    // All required fields present
    for field in &["validator_id", "hybrid_classical_pk", "bls_pk", "vrf_pk", "hybrid_seed", "WARNING"] {
        assert!(json.contains(field), "missing: {field}");
    }
}

// ── Genesis tests ─────────────────────────────────────────────────────────────

#[test]
fn genesis_with_4_validators() {
    let stake = MIN_STAKE_SPARK * 100;
    let validators: Vec<_> = (0..4u8).map(|i| {
        let seed = [i + 1; 32];
        let keys = generate_keypairs(seed, seed, seed).unwrap();
        entry_from_keys(&format!("v{i}"), &keys, stake)
    }).collect();

    let config = build_genesis_config(
        "indra-testnet-1",
        1_700_000_000,
        1_000_000_000_000_000,
        validators,
    ).unwrap();

    assert_eq!(config.validators.len(), 4);
    let toml = config.to_toml();
    assert!(toml.contains("indra-testnet-1"));
    assert!(toml.contains("[[validators]]"));
}

#[test]
fn genesis_rejects_3_validators() {
    let stake = MIN_STAKE_SPARK * 100;
    let validators: Vec<_> = (0..3u8).map(|i| {
        let seed = [i + 1; 32];
        let keys = generate_keypairs(seed, seed, seed).unwrap();
        entry_from_keys(&format!("v{i}"), &keys, stake)
    }).collect();

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
    let alice = generate_from_passphrase("alice-testnet-seed-v1").unwrap();
    let bob   = generate_from_passphrase("bob-testnet-seed-v1").unwrap();
    let carol = generate_from_passphrase("carol-testnet-seed-v1").unwrap();
    let dave  = generate_from_passphrase("dave-testnet-seed-v1").unwrap();

    // Step 2: Coordinator builds genesis
    let stake = MIN_STAKE_SPARK * 100;
    let validators = vec![
        entry_from_keys("alice", &alice, stake),
        entry_from_keys("bob",   &bob,   stake),
        entry_from_keys("carol", &carol, stake),
        entry_from_keys("dave",  &dave,  stake),
    ];

    let config = build_genesis_config(
        "indra-private-testnet-1",
        1_700_000_000,
        1_000_000_000_000_000,
        validators,
    ).unwrap();

    assert_eq!(config.validators.len(), 4);

    // Step 3: Write keys.json (verify output is valid)
    let alice_json = alice.to_json();
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
