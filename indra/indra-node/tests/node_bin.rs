//! Startup refusal tests for the shipped `node` binary.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

fn run_node(args: &[String]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_node"))
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn node");
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if child.try_wait().expect("poll node").is_some() {
            return child.wait_with_output().expect("collect node output");
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let output = child.wait_with_output().expect("collect timed-out node output");
            panic!("node did not refuse within 30 seconds: {:?}", output);
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn assert_refused(output: &Output, cause: &str) {
    assert!(!output.status.success(), "node unexpectedly succeeded");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(cause), "stderr did not contain {cause:?}: {stderr}");
    assert!(!stderr.contains("panicked at"), "panic in stderr: {stderr}");
    assert!(!stderr.contains("RUST_BACKTRACE"), "backtrace marker in stderr: {stderr}");
}

fn config_file(dir: &Path, data_dir: &Path, keys: &Path, genesis: &Path) -> PathBuf {
    let path = dir.join("config.toml");
    let contents = format!(
        "[node]\nmode = \"validator\"\ndata_dir = \"{}\"\ngenesis = \"{}\"\n\n[keys]\npath = \"{}\"\n\n[rpc]\nenabled = false\n\n[metrics]\nenabled = false\n\n[network]\ndns_discovery_enabled = false\np2p_addr = \"127.0.0.1:30303\"\n",
        data_dir.display(),
        genesis.display(),
        keys.display()
    );
    fs::write(&path, contents).expect("write test config");
    path
}

fn encrypted_keys(
    dir: &Path,
    password: &[u8],
) -> (indra_keystore::KeysFile, PathBuf, PathBuf) {
    let keys = indra_keystore::generate_from_master_seed("startup-test".into(), [0x41; 32])
        .expect("generate test keys");
    let keys_path = dir.join("keys.json");
    let password_path = dir.join("password");
    let encrypted = indra_keystore::encrypt_keys(&keys, password).expect("encrypt test keys");
    indra_keystore::write_keys_secure(keys_path.to_str().expect("keys path"), &encrypted)
        .expect("write test keys");
    fs::write(&password_path, password).expect("write password");
    fs::set_permissions(&password_path, fs::Permissions::from_mode(0o600))
        .expect("chmod password");
    (keys, keys_path, password_path)
}

fn valid_genesis_for(keys: &indra_keystore::KeysFile) -> String {
    use indra_core::types::{crypto::hybrid_identity_id, primitives::MAINNET_ACTIVE_SLOT_COEFFICIENT_NUMERATOR, staking::StakingOp};
    use indra_crypto::{vrf_prove, ClassicalKeypair, ColdHybridKeypair, PqKeypair, VrfKeypair};
    let chain_id = "node-bin-valid";
    let entries = [
        (keys.ed25519_seed, keys.ml_dsa_seed, keys.vrf_seed),
        ([0xB2; 32], [0xB2; 32], [0xB2; 32]),
        ([0xC3; 32], [0xC3; 32], [0xC3; 32]),
        ([0xD4; 32], [0xD4; 32], [0xD4; 32]),
    ];
    let mut output = format!(
        "[genesis]\nchain_id = \"{chain_id}\"\ngenesis_timestamp = 1700000000\nactive_slot_coefficient_numerator = \"{MAINNET_ACTIVE_SLOT_COEFFICIENT_NUMERATOR}\"\n"
    );
    for (index, (classical_seed, pq_seed, vrf_seed)) in entries.iter().enumerate() {
        let classical = ClassicalKeypair::from_seed(classical_seed);
        let pq = PqKeypair::from_seed(pq_seed).expect("test PQ key");
        let vrf = VrfKeypair::from_seed(vrf_seed);
        let mut cold_classical_seed = *classical_seed;
        cold_classical_seed[0] ^= 0xA5;
        let mut cold_pq_seed = *classical_seed;
        cold_pq_seed[0] ^= 0x5A;
        let cold_keypair = ColdHybridKeypair::from_independent_seeds(cold_classical_seed, cold_pq_seed)
            .expect("test cold key");
        let cold_public = cold_keypair.public_key();
        let cold = cold_public.as_complete_hybrid();
        let validator_id = hybrid_identity_id(&classical.public_key().0, &pq.public_key().0).0;
        let challenge = StakingOp::vrf_possession_challenge(
            chain_id,
            &indra_core::Bytes32::from(validator_id),
            &indra_core::Bytes32::from(vrf.public_key()),
            0,
        )
        .expect("test PoP challenge");
        let (output_bytes, proof) = vrf_prove(&vrf, &challenge);
        output.push_str(&format!(
            "\n[[validators]]\nname = \"node-bin-validator-{index}\"\nvalidator_id = \"{}\"\nstake = 1000000000000\nhybrid_classical_pk = \"{}\"\nhybrid_pq_pk = \"{}\"\nvrf_pk = \"{}\"\nvrf_possession_output = \"{}\"\nvrf_possession_proof = \"{}\"\ncold_hybrid_classical_pk = \"{}\"\ncold_hybrid_pq_pk = \"{}\"\ncold_key_version = 1\ncold_nonce = 0\n",
            hex::encode(validator_id),
            hex::encode(classical.public_key().0),
            hex::encode(pq.public_key().0),
            hex::encode(vrf.public_key()),
            hex::encode(output_bytes.0),
            hex::encode(proof.0),
            hex::encode(cold.classical.0),
            hex::encode(cold.pq.0),
        ));
    }
    output
}

fn with_password(args: &mut Vec<String>, password_path: &Path) {
    args.push("--keys-password-file".into());
    args.push(password_path.display().to_string());
}

#[test]
fn node_refuses_missing_config_without_panic() {
    let dir = tempfile::tempdir().expect("tempdir");
    let missing = dir.path().join("missing.toml");
    let output = run_node(&["--config".into(), missing.display().to_string()]);
    assert_refused(&output, "cannot read");
    assert!(!missing.exists());
}

#[test]
fn node_refuses_missing_keystore_without_panic() {
    let dir = tempfile::tempdir().expect("tempdir");
    let keys = dir.path().join("missing-keys.json");
    let genesis = dir.path().join("missing-genesis.toml");
    let config = config_file(dir.path(), &dir.path().join("data"), &keys, &genesis);
    let output = run_node(&["--config".into(), config.display().to_string()]);
    assert_refused(&output, "cannot load");
    assert!(!keys.exists());
}

#[test]
fn node_refuses_wrong_keystore_password_without_panic() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (_, keys, password) = encrypted_keys(dir.path(), b"correct");
    fs::write(&password, b"wrong").expect("replace password");
    let genesis = dir.path().join("missing-genesis.toml");
    let config = config_file(dir.path(), &dir.path().join("data"), &keys, &genesis);
    let mut args = vec!["--config".into(), config.display().to_string()];
    with_password(&mut args, &password);
    let output = run_node(&args);
    assert_refused(&output, "keystore crypto error");
}

#[test]
fn node_refuses_permissive_password_file_without_panic() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (_, keys, password) = encrypted_keys(dir.path(), b"correct");
    fs::set_permissions(&password, fs::Permissions::from_mode(0o644)).expect("chmod password");
    let genesis = dir.path().join("missing-genesis.toml");
    let config = config_file(dir.path(), &dir.path().join("data"), &keys, &genesis);
    let mut args = vec!["--config".into(), config.display().to_string()];
    with_password(&mut args, &password);
    let output = run_node(&args);
    assert_refused(&output, "permissive permissions");
}

#[test]
fn node_refuses_invalid_genesis_without_panic() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (_, keys, password) = encrypted_keys(dir.path(), b"correct");
    let genesis = dir.path().join("invalid-genesis.toml");
    fs::write(&genesis, "not a genesis manifest\n").expect("write invalid genesis");
    let config = config_file(dir.path(), &dir.path().join("data"), &keys, &genesis);
    let mut args = vec!["--config".into(), config.display().to_string()];
    with_password(&mut args, &password);
    let output = run_node(&args);
    assert_refused(&output, "cannot load genesis");
}

#[test]
fn node_refuses_corrupt_vote_safety_record_without_panic() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (key_file, keys, password) = encrypted_keys(dir.path(), b"correct");
    let genesis = dir.path().join("valid-genesis.toml");
    fs::write(&genesis, valid_genesis_for(&key_file)).expect("write valid genesis");
    let data = dir.path().join("data");
    fs::create_dir_all(&data).expect("create data dir");
    fs::write(data.join("vote_safety.dat"), [0xff, 0xff, 0xff]).expect("corrupt vote safety");
    let config = config_file(dir.path(), &data, &keys, &genesis);
    let mut args = vec!["--config".into(), config.display().to_string()];
    with_password(&mut args, &password);
    let output = run_node(&args);
    assert_refused(&output, "vote safety");
}

#[cfg(unix)]
#[test]
fn node_started_from_valid_fixture_stops_cleanly_on_sigterm() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (key_file, keys, password) = encrypted_keys(dir.path(), b"correct");
    let genesis = dir.path().join("valid-genesis.toml");
    fs::write(&genesis, valid_genesis_for(&key_file)).expect("write valid genesis");
    let data = dir.path().join("data");
    let config = config_file(dir.path(), &data, &keys, &genesis);
    let stdout_path = dir.path().join("node.stdout");
    let stderr_path = dir.path().join("node.stderr");
    let p2p_port = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("reserve p2p port")
        .local_addr()
        .expect("p2p address")
        .port();
    let stdout = fs::File::create(&stdout_path).expect("create stdout log");
    let stderr = fs::File::create(&stderr_path).expect("create stderr log");
    let mut child = Command::new(env!("CARGO_BIN_EXE_node"))
        .args(["--config", config.to_str().expect("config path")])
        .args([
            "--p2p-addr",
            &format!("127.0.0.1:{p2p_port}"),
            "--no-observer-port",
            "--no-metrics",
        ])
        .args(["--keys-password-file", password.to_str().expect("password path")])
        .stdout(stdout)
        .stderr(stderr)
        .spawn()
        .expect("spawn node");

    let startup_deadline = Instant::now() + Duration::from_secs(60);
    let mut started = false;
    while Instant::now() < startup_deadline {
        let log = fs::read_to_string(&stderr_path).unwrap_or_default();
        if log.contains("Starting P2P and consensus") && log.contains("[shutdown] watcher ready") {
            started = true;
            break;
        }
        if let Some(status) = child.try_wait().expect("poll node") {
            panic!("node exited before startup: {status}\n{log}");
        }
        thread::sleep(Duration::from_millis(100));
    }
    assert!(started, "node did not reach startup:\n{}", fs::read_to_string(&stderr_path).unwrap_or_default());

    let kill_result = unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
    assert_eq!(kill_result, 0, "send SIGTERM");
    let shutdown_deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll shutdown") {
            break status;
        }
        assert!(Instant::now() < shutdown_deadline, "node did not stop within 10 seconds");
        thread::sleep(Duration::from_millis(50));
    };
    let stderr = fs::read_to_string(&stderr_path).expect("read stderr log");
    assert_eq!(status.code(), Some(0), "unexpected exit status: {status}\n{stderr}");
    assert!(!stderr.contains("ERROR"), "clean shutdown emitted ERROR:\n{stderr}");
    assert!(!stderr.contains("panicked at"), "clean shutdown panicked:\n{stderr}");
}
