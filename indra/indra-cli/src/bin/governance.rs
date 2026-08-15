//! `indra-governance` — build and submit governance operations.

use std::{
    fs::{File, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

use indra_cli::{
    fetch_chain_id, fetch_validator_cold_replay, load_cold_keys, reconstruct_keypair,
    staking::http_post, CliError, CliResult, KeysFile, PasswordSource, Wallet,
};
use indra_core::{
    codec::Encode,
    types::{
        crypto::{HybridPubKey, HybridSignature},
        governance::{
            governance_signing_domain, governance_vote_commit_hash, ColdGovernanceAuthorization,
            GovernableAction, GovernanceOpV2, GovernancePayload,
        },
        primitives::{Bytes32, VariableBytes},
    },
};
use indra_crypto::{sha256, HybridKeypair};
use rand::RngCore;

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run() -> CliResult<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || has_flag(&args, "--help") || has_flag(&args, "-h") {
        print_help();
        return Ok(());
    }
    reject_removed_vote_nonce_flag(&args)?;

    let command = args[0].as_str();
    let keys_path = flag_value(&args, "--keys").unwrap_or_else(|| "keys.json".into());
    let keys = indra_cli::load_keys_for_cli(&keys_path, &args)?;
    let keypair = reconstruct_keypair(&keys)?;
    let signer_id = signer_id_from_keys(&keys);
    let node_url = flag_value(&args, "--node").unwrap_or_else(|| "http://127.0.0.1:8545".into());
    let wallet_path = flag_value(&args, "--wallet").unwrap_or_else(|| "wallet.json".into());
    let chain_id = fetch_chain_id(&node_url)?;
    let cold_required = matches!(command, "propose" | "commit" | "reveal" | "cancel");
    let cold_context = if cold_required {
        let cold_path = flag_value(&args, "--cold-keys").ok_or_else(|| {
            CliError::Parse("governance command requires --cold-keys <path>".into())
        })?;
        let cold_password_file = flag_value(&args, "--cold-keys-password-file");
        let cold_password = match cold_password_file.as_deref() {
            Some(path) => PasswordSource::File {
                path: Path::new(path),
                reject_permissive: false,
            },
            None => PasswordSource::Prompt,
        };
        let cold_keys = load_cold_keys(&cold_path, cold_password)
            .map_err(|error| CliError::Keystore(error.to_string()))?;
        let cold_keypair = cold_keys
            .reconstruct()
            .map_err(|error| CliError::Keystore(error.to_string()))?;
        let replay = fetch_validator_cold_replay(&node_url, &hex::encode(signer_id.0))?;
        Some((cold_keypair, replay.0, replay.1))
    } else {
        None
    };
    let nonce = if cold_required {
        if flag_value(&args, "--nonce").is_some() {
            return Err(CliError::Parse(
                "--nonce is not valid for cold-authorized governance commands; replay metadata is fetched from consensus"
                    .into(),
            ));
        }
        0
    } else {
        match flag_value(&args, "--nonce") {
            Some(raw) => parse_u64(&raw, "--nonce")?,
            None => fetch_governance_nonce(&node_url, signer_id)?,
        }
    };

    let mut proposal_deposit_utxo_id = None;
    let payload = match command {
        "propose" => {
            let deposit_utxo_id = parse_hex32_required(&args, "--deposit-utxo")?;
            proposal_deposit_utxo_id = Some(deposit_utxo_id);
            GovernancePayload::Propose {
                action: parse_governable_action(&args)?,
                deposit_utxo_id,
                proposer_pubkey: cold_hybrid_pubkey(
                    &cold_context.as_ref().expect("cold context required").0,
                )?,
                title: variable_bytes(&required_flag(&args, "--title")?, "--title")?,
                description: variable_bytes(
                    &required_flag(&args, "--description")?,
                    "--description",
                )?,
                cold_authorization: Some(cold_authorization(&cold_context)),
            }
        }
        "commit" => {
            let proposal_id = parse_hex32_required(&args, "--proposal-id")?;
            let vote = parse_vote(&required_flag(&args, "--vote")?)?;
            let vote_nonce = vote_nonce_for_commit(&args, &keys_path, proposal_id, signer_id)?;
            GovernancePayload::Commit {
                proposal_id,
                commit_hash: governance_vote_commit_hash(proposal_id, signer_id, vote, vote_nonce),
                cold_authorization: Some(cold_authorization(&cold_context)),
            }
        }
        "reveal" => {
            let proposal_id = parse_hex32_required(&args, "--proposal-id")?;
            GovernancePayload::Reveal {
                proposal_id,
                vote: parse_vote(&required_flag(&args, "--vote")?)?,
                nonce: vote_nonce_for_reveal(&args, &keys_path, proposal_id, signer_id)?,
                cold_authorization: Some(cold_authorization(&cold_context)),
            }
        }
        "redelegate" => GovernancePayload::Redelegate {
            proposal_id: parse_hex32_required(&args, "--proposal-id")?,
            from_validator: parse_hex32_required(&args, "--from-validator")?,
            to_validator: parse_hex32_required(&args, "--to-validator")?,
            amount_spark: parse_u64(&required_flag(&args, "--amount-spark")?, "--amount-spark")?,
        },
        "execute" => GovernancePayload::Execute {
            proposal_id: parse_hex32_required(&args, "--proposal-id")?,
        },
        "cancel" => GovernancePayload::Cancel {
            proposal_id: parse_hex32_required(&args, "--proposal-id")?,
            cold_authorization: Some(cold_authorization(&cold_context)),
        },
        _ => {
            print_help();
            return Err(CliError::Parse(format!(
                "unknown governance command '{command}'"
            )));
        }
    };

    let op = if let Some((cold_keypair, _, _)) = cold_context.as_ref() {
        build_cold_governance_op(signer_id, payload, cold_keypair, &chain_id)?
    } else {
        build_governance_op(signer_id, nonce, payload, &keypair, &chain_id)?
    };
    let op_bytes = op.encode_to_vec();
    let op_hex = hex::encode(&op_bytes);
    let op_id = hex::encode(sha256(&op_bytes));
    println!("governance_op_id: {op_id}");
    println!("nonce: {}", op.nonce);
    println!("op_hex: {op_hex}");

    if has_flag(&args, "--dry-run") {
        return Ok(());
    }

    let response = submit_governance_op(&node_url, &op_hex)?;
    println!("{response}");
    if let Some(deposit_utxo_id) = proposal_deposit_utxo_id {
        match mark_governance_deposit_spent(&wallet_path, deposit_utxo_id) {
            Ok(true) => println!(
                "wallet_update: marked proposal deposit UTXO {} spent in {}",
                hex::encode(deposit_utxo_id.0),
                wallet_path
            ),
            Ok(false) => eprintln!(
                "Warning: proposal deposit UTXO {} was accepted by the node but is not tracked in {}; local wallet state was not changed",
                hex::encode(deposit_utxo_id.0),
                wallet_path
            ),
            Err(error) => eprintln!("Warning: could not update wallet {}: {}", wallet_path, error),
        }
    }
    println!("status_detail: accepted into local mempool and relayed; not yet confirmed on-chain");
    if has_flag(&args, "--wait") {
        wait_for_governance_confirmation(&node_url, &op, signer_id)?;
    }
    Ok(())
}

fn mark_governance_deposit_spent(wallet_path: &str, deposit_utxo_id: Bytes32) -> CliResult<bool> {
    let mut wallet = Wallet::load(wallet_path)?;
    if !wallet.contains(&deposit_utxo_id) {
        return Ok(false);
    }
    wallet.record_accepted_transaction(&[deposit_utxo_id], None);
    wallet.save(wallet_path)?;
    Ok(true)
}

fn build_governance_op(
    signer_id: Bytes32,
    nonce: u64,
    payload: GovernancePayload,
    keypair: &HybridKeypair,
    chain_id: &str,
) -> CliResult<GovernanceOpV2> {
    let action_type = payload.action_type();
    let domain = governance_signing_domain(action_type, signer_id, nonce, &payload, chain_id);
    let msg_hash = sha256(&domain);
    let sig = keypair
        .sign(&msg_hash)
        .map_err(|e| CliError::Crypto(e.to_string()))?;
    Ok(GovernanceOpV2 {
        action_type,
        signer_id,
        nonce,
        payload,
        signature: HybridSignature {
            classical_sig: VariableBytes::from_slice(&sig.classical.0)
                .map_err(|_| CliError::Transaction("classical sig too large".into()))?,
            pq_sig: VariableBytes::from_slice(&sig.pq.0)
                .map_err(|_| CliError::Transaction("pq sig too large".into()))?,
        },
    })
}

fn cold_authorization(
    context: &Option<(indra_crypto::ColdHybridKeypair, u64, u64)>,
) -> ColdGovernanceAuthorization {
    let (_, cold_key_version, cold_nonce) = context.as_ref().expect("cold context required");
    ColdGovernanceAuthorization {
        cold_key_version: *cold_key_version,
        cold_nonce: *cold_nonce,
    }
}

fn cold_hybrid_pubkey(keypair: &indra_crypto::ColdHybridKeypair) -> CliResult<HybridPubKey> {
    let cold_public = keypair.public_key();
    let public = cold_public.as_complete_hybrid();
    Ok(HybridPubKey {
        classical_pk: Bytes32::from(public.classical.0),
        pq_pk: VariableBytes::from_slice(&public.pq.0)
            .map_err(|_| CliError::Crypto("cold PQ public key too large".into()))?,
    })
}

fn build_cold_governance_op(
    signer_id: Bytes32,
    payload: GovernancePayload,
    cold_keypair: &indra_crypto::ColdHybridKeypair,
    chain_id: &str,
) -> CliResult<GovernanceOpV2> {
    let mut op = GovernanceOpV2 {
        action_type: payload.action_type(),
        signer_id,
        nonce: 0,
        payload,
        signature: HybridSignature {
            classical_sig: VariableBytes::from_slice(&[0; indra_crypto::CLASSICAL_SIG_BYTES])
                .map_err(|_| CliError::Crypto("dummy classical signature too large".into()))?,
            pq_sig: VariableBytes::from_slice(&[0; indra_crypto::PQ_SIG_BYTES])
                .map_err(|_| CliError::Crypto("dummy PQ signature too large".into()))?,
        },
    };
    op.validate_structure()
        .map_err(|error| CliError::Crypto(error.to_string()))?;
    let signing_bytes = op
        .cold_authorization_signing_bytes(chain_id)
        .map_err(|error| CliError::Crypto(error.to_string()))?
        .ok_or_else(|| CliError::Crypto("missing cold authorization envelope".into()))?;
    let signature = cold_keypair
        .sign(&signing_bytes)
        .map_err(|error| CliError::Crypto(error.to_string()))?;
    op.signature = HybridSignature {
        classical_sig: VariableBytes::from_slice(&signature.classical.0)
            .map_err(|_| CliError::Crypto("classical signature too large".into()))?,
        pq_sig: VariableBytes::from_slice(&signature.pq.0)
            .map_err(|_| CliError::Crypto("PQ signature too large".into()))?,
    };
    Ok(op)
}

fn parse_governable_action(args: &[String]) -> CliResult<GovernableAction> {
    let action = required_flag(args, "--action")?;
    match action.as_str() {
        "slash-liveness-threshold-epochs" => {
            Ok(GovernableAction::SetSlashLivenessThresholdEpochs {
                value: parse_u64(&required_flag(args, "--value")?, "--value")?,
            })
        }
        "min-delegation-spark" => Ok(GovernableAction::SetMinDelegationSpark {
            value: parse_u64(&required_flag(args, "--value")?, "--value")?,
        }),
        "proposal-deposit-spark" => Ok(GovernableAction::SetProposalDepositSpark {
            value: parse_u64(&required_flag(args, "--value")?, "--value")?,
        }),
        "slash-liveness-bps" => Ok(GovernableAction::SetSlashLivenessBps {
            value: parse_u32(&required_flag(args, "--value")?, "--value")?,
        }),
        "slash-double-precommit-bps" => Ok(GovernableAction::SetSlashDoublePrecommitBps {
            value: parse_u32(&required_flag(args, "--value")?, "--value")?,
        }),
        "max-commission-bps" => Ok(GovernableAction::SetMaxCommissionBps {
            value: parse_u32(&required_flag(args, "--value")?, "--value")?,
        }),
        "governance-delay-epochs" => Ok(GovernableAction::SetGovernanceDelayEpochs {
            value: parse_u64(&required_flag(args, "--value")?, "--value")?,
        }),
        "governance-quorum-bps" => Ok(GovernableAction::SetGovernanceQuorumBps {
            value: parse_u32(&required_flag(args, "--value")?, "--value")?,
        }),
        "governance-critical-quorum-bps" => Ok(GovernableAction::SetGovernanceCriticalQuorumBps {
            value: parse_u32(&required_flag(args, "--value")?, "--value")?,
        }),
        _ => Err(CliError::Parse(format!(
            "unknown governable action '{action}'"
        ))),
    }
}

fn fetch_governance_nonce(node_url: &str, signer_id: Bytes32) -> CliResult<u64> {
    let body = format!(
        r#"{{"jsonrpc":"2.0","method":"indra_getGovernanceNonce","params":["{}"],"id":1}}"#,
        hex::encode(signer_id.0)
    );
    let response = http_post(node_url, &body)?;
    if let Some(message) = rpc_error_message(&response) {
        return Err(CliError::Rpc(message));
    }
    parse_u64_json_field(&response, "next_nonce")
        .ok_or_else(|| CliError::Rpc("cannot parse governance nonce from response".into()))
}

fn submit_governance_op(node_url: &str, op_hex: &str) -> CliResult<String> {
    let body = format!(
        r#"{{"jsonrpc":"2.0","method":"indra_submitGovernanceOp","params":["{}"],"id":1}}"#,
        op_hex
    );
    let response = http_post(node_url, &body)?;
    if let Some(message) = rpc_error_message(&response) {
        return Err(CliError::Rpc(message));
    }
    Ok(response)
}

fn wait_for_governance_confirmation(
    node_url: &str,
    op: &GovernanceOpV2,
    signer_id: Bytes32,
) -> CliResult<()> {
    let timeout = Duration::from_secs(120);
    let start = Instant::now();
    match &op.payload {
        GovernancePayload::Commit { proposal_id, .. } => {
            while start.elapsed() < timeout {
                let votes = fetch_proposal_votes(node_url, *proposal_id)?;
                if validator_bool_field(&votes, signer_id, "committed") == Some(true) {
                    println!("confirmed_on_chain: committed");
                    return Ok(());
                }
                thread::sleep(Duration::from_secs(2));
            }
            Err(CliError::Rpc(
                "timed out waiting for commit to appear on-chain".into(),
            ))
        }
        GovernancePayload::Reveal { proposal_id, .. } => {
            while start.elapsed() < timeout {
                let votes = fetch_proposal_votes(node_url, *proposal_id)?;
                if validator_bool_field(&votes, signer_id, "revealed") == Some(true) {
                    println!("confirmed_on_chain: revealed");
                    return Ok(());
                }
                thread::sleep(Duration::from_secs(2));
            }
            Err(CliError::Rpc(
                "timed out waiting for reveal to appear on-chain".into(),
            ))
        }
        _ => {
            println!("confirmed_on_chain: --wait is currently implemented for commit/reveal only");
            Ok(())
        }
    }
}

fn fetch_proposal_votes(node_url: &str, proposal_id: Bytes32) -> CliResult<String> {
    let body = format!(
        r#"{{"jsonrpc":"2.0","method":"indra_getProposalVotes","params":["{}"],"id":1}}"#,
        hex::encode(proposal_id.0)
    );
    let response = http_post(node_url, &body)?;
    if let Some(message) = rpc_error_message(&response) {
        return Err(CliError::Rpc(message));
    }
    Ok(response)
}

fn validator_bool_field(json: &str, validator_id: Bytes32, field: &str) -> Option<bool> {
    let needle = format!(r#""validator_id":"{}""#, hex::encode(validator_id.0));
    let start = json.find(&needle)?;
    let rest = &json[start..];
    let object_end = rest.find('}').unwrap_or(rest.len());
    let object = &rest[..object_end];
    parse_bool_json_field(object, field)
}

fn signer_id_from_keys(keys: &KeysFile) -> Bytes32 {
    Bytes32::from(keys.public.validator_id)
}

fn vote_nonce_for_commit(
    args: &[String],
    keys_path: &str,
    proposal_id: Bytes32,
    signer_id: Bytes32,
) -> CliResult<Bytes32> {
    let store_path = vote_nonce_store_path(args, keys_path);
    if let Some(existing) = load_vote_nonce(&store_path, proposal_id, signer_id)? {
        return Ok(existing);
    }
    let nonce = generate_vote_nonce();
    save_vote_nonce(&store_path, proposal_id, signer_id, nonce)?;
    println!(
        "generated_vote_nonce: {} (saved to {})",
        hex::encode(nonce.0),
        store_path.display()
    );
    Ok(nonce)
}

fn vote_nonce_for_reveal(
    args: &[String],
    keys_path: &str,
    proposal_id: Bytes32,
    signer_id: Bytes32,
) -> CliResult<Bytes32> {
    let store_path = vote_nonce_store_path(args, keys_path);
    load_vote_nonce(&store_path, proposal_id, signer_id)?.ok_or_else(|| {
        CliError::MissingArgument(format!(
            "no saved vote nonce for proposal {} / validator {} in {}",
            hex::encode(proposal_id.0),
            hex::encode(signer_id.0),
            store_path.display()
        ))
    })
}

fn generate_vote_nonce() -> Bytes32 {
    let mut bytes = [0u8; 32];
    let mut rng = rand::rngs::OsRng;
    rng.fill_bytes(&mut bytes);
    Bytes32::from(bytes)
}

fn vote_nonce_store_path(args: &[String], keys_path: &str) -> PathBuf {
    flag_value(args, "--vote-nonce-store")
        .map(PathBuf::from)
        .unwrap_or_else(|| default_vote_nonce_store_path(keys_path))
}

fn default_vote_nonce_store_path(keys_path: &str) -> PathBuf {
    let keys_path = Path::new(keys_path);
    keys_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .join("governance_vote_nonces.txt")
}

fn load_vote_nonce(
    path: &Path,
    proposal_id: Bytes32,
    signer_id: Bytes32,
) -> CliResult<Option<Bytes32>> {
    if !path.exists() {
        return Ok(None);
    }
    let contents = std::fs::read_to_string(path)
        .map_err(|e| CliError::Io(format!("{}: {}", path.display(), e)))?;
    let proposal_hex = hex::encode(proposal_id.0);
    let signer_hex = hex::encode(signer_id.0);
    for line in contents.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() == 3 && parts[0] == proposal_hex && parts[1] == signer_hex {
            return parse_hex32(parts[2]).map(Some);
        }
    }
    Ok(None)
}

fn save_vote_nonce(
    path: &Path,
    proposal_id: Bytes32,
    signer_id: Bytes32,
    nonce: Bytes32,
) -> CliResult<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)
            .map_err(|e| CliError::Io(format!("{}: {}", parent.display(), e)))?;
    }
    let proposal_hex = hex::encode(proposal_id.0);
    let signer_hex = hex::encode(signer_id.0);
    let nonce_hex = hex::encode(nonce.0);
    let mut replaced = false;
    let mut lines = Vec::new();
    if path.exists() {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| CliError::Io(format!("{}: {}", path.display(), e)))?;
        for line in contents.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() == 3 && parts[0] == proposal_hex && parts[1] == signer_hex {
                lines.push(format!("{proposal_hex} {signer_hex} {nonce_hex}"));
                replaced = true;
            } else if !line.trim().is_empty() {
                lines.push(line.to_string());
            }
        }
    }
    if !replaced {
        lines.push(format!("{proposal_hex} {signer_hex} {nonce_hex}"));
    }
    let mut out = lines.join("\n");
    out.push('\n');
    atomic_write_private(path, out.as_bytes())
}

fn atomic_write_private(path: &Path, contents: &[u8]) -> CliResult<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .ok_or_else(|| CliError::Io(format!("{} has no file name", path.display())))?;

    for _ in 0..32 {
        let temp_path = parent.join(format!(
            ".{}.tmp-{}-{:016x}",
            file_name.to_string_lossy(),
            std::process::id(),
            rand::random::<u64>()
        ));
        let mut temp = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp_path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(CliError::Io(format!("{}: {}", temp_path.display(), error))),
        };

        let result = (|| -> std::io::Result<()> {
            // `set_permissions` makes the final mode exactly 0600 even under a
            // restrictive process umask; creation itself can never be broader.
            temp.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            temp.write_all(contents)?;
            temp.sync_all()?;
            std::fs::rename(&temp_path, path)?;
            File::open(parent)?.sync_all()?;
            Ok(())
        })();
        if let Err(error) = result {
            let _ = std::fs::remove_file(&temp_path);
            return Err(CliError::Io(format!("{}: {}", path.display(), error)));
        }
        return Ok(());
    }
    Err(CliError::Io(format!(
        "could not allocate a private temporary file beside {}",
        path.display()
    )))
}

fn reject_removed_vote_nonce_flag(args: &[String]) -> CliResult<()> {
    if args
        .iter()
        .any(|arg| arg == "--vote-nonce" || arg.starts_with("--vote-nonce="))
    {
        return Err(CliError::Parse(
            "--vote-nonce has been removed; vote nonces are generated internally with the OS CSPRNG"
                .into(),
        ));
    }
    Ok(())
}

fn parse_vote(raw: &str) -> CliResult<u8> {
    match raw {
        "yes" | "YES" | "1" => Ok(1),
        "no" | "NO" | "0" => Ok(0),
        "abstain" | "ABSTAIN" => Err(CliError::Parse(
            "governance abstain is represented by not submitting a reveal op".into(),
        )),
        _ => Err(CliError::Parse(format!("invalid vote '{raw}'"))),
    }
}

fn parse_hex32_required(args: &[String], flag: &str) -> CliResult<Bytes32> {
    parse_hex32(&required_flag(args, flag)?)
}

fn parse_hex32(raw: &str) -> CliResult<Bytes32> {
    let trimmed = raw.trim_start_matches("0x");
    let bytes = hex::decode(trimmed)
        .map_err(|_| CliError::InvalidHex(format!("invalid hex value '{raw}'")))?;
    if bytes.len() != 32 {
        return Err(CliError::InvalidHex(format!(
            "expected 32-byte hex value, got {} bytes",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(Bytes32::from(out))
}

fn required_flag(args: &[String], flag: &str) -> CliResult<String> {
    flag_value(args, flag).ok_or_else(|| CliError::MissingArgument(flag.to_string()))
}

fn flag_value(args: &[String], flag: &str) -> Option<String> {
    args.windows(2)
        .find(|window| window[0] == flag)
        .map(|window| window[1].clone())
}

fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|arg| arg == flag)
}

fn parse_u64(raw: &str, name: &str) -> CliResult<u64> {
    raw.parse::<u64>()
        .map_err(|_| CliError::Parse(format!("invalid {name}: {raw}")))
}

fn parse_u32(raw: &str, name: &str) -> CliResult<u32> {
    raw.parse::<u32>()
        .map_err(|_| CliError::Parse(format!("invalid {name}: {raw}")))
}

fn variable_bytes<const N: usize>(value: &str, name: &str) -> CliResult<VariableBytes<N>> {
    VariableBytes::from_slice(value.as_bytes())
        .map_err(|_| CliError::Parse(format!("{name} exceeds {N} bytes")))
}

fn rpc_error_message(response: &str) -> Option<String> {
    if !response.contains("\"error\"") {
        return None;
    }
    parse_string_json_field(response, "message").or_else(|| Some(response.to_string()))
}

fn parse_u64_json_field(json: &str, field: &str) -> Option<u64> {
    let key = format!("\"{}\":", field);
    let pos = json.find(&key)?;
    let after = json[pos + key.len()..].trim_start();
    let value: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
    value.parse().ok()
}

fn parse_string_json_field(json: &str, field: &str) -> Option<String> {
    let key = format!("\"{}\":", field);
    let pos = json.find(&key)?;
    let after = json[pos + key.len()..].trim_start();
    let after = after.strip_prefix('"')?;
    let end = after.find('"')?;
    Some(after[..end].to_string())
}

fn parse_bool_json_field(json: &str, field: &str) -> Option<bool> {
    let key = format!("\"{}\":", field);
    let pos = json.find(&key)?;
    let after = json[pos + key.len()..].trim_start();
    if after.starts_with("true") {
        Some(true)
    } else if after.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

fn print_help() {
    println!(
        "INDRA Governance CLI\n\
Usage: indra-governance <command> [flags]\n\n\
Commands:\n\
  propose      Submit a governable parameter-change proposal\n\
  commit       Submit commit hash for a hidden vote\n\
  reveal       Reveal a committed vote\n\
  redelegate   Move governance vote weight for one proposal\n\
  execute      Execute an approved proposal after delay\n\
  cancel       Cancel your proposal during deliberation\n\n\
Common flags:\n\
  --keys <path>    Path to keys.json (default: keys.json)\n\
  --keys-password-file <path>  Password file for encrypted keys.json\n\
  --cold-keys <path>  Cold key file (required for propose/commit/reveal/cancel)\n\
  --cold-keys-password-file <path>  Password file for encrypted cold keys\n\
  --node <url>     Node RPC URL (default: http://127.0.0.1:8545)\n\
  --wallet <path>  Wallet file for proposal deposit bookkeeping (default: wallet.json)\n\
  --nonce <n>      Governance nonce override\n\
  --vote-nonce-store <path>  Local vote nonce store (default: beside keys.json)\n\
  --wait           For commit/reveal, poll until visible on-chain\n\
  --dry-run        Build and sign but do not submit\n\n\
Propose flags:\n\
  --action <name> --value <n> --deposit-utxo <hex> --title <text> --description <text>\n\n\
Vote flags:\n\
  --proposal-id <hex> --vote yes|no\n\
  Commit securely generates and saves an internal vote nonce; reveal reloads it.\n\
  Abstain by not submitting a reveal op."
    );
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static UMASK_TEST_LOCK: Mutex<()> = Mutex::new(());

    struct UmaskGuard(libc::mode_t);

    impl Drop for UmaskGuard {
        fn drop(&mut self) {
            unsafe { libc::umask(self.0) };
        }
    }

    #[test]
    fn cli_cold_proposal_is_accepted_by_consensus() {
        use indra_core::types::{primitives::DEFAULT_CHAIN_ID, transaction::OutputV1};
        use indra_crypto::hybrid::{ClassicalKeypair, ColdHybridKeypair, PqKeypair};
        use indra_state::validator::{ValidatorEntry, ValidatorStatus};

        let hot = HybridKeypair::new(
            ClassicalKeypair::from_seed(&[0x91; 32]),
            PqKeypair::from_seed(&[0x92; 32]).unwrap(),
        );
        let hot_public = hot.public_key();
        let hot_pubkey = HybridPubKey {
            classical_pk: Bytes32::from(hot_public.classical.0),
            pq_pk: VariableBytes::from_slice(&hot_public.pq.0).unwrap(),
        };
        let validator_id = hot_pubkey.identity_id();
        let cold = ColdHybridKeypair::from_independent_seeds([0x93; 32], [0x94; 32]).unwrap();
        let cold_pubkey = cold_hybrid_pubkey(&cold).unwrap();
        let mut state = indra_state::ChainState::new_genesis();
        state.governance.params.proposal_deposit_spark = 1_000;
        state
            .validators
            .upsert(ValidatorEntry {
                validator_id,
                name: "cli-governance-test".into(),
                hybrid_classical_pk: Some(hot_pubkey.classical_pk.0),
                hybrid_pq_pk: Some(hot_pubkey.pq_pk.as_slice().to_vec()),
                vrf_pk: Some([0x95; 32]),
                vrf_key_activation_epoch: 0,
                pending_vrf_pk: None,
                pending_vrf_activation_epoch: None,
                stake_spark: indra_core::types::primitives::MINIMUM_ACTIVE_SELF_STAKE_SPARK,
                status: ValidatorStatus::Active,
                registered_epoch: 0,
                last_active_epoch: 0,
                slashed_offense_id: None,
                commission_bps: indra_core::types::primitives::DEFAULT_COMMISSION_BPS,
                pending_commission_bps: None,
                pending_commission_effective_epoch: None,
                min_delegation_spark: indra_core::types::primitives::DUST_LIMIT_SPARK,
                auto_delegate_to: None,
                network_addr: None,
                network_addr_last_updated_epoch: None,
                cold_hybrid_classical_pk: Some(cold_pubkey.classical_pk.0),
                cold_hybrid_pq_pk: Some(cold_pubkey.pq_pk.as_slice().try_into().unwrap()),
                cold_key_version: 1,
                cold_nonce: 0,
            })
            .unwrap();
        let deposit = state
            .utxos
            .insert(
                OutputV1 {
                    value_spark: 1_000,
                    owner_pubkey: cold_pubkey.clone(),
                    lock_height: 0,
                },
                0,
                0,
                0,
            )
            .unwrap();
        let payload = GovernancePayload::Propose {
            action: GovernableAction::SetMinDelegationSpark {
                value: indra_core::types::primitives::DUST_LIMIT_SPARK,
            },
            deposit_utxo_id: deposit,
            proposer_pubkey: cold_pubkey,
            title: VariableBytes::from_slice(b"CLI proposal").unwrap(),
            description: VariableBytes::from_slice(b"consensus application test").unwrap(),
            cold_authorization: Some(ColdGovernanceAuthorization {
                cold_key_version: 1,
                cold_nonce: 1,
            }),
        };
        let op = build_cold_governance_op(validator_id, payload, &cold, DEFAULT_CHAIN_ID).unwrap();

        indra_state::governance_apply::apply_governance_op(&mut state, &op, 0, 1, DEFAULT_CHAIN_ID)
            .unwrap();
        assert_eq!(state.governance.proposals.len(), 1);
        assert!(state.utxos.get(&deposit).is_none());
    }

    #[test]
    fn cli_no_vote_encodes_to_state_no_value() {
        assert_eq!(parse_vote("no").unwrap(), 0);
        assert_eq!(parse_vote("NO").unwrap(), 0);
        assert_eq!(parse_vote("0").unwrap(), 0);
    }

    #[test]
    fn cli_yes_vote_encodes_to_state_yes_value() {
        assert_eq!(parse_vote("yes").unwrap(), 1);
        assert_eq!(parse_vote("YES").unwrap(), 1);
        assert_eq!(parse_vote("1").unwrap(), 1);
    }

    #[test]
    fn abstain_behavior_is_explicitly_documented() {
        let err = parse_vote("abstain").unwrap_err().to_string();
        assert!(err.contains("not submitting a reveal op"));
    }

    #[test]
    fn cli_auto_generates_distinct_nonces_across_proposals() {
        let path = std::env::temp_dir().join(format!(
            "indra-governance-nonces-{}-{}.txt",
            std::process::id(),
            rand::random::<u64>()
        ));
        let path_str = path.to_string_lossy().to_string();
        let keys_path = std::env::temp_dir()
            .join("keys.json")
            .to_string_lossy()
            .to_string();
        let args = vec![
            "commit".to_string(),
            "--vote-nonce-store".to_string(),
            path_str,
        ];
        let signer_id = Bytes32::from([0xA1; 32]);
        let proposal_a = Bytes32::from([0xB1; 32]);
        let proposal_b = Bytes32::from([0xB2; 32]);

        let nonce_a = vote_nonce_for_commit(&args, &keys_path, proposal_a, signer_id).unwrap();
        let nonce_b = vote_nonce_for_commit(&args, &keys_path, proposal_b, signer_id).unwrap();

        assert_ne!(
            nonce_a, nonce_b,
            "auto-generated vote nonces should be distinct across proposals"
        );
        assert_eq!(
            vote_nonce_for_reveal(&args, &keys_path, proposal_a, signer_id).unwrap(),
            nonce_a,
            "reveal path should load the saved nonce without an operator-supplied override"
        );
        assert_eq!(
            vote_nonce_for_reveal(&args, &keys_path, proposal_b, signer_id).unwrap(),
            nonce_b,
            "reveal path should load the saved nonce for the matching proposal"
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn vote_nonce_store_is_atomic_and_exactly_private_regardless_of_umask() {
        let _lock = UMASK_TEST_LOCK.lock().unwrap();
        let directory = std::env::temp_dir().join(format!(
            "indra-governance-private-nonce-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&directory).unwrap();
        let original_umask = unsafe { libc::umask(0o777) };
        let _guard = UmaskGuard(original_umask);
        let path = directory.join("nonces.txt");

        save_vote_nonce(
            &path,
            Bytes32::from([0x11; 32]),
            Bytes32::from([0x22; 32]),
            Bytes32::from([0x33; 32]),
        )
        .unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "nonce store permissions must ignore umask");
        let entries: Vec<_> = std::fs::read_dir(&directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(entries, vec![std::ffi::OsString::from("nonces.txt")]);

        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn caller_supplied_vote_nonce_flag_is_rejected() {
        let args = vec![
            "commit".to_string(),
            "--vote-nonce".to_string(),
            hex::encode([0x44; 32]),
        ];
        let error = reject_removed_vote_nonce_flag(&args).unwrap_err();
        assert!(error.to_string().contains("--vote-nonce has been removed"));
        let inline = vec![format!("--vote-nonce={}", hex::encode([0x55; 32]))];
        assert!(reject_removed_vote_nonce_flag(&inline).is_err());
    }

    #[test]
    fn validator_bool_field_reads_commit_and_reveal_confirmation() {
        let signer = Bytes32::from([0xAB; 32]);
        let other = Bytes32::from([0xCD; 32]);
        let json = format!(
            r#"{{"votes":[{{"validator_id":"{}","committed":false,"revealed":false}},{{"validator_id":"{}","committed":true,"revealed":true}}]}}"#,
            hex::encode(other.0),
            hex::encode(signer.0)
        );

        assert_eq!(validator_bool_field(&json, signer, "committed"), Some(true));
        assert_eq!(validator_bool_field(&json, signer, "revealed"), Some(true));
        assert_eq!(validator_bool_field(&json, other, "committed"), Some(false));
    }

    #[test]
    fn accepted_governance_proposal_marks_deposit_utxo_spent() {
        let wallet_path = std::env::temp_dir().join(format!(
            "indra-governance-wallet-{}-{}.json",
            std::process::id(),
            rand::random::<u64>()
        ));
        let wallet_path_str = wallet_path.to_string_lossy().to_string();
        let deposit_utxo_id = Bytes32::from([0xD1; 32]);
        let other_utxo_id = Bytes32::from([0xD2; 32]);
        let mut wallet = Wallet::new();
        wallet.add_utxo(deposit_utxo_id, 1_000_000, 12, 0, 0);
        wallet.add_utxo(other_utxo_id, 2_000_000, 12, 0, 1);
        wallet.save(&wallet_path_str).unwrap();

        assert!(mark_governance_deposit_spent(&wallet_path_str, deposit_utxo_id).unwrap());

        let updated = Wallet::load(&wallet_path_str).unwrap();
        assert!(updated.get(&deposit_utxo_id).unwrap().spent);
        assert!(!updated.get(&other_utxo_id).unwrap().spent);
        assert_eq!(updated.balance(), 2_000_000);
        assert!(updated.select_utxos(2_000_000, 1).is_err());

        let _ = std::fs::remove_file(wallet_path);
    }
}
