//! `indra-governance` — build and submit governance operations.

use indra_cli::{
    fetch_chain_id, reconstruct_keypair, staking::http_post, CliError, CliResult, KeysFile,
};
use indra_core::{
    codec::Encode,
    types::{
        crypto::{HybridPubKey, HybridSignature},
        governance::{
            governance_signing_domain, GovernableAction, GovernanceOpV2, GovernancePayload,
        },
        primitives::{Bytes32, VariableBytes},
    },
};
use indra_crypto::{sha256, HybridKeypair};

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

    let command = args[0].as_str();
    let keys = KeysFile::load(&flag_value(&args, "--keys").unwrap_or_else(|| "keys.json".into()))?;
    let keypair = reconstruct_keypair(&keys)?;
    let signer_id = signer_id_from_keys(&keys);
    let node_url = flag_value(&args, "--node").unwrap_or_else(|| "http://127.0.0.1:8545".into());
    let chain_id = fetch_chain_id(&node_url)?;
    let nonce = match flag_value(&args, "--nonce") {
        Some(raw) => parse_u64(&raw, "--nonce")?,
        None => fetch_governance_nonce(&node_url, signer_id)?,
    };

    let payload = match command {
        "propose" => GovernancePayload::Propose {
            action: parse_governable_action(&args)?,
            deposit_utxo_id: parse_hex32_required(&args, "--deposit-utxo")?,
            proposer_pubkey: hybrid_pubkey_from_keypair(&keypair)?,
            title: variable_bytes(&required_flag(&args, "--title")?, "--title")?,
            description: variable_bytes(&required_flag(&args, "--description")?, "--description")?,
        },
        "commit" => {
            let proposal_id = parse_hex32_required(&args, "--proposal-id")?;
            let vote = parse_vote(&required_flag(&args, "--vote")?)?;
            let vote_nonce = parse_hex32_required(&args, "--vote-nonce")?;
            GovernancePayload::Commit {
                proposal_id,
                commit_hash: compute_vote_commit_hash(vote, vote_nonce),
            }
        }
        "reveal" => GovernancePayload::Reveal {
            proposal_id: parse_hex32_required(&args, "--proposal-id")?,
            vote: parse_vote(&required_flag(&args, "--vote")?)?,
            nonce: parse_hex32_required(&args, "--vote-nonce")?,
        },
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
        },
        _ => {
            print_help();
            return Err(CliError::Parse(format!(
                "unknown governance command '{command}'"
            )));
        }
    };

    let op = build_governance_op(signer_id, nonce, payload, &keypair, &chain_id)?;
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
    Ok(())
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
        "slash-surround-vote-bps" => Ok(GovernableAction::SetSlashSurroundVoteBps {
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

fn compute_vote_commit_hash(vote: u8, nonce: Bytes32) -> Bytes32 {
    let mut bytes = Vec::with_capacity(33);
    vote.encode(&mut bytes);
    nonce.encode(&mut bytes);
    Bytes32::from(sha256(&bytes))
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

fn signer_id_from_keys(keys: &KeysFile) -> Bytes32 {
    Bytes32::from(sha256(&keys.public.hybrid_classical_pk))
}

fn hybrid_pubkey_from_keypair(keypair: &HybridKeypair) -> CliResult<HybridPubKey> {
    let public = keypair.public_key();
    Ok(HybridPubKey {
        classical_pk: Bytes32::from(public.classical.0),
        pq_pk: VariableBytes::from_slice(&public.pq.0)
            .map_err(|_| CliError::Transaction("pq pubkey too large".into()))?,
    })
}

fn parse_vote(raw: &str) -> CliResult<u8> {
    match raw {
        "yes" | "YES" | "1" => Ok(1),
        "no" | "NO" | "2" => Ok(2),
        "abstain" | "ABSTAIN" | "0" => Ok(0),
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
  --node <url>     Node RPC URL (default: http://127.0.0.1:8545)\n\
  --nonce <n>      Governance nonce override\n\
  --dry-run        Build and sign but do not submit\n\n\
Propose flags:\n\
  --action <name> --value <n> --deposit-utxo <hex> --title <text> --description <text>\n\n\
Vote flags:\n\
  --proposal-id <hex> --vote yes|no|abstain --vote-nonce <32-byte-hex>"
    );
}
