//! Bounded scheduling for network-sourced quorum-certificate verification.

use std::{
    collections::{HashMap, VecDeque},
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc, Arc, Mutex,
    },
    time::{Duration, Instant},
};

use indra_core::codec::Encode;
use indra_core::types::{
    consensus_snapshot::ConsensusSnapshot,
    primitives::Bytes32,
    qc::{verify_qc_against_snapshot, QcVerificationError, QuorumCertificateV1},
};

/// Failure returned by the network-only QC scheduler.
#[derive(Debug, thiserror::Error)]
pub enum NetworkQcVerificationError {
    /// The dedicated worker terminated and cannot return an outcome.
    #[error("network QC verifier is unavailable")]
    Unavailable,
    /// Authoritative cryptographic verification rejected the candidate.
    #[error(transparent)]
    Invalid(#[from] QcVerificationError),
}

/// Maximum queued network QCs. At the protocol maximum QC size this bounds
/// queued payload memory below 40 MiB at the absolute 10 MiB codec cap, and
/// about 4 MiB at the deployed 200-validator maximum.
pub const NETWORK_QC_QUEUE_CAPACITY: usize = 4;
/// Maximum cached outcomes. Entries contain only a compact key and error.
pub const NETWORK_QC_CACHE_CAPACITY: usize = 2_048;
/// Cache lifetime: two 8-second proposal windows, covering immediate replay
/// while expiring well before normal epoch authority churn.
pub const NETWORK_QC_CACHE_TTL: Duration = Duration::from_secs(16);
/// At most ten new expensive verifications start per second. With the measured
/// 48 ms maximum QC cost this caps this worker near 48% of one CPU core.
pub const NETWORK_QC_MIN_START_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
struct CacheKey {
    qc_hash: [u8; 32],
    height: u64,
    snapshot_root: Bytes32,
    chain_hash: [u8; 32],
}

struct Request {
    qc: QuorumCertificateV1,
    snapshot: ConsensusSnapshot,
    chain_id: String,
    response: mpsc::SyncSender<Result<(), QcVerificationError>>,
}

/// Node-owned bounded worker for attacker-controlled QC candidates.
///
/// `sync_channel` provides backpressure when its fixed queue is full. Requests
/// are never dropped: every successful submission blocks until it receives the
/// verifier's result. Canonical replay/state application does not use this type.
#[derive(Clone)]
pub struct NetworkQcVerifier {
    sender: mpsc::SyncSender<Request>,
    expensive_verifications: Arc<AtomicU64>,
    worker_handle: Arc<Mutex<Option<std::thread::JoinHandle<()>>>>,
}

impl NetworkQcVerifier {
    /// Start one dedicated verification worker for this node.
    pub fn new() -> Self {
        let (sender, receiver) = mpsc::sync_channel::<Request>(NETWORK_QC_QUEUE_CAPACITY);
        let expensive_verifications = Arc::new(AtomicU64::new(0));
        let worker_count = Arc::clone(&expensive_verifications);
        let worker_handle = std::thread::spawn(move || worker(receiver, &worker_count));
        Self {
            sender,
            expensive_verifications,
            worker_handle: Arc::new(Mutex::new(Some(worker_handle))),
        }
    }

    /// Take ownership of the verifier worker so the node supervisor can
    /// treat an unexpected worker exit as process-fatal.
    pub fn take_worker_handle(&self) -> Option<std::thread::JoinHandle<()>> {
        self.worker_handle.lock().ok()?.take()
    }

    /// Queue and await one network-sourced QC verification result.
    pub fn verify(
        &self,
        qc: &QuorumCertificateV1,
        snapshot: &ConsensusSnapshot,
        chain_id: &str,
    ) -> Result<(), NetworkQcVerificationError> {
        let (response, result) = mpsc::sync_channel(1);
        self.sender
            .send(Request {
                qc: qc.clone(),
                snapshot: snapshot.clone(),
                chain_id: chain_id.to_string(),
                response,
            })
            .map_err(|_| NetworkQcVerificationError::Unavailable)?;
        result
            .recv()
            .map_err(|_| NetworkQcVerificationError::Unavailable)?
            .map_err(NetworkQcVerificationError::Invalid)
    }

    /// Number of cache-miss cryptographic verifications started by this worker.
    pub fn expensive_verification_count(&self) -> u64 {
        self.expensive_verifications.load(Ordering::Relaxed)
    }
}

impl Default for NetworkQcVerifier {
    fn default() -> Self {
        Self::new()
    }
}

fn key(request: &Request) -> CacheKey {
    CacheKey {
        qc_hash: indra_crypto::sha256(&request.qc.encode_to_vec()),
        height: request.qc.height,
        snapshot_root: request.snapshot.snapshot_root,
        chain_hash: indra_crypto::sha256(request.chain_id.as_bytes()),
    }
}

fn worker(receiver: mpsc::Receiver<Request>, expensive_verifications: &AtomicU64) {
    let mut cache: HashMap<CacheKey, (Instant, Result<(), QcVerificationError>)> = HashMap::new();
    let mut order = VecDeque::new();
    let mut last_expensive_start = None;
    while let Ok(request) = receiver.recv() {
        let now = Instant::now();
        let cache_key = key(&request);
        if let Some((stored, result)) = cache.get(&cache_key) {
            if now.duration_since(*stored) <= NETWORK_QC_CACHE_TTL {
                let _ = request.response.send(result.clone());
                continue;
            }
        }
        if let Some(last) = last_expensive_start {
            let elapsed = now.duration_since(last);
            if elapsed < NETWORK_QC_MIN_START_INTERVAL {
                std::thread::sleep(NETWORK_QC_MIN_START_INTERVAL - elapsed);
            }
        }
        last_expensive_start = Some(Instant::now());
        expensive_verifications.fetch_add(1, Ordering::Relaxed);
        let result = verify_qc_against_snapshot(&request.qc, &request.snapshot, &request.chain_id)
            .map(|_| ());
        let inserted = Instant::now();
        cache.insert(cache_key, (inserted, result.clone()));
        order.push_back((cache_key, inserted));
        while order.len() > NETWORK_QC_CACHE_CAPACITY {
            if let Some((old_key, old_time)) = order.pop_front() {
                if cache
                    .get(&old_key)
                    .is_some_and(|(time, _)| *time == old_time)
                {
                    cache.remove(&old_key);
                }
            }
        }
        let _ = request.response.send(result);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervisor::{CriticalTaskOutcome, CriticalTasks};

    #[test]
    fn qc_worker_exit_is_reported_as_task_exit() {
        let verifier = NetworkQcVerifier::new();
        let handle = verifier.take_worker_handle().expect("worker handle");
        drop(verifier);
        let mut tasks = CriticalTasks::new();
        tasks.adopt("network-qc-verifier", handle);
        let outcome = loop {
            match tasks.try_recv() {
                Ok(outcome) => break outcome,
                Err(std::sync::mpsc::TryRecvError::Empty) => std::thread::yield_now(),
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    panic!("supervisor disconnected")
                }
            }
        };
        assert_eq!(
            outcome,
            CriticalTaskOutcome::TaskExited {
                name: "network-qc-verifier".into(),
                reason: "returned".into()
            }
        );
    }
}
