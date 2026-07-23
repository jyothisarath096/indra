//! Opaque in-process key handles for FFI wallet integrations.
//!
//! Handles are process-local capabilities. They are not persistent storage and
//! they deliberately avoid platform-specific assumptions such as iOS Keychain
//! or Android Keystore. The consuming app is responsible for storing recovery
//! material in its platform secure storage, recreating a handle on unlock, and
//! destroying it on wallet lock/logout.

use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
};

use indra_cli::KeysFile;
use indra_crypto::hybrid::{ClassicalKeypair, HybridKeypair, PqKeypair};
use indra_crypto::{PaymentKeypairV1, PaymentPubKeyV1};
use zeroize::Zeroize;

use crate::{
    errors::IndraError, IndraPublicKeyInfo, BYTES32_LEN, CLASSICAL_SK_BYTES, PQ_PK_BYTES,
    PQ_SK_BYTES,
};

pub type IndraKeyHandle = u64;
pub const INDRA_KEY_HANDLE_INVALID: IndraKeyHandle = 0;

static KEY_REGISTRY: OnceLock<Mutex<KeyRegistry>> = OnceLock::new();

fn registry() -> &'static Mutex<KeyRegistry> {
    KEY_REGISTRY.get_or_init(|| Mutex::new(KeyRegistry::new()))
}

struct KeyRegistry {
    next_handle: IndraKeyHandle,
    entries: HashMap<IndraKeyHandle, StoredKeyMaterial>,
}

impl KeyRegistry {
    fn new() -> Self {
        Self {
            next_handle: 1,
            entries: HashMap::new(),
        }
    }

    fn insert(&mut self, material: StoredKeyMaterial) -> Result<IndraKeyHandle, IndraError> {
        let start = self.next_handle.max(1);
        let mut candidate = start;
        loop {
            if candidate != INDRA_KEY_HANDLE_INVALID && !self.entries.contains_key(&candidate) {
                self.entries.insert(candidate, material);
                self.next_handle = candidate.wrapping_add(1).max(1);
                return Ok(candidate);
            }
            candidate = candidate.wrapping_add(1).max(1);
            if candidate == start {
                return Err(IndraError::Internal);
            }
        }
    }
}

struct StoredKeyMaterial {
    public: IndraPublicKeyInfo,
    classical_seed: [u8; CLASSICAL_SK_BYTES],
    pq_sk: [u8; PQ_SK_BYTES],
    bls_seed: [u8; BYTES32_LEN],
    vrf_seed: [u8; BYTES32_LEN],
    payment_keypair: PaymentKeypairV1,
}

impl StoredKeyMaterial {
    fn from_keys(keys: &KeysFile) -> Result<Self, IndraError> {
        if keys.public.hybrid_pq_pk.len() != PQ_PK_BYTES || keys.pq_sk.len() != PQ_SK_BYTES {
            return Err(IndraError::KeygenFailed);
        }
        let mut pq_pk = [0u8; PQ_PK_BYTES];
        pq_pk.copy_from_slice(&keys.public.hybrid_pq_pk);
        let mut pq_sk = [0u8; PQ_SK_BYTES];
        pq_sk.copy_from_slice(&keys.pq_sk);
        let payment_keypair = keys
            .payment_keypair
            .clone()
            .ok_or(IndraError::KeygenFailed)?;
        Ok(Self {
            public: IndraPublicKeyInfo {
                validator_id: keys.public.validator_id,
                classical_pk: keys.public.hybrid_classical_pk,
                pq_pk,
                vrf_pk: keys.public.vrf_pk,
            },
            classical_seed: keys.hybrid_seed,
            pq_sk,
            bls_seed: keys.bls_seed,
            vrf_seed: keys.vrf_seed,
            payment_keypair,
        })
    }

    fn signing_material(&self) -> SigningMaterial {
        SigningMaterial {
            public: self.public,
            classical_seed: self.classical_seed,
            pq_sk: self.pq_sk,
        }
    }

    fn payment_keypair(&self) -> PaymentKeypairV1 {
        self.payment_keypair.clone()
    }
}

impl Drop for StoredKeyMaterial {
    fn drop(&mut self) {
        self.classical_seed.zeroize();
        self.pq_sk.zeroize();
        self.bls_seed.zeroize();
        self.vrf_seed.zeroize();
        self.payment_keypair.x25519_sk.zeroize();
        self.payment_keypair.ml_kem_1024_seed.zeroize();
    }
}

pub(crate) struct SigningMaterial {
    pub public: IndraPublicKeyInfo,
    classical_seed: [u8; CLASSICAL_SK_BYTES],
    pq_sk: [u8; PQ_SK_BYTES],
}

impl SigningMaterial {
    pub(crate) fn keypair(&self) -> Result<HybridKeypair, IndraError> {
        let classical = ClassicalKeypair::from_seed(&self.classical_seed);
        let pq = PqKeypair::from_bytes(&self.public.pq_pk, &self.pq_sk)
            .map_err(|_| IndraError::KeygenFailed)?;
        Ok(HybridKeypair::new(classical, pq))
    }

    pub(crate) fn classical_seed(&self) -> [u8; CLASSICAL_SK_BYTES] {
        self.classical_seed
    }

    pub(crate) fn pq_sk(&self) -> [u8; PQ_SK_BYTES] {
        self.pq_sk
    }
}

impl Drop for SigningMaterial {
    fn drop(&mut self) {
        self.classical_seed.zeroize();
        self.pq_sk.zeroize();
    }
}

pub(crate) fn store_keys(
    keys: &KeysFile,
) -> Result<(IndraKeyHandle, IndraPublicKeyInfo), IndraError> {
    let material = StoredKeyMaterial::from_keys(keys)?;
    let public = material.public;
    let mut guard = registry().lock().map_err(|_| IndraError::Internal)?;
    let handle = guard.insert(material)?;
    Ok((handle, public))
}

pub(crate) fn public_info(handle: IndraKeyHandle) -> Result<IndraPublicKeyInfo, IndraError> {
    if handle == INDRA_KEY_HANDLE_INVALID {
        return Err(IndraError::InvalidHandle);
    }
    let guard = registry().lock().map_err(|_| IndraError::Internal)?;
    guard
        .entries
        .get(&handle)
        .map(|entry| entry.public)
        .ok_or(IndraError::InvalidHandle)
}

pub(crate) fn signing_material(handle: IndraKeyHandle) -> Result<SigningMaterial, IndraError> {
    if handle == INDRA_KEY_HANDLE_INVALID {
        return Err(IndraError::InvalidHandle);
    }
    let guard = registry().lock().map_err(|_| IndraError::Internal)?;
    guard
        .entries
        .get(&handle)
        .map(StoredKeyMaterial::signing_material)
        .ok_or(IndraError::InvalidHandle)
}

pub(crate) fn payment_pubkey(handle: IndraKeyHandle) -> Result<PaymentPubKeyV1, IndraError> {
    payment_keypair(handle).map(|keypair| keypair.public_key())
}

pub(crate) fn payment_keypair(handle: IndraKeyHandle) -> Result<PaymentKeypairV1, IndraError> {
    if handle == INDRA_KEY_HANDLE_INVALID {
        return Err(IndraError::InvalidHandle);
    }
    let guard = registry().lock().map_err(|_| IndraError::Internal)?;
    guard
        .entries
        .get(&handle)
        .map(StoredKeyMaterial::payment_keypair)
        .ok_or(IndraError::InvalidHandle)
}

pub(crate) fn destroy(handle: IndraKeyHandle) -> Result<(), IndraError> {
    if handle == INDRA_KEY_HANDLE_INVALID {
        return Err(IndraError::InvalidHandle);
    }
    let mut guard = registry().lock().map_err(|_| IndraError::Internal)?;
    guard
        .entries
        .remove(&handle)
        .map(|_| ())
        .ok_or(IndraError::InvalidHandle)
}

pub(crate) fn destroy_all() -> Result<(), IndraError> {
    let mut guard = registry().lock().map_err(|_| IndraError::Internal)?;
    guard.entries.clear();
    Ok(())
}
