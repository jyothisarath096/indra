//! Session-scoped opaque capabilities for FFI wallet integrations.

use std::{
    collections::HashMap,
    sync::{Arc, Condvar, Mutex, OnceLock},
};

use indra_cli::KeysFile;
use indra_crypto::{
    hybrid::{ClassicalKeypair, HybridKeypair, PqKeypair},
    ColdHybridKeypair,
};
use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroize;

use crate::{
    errors::IndraError, tx::BuiltTxOwned, IndraColdPublicKeyInfo, IndraPublicKeyInfo, BYTES32_LEN,
    CLASSICAL_SK_BYTES, PQ_PK_BYTES, PQ_SK_BYTES,
};

const TOKEN_BYTES: usize = 16;

macro_rules! opaque_token {
    ($name:ident, $invalid:ident) => {
        #[repr(C)]
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
        pub struct $name {
            pub bytes: [u8; TOKEN_BYTES],
        }

        pub const $invalid: $name = $name {
            bytes: [0u8; TOKEN_BYTES],
        };
    };
}

opaque_token!(IndraSessionHandle, INDRA_SESSION_HANDLE_INVALID);
opaque_token!(IndraKeyHandle, INDRA_KEY_HANDLE_INVALID);
opaque_token!(IndraResultHandle, INDRA_RESULT_HANDLE_INVALID);

impl IndraSessionHandle {
    fn is_invalid(self) -> bool {
        self.bytes == [0u8; TOKEN_BYTES]
    }
}

impl IndraKeyHandle {
    fn is_invalid(self) -> bool {
        self.bytes == [0u8; TOKEN_BYTES]
    }
}

static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();

fn registry() -> &'static Mutex<Registry> {
    REGISTRY.get_or_init(|| Mutex::new(Registry::default()))
}

#[derive(Default)]
struct Registry {
    sessions: HashMap<IndraSessionHandle, SessionEntry>,
}

#[derive(Default)]
struct SessionEntry {
    keys: HashMap<IndraKeyHandle, Arc<KeyEntry>>,
    results: HashMap<IndraResultHandle, Arc<BuiltTxOwned>>,
}

struct KeyEntry {
    state: Mutex<KeyState>,
    drained: Condvar,
}

struct KeyState {
    revoked: bool,
    active_leases: usize,
    material: Option<StoredKeyMaterial>,
}

enum StoredKeyMaterial {
    Hot {
        public: IndraPublicKeyInfo,
        classical_seed: [u8; CLASSICAL_SK_BYTES],
        ml_dsa_seed: [u8; PQ_SK_BYTES],
        vrf_seed: [u8; BYTES32_LEN],
    },
    Cold {
        public: IndraColdPublicKeyInfo,
        classical_seed: [u8; CLASSICAL_SK_BYTES],
        pq_seed: [u8; PQ_SK_BYTES],
    },
}

impl StoredKeyMaterial {
    fn from_hot_keys(keys: &KeysFile) -> Result<Self, IndraError> {
        if keys.public.hybrid_pq_pk.len() != PQ_PK_BYTES {
            return Err(IndraError::KeygenFailed);
        }
        let mut pq_pk = [0u8; PQ_PK_BYTES];
        pq_pk.copy_from_slice(&keys.public.hybrid_pq_pk);
        Ok(Self::Hot {
            public: IndraPublicKeyInfo {
                validator_id: keys.public.validator_id,
                classical_pk: keys.public.hybrid_classical_pk,
                pq_pk,
                vrf_pk: keys.public.vrf_pk,
            },
            classical_seed: keys.ed25519_seed,
            ml_dsa_seed: keys.ml_dsa_seed,
            vrf_seed: keys.vrf_seed,
        })
    }

    fn from_cold_seeds(
        classical_seed: [u8; CLASSICAL_SK_BYTES],
        pq_seed: [u8; PQ_SK_BYTES],
    ) -> Result<Self, IndraError> {
        let keypair = ColdHybridKeypair::from_independent_seeds(classical_seed, pq_seed)
            .map_err(|_| IndraError::KeygenFailed)?;
        let public = keypair.public_key();
        let public = public.as_complete_hybrid();
        let mut pq_pk = [0; PQ_PK_BYTES];
        pq_pk.copy_from_slice(&public.pq.0);
        Ok(Self::Cold {
            public: IndraColdPublicKeyInfo {
                classical_pk: public.classical.0,
                pq_pk,
            },
            classical_seed,
            pq_seed,
        })
    }

    fn hot_signing_material(&self) -> Result<SigningMaterial, IndraError> {
        match self {
            Self::Hot {
                public,
                classical_seed,
                ml_dsa_seed,
                ..
            } => Ok(SigningMaterial::Hot {
                public: *public,
                classical_seed: *classical_seed,
                ml_dsa_seed: *ml_dsa_seed,
            }),
            Self::Cold { .. } => Err(IndraError::WrongKeyRole),
        }
    }

    fn cold_signing_material(&self) -> Result<SigningMaterial, IndraError> {
        match self {
            Self::Cold {
                classical_seed,
                pq_seed,
                ..
            } => Ok(SigningMaterial::Cold {
                classical_seed: *classical_seed,
                pq_seed: *pq_seed,
            }),
            Self::Hot { .. } => Err(IndraError::WrongKeyRole),
        }
    }
}

impl Drop for StoredKeyMaterial {
    fn drop(&mut self) {
        match self {
            Self::Hot {
                classical_seed,
                ml_dsa_seed,
                vrf_seed,
                ..
            } => {
                classical_seed.zeroize();
                ml_dsa_seed.zeroize();
                vrf_seed.zeroize();
            }
            Self::Cold {
                classical_seed,
                pq_seed,
                ..
            } => {
                classical_seed.zeroize();
                pq_seed.zeroize();
            }
        }
    }
}

pub(crate) enum SigningMaterial {
    Hot {
        public: IndraPublicKeyInfo,
        classical_seed: [u8; CLASSICAL_SK_BYTES],
        ml_dsa_seed: [u8; PQ_SK_BYTES],
    },
    Cold {
        classical_seed: [u8; CLASSICAL_SK_BYTES],
        pq_seed: [u8; PQ_SK_BYTES],
    },
}

impl SigningMaterial {
    pub(crate) fn keypair(&self) -> Result<HybridKeypair, IndraError> {
        let Self::Hot {
            public,
            classical_seed,
            ml_dsa_seed,
        } = self
        else {
            return Err(IndraError::WrongKeyRole);
        };
        let classical = ClassicalKeypair::from_seed(classical_seed);
        let pq = PqKeypair::from_bytes(&public.pq_pk, ml_dsa_seed)
            .map_err(|_| IndraError::KeygenFailed)?;
        Ok(HybridKeypair::new(classical, pq))
    }

    pub(crate) fn cold_keypair(&self) -> Result<ColdHybridKeypair, IndraError> {
        let Self::Cold {
            classical_seed,
            pq_seed,
            ..
        } = self
        else {
            return Err(IndraError::WrongKeyRole);
        };
        ColdHybridKeypair::from_independent_seeds(*classical_seed, *pq_seed)
            .map_err(|_| IndraError::KeygenFailed)
    }

    pub(crate) fn hot_public(&self) -> Result<IndraPublicKeyInfo, IndraError> {
        match self {
            Self::Hot { public, .. } => Ok(*public),
            Self::Cold { .. } => Err(IndraError::WrongKeyRole),
        }
    }

    pub(crate) fn classical_seed(&self) -> [u8; CLASSICAL_SK_BYTES] {
        match self {
            Self::Hot { classical_seed, .. } => *classical_seed,
            Self::Cold { classical_seed, .. } => *classical_seed,
        }
    }

    pub(crate) fn ml_dsa_seed(&self) -> [u8; PQ_SK_BYTES] {
        match self {
            Self::Hot { ml_dsa_seed, .. } => *ml_dsa_seed,
            Self::Cold { pq_seed, .. } => *pq_seed,
        }
    }
}

impl Drop for SigningMaterial {
    fn drop(&mut self) {
        match self {
            Self::Hot {
                classical_seed,
                ml_dsa_seed,
                ..
            } => {
                classical_seed.zeroize();
                ml_dsa_seed.zeroize();
            }
            Self::Cold {
                classical_seed,
                pq_seed,
                ..
            } => {
                classical_seed.zeroize();
                pq_seed.zeroize();
            }
        }
    }
}

pub(crate) struct SigningLease {
    entry: Arc<KeyEntry>,
    material: SigningMaterial,
}

impl SigningLease {
    pub(crate) fn material(&self) -> &SigningMaterial {
        &self.material
    }

    pub(crate) fn checkpoint(&self) -> Result<(), IndraError> {
        let state = self.entry.state.lock().map_err(|_| IndraError::Internal)?;
        if state.revoked {
            Err(IndraError::HandleRevoked)
        } else {
            Ok(())
        }
    }

    pub(crate) fn publish<R>(
        &self,
        publish: impl FnOnce() -> Result<R, IndraError>,
    ) -> Result<R, IndraError> {
        #[cfg(test)]
        checkpoint_hook();
        let state = self.entry.state.lock().map_err(|_| IndraError::Internal)?;
        if state.revoked {
            return Err(IndraError::HandleRevoked);
        }
        let result = publish();
        drop(state);
        result
    }
}

impl Drop for SigningLease {
    fn drop(&mut self) {
        if let Ok(mut state) = self.entry.state.lock() {
            state.active_leases = state.active_leases.saturating_sub(1);
            if state.active_leases == 0 {
                self.entry.drained.notify_all();
            }
        }
    }
}

fn random_token<T>(wrap: impl Fn([u8; TOKEN_BYTES]) -> T) -> Result<T, IndraError> {
    let mut bytes = [0u8; TOKEN_BYTES];
    while bytes == [0u8; TOKEN_BYTES] {
        OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| IndraError::Internal)?;
    }
    Ok(wrap(bytes))
}

pub(crate) fn create_session() -> Result<IndraSessionHandle, IndraError> {
    let mut guard = registry().lock().map_err(|_| IndraError::Internal)?;
    loop {
        let handle = random_token(|bytes| IndraSessionHandle { bytes })?;
        if let std::collections::hash_map::Entry::Vacant(entry) = guard.sessions.entry(handle) {
            entry.insert(SessionEntry::default());
            return Ok(handle);
        }
    }
}

pub(crate) fn store_hot_keys(
    session: IndraSessionHandle,
    keys: &KeysFile,
) -> Result<(IndraKeyHandle, IndraPublicKeyInfo), IndraError> {
    let material = StoredKeyMaterial::from_hot_keys(keys)?;
    let StoredKeyMaterial::Hot { public, .. } = &material else {
        return Err(IndraError::WrongKeyRole);
    };
    let public = *public;
    store_key_material(session, material).map(|handle| (handle, public))
}

pub(crate) fn store_cold_seeds(
    session: IndraSessionHandle,
    classical_seed: [u8; CLASSICAL_SK_BYTES],
    pq_seed: [u8; PQ_SK_BYTES],
) -> Result<(IndraKeyHandle, IndraColdPublicKeyInfo), IndraError> {
    let material = StoredKeyMaterial::from_cold_seeds(classical_seed, pq_seed)?;
    let StoredKeyMaterial::Cold { public, .. } = &material else {
        return Err(IndraError::WrongKeyRole);
    };
    let public = *public;
    store_key_material(session, material).map(|handle| (handle, public))
}

fn store_key_material(
    session: IndraSessionHandle,
    material: StoredKeyMaterial,
) -> Result<IndraKeyHandle, IndraError> {
    let mut guard = registry().lock().map_err(|_| IndraError::Internal)?;
    let session_entry = guard
        .sessions
        .get_mut(&session)
        .ok_or(IndraError::InvalidSession)?;
    loop {
        let handle = random_token(|bytes| IndraKeyHandle { bytes })?;
        if let std::collections::hash_map::Entry::Vacant(entry) = session_entry.keys.entry(handle) {
            entry.insert(Arc::new(KeyEntry {
                state: Mutex::new(KeyState {
                    revoked: false,
                    active_leases: 0,
                    material: Some(material),
                }),
                drained: Condvar::new(),
            }));
            return Ok(handle);
        }
    }
}

fn key_entry(
    session: IndraSessionHandle,
    handle: IndraKeyHandle,
) -> Result<Arc<KeyEntry>, IndraError> {
    if session.is_invalid() {
        return Err(IndraError::InvalidSession);
    }
    if handle.is_invalid() {
        return Err(IndraError::InvalidHandle);
    }
    let guard = registry().lock().map_err(|_| IndraError::Internal)?;
    guard
        .sessions
        .get(&session)
        .ok_or(IndraError::InvalidSession)?
        .keys
        .get(&handle)
        .cloned()
        .ok_or(IndraError::InvalidHandle)
}

pub(crate) fn public_info(
    session: IndraSessionHandle,
    handle: IndraKeyHandle,
) -> Result<IndraPublicKeyInfo, IndraError> {
    let entry = key_entry(session, handle)?;
    let state = entry.state.lock().map_err(|_| IndraError::Internal)?;
    if state.revoked {
        return Err(IndraError::HandleRevoked);
    }
    match state.material.as_ref().ok_or(IndraError::HandleRevoked)? {
        StoredKeyMaterial::Hot { public, .. } => Ok(*public),
        StoredKeyMaterial::Cold { .. } => Err(IndraError::WrongKeyRole),
    }
}

pub(crate) fn cold_public_info(
    session: IndraSessionHandle,
    handle: IndraKeyHandle,
) -> Result<IndraColdPublicKeyInfo, IndraError> {
    let entry = key_entry(session, handle)?;
    let state = entry.state.lock().map_err(|_| IndraError::Internal)?;
    match state.material.as_ref().ok_or(IndraError::HandleRevoked)? {
        StoredKeyMaterial::Cold { public, .. } => Ok(*public),
        StoredKeyMaterial::Hot { .. } => Err(IndraError::WrongKeyRole),
    }
}

fn acquire_role_signing_lease(
    session: IndraSessionHandle,
    handle: IndraKeyHandle,
    material_for_role: impl FnOnce(&StoredKeyMaterial) -> Result<SigningMaterial, IndraError>,
) -> Result<SigningLease, IndraError> {
    let entry = key_entry(session, handle)?;
    let material = {
        let mut state = entry.state.lock().map_err(|_| IndraError::Internal)?;
        if state.revoked {
            return Err(IndraError::HandleRevoked);
        }
        let material = state.material.as_ref().ok_or(IndraError::HandleRevoked)?;
        let material = material_for_role(material)?;
        state.active_leases = state
            .active_leases
            .checked_add(1)
            .ok_or(IndraError::Internal)?;
        material
    };
    Ok(SigningLease { entry, material })
}

pub(crate) fn acquire_hot_signing_lease(
    session: IndraSessionHandle,
    handle: IndraKeyHandle,
) -> Result<SigningLease, IndraError> {
    acquire_role_signing_lease(session, handle, StoredKeyMaterial::hot_signing_material)
}

pub(crate) fn acquire_cold_signing_lease(
    session: IndraSessionHandle,
    handle: IndraKeyHandle,
) -> Result<SigningLease, IndraError> {
    acquire_role_signing_lease(session, handle, StoredKeyMaterial::cold_signing_material)
}

fn request_revocation(entry: &Arc<KeyEntry>) -> Result<(), IndraError> {
    let mut state = entry.state.lock().map_err(|_| IndraError::Internal)?;
    state.revoked = true;
    #[cfg(test)]
    revocation_hook();
    Ok(())
}

fn drain_and_zeroize(entry: Arc<KeyEntry>) -> Result<(), IndraError> {
    let mut state = entry.state.lock().map_err(|_| IndraError::Internal)?;
    while state.active_leases != 0 {
        state = entry
            .drained
            .wait(state)
            .map_err(|_| IndraError::Internal)?;
    }
    state.material.take();
    Ok(())
}

pub(crate) fn destroy_key(
    session: IndraSessionHandle,
    handle: IndraKeyHandle,
) -> Result<(), IndraError> {
    let entry = {
        let mut guard = registry().lock().map_err(|_| IndraError::Internal)?;
        let session_entry = guard
            .sessions
            .get_mut(&session)
            .ok_or(IndraError::InvalidSession)?;
        let entry = session_entry
            .keys
            .get(&handle)
            .cloned()
            .ok_or(IndraError::InvalidHandle)?;
        request_revocation(&entry)?;
        session_entry.keys.remove(&handle);
        entry
    };
    drain_and_zeroize(entry)
}

pub(crate) fn destroy_session(session: IndraSessionHandle) -> Result<(), IndraError> {
    let entries = {
        let mut guard = registry().lock().map_err(|_| IndraError::Internal)?;
        let session_entry = guard
            .sessions
            .get(&session)
            .ok_or(IndraError::InvalidSession)?;
        let entries: Vec<_> = session_entry.keys.values().cloned().collect();
        for entry in &entries {
            request_revocation(entry)?;
        }
        guard.sessions.remove(&session);
        entries
    };
    for entry in entries {
        drain_and_zeroize(entry)?;
    }
    Ok(())
}

pub(crate) fn store_result(
    session: IndraSessionHandle,
    result: BuiltTxOwned,
) -> Result<IndraResultHandle, IndraError> {
    let mut guard = registry().lock().map_err(|_| IndraError::Internal)?;
    let session_entry = guard
        .sessions
        .get_mut(&session)
        .ok_or(IndraError::InvalidSession)?;
    loop {
        let handle = random_token(|bytes| IndraResultHandle { bytes })?;
        if let std::collections::hash_map::Entry::Vacant(entry) =
            session_entry.results.entry(handle)
        {
            entry.insert(Arc::new(result));
            return Ok(handle);
        }
    }
}

pub(crate) fn with_result<R>(
    session: IndraSessionHandle,
    handle: IndraResultHandle,
    read: impl FnOnce(&BuiltTxOwned) -> R,
) -> Result<R, IndraError> {
    let result = {
        let guard = registry().lock().map_err(|_| IndraError::Internal)?;
        guard
            .sessions
            .get(&session)
            .ok_or(IndraError::InvalidSession)?
            .results
            .get(&handle)
            .cloned()
            .ok_or(IndraError::InvalidResult)?
    };
    Ok(read(&result))
}

pub(crate) fn destroy_result(
    session: IndraSessionHandle,
    handle: IndraResultHandle,
) -> Result<(), IndraError> {
    registry()
        .lock()
        .map_err(|_| IndraError::Internal)?
        .sessions
        .get_mut(&session)
        .ok_or(IndraError::InvalidSession)?
        .results
        .remove(&handle)
        .map(|_| ())
        .ok_or(IndraError::InvalidResult)
}

#[cfg(test)]
static CHECKPOINT_HOOK: OnceLock<
    Mutex<Option<(Arc<std::sync::Barrier>, Arc<std::sync::Barrier>)>>,
> = OnceLock::new();

#[cfg(test)]
static REVOCATION_HOOK: OnceLock<Mutex<Option<Arc<std::sync::Barrier>>>> = OnceLock::new();

#[cfg(test)]
pub(crate) fn install_checkpoint_hook(
    reached: Arc<std::sync::Barrier>,
    release: Arc<std::sync::Barrier>,
) {
    *CHECKPOINT_HOOK
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap() = Some((reached, release));
}

#[cfg(test)]
pub(crate) fn install_revocation_hook(revoked: Arc<std::sync::Barrier>) {
    *REVOCATION_HOOK
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap() = Some(revoked);
}

#[cfg(test)]
fn checkpoint_hook() {
    let hook = CHECKPOINT_HOOK
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap()
        .take();
    if let Some((reached, release)) = hook {
        reached.wait();
        release.wait();
    }
}

#[cfg(test)]
fn revocation_hook() {
    let hook = REVOCATION_HOOK
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap()
        .take();
    if let Some(revoked) = hook {
        revoked.wait();
    }
}
