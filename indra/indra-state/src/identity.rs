//! Delegator identity-registry resolution helpers.
//!
//! These helpers enforce canonical identity-registry consistency for staking and
//! governance operations.

use indra_core::types::{crypto::HybridPubKey, primitives::Bytes32};

use crate::ChainState;

/// Successful identity-check result for operations that submit a full pubkey.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityCheckOutcome {
    /// The submitted key matched an existing registry entry.
    RegistryMatch,
    /// No registry entry exists for this identity.
    NoPriorRecord,
}

/// Identity-resolution failure reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityError {
    /// A registry entry exists, but the submitted public key differs.
    RegistryPubkeyMismatch {
        /// Delegator identity being checked.
        delegator_id: Bytes32,
    },
    /// No registry entry exists for this identity.
    UnresolvableIdentity {
        /// Validator context for validator-scoped lookup paths.
        validator_id: Option<Bytes32>,
        /// Delegator identity being resolved.
        delegator_id: Bytes32,
    },
}

pub(crate) fn resolve_active_validator_cold_pubkey(
    state: &ChainState,
    validator_id: &Bytes32,
) -> Result<HybridPubKey, IdentityError> {
    let Some(validator) = state.validators.get(validator_id) else {
        if let Some(cold) = state
            .evicted_validator_tombstones
            .get(validator_id)
            .and_then(|tombstone| tombstone.cold_custody.as_ref())
        {
            return Ok(HybridPubKey {
                classical_pk: Bytes32::from(cold.classical_pk),
                pq_pk: indra_core::VariableBytes::from_slice(&cold.pq_pk).map_err(|_| {
                    IdentityError::UnresolvableIdentity {
                        validator_id: Some(*validator_id),
                        delegator_id: *validator_id,
                    }
                })?,
            });
        }
        return Err(IdentityError::UnresolvableIdentity {
            validator_id: Some(*validator_id),
            delegator_id: *validator_id,
        });
    };
    let classical =
        validator
            .cold_hybrid_classical_pk
            .ok_or(IdentityError::UnresolvableIdentity {
                validator_id: Some(*validator_id),
                delegator_id: *validator_id,
            })?;
    let pq = validator
        .cold_hybrid_pq_pk
        .ok_or(IdentityError::UnresolvableIdentity {
            validator_id: Some(*validator_id),
            delegator_id: *validator_id,
        })?;
    Ok(HybridPubKey {
        classical_pk: Bytes32::from(classical),
        pq_pk: indra_core::VariableBytes::from_slice(&pq).map_err(|_| {
            IdentityError::UnresolvableIdentity {
                validator_id: Some(*validator_id),
                delegator_id: *validator_id,
            }
        })?,
    })
}

/// Resolve and check a submitted delegator public key against existing state.
///
/// Registry entries are authoritative. Absence means this is a new identity.
pub fn resolve_and_check_identity(
    delegator_id: &Bytes32,
    submitted_pubkey: &HybridPubKey,
    state: &ChainState,
) -> Result<IdentityCheckOutcome, IdentityError> {
    if let Some(registered_pubkey) = state.delegator_identities.get(delegator_id) {
        if registered_pubkey == submitted_pubkey {
            return Ok(IdentityCheckOutcome::RegistryMatch);
        }
        return Err(IdentityError::RegistryPubkeyMismatch {
            delegator_id: *delegator_id,
        });
    }

    Ok(IdentityCheckOutcome::NoPriorRecord)
}

/// Resolve a delegator public key from state for governance redelegation.
///
/// The registry is authoritative; no alternate identity source is accepted.
pub fn resolve_delegator_identity_for_redelegation(
    validator_id: &Bytes32,
    delegator_id: &Bytes32,
    state: &ChainState,
) -> Result<HybridPubKey, IdentityError> {
    if let Some(registered_pubkey) = state.delegator_identities.get(delegator_id) {
        return Ok(registered_pubkey.clone());
    }

    Err(IdentityError::UnresolvableIdentity {
        validator_id: Some(*validator_id),
        delegator_id: *delegator_id,
    })
}

#[cfg(test)]
mod tests {
    use indra_core::types::primitives::TEST_CHAIN_ID;
    use super::*;
    use indra_core::{types::crypto::HybridPubKey, VariableBytes};

    fn id(byte: u8) -> Bytes32 {
        Bytes32::from([byte; 32])
    }

    fn pubkey(classical: u8, pq: u8) -> HybridPubKey {
        HybridPubKey {
            classical_pk: id(classical),
            pq_pk: VariableBytes::from_slice(&[pq; 32]).unwrap_or_default(),
        }
    }

    #[test]
    fn resolve_registered_identity_accepts_matching_submitted_pubkey() {
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
        let delegator_id = id(0x10);
        let registered = pubkey(0x10, 0xA0);
        state
            .delegator_identities
            .insert(delegator_id, registered.clone());

        assert_eq!(
            resolve_and_check_identity(&delegator_id, &registered, &state),
            Ok(IdentityCheckOutcome::RegistryMatch)
        );
    }

    #[test]
    fn resolve_registered_identity_rejects_different_submitted_pubkey() {
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
        let delegator_id = id(0x11);
        state
            .delegator_identities
            .insert(delegator_id, pubkey(0x11, 0xA1));

        assert_eq!(
            resolve_and_check_identity(&delegator_id, &pubkey(0x11, 0xB1), &state),
            Err(IdentityError::RegistryPubkeyMismatch { delegator_id })
        );
    }

    #[test]
    fn resolve_new_identity_without_registry_reports_no_prior_record() {
        let state = ChainState::new_genesis(TEST_CHAIN_ID);
        let delegator_id = id(0x12);

        assert_eq!(
            resolve_and_check_identity(&delegator_id, &pubkey(0x12, 0xA2), &state),
            Ok(IdentityCheckOutcome::NoPriorRecord)
        );
    }
}
