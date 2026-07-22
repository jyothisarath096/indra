//! Delegator identity-registry resolution helpers.
//!
//! Stage 3 intentionally exposes these helpers without wiring them into live
//! staking or governance operations. Later stages use them to enforce
//! post-activation PQ-key consistency while preserving legacy fallback behavior.

use indra_core::types::{crypto::HybridPubKey, primitives::Bytes32};

use crate::ChainState;

/// Successful identity-check result for operations that submit a full pubkey.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityCheckOutcome {
    /// The submitted key matched an existing registry entry.
    RegistryMatch,
    /// No registry entry existed, but legacy bond history had one matching key.
    LegacyBondMatch,
    /// No registry entry and no legacy bond history existed for this identity.
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
    /// Legacy bond history exists and is internally consistent, but differs from
    /// the submitted public key.
    LegacyPubkeyMismatch {
        /// Delegator identity being checked.
        delegator_id: Bytes32,
    },
    /// Legacy bond history has more than one embedded public key for the same
    /// identity, so no key can be selected safely.
    AmbiguousLegacyPubkeys {
        /// Delegator identity being checked.
        delegator_id: Bytes32,
    },
    /// No registry entry or usable legacy bond key exists for this identity.
    UnresolvableIdentity {
        /// Validator context for validator-scoped lookup paths.
        validator_id: Option<Bytes32>,
        /// Delegator identity being resolved.
        delegator_id: Bytes32,
    },
}

/// Resolve the spend owner for a stake bond.
///
/// Legacy and range-proof-compact bonds are authoritative for their own embedded
/// owner key. Fully compact bonds must resolve through the identity registry.
pub fn resolve_bond_owner_pubkey(
    bond: &crate::validator::StakeBondEntry,
    state: &ChainState,
) -> Result<HybridPubKey, IdentityError> {
    if let Some(owner_pubkey) = &bond.original_output.owner_pubkey {
        return Ok(owner_pubkey.clone());
    }
    state
        .delegator_identities
        .get(&bond.delegator_id)
        .cloned()
        .ok_or(IdentityError::UnresolvableIdentity {
            validator_id: Some(bond.validator_id),
            delegator_id: bond.delegator_id,
        })
}

/// Resolve and check a submitted delegator public key against existing state.
///
/// Registry entries are authoritative. If no registry entry exists, only legacy
/// stake bonds that retained a range proof are considered as fallback evidence.
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

    match unique_legacy_bond_pubkey(state, |bond| &bond.delegator_id == delegator_id) {
        LegacyPubkeyResolution::None => Ok(IdentityCheckOutcome::NoPriorRecord),
        LegacyPubkeyResolution::Unique(pubkey) => {
            if &pubkey == submitted_pubkey {
                Ok(IdentityCheckOutcome::LegacyBondMatch)
            } else {
                Err(IdentityError::LegacyPubkeyMismatch {
                    delegator_id: *delegator_id,
                })
            }
        }
        LegacyPubkeyResolution::Ambiguous => Err(IdentityError::AmbiguousLegacyPubkeys {
            delegator_id: *delegator_id,
        }),
    }
}

/// Resolve a delegator public key from state for governance redelegation.
///
/// Registry entries are authoritative. If no registry entry exists, this falls
/// back to the unique active legacy bond key for `(validator_id, delegator_id)`.
pub fn resolve_delegator_identity_for_redelegation(
    validator_id: &Bytes32,
    delegator_id: &Bytes32,
    state: &ChainState,
) -> Result<HybridPubKey, IdentityError> {
    if let Some(registered_pubkey) = state.delegator_identities.get(delegator_id) {
        return Ok(registered_pubkey.clone());
    }

    match unique_legacy_bond_pubkey(state, |bond| {
        &bond.validator_id == validator_id
            && &bond.delegator_id == delegator_id
            && bond.unbonding_end_epoch.is_none()
    }) {
        LegacyPubkeyResolution::None => Err(IdentityError::UnresolvableIdentity {
            validator_id: Some(*validator_id),
            delegator_id: *delegator_id,
        }),
        LegacyPubkeyResolution::Unique(pubkey) => Ok(pubkey),
        LegacyPubkeyResolution::Ambiguous => Err(IdentityError::AmbiguousLegacyPubkeys {
            delegator_id: *delegator_id,
        }),
    }
}

enum LegacyPubkeyResolution {
    None,
    Unique(HybridPubKey),
    Ambiguous,
}

fn unique_legacy_bond_pubkey(
    state: &ChainState,
    mut include_bond: impl FnMut(&crate::validator::StakeBondEntry) -> bool,
) -> LegacyPubkeyResolution {
    let mut unique_pubkey: Option<HybridPubKey> = None;
    for (_utxo_id, bond) in &state.staked_bonds {
        if bond.original_output.owner_pubkey.is_none()
            || bond.original_output.range_proof.is_none()
            || !include_bond(bond)
        {
            continue;
        }
        let owner_pubkey = bond
            .original_output
            .owner_pubkey
            .as_ref()
            .expect("checked above");
        match &unique_pubkey {
            Some(existing) if existing != owner_pubkey => {
                return LegacyPubkeyResolution::Ambiguous;
            }
            Some(_) => {}
            None => unique_pubkey = Some(owner_pubkey.clone()),
        }
    }

    unique_pubkey
        .map(LegacyPubkeyResolution::Unique)
        .unwrap_or(LegacyPubkeyResolution::None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_core::{
        types::{
            crypto::{CommitmentV1, HybridPubKey},
            transaction::OutputV1,
        },
        VariableBytes,
    };

    use crate::validator::StakeBondEntry;

    fn id(byte: u8) -> Bytes32 {
        Bytes32::from([byte; 32])
    }

    fn pubkey(classical: u8, pq: u8) -> HybridPubKey {
        HybridPubKey {
            classical_pk: id(classical),
            pq_pk: VariableBytes::from_slice(&[pq; 32]).unwrap_or_default(),
        }
    }

    fn output(owner_pubkey: HybridPubKey, byte: u8) -> OutputV1 {
        OutputV1 {
            value_spark: 1_000,
            commitment: CommitmentV1 {
                compressed_point: id(byte),
            },
            owner_pubkey,
            range_proof: VariableBytes::from_slice(&[byte]).unwrap_or_default(),
            lock_height: 0,
        }
    }

    fn legacy_bond(
        utxo_id: Bytes32,
        validator_id: Bytes32,
        delegator_id: Bytes32,
        owner_pubkey: HybridPubKey,
        byte: u8,
    ) -> StakeBondEntry {
        StakeBondEntry::new_for_test_with_compact_activation(
            utxo_id,
            validator_id,
            delegator_id,
            1_000,
            1,
            output(owner_pubkey, byte),
            0,
            u64::MAX,
        )
    }

    fn compact_bond(
        utxo_id: Bytes32,
        validator_id: Bytes32,
        delegator_id: Bytes32,
        owner_pubkey: HybridPubKey,
        byte: u8,
    ) -> StakeBondEntry {
        StakeBondEntry::new_for_test_with_compact_activation(
            utxo_id,
            validator_id,
            delegator_id,
            1_000,
            1,
            output(owner_pubkey, byte),
            2,
            1,
        )
    }

    fn fully_compact_bond(
        utxo_id: Bytes32,
        validator_id: Bytes32,
        delegator_id: Bytes32,
        owner_pubkey: HybridPubKey,
        byte: u8,
    ) -> StakeBondEntry {
        StakeBondEntry::new_for_test_with_compact_and_pubkey_activation(
            utxo_id,
            validator_id,
            delegator_id,
            1_000,
            1,
            output(owner_pubkey, byte),
            2,
            1,
            2,
        )
    }

    #[test]
    fn resolve_registered_identity_accepts_matching_submitted_pubkey() {
        let mut state = ChainState::new_genesis();
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
        let mut state = ChainState::new_genesis();
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
    fn resolve_new_identity_without_registry_or_legacy_bonds_reports_no_prior_record() {
        let state = ChainState::new_genesis();
        let delegator_id = id(0x12);

        assert_eq!(
            resolve_and_check_identity(&delegator_id, &pubkey(0x12, 0xA2), &state),
            Ok(IdentityCheckOutcome::NoPriorRecord)
        );
    }

    #[test]
    fn resolve_single_legacy_bond_accepts_matching_submitted_pubkey() {
        let mut state = ChainState::new_genesis();
        let validator_id = id(0x20);
        let delegator_id = id(0x13);
        let owner = pubkey(0x13, 0xA3);
        let bond = legacy_bond(id(0x80), validator_id, delegator_id, owner.clone(), 0x80);
        state.staked_bonds.insert(bond.utxo_id, bond);

        assert_eq!(
            resolve_and_check_identity(&delegator_id, &owner, &state),
            Ok(IdentityCheckOutcome::LegacyBondMatch)
        );
    }

    #[test]
    fn resolve_single_legacy_bond_rejects_different_submitted_pubkey() {
        let mut state = ChainState::new_genesis();
        let validator_id = id(0x21);
        let delegator_id = id(0x14);
        let bond = legacy_bond(
            id(0x81),
            validator_id,
            delegator_id,
            pubkey(0x14, 0xA4),
            0x81,
        );
        state.staked_bonds.insert(bond.utxo_id, bond);

        assert_eq!(
            resolve_and_check_identity(&delegator_id, &pubkey(0x14, 0xB4), &state),
            Err(IdentityError::LegacyPubkeyMismatch { delegator_id })
        );
    }

    #[test]
    fn resolve_multiple_agreeing_legacy_bonds_accepts_matching_submitted_pubkey() {
        let mut state = ChainState::new_genesis();
        let delegator_id = id(0x15);
        let owner = pubkey(0x15, 0xA5);
        for (index, validator_byte) in [0x30u8, 0x31, 0x32].into_iter().enumerate() {
            let utxo_id = id(0x90 + index as u8);
            let bond = legacy_bond(
                utxo_id,
                id(validator_byte),
                delegator_id,
                owner.clone(),
                0x90 + index as u8,
            );
            state.staked_bonds.insert(bond.utxo_id, bond);
        }

        assert_eq!(
            resolve_and_check_identity(&delegator_id, &owner, &state),
            Ok(IdentityCheckOutcome::LegacyBondMatch)
        );
    }

    #[test]
    fn resolve_conflicting_legacy_bonds_reject_even_when_submitted_matches_one() {
        let mut state = ChainState::new_genesis();
        let validator_id = id(0x22);
        let delegator_id = id(0x16);
        let first = pubkey(0x16, 0xA6);
        let second = pubkey(0x16, 0xB6);
        let first_bond = legacy_bond(id(0x91), validator_id, delegator_id, first.clone(), 0x91);
        let second_bond = legacy_bond(id(0x92), validator_id, delegator_id, second, 0x92);
        state.staked_bonds.insert(first_bond.utxo_id, first_bond);
        state.staked_bonds.insert(second_bond.utxo_id, second_bond);

        assert_eq!(
            resolve_and_check_identity(&delegator_id, &first, &state),
            Err(IdentityError::AmbiguousLegacyPubkeys { delegator_id })
        );
    }

    #[test]
    fn resolve_ignores_compact_bonds_when_registry_is_absent() {
        let mut state = ChainState::new_genesis();
        let validator_id = id(0x23);
        let delegator_id = id(0x17);
        let owner = pubkey(0x17, 0xA7);
        let bond = compact_bond(id(0x93), validator_id, delegator_id, owner.clone(), 0x93);
        assert!(bond.original_output.range_proof.is_none());
        state.staked_bonds.insert(bond.utxo_id, bond);

        assert_eq!(
            resolve_and_check_identity(&delegator_id, &owner, &state),
            Ok(IdentityCheckOutcome::NoPriorRecord)
        );
    }

    #[test]
    fn bond_owner_resolution_prefers_embedded_pubkey() {
        let mut state = ChainState::new_genesis();
        let validator_id = id(0x27);
        let delegator_id = id(0x1C);
        let owner = pubkey(0x1C, 0xAC);
        let registry_owner = pubkey(0x1C, 0xBC);
        state
            .delegator_identities
            .insert(delegator_id, registry_owner);
        let bond = compact_bond(id(0x98), validator_id, delegator_id, owner.clone(), 0x98);

        assert_eq!(resolve_bond_owner_pubkey(&bond, &state), Ok(owner));
    }

    #[test]
    fn fully_compact_bond_owner_resolution_uses_registry_or_fails_loudly() {
        let mut state = ChainState::new_genesis();
        let validator_id = id(0x28);
        let delegator_id = id(0x1D);
        let owner = pubkey(0x1D, 0xAD);
        let bond = fully_compact_bond(id(0x99), validator_id, delegator_id, owner.clone(), 0x99);
        assert!(bond.original_output.owner_pubkey.is_none());

        assert_eq!(
            resolve_bond_owner_pubkey(&bond, &state),
            Err(IdentityError::UnresolvableIdentity {
                validator_id: Some(validator_id),
                delegator_id
            })
        );

        state
            .delegator_identities
            .insert(delegator_id, owner.clone());
        assert_eq!(resolve_bond_owner_pubkey(&bond, &state), Ok(owner));
    }

    #[test]
    fn redelegation_resolution_prefers_registry_entry() {
        let mut state = ChainState::new_genesis();
        let validator_id = id(0x24);
        let delegator_id = id(0x18);
        let registered = pubkey(0x18, 0xA8);
        state
            .delegator_identities
            .insert(delegator_id, registered.clone());

        let conflicting_legacy = legacy_bond(
            id(0x94),
            validator_id,
            delegator_id,
            pubkey(0x18, 0xB8),
            0x94,
        );
        state
            .staked_bonds
            .insert(conflicting_legacy.utxo_id, conflicting_legacy);

        assert_eq!(
            resolve_delegator_identity_for_redelegation(&validator_id, &delegator_id, &state),
            Ok(registered)
        );
    }

    #[test]
    fn redelegation_resolution_uses_unambiguous_active_legacy_bond() {
        let mut state = ChainState::new_genesis();
        let validator_id = id(0x25);
        let delegator_id = id(0x19);
        let owner = pubkey(0x19, 0xA9);
        let bond = legacy_bond(id(0x95), validator_id, delegator_id, owner.clone(), 0x95);
        state.staked_bonds.insert(bond.utxo_id, bond);

        assert_eq!(
            resolve_delegator_identity_for_redelegation(&validator_id, &delegator_id, &state),
            Ok(owner)
        );
    }

    #[test]
    fn redelegation_resolution_rejects_missing_or_ambiguous_legacy_state() {
        let mut state = ChainState::new_genesis();
        let validator_id = id(0x26);
        let missing_delegator_id = id(0x1A);

        assert_eq!(
            resolve_delegator_identity_for_redelegation(
                &validator_id,
                &missing_delegator_id,
                &state
            ),
            Err(IdentityError::UnresolvableIdentity {
                validator_id: Some(validator_id),
                delegator_id: missing_delegator_id
            })
        );

        let ambiguous_delegator_id = id(0x1B);
        let first_bond = legacy_bond(
            id(0x96),
            validator_id,
            ambiguous_delegator_id,
            pubkey(0x1B, 0xAA),
            0x96,
        );
        let second_bond = legacy_bond(
            id(0x97),
            validator_id,
            ambiguous_delegator_id,
            pubkey(0x1B, 0xBB),
            0x97,
        );
        state.staked_bonds.insert(first_bond.utxo_id, first_bond);
        state.staked_bonds.insert(second_bond.utxo_id, second_bond);

        assert_eq!(
            resolve_delegator_identity_for_redelegation(
                &validator_id,
                &ambiguous_delegator_id,
                &state
            ),
            Err(IdentityError::AmbiguousLegacyPubkeys {
                delegator_id: ambiguous_delegator_id
            })
        );
    }

    #[test]
    fn redelegation_resolution_ignores_unbonding_legacy_bonds() {
        let mut state = ChainState::new_genesis();
        let validator_id = id(0x27);
        let delegator_id = id(0x1C);
        let mut bond = legacy_bond(
            id(0x98),
            validator_id,
            delegator_id,
            pubkey(0x1C, 0xAC),
            0x98,
        );
        bond.unbonding_end_epoch = Some(9);
        state.staked_bonds.insert(bond.utxo_id, bond);

        assert_eq!(
            resolve_delegator_identity_for_redelegation(&validator_id, &delegator_id, &state),
            Err(IdentityError::UnresolvableIdentity {
                validator_id: Some(validator_id),
                delegator_id
            })
        );
    }
}
