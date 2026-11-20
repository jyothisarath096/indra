//! Canonical hot/cold authorization envelopes.

use crate::{
    codec::{ByteReader, Decode, Encode},
    error::{IndraError, IndraResult},
    types::primitives::{
        Bytes32, VariableBytes, MAX_AUTHORIZATION_PAYLOAD_BYTES, MAX_CHAIN_ID_BYTES,
    },
};

/// Canonical hot-authorization domain.
pub const HOT_AUTHORIZATION_DOMAIN: &[u8] = b"INDRA-validator-hot-auth-v1";

/// Canonical cold-authorization domain.
pub const COLD_AUTHORIZATION_DOMAIN: &[u8] = b"INDRA-validator-cold-auth-v1";

const MAX_AUTHORIZATION_DOMAIN_BYTES: usize = COLD_AUTHORIZATION_DOMAIN.len();

/// Role whose complete hybrid key authorizes an envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityRole {
    /// Continuously online validator authority.
    Hot,
    /// Offline custody and governance authority.
    Cold,
}

impl Encode for AuthorityRole {
    fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            Self::Hot => 0u8.encode(buf),
            Self::Cold => 1u8.encode(buf),
        }
    }

    fn encoded_len(&self) -> usize {
        1
    }
}

impl Decode for AuthorityRole {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        match u8::decode(r)? {
            0 => Ok(Self::Hot),
            1 => Ok(Self::Cold),
            value => Err(IndraError::InvalidAuthorizationEnvelope(format!(
                "unknown authority role {value}"
            ))),
        }
    }
}

/// Structurally distinct domain for a role-authorized message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationDomain {
    /// Domain reserved for hot-role operations.
    Hot,
    /// Domain reserved for cold-role operations.
    Cold,
}

impl AuthorizationDomain {
    fn bytes(self) -> &'static [u8] {
        match self {
            Self::Hot => HOT_AUTHORIZATION_DOMAIN,
            Self::Cold => COLD_AUTHORIZATION_DOMAIN,
        }
    }

    fn required_role(self) -> AuthorityRole {
        match self {
            Self::Hot => AuthorityRole::Hot,
            Self::Cold => AuthorityRole::Cold,
        }
    }
}

impl Encode for AuthorizationDomain {
    fn encode(&self, buf: &mut Vec<u8>) {
        let bytes = self.bytes();
        (bytes.len() as u32).encode(buf);
        buf.extend_from_slice(bytes);
    }

    fn encoded_len(&self) -> usize {
        4 + self.bytes().len()
    }
}

impl Decode for AuthorizationDomain {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        let bytes = VariableBytes::<MAX_AUTHORIZATION_DOMAIN_BYTES>::decode(r)?;
        match bytes.as_slice() {
            HOT_AUTHORIZATION_DOMAIN => Ok(Self::Hot),
            COLD_AUTHORIZATION_DOMAIN => Ok(Self::Cold),
            _ => Err(IndraError::InvalidAuthorizationEnvelope(
                "unknown authorization domain".into(),
            )),
        }
    }
}

/// Reusable canonical message covered by hot and cold role signatures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationEnvelope {
    /// Structurally distinct hot or cold signing domain.
    domain: AuthorizationDomain,
    /// Chain identifier.
    chain_id: VariableBytes<MAX_CHAIN_ID_BYTES>,
    /// Operation-specific stable tag.
    operation_tag: u16,
    /// Validator or delegator identity being authorized.
    identity_id: Bytes32,
    /// Role declared by this envelope.
    authority_role: AuthorityRole,
    /// Registered role-key version.
    authority_key_version: u64,
    /// Monotonic nonce in the role's nonce namespace.
    role_nonce: u64,
    /// Complete canonical operation payload.
    payload: VariableBytes<MAX_AUTHORIZATION_PAYLOAD_BYTES>,
}

impl AuthorizationEnvelope {
    /// Construct a canonical hot-role envelope.
    pub fn new_hot(
        chain_id: &[u8],
        operation_tag: u16,
        identity_id: Bytes32,
        authority_key_version: u64,
        role_nonce: u64,
        payload: &[u8],
    ) -> IndraResult<Self> {
        Self::new(AuthorizationInput {
            domain: AuthorizationDomain::Hot,
            authority_role: AuthorityRole::Hot,
            chain_id,
            operation_tag,
            identity_id,
            authority_key_version,
            role_nonce,
            payload,
        })
    }

    /// Construct a canonical cold-role envelope.
    pub fn new_cold(
        chain_id: &[u8],
        operation_tag: u16,
        identity_id: Bytes32,
        authority_key_version: u64,
        role_nonce: u64,
        payload: &[u8],
    ) -> IndraResult<Self> {
        Self::new(AuthorizationInput {
            domain: AuthorizationDomain::Cold,
            authority_role: AuthorityRole::Cold,
            chain_id,
            operation_tag,
            identity_id,
            authority_key_version,
            role_nonce,
            payload,
        })
    }

    fn new(input: AuthorizationInput<'_>) -> IndraResult<Self> {
        let chain_id = VariableBytes::from_slice(input.chain_id)?;
        let payload = VariableBytes::from_slice(input.payload)?;
        let envelope = Self {
            domain: input.domain,
            chain_id,
            operation_tag: input.operation_tag,
            identity_id: input.identity_id,
            authority_role: input.authority_role,
            authority_key_version: input.authority_key_version,
            role_nonce: input.role_nonce,
            payload,
        };
        envelope.validate_domain_role()?;
        Ok(envelope)
    }

    /// Return the canonical bytes covered by role signatures.
    pub fn signing_bytes(&self) -> Vec<u8> {
        self.encode_to_vec()
    }

    /// Return the structurally bound authorization domain.
    pub fn domain(&self) -> AuthorizationDomain {
        self.domain
    }

    /// Return the encoded chain identifier.
    pub fn chain_id(&self) -> &[u8] {
        self.chain_id.as_slice()
    }

    /// Return the stable operation tag.
    pub fn operation_tag(&self) -> u16 {
        self.operation_tag
    }

    /// Return the validator or delegator identity.
    pub fn identity_id(&self) -> Bytes32 {
        self.identity_id
    }

    /// Return the role bound to the domain.
    pub fn authority_role(&self) -> AuthorityRole {
        self.authority_role
    }

    /// Return the role-key version.
    pub fn authority_key_version(&self) -> u64 {
        self.authority_key_version
    }

    /// Return the role-specific nonce.
    pub fn role_nonce(&self) -> u64 {
        self.role_nonce
    }

    /// Return the complete canonical operation payload.
    pub fn payload(&self) -> &[u8] {
        self.payload.as_slice()
    }

    fn validate_domain_role(&self) -> IndraResult<()> {
        if self.domain.required_role() != self.authority_role {
            return Err(IndraError::InvalidAuthorizationEnvelope(
                "authorization domain does not match authority role".into(),
            ));
        }
        Ok(())
    }
}

struct AuthorizationInput<'a> {
    domain: AuthorizationDomain,
    authority_role: AuthorityRole,
    chain_id: &'a [u8],
    operation_tag: u16,
    identity_id: Bytes32,
    authority_key_version: u64,
    role_nonce: u64,
    payload: &'a [u8],
}

impl Encode for AuthorizationEnvelope {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.domain.encode(buf);
        self.chain_id.encode(buf);
        self.operation_tag.encode(buf);
        self.identity_id.encode(buf);
        self.authority_role.encode(buf);
        self.authority_key_version.encode(buf);
        self.role_nonce.encode(buf);
        self.payload.encode(buf);
    }

    fn encoded_len(&self) -> usize {
        self.domain.encoded_len()
            + self.chain_id.encoded_len()
            + self.operation_tag.encoded_len()
            + self.identity_id.encoded_len()
            + self.authority_role.encoded_len()
            + self.authority_key_version.encoded_len()
            + self.role_nonce.encoded_len()
            + self.payload.encoded_len()
    }
}

impl Decode for AuthorizationEnvelope {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        let envelope = Self {
            domain: AuthorizationDomain::decode(r)?,
            chain_id: VariableBytes::decode(r)?,
            operation_tag: u16::decode(r)?,
            identity_id: Bytes32::decode(r)?,
            authority_role: AuthorityRole::decode(r)?,
            authority_key_version: u64::decode(r)?,
            role_nonce: u64::decode(r)?,
            payload: VariableBytes::decode(r)?,
        };
        envelope.validate_domain_role()?;
        Ok(envelope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorization_envelope_round_trip_and_domains_are_distinct() {
        let identity = Bytes32::from([0x55; 32]);
        let payload = b"complete operation payload";
        let hot = AuthorizationEnvelope::new_hot(b"indra-testnet-1", 17, identity, 3, 9, payload)
            .unwrap();
        let cold = AuthorizationEnvelope::new_cold(b"indra-testnet-1", 17, identity, 3, 9, payload)
            .unwrap();

        let hot_bytes = hot.signing_bytes();
        let cold_bytes = cold.signing_bytes();
        assert_ne!(HOT_AUTHORIZATION_DOMAIN, COLD_AUTHORIZATION_DOMAIN);
        assert_ne!(hot_bytes, cold_bytes);
        assert_eq!(
            hot,
            AuthorizationEnvelope::decode_exact(&hot_bytes).unwrap()
        );
        assert_eq!(
            cold,
            AuthorizationEnvelope::decode_exact(&cold_bytes).unwrap()
        );

        let role_offset = hot.domain.encoded_len()
            + hot.chain_id.encoded_len()
            + hot.operation_tag.encoded_len()
            + hot.identity_id.encoded_len();
        let mut hot_reinterpreted_as_cold = hot_bytes;
        hot_reinterpreted_as_cold[role_offset] = 1;
        assert_eq!(
            AuthorizationEnvelope::decode_exact(&hot_reinterpreted_as_cold),
            Err(IndraError::InvalidAuthorizationEnvelope(
                "authorization domain does not match authority role".into()
            ))
        );
    }
}
