//! Fiat-Shamir transcript for non-interactive proofs.

use alloc::vec::Vec;

use curve25519_dalek::{
    ristretto::CompressedRistretto,
    scalar::Scalar,
};
use sha2::{Digest, Sha512};

/// A Fiat-Shamir transcript using SHA-512.
pub struct Transcript {
    state: Vec<u8>,
}

impl Transcript {
    /// Create a new transcript with a domain separator.
    pub fn new(label: &[u8]) -> Self {
        let mut transcript = Self { state: Vec::new() };
        transcript.append_message(b"dom-sep", label);
        transcript
    }

    /// Absorb a labelled message into the transcript.
    pub fn append_message(&mut self, label: &[u8], message: &[u8]) {
        self.state
            .extend_from_slice(&(label.len() as u32).to_le_bytes());
        self.state.extend_from_slice(label);
        self.state
            .extend_from_slice(&(message.len() as u64).to_le_bytes());
        self.state.extend_from_slice(message);
    }

    /// Absorb a Ristretto point.
    pub fn append_point(&mut self, label: &[u8], point: &CompressedRistretto) {
        self.append_message(label, point.as_bytes());
    }

    /// Absorb a scalar.
    pub fn append_scalar(&mut self, label: &[u8], scalar: &Scalar) {
        self.append_message(label, scalar.as_bytes());
    }

    /// Absorb a `u64`.
    pub fn append_u64(&mut self, label: &[u8], value: u64) {
        self.append_message(label, &value.to_le_bytes());
    }

    /// Squeeze a challenge scalar and absorb it back into the transcript.
    pub fn challenge_scalar(&mut self, label: &[u8]) -> Scalar {
        let mut hasher = Sha512::new();
        hasher.update(&self.state);
        hasher.update(b"challenge");
        hasher.update((label.len() as u32).to_le_bytes());
        hasher.update(label);

        let hash = hasher.finalize();
        let mut wide = [0u8; 64];
        wide.copy_from_slice(&hash);
        let challenge = Scalar::from_bytes_mod_order_wide(&wide);

        self.append_message(b"challenge-out", challenge.as_bytes());
        challenge
    }
}
