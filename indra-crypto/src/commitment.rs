//! Commitment balance: sum(inputs) == sum(outputs) + fee

use crate::{error::{CryptoError, CryptoResult}, pedersen::PedersenCommitment};

/// Verify the commitment balance equation.
pub fn verify_balance(
    input_commitments: &[PedersenCommitment],
    output_commitments: &[PedersenCommitment],
    fee_commitment: &PedersenCommitment,
) -> CryptoResult<()> {
    let mut input_sum = PedersenCommitment::ZERO;
    for c in input_commitments { input_sum = input_sum.add(c)?; }

    let mut output_sum = PedersenCommitment::ZERO;
    for c in output_commitments { output_sum = output_sum.add(c)?; }
    output_sum = output_sum.add(fee_commitment)?;

    if input_sum == output_sum { Ok(()) } else { Err(CryptoError::CommitmentBalanceFailed) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pedersen::commit;
    use curve25519_dalek::scalar::Scalar;

    #[test]
    fn balanced_passes() {
        let r_out = Scalar::from_bytes_mod_order([0x01u8; 32]);
        let r_fee = Scalar::from_bytes_mod_order([0x02u8; 32]);
        let r_in  = r_out + r_fee;
        assert!(verify_balance(
            &[commit(1000, &r_in.to_bytes())],
            &[commit(900, &r_out.to_bytes())],
            &commit(100, &r_fee.to_bytes()),
        ).is_ok());
    }

    #[test]
    fn unbalanced_fails() {
        assert!(verify_balance(
            &[commit(1000, &[0x01u8; 32])],
            &[commit(800,  &[0x02u8; 32])],
            &commit(100,   &[0x03u8; 32]),
        ).is_err());
    }
}
