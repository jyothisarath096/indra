#![no_main]

use curve25519_dalek_v5::{edwards::CompressedEdwardsY, traits::IsIdentity};
use indra_crypto::validate_vrf_public_key;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(public_key) = <[u8; 32]>::try_from(data) else {
        return;
    };
    if validate_vrf_public_key(&public_key).is_ok() {
        let point = CompressedEdwardsY(public_key)
            .decompress()
            .expect("accepted key must decompress");
        assert_eq!(point.compress().to_bytes(), public_key);
        assert!(!point.is_identity());
        assert!(point.is_torsion_free());
    }
});
