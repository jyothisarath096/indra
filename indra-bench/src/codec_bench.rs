//! Serialisation/deserialisation benchmarks.

use std::time::Duration;

use indra_core::codec::{ByteReader, Decode, Encode};

use crate::{fixtures::dummy_tx, timer::bench};

/// Benchmark transaction encode.
pub fn bench_tx_encode(iterations: u64) {
    let tx = dummy_tx(0x01, 10_000);

    let r = bench("tx_encode", iterations, || {
        let _ = tx.encode_to_vec();
    });
    r.print();
    r.assert_faster_than(Duration::from_micros(50));
}

/// Benchmark transaction decode.
pub fn bench_tx_decode(iterations: u64) {
    let tx = dummy_tx(0x01, 10_000);
    let encoded = tx.encode_to_vec();

    let r = bench("tx_decode", iterations, || {
        let mut reader = ByteReader::new(&encoded);
        let _ = indra_core::types::transaction::TransactionV1::decode(&mut reader);
    });
    r.print();
    r.assert_faster_than(Duration::from_micros(50));
}

/// Benchmark block encode (200 transactions).
pub fn bench_block_encode(iterations: u64) {
    use crate::fixtures::dummy_block;
    use indra_core::Bytes32;
    let block = dummy_block(1, Bytes32::ZERO, 200);

    let r = bench("block_encode_200tx", iterations, || {
        let _ = block.encode_to_vec();
    });
    r.print();
    r.assert_faster_than(Duration::from_millis(5));
}

/// Benchmark block decode (200 transactions).
pub fn bench_block_decode(iterations: u64) {
    use crate::fixtures::dummy_block;
    use indra_core::Bytes32;
    let block = dummy_block(1, Bytes32::ZERO, 200);
    let encoded = block.encode_to_vec();

    let r = bench("block_decode_200tx", iterations, || {
        let mut reader = ByteReader::new(&encoded);
        let _ = indra_core::types::block::BlockV1::decode(&mut reader);
    });
    r.print();
    r.assert_faster_than(Duration::from_millis(5));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bench_tx_encode_runs() {
        bench_tx_encode(500);
    }

    #[test]
    fn bench_tx_decode_runs() {
        bench_tx_decode(500);
    }

    #[test]
    fn bench_block_encode_runs() {
        bench_block_encode(100);
    }

    #[test]
    fn bench_block_decode_runs() {
        bench_block_decode(100);
    }
}
