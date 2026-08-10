//! Core encode/decode traits and byte-level utilities.
//!
//! All consensus serialisation flows through these traits.
//! No other encoding mechanism is permitted in the consensus path.

use crate::error::{IndraError, IndraResult};

pub mod reader;

pub use reader::ByteReader;

// ── Core traits ───────────────────────────────────────────────────────────────

/// Encode `self` into the canonical INDRA byte representation.
///
/// Implementations must be:
/// - Deterministic: same value always produces same bytes.
/// - Canonical: there is exactly one valid encoding per value.
/// - Infallible for valid values.
pub trait Encode {
    /// Append the canonical encoding to `buf`.
    fn encode(&self, buf: &mut Vec<u8>);

    /// Convenience: encode to a fresh Vec.
    fn encode_to_vec(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.encoded_len());
        self.encode(&mut buf);
        buf
    }

    /// Return the exact encoded byte length without allocating.
    fn encoded_len(&self) -> usize;
}

/// Decode a value from a canonical INDRA byte slice.
pub trait Decode: Sized {
    /// Attempt to decode from the front of `reader`.
    fn decode(reader: &mut ByteReader<'_>) -> IndraResult<Self>;

    /// Convenience: decode from a complete slice.
    /// Returns error if any trailing bytes remain after decoding.
    fn decode_exact(bytes: &[u8]) -> IndraResult<Self> {
        let mut r = ByteReader::new(bytes);
        let v = Self::decode(&mut r)?;
        let rem = r.remaining();
        if rem != 0 {
            return Err(IndraError::TrailingBytes { count: rem });
        }
        Ok(v)
    }
}

// ── Primitive encode/decode ───────────────────────────────────────────────────

impl Encode for u8 {
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.push(*self);
    }
    fn encoded_len(&self) -> usize {
        1
    }
}
impl Decode for u8 {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        r.read_u8()
    }
}

impl Encode for u16 {
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.to_le_bytes());
    }
    fn encoded_len(&self) -> usize {
        2
    }
}
impl Decode for u16 {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        r.read_u16_le()
    }
}

impl Encode for u32 {
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.to_le_bytes());
    }
    fn encoded_len(&self) -> usize {
        4
    }
}
impl Decode for u32 {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        r.read_u32_le()
    }
}

impl Encode for u64 {
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.to_le_bytes());
    }
    fn encoded_len(&self) -> usize {
        8
    }
}
impl Decode for u64 {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        r.read_u64_le()
    }
}

impl Encode for bool {
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.push(if *self { 0x01 } else { 0x00 });
    }
    fn encoded_len(&self) -> usize {
        1
    }
}
impl Decode for bool {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        match r.read_u8()? {
            0x00 => Ok(false),
            0x01 => Ok(true),
            byte => Err(IndraError::InvalidBool { byte }),
        }
    }
}

// ── Bounded list encode/decode ────────────────────────────────────────────────

/// Encode a list: u32_le(count) || item_0 || item_1 || ...
pub fn encode_list<T: Encode>(items: &[T], buf: &mut Vec<u8>) {
    buf.extend_from_slice(&(items.len() as u32).to_le_bytes());
    for item in items {
        item.encode(buf);
    }
}

/// Decode a bounded list. Returns error if count exceeds `max`.
pub fn decode_list<T: Decode>(
    r: &mut ByteReader<'_>,
    max: usize,
    field: &'static str,
) -> IndraResult<Vec<T>> {
    let count = r.read_u32_le()? as usize;
    if count > max {
        return Err(IndraError::LengthExceeded {
            field,
            max,
            actual: count,
        });
    }
    let mut items = Vec::with_capacity(count);
    for _ in 0..count {
        items.push(T::decode(r)?);
    }
    Ok(items)
}

/// Encoded length for a list of items.
pub fn list_encoded_len<T: Encode>(items: &[T]) -> usize {
    4 + items.iter().map(|i| i.encoded_len()).sum::<usize>()
}
