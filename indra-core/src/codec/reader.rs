//! Stateful byte reader — sequential decoding over an immutable slice.

use crate::error::{IndraError, IndraResult};

/// A cursor over an immutable byte slice for sequential decoding.
///
/// All reads are bounds-checked. No panics. No unsafe.
pub struct ByteReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ByteReader<'a> {
    /// Create a new reader starting at the beginning of `data`.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Bytes not yet consumed.
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    /// Current read position.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Read exactly `n` bytes, advancing the cursor.
    pub fn read_bytes(&mut self, n: usize) -> IndraResult<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or(IndraError::UnexpectedEof {
            needed: n,
            available: self.remaining(),
        })?;
        let Some(slice) = self.data.get(self.pos..end) else {
            return Err(IndraError::UnexpectedEof {
                needed: n,
                available: self.remaining(),
            });
        };
        self.pos = end;
        Ok(slice)
    }

    /// Read exactly 32 bytes as a fixed array.
    pub fn read_bytes32(&mut self) -> IndraResult<[u8; 32]> {
        let bytes = self.read_bytes(32)?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(arr)
    }

    /// Read one byte.
    pub fn read_u8(&mut self) -> IndraResult<u8> {
        let b = self.read_bytes(1)?;
        b.first().copied().ok_or(IndraError::UnexpectedEof {
            needed: 1,
            available: 0,
        })
    }

    /// Read a little-endian u16.
    pub fn read_u16_le(&mut self) -> IndraResult<u16> {
        let b = self.read_bytes(2)?;
        let arr: [u8; 2] = b.try_into().map_err(|_| IndraError::UnexpectedEof {
            needed: 2,
            available: b.len(),
        })?;
        Ok(u16::from_le_bytes(arr))
    }

    /// Read a little-endian u32.
    pub fn read_u32_le(&mut self) -> IndraResult<u32> {
        let b = self.read_bytes(4)?;
        let arr: [u8; 4] = b.try_into().map_err(|_| IndraError::UnexpectedEof {
            needed: 4,
            available: b.len(),
        })?;
        Ok(u32::from_le_bytes(arr))
    }

    /// Read a little-endian u64.
    pub fn read_u64_le(&mut self) -> IndraResult<u64> {
        let b = self.read_bytes(8)?;
        let mut arr = [0u8; 8];
        arr.copy_from_slice(b);
        Ok(u64::from_le_bytes(arr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_sequence() {
        let data = [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09];
        let mut r = ByteReader::new(&data);
        assert_eq!(r.read_u8().unwrap(), 0x01);
        assert_eq!(r.read_u16_le().unwrap(), 0x0302);
        assert_eq!(r.read_u32_le().unwrap(), 0x07060504);
        assert_eq!(r.remaining(), 2);
    }

    #[test]
    fn eof_returns_error() {
        let data = [0x01u8, 0x02];
        let mut r = ByteReader::new(&data);
        r.read_u8().unwrap();
        r.read_u8().unwrap();
        assert!(r.read_u8().is_err());
    }

    #[test]
    fn read_bytes32_ok() {
        let data = [0xFFu8; 32];
        let mut r = ByteReader::new(&data);
        let arr = r.read_bytes32().unwrap();
        assert_eq!(arr, [0xFFu8; 32]);
        assert_eq!(r.remaining(), 0);
    }
}
