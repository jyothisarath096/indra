//! Append-only byte writer for encoding.

/// An append-only byte buffer.
///
/// Thin wrapper around Vec<u8> with explicit methods,
/// making encoding auditable.
pub struct ByteWriter {
    buf: Vec<u8>,
}

impl ByteWriter {
    /// Create a new empty writer.
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Create with pre-allocated capacity.
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            buf: Vec::with_capacity(cap),
        }
    }

    /// Write one byte.
    pub fn write_u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    /// Write a little-endian u16.
    pub fn write_u16_le(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Write a little-endian u32.
    pub fn write_u32_le(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Write a little-endian u64.
    pub fn write_u64_le(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Write a byte slice.
    pub fn write_bytes(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Current byte count.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// True if nothing written yet.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Consume and return the buffer.
    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}

impl Default for ByteWriter {
    fn default() -> Self {
        Self::new()
    }
}
