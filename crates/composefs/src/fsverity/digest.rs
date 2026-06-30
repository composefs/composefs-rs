//! Userspace fs-verity digest computation.
//!
//! This module implements the fs-verity Merkle tree algorithm in userspace,
//! allowing computation of fs-verity digests without kernel support.

use core::mem::size_of;

use sha2::Digest;

use super::FsVerityHashValue;

#[derive(Debug)]
struct FsVerityLayer<H: FsVerityHashValue, const LG_BLKSZ: u8 = 12> {
    context: H::Digest,
    remaining: usize,
}

impl<H: FsVerityHashValue, const LG_BLKSZ: u8> FsVerityLayer<H, LG_BLKSZ> {
    fn new() -> Self {
        Self {
            context: H::Digest::new(),
            remaining: 1 << LG_BLKSZ,
        }
    }

    fn add_data(&mut self, data: &[u8]) {
        self.context.update(data);
        self.remaining -= data.len();
    }

    fn complete(&mut self) -> H {
        self.context.update([0].repeat(self.remaining));
        self.remaining = 1 << LG_BLKSZ;
        self.context.finalize_reset().into()
    }
}

/// Incremental fs-verity digest computation.
///
/// This hasher allows computing fs-verity digests incrementally by feeding
/// data in chunks. The data must be provided in block-aligned chunks (4KB by default)
/// except for the final chunk which may be smaller.
///
/// # Example
/// ```ignore
/// use composefs::fsverity::{FsVerityHasher, Sha256HashValue};
///
/// let mut hasher = FsVerityHasher::<Sha256HashValue>::new();
/// hasher.write_all(b"hello world");
/// let digest = hasher.digest();
/// ```
#[derive(Debug)]
pub struct FsVerityHasher<H: FsVerityHashValue, const LG_BLKSZ: u8 = 12> {
    layers: Vec<FsVerityLayer<H, LG_BLKSZ>>,
    value: Option<H>,
    n_bytes: u64,
    partial: Vec<u8>,
    wrote_final_block: bool,
}

impl<H: FsVerityHashValue, const LG_BLKSZ: u8> FsVerityHasher<H, LG_BLKSZ> {
    /// The block size in bytes used for fs-verity Merkle tree computation.
    pub const BLOCK_SIZE: usize = 1 << LG_BLKSZ;

    /// Hash a complete buffer and return the fs-verity digest.
    pub fn hash(buffer: &[u8]) -> H {
        use std::io::Write;

        let mut hasher = Self::new();
        hasher.write_all(buffer).expect("infallible write");
        hasher.digest()
    }

    /// Create a new incremental fs-verity hasher.
    pub fn new() -> Self {
        Self {
            layers: vec![],
            value: None,
            n_bytes: 0,
            partial: Vec::with_capacity(Self::BLOCK_SIZE),
            wrote_final_block: false,
        }
    }

    fn add_block_from_partial(&mut self) {
        let block = std::mem::replace(&mut self.partial, Vec::with_capacity(Self::BLOCK_SIZE));
        self.add_block(&block);
    }

    /// Add a complete block of data to the hasher.
    ///
    /// The data must be exactly `BLOCK_SIZE` bytes, except for the
    /// final block which may be smaller. Prefer the [`std::io::Write`]
    /// impl which handles buffering automatically.
    pub fn add_block(&mut self, data: &[u8]) {
        assert!(
            !self.wrote_final_block,
            "cannot add data after a partial block"
        );
        if data.len() < Self::BLOCK_SIZE {
            self.wrote_final_block = true;
        }

        if let Some(value) = self.value.take() {
            // We had a complete value, but now we're adding new data.
            // This means that we need to add a new hash layer...
            let mut new_layer = FsVerityLayer::new();
            new_layer.add_data(value.as_bytes());
            self.layers.push(new_layer);
        }

        // Get the value of this block
        let mut context = FsVerityLayer::<H, LG_BLKSZ>::new();
        context.add_data(data);
        let mut value = context.complete();
        self.n_bytes += data.len() as u64;

        for layer in self.layers.iter_mut() {
            // We have a layer we need to hash this value into
            layer.add_data(value.as_bytes());
            if layer.remaining != 0 {
                return;
            }
            // ...but now this layer itself is now complete, so get the value of *it*.
            value = layer.complete();
        }

        // If we made it this far, we completed the last layer and have a value.  Store it.
        self.value = Some(value);
    }

    fn root_hash(&mut self) -> H {
        if let Some(value) = &self.value {
            value.clone()
        } else {
            let mut value = H::EMPTY;

            for layer in self.layers.iter_mut() {
                // We have a layer we need to hash this value into
                if value != H::EMPTY {
                    layer.add_data(value.as_bytes());
                }
                if layer.remaining != (1 << LG_BLKSZ) {
                    // ...but now this layer itself is complete, so get the value of *it*.
                    value = layer.complete();
                } else {
                    value = H::EMPTY;
                }
            }

            self.value = Some(value.clone());

            value
        }
    }

    /// Finalize and return the fs-verity digest.
    ///
    /// Flushes any buffered partial block and computes the final digest.
    pub fn digest(&mut self) -> H {
        if !self.partial.is_empty() {
            self.add_block_from_partial();
        }
        /*
        let mut root_hash = [0u8; 64];
        let result = self.root_hash();
        root_hash[..result.as_ref().len()].copy_from_slice(result.as_ref());

        let descriptor = FsVerityDescriptor {
            version: 1,
            hash_algorithm: H::ALGORITHM,
            log_blocksize: LG_BLKSZ,
            salt_size: 0,
            reserved_0x04: U32::new(0),
            data_size: U64::new(self.n_bytes),
            root_hash,
            salt: [0; 32],
            reserved: [0; 144],
        };

        let mut context = H::Digest::new();
        context.update(descriptor.as_bytes());
        context.finalize().into()
            */

        let mut context = H::Digest::new();
        context.update(1u8.to_le_bytes()); /* version */
        context.update(H::ALGORITHM.kernel_id().to_le_bytes()); /* hash_algorithm */
        context.update(LG_BLKSZ.to_le_bytes()); /* log_blocksize */
        context.update(0u8.to_le_bytes()); /* salt_size */
        context.update([0; 4]); /* reserved */
        context.update(self.n_bytes.to_le_bytes());
        context.update(self.root_hash().as_bytes());
        context.update([0].repeat(64 - size_of::<H>()));
        context.update([0; 32]); /* salt */
        context.update([0; 144]); /* reserved */
        context.finalize().into()
    }
}

impl<H: FsVerityHashValue, const LG_BLKSZ: u8> std::io::Write for FsVerityHasher<H, LG_BLKSZ> {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let len = data.len();
        let mut remaining = data;
        while !remaining.is_empty() {
            let space = Self::BLOCK_SIZE - self.partial.len();
            let n = remaining.len().min(space);
            self.partial.extend_from_slice(&remaining[..n]);
            remaining = &remaining[n..];
            if self.partial.len() == Self::BLOCK_SIZE {
                self.add_block_from_partial();
            }
        }
        Ok(len)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<H: FsVerityHashValue, const LG_BLKSZ: u8> Default for FsVerityHasher<H, LG_BLKSZ> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use similar_asserts::assert_eq;

    use crate::fsverity::{Sha256HashValue, Sha512HashValue};

    use super::*;

    #[test]
    fn test_digest() {
        assert_eq!(
            FsVerityHasher::<Sha256HashValue, 12>::hash(b"hello world").to_hex(),
            "1e2eaa4202d750a41174ee454970b92c1bc2f925b1e35076d8c7d5f56362ba64"
        );

        assert_eq!(
            FsVerityHasher::<Sha512HashValue, 12>::hash(b"hello world").to_hex(),
            "18430270729d162d4e469daca123ae61893db4b0583d8f7081e3bf4f92b88ba514e7982f10733fb6aa895195c5ae8fd2eb2c47a8be05513ce5a0c51a6f570409"
        );
    }
}
