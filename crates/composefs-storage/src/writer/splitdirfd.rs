//! Decode a splitdirfd layer without flattening file-backed payloads.

use std::collections::VecDeque;
use std::fs::File;
use std::io::Read;
use std::os::fd::{AsFd, OwnedFd};

use composefs_splitdirfdstream::{Chunk, SplitDirFdStream, SplitdirfdstreamReader, open_beneath};

use super::{ImportError, LayerChunk, LayerSource, Result};

pub(super) struct SplitDirFdSource {
    reader: SplitdirfdstreamReader<File>,
    dirs: Vec<OwnedFd>,
    // The source itself lives through registration and error cleanup, not just EOF.
    _lifetime: Vec<OwnedFd>,
    pending: VecDeque<u8>,
}

impl SplitDirFdSource {
    pub(super) fn new(stream: SplitDirFdStream) -> Self {
        let (data, dirs, lifetime) = stream.into_parts();
        Self {
            reader: SplitdirfdstreamReader::new(File::from(data)),
            dirs,
            _lifetime: lifetime,
            pending: VecDeque::new(),
        }
    }
}

impl LayerSource for SplitDirFdSource {
    fn next_chunk(&mut self, buffer: &mut [u8]) -> Result<Option<LayerChunk>> {
        if buffer.is_empty() {
            return Err(ImportError::Malformed("empty layer read buffer".into()));
        }
        let n = self.pending.read(buffer)?;
        if n != 0 {
            return Ok(Some(LayerChunk::Inline(n)));
        }
        loop {
            match self.reader.next_chunk()? {
                None => return Ok(None),
                Some(Chunk::Metadata(mut bytes) | Chunk::InlineData(mut bytes)) => {
                    let n = bytes.read(buffer)?;
                    // Empty inline payloads are legal in the wire format.
                    if n == 0 {
                        continue;
                    }
                    self.pending.extend(bytes);
                    return Ok(Some(LayerChunk::Inline(n)));
                }
                Some(Chunk::FileBackedData {
                    dirfd_index,
                    length,
                    filename,
                }) => {
                    let dir = self.dirs.get(dirfd_index as usize).ok_or(
                        composefs_splitdirfdstream::Error::DirfdIndexOutOfRange {
                            index: dirfd_index,
                            count: self.dirs.len(),
                        },
                    )?;
                    let file = File::from(open_beneath(dir.as_fd(), filename)?);
                    return Ok(Some(LayerChunk::File { file, length }));
                }
            }
        }
    }
}
