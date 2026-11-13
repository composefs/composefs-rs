//! An owned stream and its out-of-band directory and lifetime descriptors.

use std::io;
use std::os::fd::OwnedFd;

/// The receiving end of a splitdirfdstream transfer.
///
/// This contains descriptors only, so it can be consumed locally or forwarded
/// over an FD-passing transport. Directory slots retain their original indices,
/// including dummy slots. Keep every lifetime descriptor open until all source
/// files have been processed, even after the data pipe reaches EOF.
#[derive(Debug)]
pub struct SplitDirFdStream {
    dir_count: u32,
    fds: Vec<OwnedFd>,
}

impl SplitDirFdStream {
    /// Take ownership of a logical FD array: data pipe, `dir_count` directory
    /// slots, then one or more opaque lifetime descriptors.
    ///
    /// Checks the array length. Descriptor types and referenced directory slots
    /// are checked by the consumer when used; dummy slots need not be directories.
    pub fn from_fds(dir_count: u32, fds: Vec<OwnedFd>) -> io::Result<Self> {
        let minimum = usize::try_from(dir_count)
            .ok()
            .and_then(|count| count.checked_add(2))
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "directory count overflow")
            })?;
        if fds.len() < minimum {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "expected data pipe, directory slots and lifetime descriptors",
            ));
        }
        Ok(Self { dir_count, fds })
    }

    /// Number of directory slots, including dummy slots.
    pub fn dir_count(&self) -> u32 {
        self.dir_count
    }

    /// Borrow the full logical FD array for descriptor passing.
    pub fn fds(&self) -> &[OwnedFd] {
        &self.fds
    }

    /// Transfer ownership of the directory count and full logical FD array.
    ///
    /// This does not stop the producer. After successful descriptor passing,
    /// close the sender's copies so the receiver controls the transfer lifetime.
    pub fn into_fds(self) -> (u32, Vec<OwnedFd>) {
        (self.dir_count, self.fds)
    }

    /// Separate the data pipe, directory slots and opaque lifetime descriptors.
    pub fn into_parts(self) -> (OwnedFd, Vec<OwnedFd>, Vec<OwnedFd>) {
        let mut fds = self.fds.into_iter();
        let data = fds.next().expect("validated data pipe slot");
        let dirs = fds.by_ref().take(self.dir_count as usize).collect();
        (data, dirs, fds.collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    #[test]
    fn fd_layout_round_trips_and_rejects_missing_slots() {
        for (dir_count, count, valid) in [(0, 2, true), (3, 7, true), (0, 1, false), (3, 4, false)]
        {
            let fds = (0..count)
                .map(|_| crate::open_devnull().unwrap())
                .collect::<Vec<_>>();
            let raw = fds.iter().map(AsRawFd::as_raw_fd).collect::<Vec<_>>();
            let result = SplitDirFdStream::from_fds(dir_count, fds);
            if !valid {
                assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidInput);
                continue;
            }
            let stream = result.unwrap();
            assert_eq!(stream.dir_count(), dir_count);
            assert_eq!(stream.fds().len(), count);
            let (returned_count, fds) = stream.into_fds();
            assert_eq!(returned_count, dir_count);
            assert_eq!(fds.iter().map(AsRawFd::as_raw_fd).collect::<Vec<_>>(), raw);
            let (data, dirs, lifetime) = SplitDirFdStream::from_fds(dir_count, fds)
                .unwrap()
                .into_parts();
            assert_eq!(data.as_raw_fd(), raw[0]);
            assert_eq!(dirs.len(), dir_count as usize);
            assert_eq!(lifetime.len(), count - dir_count as usize - 1);
        }
    }
}
