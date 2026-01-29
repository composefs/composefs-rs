//! Configurable security limits for tar stream parsing.

/// Configurable security limits for tar stream parsing.
///
/// These limits protect against malicious or malformed archives that could
/// exhaust memory or create excessively long paths.
///
/// # Example
///
/// ```
/// use tar_header::stream::Limits;
///
/// // Use defaults
/// let limits = Limits::default();
///
/// // Customize limits
/// let strict_limits = Limits {
///     max_path_len: 1024,
///     max_pax_size: 64 * 1024,
///     ..Default::default()
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    /// Maximum path length in bytes.
    ///
    /// Applies to both file paths and link targets. Paths exceeding this
    /// limit will cause a [`StreamError::PathTooLong`] error.
    ///
    /// Default: 4096 bytes (Linux PATH_MAX).
    ///
    /// [`StreamError::PathTooLong`]: super::StreamError::PathTooLong
    pub max_path_len: usize,

    /// Maximum size of PAX extended header data in bytes.
    ///
    /// This limits the total size of a single PAX 'x' entry's content.
    /// PAX headers larger than this will cause a [`StreamError::PaxTooLarge`] error.
    ///
    /// Default: 1 MiB (1,048,576 bytes).
    ///
    /// [`StreamError::PaxTooLarge`]: super::StreamError::PaxTooLarge
    pub max_pax_size: u64,

    /// Maximum size of GNU long name/link data in bytes.
    ///
    /// GNU 'L' (long name) and 'K' (long link) entries should only contain
    /// a single path. Values exceeding this limit will cause a
    /// [`StreamError::GnuLongTooLarge`] error.
    ///
    /// Default: 4096 bytes.
    ///
    /// [`StreamError::GnuLongTooLarge`]: super::StreamError::GnuLongTooLarge
    pub max_gnu_long_size: u64,

    /// Maximum number of consecutive metadata entries before an actual entry.
    ///
    /// Prevents infinite loops from malformed archives that contain only
    /// metadata entries (GNU long name, PAX headers) without actual file entries.
    /// Exceeding this limit will cause a [`StreamError::TooManyPendingEntries`] error.
    ///
    /// Default: 16 entries.
    ///
    /// [`StreamError::TooManyPendingEntries`]: super::StreamError::TooManyPendingEntries
    pub max_pending_entries: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_path_len: 4096,
            max_pax_size: 1024 * 1024, // 1 MiB
            max_gnu_long_size: 4096,
            max_pending_entries: 16,
        }
    }
}

impl Limits {
    /// Create a new `Limits` with default values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create permissive limits suitable for trusted archives.
    ///
    /// This sets very high limits that effectively disable most checks.
    /// Only use this for archives from trusted sources.
    #[must_use]
    pub fn permissive() -> Self {
        Self {
            max_path_len: usize::MAX,
            max_pax_size: u64::MAX,
            max_gnu_long_size: u64::MAX,
            max_pending_entries: usize::MAX,
        }
    }

    /// Create strict limits suitable for untrusted archives.
    ///
    /// This sets conservative limits to minimize resource consumption
    /// from potentially malicious archives.
    #[must_use]
    pub fn strict() -> Self {
        Self {
            max_path_len: 1024,
            max_pax_size: 64 * 1024, // 64 KiB
            max_gnu_long_size: 1024,
            max_pending_entries: 8,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_limits() {
        let limits = Limits::default();
        assert_eq!(limits.max_path_len, 4096);
        assert_eq!(limits.max_pax_size, 1024 * 1024);
        assert_eq!(limits.max_gnu_long_size, 4096);
        assert_eq!(limits.max_pending_entries, 16);
    }

    #[test]
    fn test_permissive_limits() {
        let limits = Limits::permissive();
        assert_eq!(limits.max_path_len, usize::MAX);
        assert_eq!(limits.max_pax_size, u64::MAX);
    }

    #[test]
    fn test_strict_limits() {
        let limits = Limits::strict();
        assert!(limits.max_path_len < Limits::default().max_path_len);
        assert!(limits.max_pax_size < Limits::default().max_pax_size);
    }
}
