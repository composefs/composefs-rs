//! User namespace utilities for rootless containers-storage access.
//!
//! This module provides utilities for determining when user namespace entry is
//! needed to access overlay storage files that are owned by remapped UIDs/GIDs.
//!
//! # Background
//!
//! When podman runs rootless, it uses user namespaces to remap UIDs. Files in
//! the overlay storage are owned by these remapped UIDs (e.g., UID 100000+N on
//! the host corresponds to UID N inside the container). These files also retain
//! their original permission bits from the container image.
//!
//! Files with restrictive permissions (e.g., `/etc/shadow` with mode 0600) are
//! only readable by their owner - a remapped UID we cannot access as an
//! unprivileged user.
//!
//! # Solution
//!
//! Rather than manually setting up user namespaces (parsing `/etc/subuid`,
//! calling `newuidmap`/`newgidmap`, etc.), we delegate to `podman unshare`
//! which handles all the edge cases. See [`crate::userns_helper`] for the
//! helper process that runs inside the user namespace.

use rustix::process::getuid;
use rustix::thread::{capabilities, CapabilitySet};

/// Check if the current process can read arbitrary files regardless of permissions.
///
/// This returns `true` if:
/// - The process is running as real root (UID 0), or
/// - The process has `CAP_DAC_OVERRIDE` in its effective capability set
///
/// When this returns `true`, there's no need to spawn a userns helper for
/// file access - the process can already read any file in the storage.
pub fn can_bypass_file_permissions() -> bool {
    // Real root can read anything
    if getuid().is_root() {
        return true;
    }

    // Check for CAP_DAC_OVERRIDE capability
    if let Ok(caps) = capabilities(None) {
        if caps.effective.contains(CapabilitySet::DAC_OVERRIDE) {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_can_bypass_file_permissions() {
        // This function should not panic and should return a consistent result
        let result1 = can_bypass_file_permissions();
        let result2 = can_bypass_file_permissions();
        assert_eq!(result1, result2);

        // If we're root, it should return true
        if getuid().is_root() {
            assert!(result1, "root should be able to bypass permissions");
        }
    }
}
