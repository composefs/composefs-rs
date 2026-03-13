//! Kernel keyring integration for fs-verity certificates.
//!
//! This module provides functions for injecting CA certificates into the
//! kernel's `.fs-verity` keyring, enabling kernel-level signature verification
//! for fsverity-protected files.

use std::num::NonZeroI32;
use thiserror::Error;

/// The kernel keyring serial for the `.fs-verity` keyring.
///
/// This is `KEY_SPEC_FS_FSVERITY_KEYRING` from the Linux kernel, defined as -4.
/// See `fs/verity/signature.c` in the kernel source.
const KEY_SPEC_FS_FSVERITY_KEYRING: i32 = -4;

/// Errors that can occur when injecting a certificate into the kernel keyring.
#[derive(Error, Debug)]
pub enum KeyringError {
    /// Failed to parse the PEM certificate (wraps openssl error).
    #[error("failed to parse PEM certificate: {0}")]
    PemParseFailed(#[from] openssl::error::ErrorStack),
    /// Failed to add key to the keyring.
    #[error("failed to add key to keyring: {0}")]
    KeyAddFailed(#[from] keyutils::Error),
    /// Permission denied (requires CAP_SYS_ADMIN).
    #[error("permission denied: adding keys to .fs-verity keyring requires root/CAP_SYS_ADMIN")]
    PermissionDenied,
    /// The keyring does not exist (kernel may not have fs-verity signature support).
    #[error("the .fs-verity keyring does not exist; kernel may not support fs-verity signatures")]
    KeyringNotFound,
}

/// Inject a CA certificate into the kernel's `.fs-verity` keyring.
///
/// This allows the kernel to require valid PKCS#7 signatures when `FS_IOC_ENABLE_VERITY`
/// is called. The certificate must be PEM-encoded and will be converted to DER format
/// before being added to the keyring.
///
/// # Trust Model
///
/// When a certificate is loaded into the `.fs-verity` keyring, the kernel will verify
/// PKCS#7 signatures passed to `FS_IOC_ENABLE_VERITY` against this keyring. If the
/// signature is invalid or the signing certificate is not trusted by a key in the
/// keyring, the ioctl will fail.
///
/// This provides kernel-level enforcement of file integrity signatures, complementing
/// the application-level verification provided by OCI signature artifacts.
///
/// # Requirements
///
/// - Requires `CAP_SYS_ADMIN` capability (typically root).
/// - The kernel must be built with `CONFIG_FS_VERITY_BUILTIN_SIGNATURES=y`.
/// - The `.fs-verity` keyring must exist.
///
/// # Arguments
///
/// * `cert_pem` - The PEM-encoded X.509 certificate to add to the keyring.
///
/// # Example
///
/// ```ignore
/// use composefs_ioctls::keyring::inject_fsverity_cert;
///
/// let cert_pem = std::fs::read("my-ca-cert.pem")?;
/// inject_fsverity_cert(&cert_pem)?;
/// println!("Certificate added to .fs-verity keyring");
/// ```
#[allow(unsafe_code)]
pub fn inject_fsverity_cert(cert_pem: &[u8]) -> Result<(), KeyringError> {
    // Parse PEM and extract DER using openssl
    let cert = openssl::x509::X509::from_pem(cert_pem)?;
    let cert_der = cert.to_der()?;

    // Get the .fs-verity keyring
    // SAFETY: The kernel defines KEY_SPEC_FS_FSVERITY_KEYRING as a valid special keyring ID.
    // NonZeroI32::new(-4) is guaranteed to succeed since -4 != 0.
    let keyring_serial = NonZeroI32::new(KEY_SPEC_FS_FSVERITY_KEYRING)
        .expect("KEY_SPEC_FS_FSVERITY_KEYRING is non-zero");
    let mut keyring = unsafe { keyutils::Keyring::new(keyring_serial) };

    // Add the certificate as an asymmetric key.
    // The description can be anything — the kernel derives the actual description
    // from the certificate's subject and issuer.
    let result = keyring.add_key::<keyutils::keytypes::Asymmetric, _, _>("", &cert_der[..]);

    match result {
        Ok(_key) => Ok(()),
        Err(e) => {
            // Check for specific error conditions using errno values.
            // keyutils::Error is an alias for errno::Errno.
            let errno_val = e.0;
            if errno_val == rustix::io::Errno::ACCESS.raw_os_error()
                || errno_val == rustix::io::Errno::PERM.raw_os_error()
            {
                Err(KeyringError::PermissionDenied)
            } else if errno_val == 126 || errno_val == 128 {
                // ENOKEY = 126, EKEYREVOKED = 128 on Linux
                Err(KeyringError::KeyringNotFound)
            } else {
                Err(KeyringError::KeyAddFailed(e))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate a self-signed PEM certificate for testing via openssl.
    fn generate_test_cert_pem() -> Vec<u8> {
        use openssl::asn1::Asn1Time;
        use openssl::hash::MessageDigest;
        use openssl::pkey::PKey;
        use openssl::rsa::Rsa;
        use openssl::x509::{X509Builder, X509NameBuilder};

        let rsa = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();

        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "test-ca").unwrap();
        let name = name.build();

        let mut builder = X509Builder::new().unwrap();
        builder.set_version(2).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&pkey).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(365).unwrap())
            .unwrap();
        builder.sign(&pkey, MessageDigest::sha256()).unwrap();

        let cert = builder.build();
        cert.to_pem().unwrap()
    }

    #[test]
    fn test_pem_parse_valid_cert() {
        let pem = generate_test_cert_pem();
        let cert = openssl::x509::X509::from_pem(&pem).unwrap();
        let der = cert.to_der().unwrap();
        assert!(!der.is_empty());
    }

    #[test]
    fn test_pem_parse_invalid() {
        let bad_pem = b"this is not a PEM certificate";
        let result = openssl::x509::X509::from_pem(bad_pem);
        assert!(result.is_err());
    }

    #[test]
    fn test_inject_invalid_pem() {
        let result = inject_fsverity_cert(b"not a cert");
        assert!(matches!(result, Err(KeyringError::PemParseFailed(_))));
    }
}
