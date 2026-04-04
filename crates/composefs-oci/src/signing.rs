//! PKCS#7 signing and verification for composefs fsverity digests.
//!
//! This module produces DER-encoded PKCS#7 detached signatures compatible with
//! the Linux kernel's fsverity signature verification. Signatures cover the
//! `fsverity_formatted_digest` structure (see [`composefs::fsverity::formatted_digest`]).
//!
//! # External `openssl` CLI alternative
//!
//! For environments where linking against libssl is not desired, equivalent
//! signatures can be produced using the `openssl` command-line tool:
//!
//! ```bash
//! # 1. Compute the fsverity digest
//! DIGEST=$(fsverity digest --hash-alg=sha256 myfile | awk '{print $1}')
//!
//! # 2. Construct the formatted_digest structure and sign it
//! # (see doc/plans/oci-sealing-spec.md for the byte layout)
//! printf 'FSVerity' > /tmp/formatted_digest
//! printf '\x01\x00\x20\x00' >> /tmp/formatted_digest  # SHA256, 32 bytes
//! echo -n "$DIGEST" | xxd -r -p >> /tmp/formatted_digest
//!
//! # 3. Sign with PKCS#7
//! openssl smime -sign -binary -in /tmp/formatted_digest \
//!     -signer cert.pem -inkey key.pem -outform DER -noattr -out sig.der
//! ```

use anyhow::{Context, Result};
use composefs::fsverity::FsVerityHashValue;
use openssl::pkcs7::{Pkcs7, Pkcs7Flags};
use openssl::pkey::{PKey, Private};
use openssl::stack::Stack;
use openssl::x509::X509;
use openssl::x509::store::X509StoreBuilder;

/// A signing key pair for fsverity PKCS#7 signatures.
///
/// Holds a certificate and private key used to produce DER-encoded PKCS#7
/// detached signatures over the `fsverity_formatted_digest` structure.
pub struct FsVeritySigningKey {
    cert: X509,
    key: PKey<Private>,
}

impl std::fmt::Debug for FsVeritySigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FsVeritySigningKey")
            .field("cert_subject", &"<redacted>")
            .finish()
    }
}

impl FsVeritySigningKey {
    /// Load from PEM-encoded certificate and private key.
    ///
    /// The certificate must correspond to the private key. The certificate
    /// is included in the PKCS#7 signature so that verifiers can extract it.
    pub fn from_pem(cert_pem: &[u8], key_pem: &[u8]) -> Result<Self> {
        let cert = X509::from_pem(cert_pem).context("parsing certificate PEM")?;
        let key = PKey::private_key_from_pem(key_pem).context("parsing private key PEM")?;

        // Verify cert and key correspond to each other
        let cert_pubkey = cert
            .public_key()
            .context("extracting public key from certificate")?;
        anyhow::ensure!(
            cert_pubkey.public_eq(&key),
            "certificate public key does not match the provided private key"
        );

        Ok(Self { cert, key })
    }

    /// Sign an fsverity digest, producing a DER-encoded PKCS#7 detached signature.
    ///
    /// The signature covers the `fsverity_formatted_digest` structure, making it
    /// compatible with the kernel's `FS_IOC_ENABLE_VERITY` ioctl.
    pub fn sign<ObjectID: FsVerityHashValue>(&self, digest: &ObjectID) -> Result<Vec<u8>> {
        self.sign_raw(ObjectID::ALGORITHM.kernel_id(), digest.as_bytes())
    }

    /// Sign a raw digest with explicit algorithm, for when you don't have a typed ObjectID.
    ///
    /// # Arguments
    /// * `algorithm` - Kernel hash algorithm identifier (1=SHA-256, 2=SHA-512)
    /// * `digest` - Raw digest bytes
    pub fn sign_raw(&self, algorithm: u8, digest: &[u8]) -> Result<Vec<u8>> {
        // Validate algorithm and digest length
        let expected_size = match algorithm {
            1 => 32, // SHA-256
            2 => 64, // SHA-512
            _ => anyhow::bail!("unsupported fsverity algorithm: {algorithm}"),
        };
        anyhow::ensure!(
            digest.len() == expected_size,
            "digest length mismatch: expected {expected_size} bytes for algorithm {algorithm}, got {}",
            digest.len()
        );

        let formatted =
            composefs::fsverity::formatted_digest::format_fsverity_digest_raw(algorithm, digest);

        let certs = Stack::new().context("failed to create certificate stack")?;
        let flags = Pkcs7Flags::DETACHED | Pkcs7Flags::BINARY | Pkcs7Flags::NOATTR;

        let pkcs7 = Pkcs7::sign(&self.cert, &self.key, &certs, &formatted, flags)
            .context("PKCS#7 signing failed")?;

        pkcs7.to_der().context("PKCS#7 DER encoding failed")
    }
}

/// Verifier for fsverity PKCS#7 signatures.
///
/// Holds a trusted certificate used to verify DER-encoded PKCS#7 detached
/// signatures over the `fsverity_formatted_digest` structure.
#[derive(Debug)]
pub struct FsVeritySignatureVerifier {
    cert: X509,
}

impl FsVeritySignatureVerifier {
    /// Create a verifier trusting the given PEM-encoded certificate(s).
    ///
    /// The first certificate in the PEM data is used as the trusted root.
    pub fn from_pem(cert_pem: &[u8]) -> Result<Self> {
        let cert = X509::from_pem(cert_pem).context("failed to parse trusted certificate PEM")?;
        Ok(Self { cert })
    }

    /// Verify a DER-encoded PKCS#7 signature against an fsverity digest.
    ///
    /// Returns `Ok(())` if the signature is valid for the given digest under
    /// the trusted certificate. Returns an error if verification fails for
    /// any reason (wrong digest, wrong key, malformed signature, etc.).
    pub fn verify<ObjectID: FsVerityHashValue>(
        &self,
        signature: &[u8],
        digest: &ObjectID,
    ) -> Result<()> {
        self.verify_raw(
            signature,
            ObjectID::ALGORITHM.kernel_id(),
            digest.as_bytes(),
        )
    }

    /// Verify with raw algorithm + digest bytes.
    ///
    /// # Arguments
    /// * `signature` - DER-encoded PKCS#7 detached signature
    /// * `algorithm` - Kernel hash algorithm identifier (1=SHA-256, 2=SHA-512)
    /// * `digest` - Raw digest bytes
    pub fn verify_raw(&self, signature: &[u8], algorithm: u8, digest: &[u8]) -> Result<()> {
        // Validate algorithm and digest length
        let expected_size = match algorithm {
            1 => 32, // SHA-256
            2 => 64, // SHA-512
            _ => anyhow::bail!("unsupported fsverity algorithm: {algorithm}"),
        };
        anyhow::ensure!(
            digest.len() == expected_size,
            "digest length mismatch: expected {expected_size} bytes for algorithm {algorithm}, got {}",
            digest.len()
        );

        let formatted =
            composefs::fsverity::formatted_digest::format_fsverity_digest_raw(algorithm, digest);

        let pkcs7 = Pkcs7::from_der(signature).context("failed to parse PKCS#7 DER signature")?;

        let mut store_builder = X509StoreBuilder::new().context("failed to create X509 store")?;
        store_builder
            .add_cert(self.cert.clone())
            .context("failed to add trusted cert to store")?;
        let store = store_builder.build();

        let mut certs = Stack::new().context("failed to create certificate stack")?;
        certs
            .push(self.cert.clone())
            .context("failed to push cert to stack")?;

        // Do NOT use Pkcs7Flags::NOVERIFY — we want full certificate chain validation.
        let flags = Pkcs7Flags::BINARY;
        pkcs7
            .verify(&certs, &store, Some(&formatted), None, flags)
            .context("PKCS#7 signature verification failed")?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use composefs::fsverity::{Sha256HashValue, Sha512HashValue};
    use openssl::asn1::Asn1Time;
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::x509::{X509Builder, X509NameBuilder};

    /// Generate a self-signed test certificate and RSA-2048 private key.
    /// Returns (cert_pem, key_pem).
    fn generate_test_keypair() -> (Vec<u8>, Vec<u8>) {
        let rsa = Rsa::generate(2048).expect("RSA key generation");
        let key = PKey::from_rsa(rsa).expect("PKey from RSA");

        let mut name_builder = X509NameBuilder::new().expect("X509NameBuilder");
        name_builder
            .append_entry_by_text("CN", "composefs-test")
            .expect("append CN");
        let name = name_builder.build();

        let mut builder = X509Builder::new().expect("X509Builder");
        builder.set_version(2).expect("set version");
        builder.set_subject_name(&name).expect("set subject");
        builder.set_issuer_name(&name).expect("set issuer");
        builder.set_pubkey(&key).expect("set pubkey");

        let not_before = Asn1Time::days_from_now(0).expect("not_before");
        let not_after = Asn1Time::days_from_now(365).expect("not_after");
        builder.set_not_before(&not_before).expect("set not_before");
        builder.set_not_after(&not_after).expect("set not_after");

        builder
            .sign(&key, MessageDigest::sha256())
            .expect("self-sign");
        let cert = builder.build();

        let cert_pem = cert.to_pem().expect("cert to PEM");
        let key_pem = key.private_key_to_pem_pkcs8().expect("key to PEM");

        (cert_pem, key_pem)
    }

    #[test]
    fn test_rejects_mismatched_cert_key() {
        let (cert_pem_a, _key_pem_a) = generate_test_keypair();
        let (_cert_pem_b, key_pem_b) = generate_test_keypair();
        let result = FsVeritySigningKey::from_pem(&cert_pem_a, &key_pem_b);
        assert!(result.is_err());
        let err = format!("{:#}", result.unwrap_err());
        assert!(err.contains("does not match"), "unexpected error: {err}");
    }

    #[test]
    fn test_sign_and_verify_sha256() {
        let (cert_pem, key_pem) = generate_test_keypair();
        let signer = FsVeritySigningKey::from_pem(&cert_pem, &key_pem).unwrap();
        let verifier = FsVeritySignatureVerifier::from_pem(&cert_pem).unwrap();

        let digest = Sha256HashValue::from_hex(
            "1e2eaa4202d750a41174ee454970b92c1bc2f925b1e35076d8c7d5f56362ba64",
        )
        .unwrap();

        let sig = signer.sign(&digest).unwrap();
        verifier.verify(&sig, &digest).unwrap();
    }

    #[test]
    fn test_sign_and_verify_sha512() {
        let (cert_pem, key_pem) = generate_test_keypair();
        let signer = FsVeritySigningKey::from_pem(&cert_pem, &key_pem).unwrap();
        let verifier = FsVeritySignatureVerifier::from_pem(&cert_pem).unwrap();

        let hex_str = "ab".repeat(64); // 64 bytes = valid SHA-512
        let digest = Sha512HashValue::from_hex(&hex_str).unwrap();

        let sig = signer.sign(&digest).unwrap();
        verifier.verify(&sig, &digest).unwrap();
    }

    #[test]
    fn test_verify_rejects_wrong_digest() {
        let (cert_pem, key_pem) = generate_test_keypair();
        let signer = FsVeritySigningKey::from_pem(&cert_pem, &key_pem).unwrap();
        let verifier = FsVeritySignatureVerifier::from_pem(&cert_pem).unwrap();

        let digest_a = Sha256HashValue::from_hex(
            "1e2eaa4202d750a41174ee454970b92c1bc2f925b1e35076d8c7d5f56362ba64",
        )
        .unwrap();
        let digest_b = Sha256HashValue::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap();

        let sig = signer.sign(&digest_a).unwrap();
        let result = verifier.verify(&sig, &digest_b);
        assert!(
            result.is_err(),
            "verification should fail with wrong digest"
        );
    }

    #[test]
    fn test_verify_rejects_wrong_cert() {
        let (cert_a, key_a) = generate_test_keypair();
        let (cert_b, _key_b) = generate_test_keypair();

        let signer = FsVeritySigningKey::from_pem(&cert_a, &key_a).unwrap();
        let verifier = FsVeritySignatureVerifier::from_pem(&cert_b).unwrap();

        let digest = Sha256HashValue::from_hex(
            "1e2eaa4202d750a41174ee454970b92c1bc2f925b1e35076d8c7d5f56362ba64",
        )
        .unwrap();

        let sig = signer.sign(&digest).unwrap();
        let result = verifier.verify(&sig, &digest);
        assert!(
            result.is_err(),
            "verification should fail with untrusted cert"
        );
    }

    #[test]
    fn test_verify_rejects_tampered_signature() {
        let (cert_pem, key_pem) = generate_test_keypair();
        let signer = FsVeritySigningKey::from_pem(&cert_pem, &key_pem).unwrap();
        let verifier = FsVeritySignatureVerifier::from_pem(&cert_pem).unwrap();

        let digest = Sha256HashValue::from_hex(
            "1e2eaa4202d750a41174ee454970b92c1bc2f925b1e35076d8c7d5f56362ba64",
        )
        .unwrap();

        let mut sig = signer.sign(&digest).unwrap();

        // Tamper with a byte near the end of the signature (inside the actual
        // signature data, not the ASN.1 framing at the beginning).
        let tamper_idx = sig.len() - 10;
        sig[tamper_idx] ^= 0xff;

        let result = verifier.verify(&sig, &digest);
        assert!(
            result.is_err(),
            "verification should fail with tampered signature"
        );
    }

    #[test]
    fn test_sign_raw_matches_typed() {
        let (cert_pem, key_pem) = generate_test_keypair();
        let signer = FsVeritySigningKey::from_pem(&cert_pem, &key_pem).unwrap();
        let verifier = FsVeritySignatureVerifier::from_pem(&cert_pem).unwrap();

        let hex = "1e2eaa4202d750a41174ee454970b92c1bc2f925b1e35076d8c7d5f56362ba64";
        let digest = Sha256HashValue::from_hex(hex).unwrap();
        let raw_bytes = hex::decode(hex).unwrap();

        // Both signing paths should produce signatures that verify
        let sig_typed = signer.sign(&digest).unwrap();
        let sig_raw = signer
            .sign_raw(Sha256HashValue::ALGORITHM.kernel_id(), &raw_bytes)
            .unwrap();

        // The DER content may differ (timestamps, nonces) but both must verify
        verifier.verify(&sig_typed, &digest).unwrap();
        verifier
            .verify_raw(&sig_raw, Sha256HashValue::ALGORITHM.kernel_id(), &raw_bytes)
            .unwrap();

        // And cross-verify: raw sig verifies with typed API, typed sig with raw API
        verifier.verify(&sig_raw, &digest).unwrap();
        verifier
            .verify_raw(
                &sig_typed,
                Sha256HashValue::ALGORITHM.kernel_id(),
                &raw_bytes,
            )
            .unwrap();
    }

    /// Data-driven tests for sign_raw / verify_raw input validation.
    #[test]
    fn test_sign_raw_rejects_bad_inputs() {
        let (cert_pem, key_pem) = generate_test_keypair();
        let signer = FsVeritySigningKey::from_pem(&cert_pem, &key_pem).unwrap();

        // (algorithm, digest_bytes, expected_err_substring)
        let cases: &[(u8, &[u8], &str)] = &[
            (0, &[0u8; 32], "unsupported"),
            (3, &[0u8; 32], "unsupported"),
            (255, &[0u8; 32], "unsupported"),
            (1, &[0xab; 64], "digest length mismatch"), // SHA-256 expects 32, got 64
            (2, &[0xab; 32], "digest length mismatch"), // SHA-512 expects 64, got 32
            (1, &[], "digest length mismatch"),         // empty digest
        ];

        for (alg, digest, expected) in cases {
            let err = signer.sign_raw(*alg, digest).unwrap_err();
            let msg = format!("{err:#}");
            assert!(
                msg.contains(expected),
                "sign_raw(alg={alg}, len={}): unexpected error: {msg}",
                digest.len()
            );
        }
    }

    #[test]
    fn test_verify_raw_rejects_bad_inputs() {
        let (cert_pem, _) = generate_test_keypair();
        let verifier = FsVeritySignatureVerifier::from_pem(&cert_pem).unwrap();
        let dummy_sig = &[0x30, 0x82, 0x01, 0x00];

        // (signature, algorithm, digest, expected_err_substring)
        let cases: &[(&[u8], u8, &[u8], &str)] = &[
            (dummy_sig, 3, &[0u8; 64], "unsupported"),
            (dummy_sig, 0, &[0u8; 32], "unsupported"),
            (dummy_sig, 2, &[0xab; 32], "digest length mismatch"), // SHA-512 expects 64
            (dummy_sig, 1, &[0xab; 64], "digest length mismatch"), // SHA-256 expects 32
            (b"not-valid-der", 1, &[0xab; 32], "PKCS#7 DER"),
            (&[], 1, &[0xab; 32], "PKCS#7 DER"), // empty signature
        ];

        for (sig, alg, digest, expected) in cases {
            let err = verifier.verify_raw(sig, *alg, digest).unwrap_err();
            let msg = format!("{err:#}");
            assert!(
                msg.contains(expected),
                "verify_raw(alg={alg}, sig_len={}, digest_len={}): unexpected error: {msg}",
                sig.len(),
                digest.len()
            );
        }
    }

    #[test]
    fn test_from_pem_rejects_garbage() {
        assert!(FsVeritySigningKey::from_pem(b"garbage", b"garbage").is_err());
        assert!(FsVeritySignatureVerifier::from_pem(b"garbage").is_err());
    }
}
