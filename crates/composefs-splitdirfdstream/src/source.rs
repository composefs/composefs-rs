//! Image metadata and on-demand layer streams shared by producers and consumers.

use std::error::Error;
use std::future::Future;

use crate::SplitDirFdStream;

/// A destination-independent source of raw image metadata and layer streams.
///
/// Consumers choose which layers to request, their ordering, and publication
/// policy. The intent is for this to be either backed by in-process produced
/// streamed splitstream data, or a varlink based source such as skopeo.
pub trait ImageSource: Send {
    /// Failure to prepare a stream or request it from a remote producer.
    type Error: Into<Box<dyn Error + Send + Sync>> + Send;

    /// Expected digest of the original manifest, including its algorithm prefix.
    fn manifest_digest(&self) -> &str;

    /// Original manifest bytes, without JSON normalization.
    fn manifest_json(&self) -> &[u8];

    /// Original configuration bytes referenced by the manifest.
    fn config_json(&self) -> &[u8];

    /// Start production of a layer by its index in the manifest.
    ///
    /// Production runs independently once this returns. The consumer verifies
    /// reconstructed content against the identities in the image metadata.
    /// Mutable access allows a remote implementation to drive its connection.
    fn get_layer(
        &mut self,
        index: usize,
    ) -> impl Future<Output = Result<SplitDirFdStream, Self::Error>> + Send;
}
