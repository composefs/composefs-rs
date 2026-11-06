//! Drive image publication from a generic descriptor-based source.

use composefs::progress::{ComponentId, ProgressEvent, ProgressUnit, SharedReporter};

use super::{
    ImageSource, ImportError, ImportOptions, LayerStatus, PublishedImage, RawImage, Result,
    StorageWriter, StoreLocation,
};

/// Drives the process of importing a complete image, including requesting the
/// missing layers as splitdirfd streams.
///
/// This helper consumes and verifies each stream and reports completed or reused
/// layers through a SharedReported.
///
/// Names must be complete, canonical references with an explicit registry and
/// tag or digest. Digests must match the source manifest. An empty list assigns
/// no new names. Names are validated before creating the store or requesting layers.
///
/// Dropping the future stops further layers. A layer already running on a
/// worker finishes or cleans up before releasing its locks and source lifetime
/// descriptors. Durable image publication, once started, runs to completion.
pub async fn import_image<S: ImageSource + ?Sized>(
    source: &mut S,
    destination: StoreLocation,
    names: &[String],
    options: ImportOptions,
    progress: Option<SharedReporter>,
) -> Result<PublishedImage> {
    let raw = RawImage {
        expected_manifest: source.manifest_digest().parse().map_err(|error| {
            ImportError::Malformed(format!("invalid source manifest digest: {error}"))
        })?,
        manifest_json: source.manifest_json().to_vec(),
        config_json: source.config_json().to_vec(),
    };
    let names = super::names::requested(names, &raw.expected_manifest)?;
    let mut import = StorageWriter::ensure(destination)
        .await?
        .begin_image(raw, options)
        .await?;
    let layer_count = import.layer_count()?;
    let total = layer_count as u64;
    let id = ComponentId::from(format!("storage-export:{}", source.manifest_digest()));
    let report = |event| {
        if let Some(reporter) = &progress {
            reporter.report(event);
        }
    };
    report(ProgressEvent::Started {
        id: id.clone(),
        total: Some(total),
        unit: ProgressUnit::Items,
    });

    for index in 0..layer_count {
        // Cancellation must also take effect when every layer is reusable.
        tokio::task::yield_now().await;
        let layer_index = index as u32;
        match import.layer_status(layer_index)? {
            LayerStatus::Reusable(_) => report(ProgressEvent::Message(format!(
                "Reusing layer {}/{total}",
                index + 1
            ))),
            LayerStatus::NeedsParent => return Err(ImportError::NeedsParent(layer_index)),
            LayerStatus::Missing => {
                report(ProgressEvent::Message(format!(
                    "Importing layer {}/{total}",
                    index + 1
                )));
                let stream =
                    source
                        .get_layer(index)
                        .await
                        .map_err(|error| ImportError::Source {
                            index: layer_index,
                            source: error.into(),
                        })?;
                import.put_layer_stream(layer_index, stream).await?;
            }
        }
        report(ProgressEvent::Progress {
            id: id.clone(),
            fetched: (index + 1) as u64,
            total: Some(total),
        });
    }
    report(ProgressEvent::Message(
        "Publishing image to containers/storage".into(),
    ));
    let published = import.prepare_publication().await?.finish(&names).await?;
    report(ProgressEvent::Done {
        id,
        transferred: total,
    });
    Ok(published)
}
