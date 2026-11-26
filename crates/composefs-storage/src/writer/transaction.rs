//! Image import sessions and publication to the destination store.

use std::collections::HashSet;
use std::fs::File;
use std::path::{Path, PathBuf};

use cap_std::fs::Dir;
use oci_spec::image::Descriptor;
use rustix::fs::{self, Mode, OFlags};

use super::extract;
use super::locking::{LockFile, ReadLock, WriteLock};
use super::overlay::{LowerChain, read_optional, valid_link};
use super::records::{
    self, ContainerRecord, ImageRecord, LayerFlags, LayerRecord, MountRecord, ValidatedImage,
    allow_missing, find_by_id, find_by_id_mut,
};
use super::*;

/// Imports OCI images into a containers/storage overlay store.
///
/// Lock waits are asynchronous; long filesystem operations run on blocking workers.
#[derive(Debug)]
pub struct StorageWriter {
    location: OpenedStoreLocation,
}

impl StorageWriter {
    /// Create missing storage directories and scaffolding, or open an existing store.
    ///
    /// Configuration requirements are the same as for [`Self::open`]. Existing
    /// image and layer records are preserved.
    pub async fn ensure(location: StoreLocation) -> Result<Self> {
        super::initialize::ensure(location).await
    }

    /// Open an initialized containers/storage overlay destination.
    ///
    /// The caller must supply a rootful store using the default native overlay
    /// configuration, persistent metadata, and no separate writable image store.
    /// New layers use unshifted ownership and Go's storage layer IDs;
    /// existing mapped layers are preserved.
    pub fn open(location: StoreLocation) -> Result<Self> {
        Self::open_inner(location.open()?)
    }

    pub(super) fn open_inner(location: OpenedStoreLocation) -> Result<Self> {
        let overlay = records::open_dir(&location.graphroot, Path::new("overlay"))?;
        records::open_dir(&overlay, Path::new("l"))?;
        for name in ["overlay-layers", "overlay-images"] {
            records::open_dir(&location.graphroot, Path::new(name))?;
        }
        Ok(Self { location })
    }

    /// Begin importing an image from its OCI manifest and configuration.
    ///
    /// The returned session owns the layer-store write lock until publication or drop.
    /// Image-store locks are acquired for initialization and publication.
    pub async fn begin_image(self, image: RawImage, options: ImportOptions) -> Result<ImageImport> {
        let image = ValidatedImage::new(image)?;
        let layers = LayerStore::open(&self.location.graphroot).await?;
        let state = ImportState::new(self, image, options, layers)?;
        let images = LockFile::open(&state.image_dir, "images.lock")?;
        let images = images.read().await?;
        let state = state.initialize(images).await?;
        Ok(ImageImport { state: Some(state) })
    }
}

/// An image being imported into the destination store.
///
/// Completed layers are retained for reuse when the session is dropped. A layer
/// already running on a worker finishes before releasing its locks.
#[derive(Debug)]
pub struct ImageImport {
    state: Option<ImportState>,
}

/// An import ready to publish its metadata and names.
///
/// Created by [`ImageImport::prepare_publication`].
#[derive(Debug)]
pub struct ImagePublication {
    // Release the image lock before the layer transaction.
    images: WriteLock,
    state: ImportState,
}

impl ImageImport {
    pub(super) fn layer_count(&self) -> Result<usize> {
        Ok(self
            .state
            .as_ref()
            .ok_or_else(unavailable)?
            .image
            .diff_ids
            .len())
    }

    /// Import a splitdirfdstream on a filesystem worker, retaining all received
    /// lifetime descriptors through layer registration or error cleanup.
    ///
    /// File-backed chunks remain whole-file references for sharing. The stream
    /// must reconstruct the uncompressed tar identified by this config index.
    /// Cancellation has the same semantics as [`Self::put_layer`].
    pub async fn put_layer_stream(
        &mut self,
        index: u32,
        stream: composefs_splitdirfdstream::SplitDirFdStream,
    ) -> Result<LayerResult> {
        self.put_layer(index, super::splitdirfd::SplitDirFdSource::new(stream))
            .await
    }

    /// Check a layer's availability and select it for reuse when possible.
    pub fn layer_status(&mut self, index: u32) -> Result<LayerStatus> {
        self.state
            .as_mut()
            .ok_or_else(unavailable)?
            .layer_status(index)
    }

    /// Import a complete layer on a filesystem worker.
    ///
    /// Once started, the worker finishes the layer or its error cleanup even if
    /// the awaiting future is dropped. Cancellation takes effect between layers.
    /// After dropping a layer future, start a new import to retry the operation.
    pub async fn put_layer(
        &mut self,
        index: u32,
        mut source: impl LayerSource + Send + 'static,
    ) -> Result<LayerResult> {
        let state = self.state.take().ok_or_else(unavailable)?;
        let (next, result) = worker(move || {
            // Keep the source and any lifetime guards it owns until registration
            // and error cleanup have finished, not just until extraction ends.
            state.put_layer(index, &mut source)
        })
        .await?;
        self.state = Some(next);
        result
    }

    /// Acquire publication access (and locks) after all layers have been selected.
    pub async fn prepare_publication(mut self) -> Result<ImagePublication> {
        let state = self.state.take().ok_or_else(unavailable)?;
        state.ensure_live()?;
        state.require_layers()?;
        let request = LockFile::open(&state.image_dir, "images.lock")?;
        let images = request.write().await?;
        Ok(ImagePublication { images, state })
    }

    /// End an import, retaining completed layers for reuse.
    pub async fn abort(mut self) -> Result<AbortReport> {
        self.state.take().ok_or_else(unavailable)?.abort()
    }
}

impl ImagePublication {
    /// Publish the image with the requested names.
    ///
    /// Names must be complete, canonical references with an explicit registry and
    /// tag or digest. Digests must match the published manifest. Names are stored
    /// unchanged; an empty list assigns no new names.
    ///
    /// Once the durable commit starts, it runs to completion even if its future is dropped.
    /// The Tokio runtime must remain running for the commit to finish.
    pub async fn finish(self, names: &[String]) -> Result<PublishedImage> {
        self.state.finish(names, self.images).await
    }
}

fn unavailable() -> ImportError {
    ImportError::MetadataConflict("import no longer available after interrupted work".into())
}

#[derive(Debug)]
struct CurrentLayer {
    id: String,
    links: LayerLinks,
}

#[derive(Debug, Clone)]
enum LayerLinks {
    Created(Option<String>),
    Recover,
}

/// Layer records and overlay data protected by the layer-store write lock.
#[derive(Debug)]
struct LayerStore {
    layer_dir: Dir,
    overlay: Dir,
    layers: Vec<LayerRecord>,
    other_layers: Vec<LayerRecord>,
    // Keep the write lock until the cached records and directory handles drop.
    lock: WriteLock,
}

impl LayerStore {
    async fn open(graphroot: &Dir) -> Result<Self> {
        let layer_dir = records::open_dir(graphroot, Path::new("overlay-layers"))?;
        // Driver setup uses the graph lock. Imports take the layer lock before
        // image locks, matching containers/storage's lock order.
        let lock = LockFile::open(&layer_dir, "layers.lock")?.write().await?;
        let layers = records::records(&layer_dir, "layers.json")?;
        let other_layers: Vec<LayerRecord> = records::records(&layer_dir, "volatile-layers.json")?;
        if other_layers.iter().any(LayerRecord::is_incomplete) {
            return Err(ImportError::RecoveryRequired(
                "incomplete volatile layers require a Go writer".into(),
            ));
        }
        let overlay = records::open_dir(graphroot, Path::new("overlay"))?;
        Ok(Self {
            layer_dir,
            overlay,
            layers,
            other_layers,
            lock,
        })
    }

    fn layer_dir(&self) -> &Dir {
        &self.layer_dir
    }

    fn overlay(&self) -> &Dir {
        &self.overlay
    }

    fn records(&self) -> &[LayerRecord] {
        &self.layers
    }

    fn all_records(&self) -> impl Iterator<Item = &LayerRecord> {
        self.layers.iter().chain(&self.other_layers)
    }

    fn get(&self, id: &str) -> Option<&LayerRecord> {
        find_by_id(&self.layers, id)
    }

    fn get_mut(&mut self, id: &str) -> Option<&mut LayerRecord> {
        find_by_id_mut(&mut self.layers, id)
    }

    fn find(&self, id: &str) -> Result<&LayerRecord> {
        self.get(id)
            .ok_or_else(|| ImportError::RecoveryRequired(format!("missing layer record {id}")))
    }

    fn find_mut(&mut self, id: &str) -> Result<&mut LayerRecord> {
        self.get_mut(id)
            .ok_or_else(|| ImportError::RecoveryRequired(format!("missing layer record {id}")))
    }

    fn get_volatile(&self, id: &str) -> Option<&LayerRecord> {
        find_by_id(&self.other_layers, id)
    }

    fn save(&self) -> Result<()> {
        self.lock
            .write_records(&self.layer_dir, "layers.json", &self.layers)
    }

    fn reload(&mut self) -> Result<()> {
        self.layers = records::records(&self.layer_dir, "layers.json")?;
        Ok(())
    }

    fn insert(&mut self, layer: LayerRecord) -> Result<()> {
        self.layers.push(layer);
        self.save()
    }

    fn remove_record(&mut self, id: &str) -> Result<()> {
        self.layers.retain(|layer| layer.id != id);
        self.save()
    }

    /// Publish the extracted identity after the layer-wide durability barrier.
    fn complete_layer(
        &mut self,
        id: &str,
        descriptor: &Descriptor,
        extracted: &extract::Extracted,
    ) -> Result<()> {
        let record = self.find_mut(id)?;
        record.flags = None;
        record.diff_digest = Some(extracted.digest.clone());
        record.diff_size = Some(extracted.bytes.try_into().map_err(|_| {
            ImportError::Malformed("layer size exceeds Go's signed size range".into())
        })?);
        // Retain the original blob identity for Go's later pull lookups, as
        // OriginalDigest/OriginalSize do. Compression describes the applied
        // stream, which is uncompressed even when the original blob was not.
        record.compressed_diff_digest = Some(descriptor.digest().to_string());
        record.compressed_size = Some(descriptor.size().try_into().map_err(|_| {
            ImportError::Malformed("compressed layer size exceeds Go's signed size range".into())
        })?);
        record.compression = Some(0);
        record.uidset = Some(extracted.uids.iter().copied().collect());
        record.gidset = Some(extracted.gids.iter().copied().collect());
        self.save()
    }

    fn data_present(&self, id: &str) -> bool {
        self.overlay.is_dir(format!("{id}/diff"))
            && self.layer_dir.is_file(format!("{id}.tar-split.gz"))
    }

    /// Check store-side reuse requirements. Callers also check image identity
    /// and exclude container writable layers.
    fn reusable_for_extraction(&self, layer: &LayerRecord) -> Result<bool> {
        Ok(!layer.is_incomplete()
            && layer.is_reusable()
            && self.data_present(&layer.id)
            && self.reusable_layout(layer)?)
    }

    /// Extraction reads each ancestor's diff directory directly. Remapped
    /// variants can instead depend on rotated diff directories or template
    /// layers outside their logical parent chain, and cannot be reused here.
    fn reusable_layout(&self, layer: &LayerRecord) -> Result<bool> {
        let id = &layer.id;
        let dir = records::open_dir(&self.overlay, Path::new(id))?;
        if dir.try_exists("diff1")? {
            return Ok(false);
        }
        let Some(link) = read_optional(&dir, "link")? else {
            return Ok(false);
        };
        if !valid_link(&link) {
            return Ok(false);
        }
        if allow_missing(self.overlay.read_link(format!("l/{link}")))?
            .is_none_or(|target| target != Path::new(&format!("../{id}/diff")))
        {
            return Ok(false);
        }
        let ids = match overlay::parent_chain(&self.layers, layer.parent()) {
            Ok(ids) => ids,
            // An invalid logical chain disqualifies this candidate.
            Err(_) => return Ok(false),
        };
        let Some(lowers) = LowerChain::read(&self.overlay, &ids)? else {
            return Ok(false);
        };
        Ok(lowers.matches(
            read_optional(&dir, "lower")?,
            read_optional(&dir, "lower-layers")?,
        ))
    }
}

#[derive(Debug)]
struct ImportState {
    writer: StorageWriter,
    layers: LayerStore,
    image_dir: Dir,
    image: ValidatedImage,
    options: ImportOptions,
    selected: Vec<Option<LayerResult>>,
    writable_layers: HashSet<String>,
    // Existing candidates checked under the layer lock for metadata/layout compatibility.
    reusable_layers: HashSet<String>,
    current: Option<CurrentLayer>,
    failed: bool,
    closed: bool,
    stats: MaterializationStats,
}

impl ImportState {
    fn new(
        writer: StorageWriter,
        image: ValidatedImage,
        options: ImportOptions,
        layers: LayerStore,
    ) -> Result<Self> {
        let image_dir = records::open_dir(&writer.location.graphroot, Path::new("overlay-images"))?;
        let count = image.diff_ids.len();
        Ok(Self {
            writer,
            layers,
            image_dir,
            image,
            options,
            selected: vec![None; count],
            writable_layers: HashSet::new(),
            reusable_layers: HashSet::new(),
            current: None,
            failed: false,
            closed: false,
            stats: MaterializationStats::default(),
        })
    }

    /// Prepare the store for this import by recovering interrupted layers,
    /// finding reusable layers, and validating any existing publication of the image.
    async fn initialize(self, images: ReadLock) -> Result<Self> {
        let (mut state, images) = self.recover(images).await?;
        if state.select_existing(&images)? {
            return Ok(state);
        }
        // The layer lock keeps these paths stable until the session ends.
        // Check only candidates for this image, leaving status queries in memory.
        let expected: HashSet<_> = state.image.diff_ids.iter().map(|d| d.as_ref()).collect();
        for layer in state.layers.records() {
            let id = &layer.id;
            if layer
                .diff_digest
                .as_deref()
                .is_some_and(|diff| expected.contains(diff))
                && !state.writable_layers.contains(id)
                && state.layers.reusable_for_extraction(layer)?
            {
                state.reusable_layers.insert(id.to_owned());
            }
        }
        Ok(state)
    }

    /// Retain an identical image's entire chain for publication and name updates.
    /// Its physical ownership/layout need not support extraction: selecting every
    /// layer together prevents using just part of that chain as extraction parents.
    fn select_existing(&mut self, _guard: &ReadLock) -> Result<bool> {
        let images = records::records(&self.image_dir, "images.json")?;
        let Some(record) = self.preflight(&images)? else {
            return Ok(false);
        };
        let chain = existing_image_chain(&self.layers, record.layer(), self.selected.len())?;
        let selections = chain
            .into_iter()
            .rev()
            .enumerate()
            .map(|(index, layer)| self.validate_existing_layer(index, layer))
            .collect::<Result<Vec<_>>>()?;
        for (selected, result) in self.selected.iter_mut().zip(selections) {
            self.stats.add(result.stats);
            *selected = Some(result);
        }
        Ok(true)
    }

    fn validate_existing_layer(&self, index: usize, layer: &LayerRecord) -> Result<LayerResult> {
        let id = &layer.id;
        if layer.diff_digest.as_deref() != Some(self.image.diff_ids[index].as_ref())
            || layer.is_incomplete()
        {
            return Err(ImportError::MetadataConflict(
                "existing image has a different layer identity".into(),
            ));
        }
        if self.writable_layers.contains(id) {
            return Err(ImportError::RecoveryRequired(format!(
                "image references container writable layer {id}"
            )));
        }
        if !self.layers.data_present(id) {
            return Err(ImportError::RecoveryRequired(format!(
                "image references missing layer data for {id}"
            )));
        }
        self.reused_layer(index, layer)
    }

    fn reused_layer(&self, index: usize, layer: &LayerRecord) -> Result<LayerResult> {
        if self
            .image
            .uncompressed_size(index)
            .is_some_and(|expected| layer.uncompressed_size() != Some(expected))
        {
            return Err(ImportError::Malformed(
                "uncompressed layer descriptor size disagrees with stored layer".into(),
            ));
        }
        Ok(LayerResult {
            storage_layer_id: layer.id.clone(),
            diff_id: self.image.diff_ids[index].clone(),
            reused: true,
            stats: MaterializationStats {
                reused_layers: 1,
                reused_bytes: layer.uncompressed_size().unwrap_or(0),
                ..MaterializationStats::default()
            },
        })
    }

    fn require_layers(&self) -> Result<()> {
        for (i, layer) in self.selected.iter().enumerate() {
            if layer.is_none() {
                return Err(ImportError::MissingLayer(i as u32));
            }
        }
        Ok(())
    }

    fn parent_id(&self, index: usize) -> &str {
        if index == 0 {
            ""
        } else {
            &self.selected[index - 1].as_ref().unwrap().storage_layer_id
        }
    }

    /// Check a layer's availability and select it for reuse when possible.
    pub fn layer_status(&mut self, index: u32) -> Result<LayerStatus> {
        self.ensure_live()?;
        let i = index as usize;
        if i >= self.selected.len() {
            return Err(ImportError::Malformed(format!(
                "layer index {index} out of range"
            )));
        }
        if let Some(result) = &self.selected[i] {
            return Ok(LayerStatus::Reusable(result.storage_layer_id.clone()));
        }
        if i > 0 && self.selected[i - 1].is_none() {
            return Ok(LayerStatus::NeedsParent);
        }
        let parent = self.parent_id(i);
        let expected = &self.image.diff_ids[i];
        // Go's pull path only reuses this exact storage ID. Selecting arbitrary
        // matching layers would make subsequent Go pulls build a different chain.
        let id = records::layer_id(parent, expected);
        if self.layers.get_volatile(&id).is_some() {
            return Err(ImportError::MetadataConflict(format!(
                "layer ID {id} is occupied by a volatile layer"
            )));
        }
        let candidate = self.layers.get(&id);
        if let Some(layer) = candidate {
            if layer.diff_digest.as_deref() != Some(expected.as_ref())
                || layer.parent() != parent
                || !self.reusable_layers.contains(&id)
            {
                return Err(ImportError::MetadataConflict(format!(
                    "layer ID {id} exists but cannot be reused"
                )));
            }
            let result = self.reused_layer(i, layer)?;
            let id = result.storage_layer_id.clone();
            self.stats.add(result.stats);
            self.selected[i] = Some(result);
            Ok(LayerStatus::Reusable(id))
        } else {
            Ok(LayerStatus::Missing)
        }
    }

    /// Import a layer from its uncompressed tar data and file references.
    ///
    /// Return the session after success or successful error cleanup. If cleanup
    /// fails, drop it here so Drop's final attempt also runs on the worker.
    fn put_layer(
        mut self,
        index: u32,
        source: &mut impl LayerSource,
    ) -> Result<(Self, Result<LayerResult>)> {
        let result = match self.try_put_layer(index, source) {
            Ok(result) => Ok(result),
            Err(error) => {
                if let Err(cleanup) = self.cleanup_current() {
                    tracing::warn!(%cleanup, %error, "incomplete layer cleanup failed; recovery required");
                    return Err(error);
                }
                Err(error)
            }
        };
        Ok((self, result))
    }

    fn try_put_layer(&mut self, index: u32, source: impl LayerSource) -> Result<LayerResult> {
        match self.layer_status(index)? {
            LayerStatus::NeedsParent => return Err(ImportError::NeedsParent(index)),
            LayerStatus::Reusable(_) => {
                return Ok(self.selected[index as usize].as_ref().unwrap().clone());
            }
            LayerStatus::Missing => {}
        }
        let i = index as usize;
        let id = records::layer_id(self.parent_id(i), &self.image.diff_ids[i]);
        // Establish ownership only after excluding unrecorded data. Cleanup
        // must never delete a preexisting namespace at this deterministic ID.
        for (dir, path) in [
            (self.layers.overlay(), id.clone()),
            (self.layers.layer_dir(), id.clone()),
            (self.layers.layer_dir(), format!("{id}.tar-split.gz")),
        ] {
            if allow_missing(dir.symlink_metadata(&path))?.is_some() {
                return Err(ImportError::RecoveryRequired(format!(
                    "unrecorded layer data at {path}"
                )));
            }
        }
        self.current = Some(CurrentLayer {
            id: id.clone(),
            links: LayerLinks::Created(None),
        });
        let result = self.install_layer(index, &id, source);
        match result {
            Ok(result) => {
                self.current = None;
                self.stats.add(result.stats);
                self.selected[index as usize] = Some(result.clone());
                Ok(result)
            }
            Err(error) => {
                self.failed = true;
                Err(ImportError::Layer {
                    index,
                    id,
                    source: Box::new(error),
                })
            }
        }
    }

    fn install_layer(
        &mut self,
        index: u32,
        id: &str,
        source: impl LayerSource,
    ) -> Result<LayerResult> {
        let sync_dirs = self.layer_sync_dirs()?;
        let parent = self.parent_id(index as usize).to_owned();
        let parents = overlay::parent_chain(self.layers.records(), &parent)?;
        let lower_chain = LowerChain::read(self.layers.overlay(), &parents)?.ok_or_else(|| {
            ImportError::RecoveryRequired("missing or invalid parent overlay link".into())
        })?;
        self.layers.insert(LayerRecord {
            id: id.into(),
            parent: Some(parent),
            created: Some(records::now()),
            flags: Some(LayerFlags {
                incomplete: Some(true),
                ..Default::default()
            }),
            ..Default::default()
        })?;
        let Some(CurrentLayer {
            links: LayerLinks::Created(link),
            ..
        }) = self.current.as_mut()
        else {
            return Err(ImportError::MetadataConflict(
                "layer installation has no cleanup owner".into(),
            ));
        };
        let diff = overlay::create_layer(self.layers.overlay(), id, &lower_chain, link)?;
        let tar_name = format!("{id}.tar-split.gz");
        let fd = fs::openat(
            self.layers.layer_dir(),
            tar_name.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_bits_truncate(records::PRIVATE_FILE_MODE),
        )?;

        let lower_dirs = self.selected[..index as usize]
            .iter()
            .rev()
            .map(|layer| {
                records::open_dir(
                    self.layers.overlay(),
                    &Path::new(&layer.as_ref().unwrap().storage_layer_id).join("diff"),
                )
            })
            .collect::<Result<Vec<_>>>()?;
        let extracted = extract::extract(
            &diff,
            &lower_dirs,
            File::from(fd),
            source,
            self.options.sharing,
        )?;
        self.verify_layer(index as usize, &extracted)?;
        // Flush layer contents, tar-split and inode/directory metadata together
        // before publishing the completed record. Extraction needs no per-file
        // or per-entry syncs while the durable incomplete record protects it.
        for dir in sync_dirs {
            fs::syncfs(&dir)?;
        }
        self.layers.complete_layer(
            id,
            &self.image.layer_descriptors[index as usize],
            &extracted,
        )?;
        Ok(LayerResult {
            storage_layer_id: id.into(),
            diff_id: self.image.diff_ids[index as usize].clone(),
            reused: false,
            stats: extracted.stats,
        })
    }

    fn layer_sync_dirs(&self) -> Result<Vec<Dir>> {
        // Open before any writes so syncfs observes writeback errors reported
        // during this transaction, including after payload FDs close. Driver
        // and metadata directories may be mounted on separate filesystems.
        let mut filesystems = HashSet::new();
        let mut sync_dirs = Vec::new();
        for dir in [
            &self.writer.location.graphroot,
            self.layers.overlay(),
            self.layers.layer_dir(),
        ] {
            let dir = records::open_dir(dir, Path::new("."))?;
            if filesystems.insert(fs::fstat(&dir)?.st_dev) {
                sync_dirs.push(dir);
            }
        }
        Ok(sync_dirs)
    }

    fn verify_layer(&self, index: usize, extracted: &extract::Extracted) -> Result<()> {
        records::check_digest(
            "layer diff ID",
            &self.image.diff_ids[index],
            &extracted.digest,
        )?;
        if self
            .image
            .uncompressed_size(index)
            .is_some_and(|expected| expected != extracted.bytes)
        {
            return Err(ImportError::Malformed(
                "uncompressed layer descriptor size mismatch".into(),
            ));
        }
        Ok(())
    }

    /// Publish the image with the requested names once all layers are available.
    async fn finish(self, names: &[String], lock: WriteLock) -> Result<PublishedImage> {
        self.ensure_live()?;
        let mut ids = Vec::with_capacity(self.selected.len());
        for (i, layer) in self.selected.iter().enumerate() {
            ids.push(
                layer
                    .as_ref()
                    .ok_or(ImportError::MissingLayer(i as u32))?
                    .storage_layer_id
                    .clone(),
            );
        }
        let unique = names::requested(names, &self.image.raw.expected_manifest)?;
        let mut images = records::records(&self.image_dir, "images.json")?;
        let existing = self.preflight(&images)?;
        let already_present = existing.is_some();
        if let Some(record) = existing
            && record.layer() != ids.last().map(String::as_str).unwrap_or("")
        {
            return Err(ImportError::MetadataConflict(
                "existing image points to a different destination chain".into(),
            ));
        }
        if !already_present {
            let mut record = ImageRecord {
                id: self.image.id.clone(),
                digest: Some(self.image.raw.expected_manifest.to_string()),
                layer: Some(ids.last().cloned().unwrap_or_default()),
                created: Some(self.image.created.clone()),
                names: Some(Vec::new()),
                names_history: Some(Vec::new()),
                ..Default::default()
            };
            for (key, bytes) in self.image_data() {
                record
                    .big_data_names
                    .get_or_insert_default()
                    .push(key.clone());
                record
                    .big_data_sizes
                    .get_or_insert_default()
                    .insert(key.clone(), bytes.len() as i64);
                record
                    .big_data_digests
                    .get_or_insert_default()
                    .insert(key, records::digest(bytes));
            }
            images.push(record);
        }
        names::assign(&mut images, &self.image.id, &unique, self.options.names)?;
        let published = PublishedImage {
            image_id: self.image.id.clone(),
            manifest_digest: self.image.raw.expected_manifest.clone(),
            config_digest: self.image.config_digest.clone(),
            layer_ids: ids,
            already_present,
            stats: self.stats,
        };
        // The commit task owns all locks and finishes the remaining writes
        // even if the caller drops the future waiting for its result.
        tokio::spawn(self.commit_image(images, lock, published)).await?
    }

    fn image_data(&self) -> [(String, &[u8]); 3] {
        [
            ("manifest".into(), &self.image.raw.manifest_json),
            (
                format!("manifest-{}", self.image.raw.expected_manifest),
                &self.image.raw.manifest_json,
            ),
            (
                self.image.config_digest.to_string(),
                &self.image.raw.config_json,
            ),
        ]
    }

    /// Write image data before publishing its record, retaining all locks until
    /// the durable commit finishes.
    async fn commit_image(
        self,
        images: Vec<ImageRecord>,
        lock: WriteLock,
        published: PublishedImage,
    ) -> Result<PublishedImage> {
        let mut publication = ImagePublication {
            images: lock,
            state: self,
        };
        if !published.already_present {
            let state = &publication.state;
            let image_dir = match allow_missing(records::open_dir(
                &state.image_dir,
                Path::new(&state.image.id),
            ))? {
                Some(dir) => dir,
                None => records::create_dir(
                    &state.image_dir,
                    &state.image.id,
                    records::PRIVATE_DIR_MODE,
                )?,
            };
            let data = state.image_data().map(|(key, bytes)| (key, bytes.to_vec()));
            for (key, bytes) in data {
                let name = records::big_data_name(&key);
                publication = records::atomic_write_async(
                    image_dir.try_clone()?,
                    name,
                    bytes,
                    records::PRIVATE_FILE_MODE,
                    publication,
                )
                .await?;
            }
            records::sync_dir_async(&publication.state.image_dir).await?;
        }
        let dir = publication.state.image_dir.try_clone()?;
        let (images, state) = publication
            .images
            .write_records_async(dir, "images.json".into(), images, publication.state)
            .await?;
        let mut publication = ImagePublication { images, state };
        publication.state.closed = true;
        Ok(published)
    }

    /// Cancel the import and clean up incomplete work.
    pub fn abort(mut self) -> Result<AbortReport> {
        let result = self.cleanup_current();
        self.closed = true;
        result?;
        Ok(AbortReport {
            retained_layers: self
                .selected
                .iter()
                .flatten()
                .filter(|r| !r.reused)
                .map(|r| r.storage_layer_id.clone())
                .collect(),
        })
    }

    fn ensure_live(&self) -> Result<()> {
        if self.failed {
            Err(ImportError::MetadataConflict(
                "failed import requires abort".into(),
            ))
        } else {
            Ok(())
        }
    }
    /// Check whether this image is already published with matching OCI metadata.
    fn preflight<'a>(&self, images: &'a [ImageRecord]) -> Result<Option<&'a ImageRecord>> {
        let Some(record) = find_by_id(images, &self.image.id) else {
            return Ok(None);
        };
        let metadata_error = |error| match error {
            ImportError::Io(e) if e.kind() == std::io::ErrorKind::NotFound => {
                ImportError::RecoveryRequired(format!(
                    "image {} has a record but is missing stored metadata",
                    self.image.id
                ))
            }
            error => error,
        };
        let dir = records::open_dir(&self.image_dir, Path::new(&self.image.id))
            .map_err(metadata_error)?;
        let manifest = dir.read("manifest").map_err(|e| metadata_error(e.into()))?;
        if manifest != self.image.raw.manifest_json {
            return Err(ImportError::ManifestVariantConflict(self.image.id.clone()));
        }
        let config = dir
            .read(records::big_data_name(self.image.config_digest.as_ref()))
            .map_err(|e| metadata_error(e.into()))?;
        if config != self.image.raw.config_json {
            return Err(ImportError::MetadataConflict(
                "existing config data differs".into(),
            ));
        }
        Ok(Some(record))
    }

    /// Remove incomplete layers left by interrupted imports, refusing recovery
    /// if images, containers, child layers or active mounts still reference them.
    /// Also identify container writable layers so they cannot be reused as image layers.
    /// Deletion runs on a worker that retains the layer and image locks.
    async fn recover(mut self, images_lock: ReadLock) -> Result<(Self, ReadLock)> {
        let ids: Vec<String> = self
            .layers
            .records()
            .iter()
            .filter(|layer| layer.is_incomplete())
            .map(|l| {
                // Deleting native overlay state does not interpret ownership
                // mappings or require a layout suitable for layer reuse.
                l.check_flags()?;
                Ok(l.id.clone())
            })
            .collect::<Result<_>>()?;
        // Native overlay container creation/deletion and mount/unmount take
        // the layer lock we already hold. Container-only metadata updates
        // atomically replace JSON without changing layer associations.
        let containers: Vec<ContainerRecord> = records::records_in(
            &self.writer.location.graphroot,
            "overlay-containers",
            &["containers.json", "volatile-containers.json"],
        )?;
        self.writable_layers = containers
            .iter()
            .filter_map(|record| record.layer.clone())
            .collect();
        if ids.is_empty() {
            return Ok((self, images_lock));
        }
        let mounts: Vec<MountRecord> = match &self.writer.location.runroot {
            Some(runroot) => records::records_in(runroot, "overlay-layers", &["mountpoints.json"])?,
            None => Vec::new(),
        };
        let images: Vec<ImageRecord> = records::records(&self.image_dir, "images.json")?;
        for id in &ids {
            if self.layers.all_records().any(|l| l.parent() == id)
                || containers.iter().any(|c| c.layer.as_ref() == Some(id))
                || images.iter().any(|i| {
                    i.layer() == id
                        || i.mapped_layers
                            .as_ref()
                            .is_some_and(|layers| layers.contains(id))
                })
                || mounts.iter().any(|m| {
                    &m.id == id
                        && (m.count.unwrap_or(0) > 0
                            || m.path.as_ref().is_some_and(|path| !path.is_empty()))
                })
            {
                return Err(ImportError::RecoveryRequired(format!(
                    "incomplete layer {id} has live references or mount state"
                )));
            }
        }
        // Drop state before the image guard, including on cleanup errors:
        // its Drop may retry cleanup and must still hold all the locks.
        let mut recovery = (self, images_lock);
        worker(move || {
            for id in ids {
                recovery.0.current = Some(CurrentLayer {
                    id,
                    links: LayerLinks::Recover,
                });
                recovery.0.cleanup_current()?;
            }
            Ok(recovery)
        })
        .await
    }

    /// Discard the current layer's data and records after a failed or interrupted
    /// installation, keeping incomplete state until cleanup finishes.
    fn cleanup_current(&mut self) -> Result<()> {
        let Some(current) = &self.current else {
            return Ok(());
        };
        let id = current.id.clone();
        let link_cleanup = current.links.clone();
        records::safe_id(&id)?;
        // A completed-record rename may have succeeded before a later fsync
        // failed. Restore durable recovery state before deleting any data.
        self.layers.reload()?;
        if let Some(record) = self.layers.get_mut(&id) {
            record.flags.get_or_insert_default().incomplete = Some(true);
            self.layers.save()?;
        }
        let links = records::open_dir(self.layers.overlay(), Path::new("l"))?;
        let target = PathBuf::from(format!("../{id}/diff"));
        match link_cleanup {
            LayerLinks::Created(link) => {
                // Rollback owns only the link it created, including when an
                // older dangling link already targeted this deterministic ID.
                if let Some(link) = link {
                    remove_layer_link(&links, link, &target)?;
                }
            }
            LayerLinks::Recover => {
                // Go may crash after creating a short link but before writing
                // the link file. Recovery discovers every matching target.
                for entry in links.entries()? {
                    let entry = entry?;
                    if entry.file_type()?.is_symlink() {
                        remove_layer_link(&links, entry.file_name(), &target)?;
                    }
                }
            }
        }
        records::sync_dir(&links)?;
        allow_missing(self.layers.overlay().remove_dir_all(&id))?;
        records::sync_dir(self.layers.overlay())?;
        allow_missing(
            self.layers
                .layer_dir()
                .remove_file(format!("{id}.tar-split.gz")),
        )?;
        allow_missing(self.layers.layer_dir().remove_dir_all(&id))?;
        records::sync_dir(self.layers.layer_dir())?;
        self.layers.remove_record(&id)?;
        self.current = None;
        Ok(())
    }
}

/// Resolve an existing image's complete chain in overlay order, nearest first.
fn existing_image_chain<'a>(
    layers: &'a LayerStore,
    mut id: &'a str,
    count: usize,
) -> Result<Vec<&'a LayerRecord>> {
    let mut chain = Vec::new();
    while !id.is_empty() {
        if chain.len() >= count {
            return Err(ImportError::MetadataConflict(
                "existing image has a different layer chain".into(),
            ));
        }
        let layer = layers.find(id)?;
        layer.check_flags()?;
        chain.push(layer);
        id = layer.parent();
    }
    if chain.len() != count {
        return Err(ImportError::MetadataConflict(
            "existing image has a different layer count".into(),
        ));
    }
    Ok(chain)
}

fn remove_layer_link(links: &Dir, name: impl AsRef<Path>, target: &Path) -> Result<()> {
    let name = name.as_ref();
    if allow_missing(links.read_link(name))?.is_some_and(|actual| actual == target) {
        links.remove_file(name)?;
    }
    Ok(())
}

impl Drop for ImportState {
    fn drop(&mut self) {
        if !self.closed
            && let Err(error) = self.cleanup_current()
        {
            tracing::warn!(%error,"image import drop left incomplete state requiring recovery");
        }
    }
}
