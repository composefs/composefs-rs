//! Android boot image v2 parsing.
//!
//! This module provides functionality to parse android boot format! version 2 files
//! and extract embedded components like kernel, initrd, commandline and dtb.

use std::io::{Read, Seek, SeekFrom};
use thiserror::Error;
use zerocopy::{
    FromBytes, Immutable, KnownLayout,
    little_endian::{U32, U64},
};

// Layout from Android's boot image specification:
// https://android.googlesource.com/platform/system/tools/mkbootimg/+/refs/heads/main/include/bootimg/bootimg.h
#[derive(Debug, FromBytes, Immutable, KnownLayout)]
#[cfg_attr(test, derive(zerocopy::IntoBytes))]
#[repr(C)]
struct BootImageHeaderV2 {
    magic: [u8; 8],
    kernel_size: U32,
    kernel_addr: U32,
    ramdisk_size: U32,
    ramdisk_addr: U32,
    second_size: U32,
    second_addr: U32,
    tags_addr: U32,
    page_size: U32,
    header_version: U32,
    os_version: U32,
    name: [u8; 16],
    cmdline: [u8; CMDLINE_SIZE],
    id: [U32; 8],
    extra_cmdline: [u8; EXTRA_CMDLINE_SIZE],
    recovery_dtbo_size: U32,
    recovery_dtbo_offset: U64,
    header_size: U32,
    dtb_size: U32,
    dtb_addr: U64,
}

const MAGIC: [u8; 8] = *b"ANDROID!";
const CMDLINE_SIZE: usize = 512;
const EXTRA_CMDLINE_SIZE: usize = 1024;
const TOTAL_CMDLINE_SIZE: usize = CMDLINE_SIZE + EXTRA_CMDLINE_SIZE;
const HEADER_SIZE: usize = std::mem::size_of::<BootImageHeaderV2>();
const _: () = assert!(HEADER_SIZE == 1660);

/// Errors encountered while parsing an Android boot image.
#[derive(Debug, Error)]
pub enum AndroidBootError {
    #[error("I/O error")]
    /// Reading the image failed.
    Io(#[from] std::io::Error),
    #[error("not an Android boot image")]
    /// The image magic is not `ANDROID!`.
    InvalidMagic,
    #[error("unsupported Android boot header version {0}")]
    /// The image uses a header version other than v2.
    UnsupportedVersion(u32),
    #[error("invalid Android boot image header")]
    /// Header fields are inconsistent.
    InvalidHeader,
    #[error("component {0} is not present")]
    /// The requested component has zero length.
    MissingComponent(&'static str),
    #[error("kernel command line is not UTF-8")]
    /// The kernel command line is not valid UTF-8.
    InvalidCmdline(#[from] std::str::Utf8Error),
}

/// Android boot image payloads.
#[derive(Debug, Clone, Copy)]
pub enum Component {
    /// The compressed or uncompressed kernel payload.
    Kernel,
    /// The initramfs payload.
    Ramdisk,
    /// The device-tree blob payload.
    Dtb,
}

/// Metadata needed to locate Android boot image v2 payloads.
#[derive(Debug, Clone, Copy)]
pub struct AndroidBootImage {
    page_size: u32,
    kernel_size: u32,
    ramdisk_size: u32,
    second_size: u32,
    recovery_dtbo_size: u32,
    dtb_size: u32,
    header_size: u32,
    cmdline: [u8; TOTAL_CMDLINE_SIZE],
}

impl AndroidBootImage {
    /// Parse and validate an Android boot image v2 header.
    pub fn parse<R: Read + Seek>(image: &mut R) -> Result<Self, AndroidBootError> {
        image.seek(SeekFrom::Start(0))?;
        let mut header = [0; HEADER_SIZE];
        image.read_exact(&mut header)?;
        let header = BootImageHeaderV2::ref_from_bytes(&header)
            .map_err(|_| AndroidBootError::InvalidHeader)?;
        if header.magic != MAGIC {
            return Err(AndroidBootError::InvalidMagic);
        }

        let page_size = header.page_size.get();
        let header_version = header.header_version.get();
        let header_size = header.header_size.get();
        if header_version != 2 {
            return Err(AndroidBootError::UnsupportedVersion(header_version));
        }
        if page_size == 0 || header_size < HEADER_SIZE as u32 || header_size > page_size {
            return Err(AndroidBootError::InvalidHeader);
        }

        // mkbootimg splits long command lines (with a null terminator for each)
        let primary_len = nul_terminated_len(&header.cmdline);
        let extra_len = nul_terminated_len(&header.extra_cmdline);
        let mut cmdline = [0; TOTAL_CMDLINE_SIZE];
        cmdline[..primary_len].copy_from_slice(&header.cmdline[..primary_len]);
        cmdline[primary_len..primary_len + extra_len]
            .copy_from_slice(&header.extra_cmdline[..extra_len]);

        Ok(Self {
            page_size,
            kernel_size: header.kernel_size.get(),
            ramdisk_size: header.ramdisk_size.get(),
            second_size: header.second_size.get(),
            recovery_dtbo_size: header.recovery_dtbo_size.get(),
            dtb_size: header.dtb_size.get(),
            header_size,
            cmdline,
        })
    }

    /// Read one payload from the image.
    pub fn component<R: Read + Seek>(
        &self,
        image: &mut R,
        component: Component,
    ) -> Result<Vec<u8>, AndroidBootError> {
        let mut offset = u64::from(self.page_size);
        let (name, size) = match component {
            Component::Kernel => ("kernel", self.kernel_size),
            Component::Ramdisk => {
                offset = add_aligned(offset, self.kernel_size, self.page_size)?;
                ("ramdisk", self.ramdisk_size)
            }
            Component::Dtb => {
                offset = add_aligned(offset, self.kernel_size, self.page_size)?;
                offset = add_aligned(offset, self.ramdisk_size, self.page_size)?;
                offset = add_aligned(offset, self.second_size, self.page_size)?;
                offset = add_aligned(offset, self.recovery_dtbo_size, self.page_size)?;
                ("dtb", self.dtb_size)
            }
        };
        if size == 0 {
            return Err(AndroidBootError::MissingComponent(name));
        }
        image.seek(SeekFrom::Start(offset))?;
        let mut data = vec![0; size as usize];
        image.read_exact(&mut data)?;
        Ok(data)
    }

    /// Return the v2 header size stored in the image.
    pub fn header_size(&self) -> u32 {
        self.header_size
    }

    /// Return the kernel command line stored in the image header.
    pub fn cmdline(&self) -> Result<&str, AndroidBootError> {
        let end = nul_terminated_len(&self.cmdline);
        Ok(std::str::from_utf8(&self.cmdline[..end])?)
    }
}

fn nul_terminated_len(bytes: &[u8]) -> usize {
    bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len())
}

fn add_aligned(
    offset: impl TryInto<u64>,
    size: impl TryInto<u64>,
    alignment: impl TryInto<u64>,
) -> Result<u64, AndroidBootError> {
    let offset = offset
        .try_into()
        .map_err(|_| AndroidBootError::InvalidHeader)?;
    let size = size
        .try_into()
        .map_err(|_| AndroidBootError::InvalidHeader)?;
    let alignment = alignment
        .try_into()
        .map_err(|_| AndroidBootError::InvalidHeader)?;
    let end = offset
        .checked_add(size)
        .ok_or(AndroidBootError::InvalidHeader)?;
    let padding = alignment
        .checked_sub(1)
        .ok_or(AndroidBootError::InvalidHeader)?;
    let blocks = end
        .checked_add(padding)
        .ok_or(AndroidBootError::InvalidHeader)?
        / alignment;
    blocks
        .checked_mul(alignment)
        .ok_or(AndroidBootError::InvalidHeader)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::Cursor;
    use zerocopy::IntoBytes;

    fn image_with_cmdline(kernel: &[u8], ramdisk: &[u8], dtb: &[u8], cmdline: &[u8]) -> Vec<u8> {
        assert!(cmdline.len() < TOTAL_CMDLINE_SIZE);
        let page = 2048;
        let kernel_offset = page as usize;
        let ramdisk_offset = add_aligned(kernel_offset, kernel.len(), page).unwrap() as usize;
        let dtb_offset = add_aligned(ramdisk_offset, ramdisk.len(), page).unwrap() as usize;
        let mut image = vec![0; dtb_offset + dtb.len()];
        let mut header = BootImageHeaderV2 {
            magic: MAGIC,
            kernel_size: U32::new(kernel.len() as u32),
            kernel_addr: U32::new(0),
            ramdisk_size: U32::new(ramdisk.len() as u32),
            ramdisk_addr: U32::new(0),
            second_size: U32::new(0),
            second_addr: U32::new(0),
            tags_addr: U32::new(0),
            page_size: U32::new(page),
            header_version: U32::new(2),
            os_version: U32::new(0),
            name: [0; 16],
            cmdline: [0; CMDLINE_SIZE],
            id: [U32::new(0); 8],
            extra_cmdline: [0; EXTRA_CMDLINE_SIZE],
            recovery_dtbo_size: U32::new(0),
            recovery_dtbo_offset: U64::new(0),
            header_size: U32::new(HEADER_SIZE as u32),
            dtb_size: U32::new(dtb.len() as u32),
            dtb_addr: U64::new(0),
        };
        // Match mkbootimg's v0-v2 layout: 511 bytes, a NUL, then the rest.
        let split = cmdline.len().min(CMDLINE_SIZE - 1);
        header.cmdline[..split].copy_from_slice(&cmdline[..split]);
        header.extra_cmdline[..cmdline.len() - split].copy_from_slice(&cmdline[split..]);
        image[..HEADER_SIZE].copy_from_slice(header.as_bytes());
        image[kernel_offset..kernel_offset + kernel.len()].copy_from_slice(kernel);
        image[ramdisk_offset..ramdisk_offset + ramdisk.len()].copy_from_slice(ramdisk);
        image[dtb_offset..dtb_offset + dtb.len()].copy_from_slice(dtb);
        image
    }

    pub(crate) fn image(kernel: &[u8], ramdisk: &[u8], dtb: &[u8]) -> Vec<u8> {
        image_with_cmdline(kernel, ramdisk, dtb, b"")
    }

    #[test]
    fn parses_v2_components() -> Result<(), AndroidBootError> {
        let kernel = b"kernel";
        let ramdisk = b"ramdisk";
        let dtb = b"dtb";

        let mut image = Cursor::new(image(kernel, ramdisk, dtb));
        let header = AndroidBootImage::parse(&mut image).unwrap();
        assert_eq!(
            header.component(&mut image, Component::Kernel).unwrap(),
            kernel
        );
        assert_eq!(
            header.component(&mut image, Component::Ramdisk).unwrap(),
            ramdisk
        );
        assert_eq!(header.component(&mut image, Component::Dtb).unwrap(), dtb);
        Ok(())
    }

    #[test]
    fn parses_cmdline() -> Result<(), AndroidBootError> {
        for expected in [
            "quiet".to_string(),
            "x".repeat(CMDLINE_SIZE - 1),
            format!("{} composefs=digest", "x".repeat(CMDLINE_SIZE - 1)),
            "x".repeat(TOTAL_CMDLINE_SIZE - 1),
        ] {
            let bytes = image_with_cmdline(b"kernel", b"ramdisk", b"", expected.as_bytes());
            let image = AndroidBootImage::parse(&mut Cursor::new(bytes))?;
            assert_eq!(image.cmdline()?, expected);
        }
        Ok(())
    }

    #[test]
    fn rejects_non_utf8_cmdline() -> Result<(), AndroidBootError> {
        let bytes = image_with_cmdline(b"kernel", b"ramdisk", b"", &[0xff]);
        let image = AndroidBootImage::parse(&mut Cursor::new(bytes))?;
        assert!(matches!(
            image.cmdline(),
            Err(AndroidBootError::InvalidCmdline(_))
        ));
        Ok(())
    }
}
