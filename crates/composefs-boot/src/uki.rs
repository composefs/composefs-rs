//! Unified Kernel Image (UKI) parsing and metadata extraction.
//!
//! This module provides functionality to parse PE (Portable Executable) format UKI files
//! and extract embedded sections like .osrel and .cmdline. It implements the Boot Loader
//! Specification Type 2 requirements for UKI boot entries, including extraction of boot
//! labels from os-release information embedded in the UKI binary.

use std::io::{Read, Seek, SeekFrom};
use thiserror::Error;
use zerocopy::{
    FromBytes, Immutable, KnownLayout,
    little_endian::{U16, U32},
};

use crate::os_release::OsReleaseInfo;

// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
#[derive(Debug, FromBytes, Immutable, KnownLayout)]
#[cfg_attr(test, derive(zerocopy::IntoBytes, Default))]
#[repr(C)]
struct DosStub {
    _unused1: [u8; 0x20],
    _unused2: [u8; 0x1c],
    pe_offset: U32,
}

#[derive(Debug, FromBytes, Immutable, KnownLayout)]
#[cfg_attr(test, derive(zerocopy::IntoBytes, Default))]
#[repr(C)]
struct CoffFileHeader {
    machine: U16,
    number_of_sections: U16,
    time_date_stamp: U32,
    pointer_to_symbol_table: U32,
    number_of_symbols: U32,
    size_of_optional_header: U16,
    characteristics: U16,
}

#[derive(Debug, FromBytes, Immutable, KnownLayout)]
#[cfg_attr(test, derive(zerocopy::IntoBytes, Default))]
#[repr(C)]
struct PeHeader {
    pe_magic: [u8; 4], // P E \0 \0
    coff_file_header: CoffFileHeader,
}
const PE_MAGIC: [u8; 4] = *b"PE\0\0";

#[derive(Debug, FromBytes, Immutable, KnownLayout)]
#[cfg_attr(test, derive(zerocopy::IntoBytes, Default))]
#[repr(C)]
struct SectionHeader {
    name: [u8; 8],
    virtual_size: U32,
    virtual_address: U32,
    size_of_raw_data: U32,
    pointer_to_raw_data: U32,
    pointer_to_relocations: U32,
    pointer_to_line_numbers: U32,
    number_of_relocations: U16,
    number_of_line_numbers: U16,
    characteristics: U32,
}

/// Errors that can occur when parsing UKI files.
#[derive(Debug, Error)]
pub enum UkiError {
    /// IO Error while reading or seeking
    #[error("IO Error")]
    Io(#[from] std::io::Error),
    /// The file is not a valid Portable Executable (PE/EFI) format
    #[error("UKI is not valid EFI executable")]
    PortableExecutableError,
    /// A required PE section is missing from the UKI
    #[error("UKI doesn't contain a '{0}' section")]
    MissingSection(String),
    /// A PE section contains invalid UTF-8
    #[error("UKI section '{0}' is not UTF-8")]
    UnicodeError(String),
    /// The .osrel section lacks name information
    #[error("No name information found in .osrel section")]
    NoName,
}

/// Extracts a text section from a UKI PE file by name and validates it as UTF-8.
///
/// This is a convenience wrapper around [`get_section`] that additionally validates
/// the section contents as valid UTF-8 text.
///
/// # Arguments
///
/// * `image` - The complete UKI image as a byte slice
/// * `section_name` - Name of the PE section to extract (e.g., ".osrel", ".cmdline")
///
/// # Returns
///
/// * `Ok(&str)` - If the section is found and contains valid UTF-8
/// * `Err(UkiError)` - If the PE is invalid, section is missing or the section contains invalid UTF-8
pub fn get_text_section<'a>(
    image: &'a [u8],
    section_name: &'static str,
) -> Result<&'a str, UkiError> {
    let bytes = get_section(image, section_name).ok_or(UkiError::PortableExecutableError)??;
    std::str::from_utf8(bytes).or(Err(UkiError::UnicodeError(section_name.into())))
}

/// Buffered version of [`get_text_section`]. 
///
/// See [`get_text_section`] for details. This version works with any [`Read`] + [`Seek`] 
/// source instead of requiring the entire image in memory.
pub fn get_text_section_buffered<'a, R: Read + Seek>(
    image: &'a mut R,
    section_name: &'a str,
) -> Result<String, UkiError> {
    let bytes = get_section_buffered(image, section_name)?;
    String::from_utf8(bytes).or(Err(UkiError::UnicodeError(section_name.into())))
}

/// Extracts a raw section from a UKI PE file by name.
///
/// Parses the PE file format to locate and extract the raw bytes of a named
/// section (e.g., ".osrel", ".cmdline"). This function returns the section
/// contents as raw bytes without any UTF-8 validation.
///
/// # Arguments
///
/// * `image` - The complete UKI image as a byte slice
/// * `section_name` - Name of the PE section to extract (must be ≤ 8 characters)
///
/// # Returns
///
/// * `None` - If the PE format is invalid or cannot be parsed
/// * `Some(Ok(&[u8]))` - If the section is found, containing the raw section data
/// * `Some(Err(UkiError::MissingSection))` - If the section is not found in the PE file
///
/// # Implementation Notes
// We use `None` as a way to say `Err(UkiError::PortableExecutableError)` for two reasons:
//   - .get(..) returns Option<> and using `?` with that is extremely convenient
//   - the error types returned from FromBytes can't be used with `?` because they try to return a
//     reference to the data, which causes problems with lifetime rules
//   - it saves us from having to type Err(UkiError::PortableExecutableError) everywhere
pub fn get_section<'a>(
    image: &'a [u8],
    section_name: &'static str,
) -> Option<Result<&'a [u8], UkiError>> {
    // Turn the section_name ".osrel" into a section_key b".osrel\0\0".
    // This will panic if section_name.len() > 8, which is what we want.
    let mut section_key = [0u8; 8];
    section_key[..section_name.len()].copy_from_slice(section_name.as_bytes());

    // Skip the DOS stub
    let (dos_stub, ..) = DosStub::ref_from_prefix(image).ok()?;
    let rest = image.get(dos_stub.pe_offset.get() as usize..)?;

    // Get the PE header
    let (pe_header, rest) = PeHeader::ref_from_prefix(rest).ok()?;
    if pe_header.pe_magic != PE_MAGIC {
        return None;
    }

    // Skip the optional header
    let rest = rest.get(pe_header.coff_file_header.size_of_optional_header.get() as usize..)?;

    // Try to load the section headers
    let n_sections = pe_header.coff_file_header.number_of_sections.get() as usize;
    let (sections, ..) = <[SectionHeader]>::ref_from_prefix_with_elems(rest, n_sections).ok()?;

    for section in sections {
        if section.name == section_key {
            let bytes = image
                .get(section.pointer_to_raw_data.get() as usize..)?
                .get(..section.virtual_size.get() as usize)?;
            return Some(Ok(bytes));
        }
    }

    Some(Err(UkiError::MissingSection(section_name.into())))
}

/// Buffered version of [`get_section`].
///
/// See [`get_section`] for details. This version works with any [`Read`] + [`Seek`] 
/// source and returns owned data instead of borrowed slices.
pub fn get_section_buffered<R: Read + Seek>(
    image: &mut R,
    section_name: &str,
) -> Result<Vec<u8>, UkiError> {
    use std::io::Error as IOError;

    // Turn the section_name ".osrel" into a section_key b".osrel\0\0".
    // This will panic if section_name.len() > 8, which is what we want.
    let mut section_key = [0u8; 8];
    section_key[..section_name.len()].copy_from_slice(section_name.as_bytes());

    // Skip the DOS stub
    let mut buf: Vec<u8> = vec![0; std::mem::size_of::<DosStub>()];
    image.read_exact(&mut buf)?;
    let dos_stub =
        DosStub::ref_from_bytes(&buf).map_err(|e| UkiError::Io(IOError::other(e.to_string())))?;
    image.seek(SeekFrom::Start(dos_stub.pe_offset.get() as u64))?;

    // Get the PE header
    let mut buf: Vec<u8> = vec![0; std::mem::size_of::<PeHeader>()];
    image.read_exact(&mut buf)?;
    let pe_header =
        PeHeader::ref_from_bytes(&buf).map_err(|e| UkiError::Io(IOError::other(e.to_string())))?;
    if pe_header.pe_magic != PE_MAGIC {
        return Err(UkiError::PortableExecutableError);
    }

    // Skip the optional header
    image.seek(SeekFrom::Current(
        pe_header.coff_file_header.size_of_optional_header.get() as i64,
    ))?;

    // Try to load the section headers
    let n_sections = pe_header.coff_file_header.number_of_sections.get() as usize;
    let mut sections = vec![0; std::mem::size_of::<SectionHeader>() * n_sections];
    image.read_exact(&mut sections)?;
    let sections = <[SectionHeader]>::ref_from_bytes_with_elems(&sections, n_sections)
        .map_err(|e| UkiError::Io(IOError::other(e.to_string())))?;

    for section in sections {
        if section.name != section_key {
            continue;
        }

        let mut buffer = vec![0; section.virtual_size.get() as usize];
        image.seek(SeekFrom::Start(section.pointer_to_raw_data.get() as u64))?;
        image.read_exact(&mut buffer)?;
        return Ok(buffer);
    }

    Err(UkiError::MissingSection(section_name.to_string()))
}

/// Gets an appropriate label for display in the boot menu for the given UKI image, according to
/// the "Type #2 EFI Unified Kernel Images" section in the Boot Loader Specification.  This will be
/// based on the "PRETTY_NAME" and "VERSION_ID" fields found in the os-release file (falling back
/// to "ID" and/or "VERSION" if they are not present).
///
/// For more information, see:
///  - <https://uapi-group.org/specifications/specs/boot_loader_specification/>
///  - <https://www.freedesktop.org/software/systemd/man/latest/os-release.html>
///
/// # Arguments
///
///  * `image`: the complete UKI image as a byte slice
///
/// # Return value
///
/// If we could successfully parse the provided UKI as a Portable Executable file and find an
/// ".osrel" section in it, return a string to use as the boootloader entry.  If we were unable to
/// find any meaningful content in the os-release information this will be "Unknown 0".
///
/// If we couldn't parse the PE file or couldn't find an ".osrel" section then an error will be
/// returned.
pub fn get_boot_label(image: &[u8]) -> Result<String, UkiError> {
    let osrel = get_text_section(image, ".osrel")?;
    OsReleaseInfo::parse(osrel)
        .get_boot_label()
        .ok_or(UkiError::NoName)
}

/// Buffered version of [`get_boot_label`].
///
/// See [`get_boot_label`] for details. This version works with any [`Read`] + [`Seek`] source.
pub fn get_boot_label_buffered<R: Read + Seek>(image: &mut R) -> Result<String, UkiError> {
    let osrel = get_text_section_buffered(image, ".osrel")?;
    OsReleaseInfo::parse(&osrel)
        .get_boot_label()
        .ok_or(UkiError::NoName)
}

/// Gets the contents of the .cmdline section of a UKI.
pub fn get_cmdline(image: &[u8]) -> Result<&str, UkiError> {
    get_text_section(image, ".cmdline")
}

/// Buffered version of [`get_cmdline`]. See [`get_cmdline`] for details.
pub fn get_cmdline_buffered<R: Read + Seek>(image: &mut R) -> Result<String, UkiError> {
    get_text_section_buffered(image, ".cmdline")
}

#[cfg(test)]
mod test {
    use core::mem::size_of;

    use similar_asserts::assert_eq;
    use zerocopy::IntoBytes;

    use super::*;

    fn data_offset(n_sections: usize) -> usize {
        size_of::<DosStub>() + size_of::<PeHeader>() + n_sections * size_of::<SectionHeader>()
    }

    fn peify(optional: &[u8], sections: &[SectionHeader], rest: &[&[u8]]) -> Vec<u8> {
        let mut output = vec![];
        output.extend_from_slice(
            DosStub {
                pe_offset: U32::new(size_of::<DosStub>() as u32),
                ..Default::default()
            }
            .as_bytes(),
        );
        output.extend_from_slice(
            PeHeader {
                pe_magic: PE_MAGIC,
                coff_file_header: CoffFileHeader {
                    number_of_sections: U16::new(sections.len() as u16),
                    size_of_optional_header: U16::new(optional.len() as u16),
                    ..Default::default()
                },
            }
            .as_bytes(),
        );
        output.extend_from_slice(optional);
        for section in sections {
            output.extend_from_slice(section.as_bytes());
        }
        assert_eq!(output.len(), data_offset(sections.len()));
        for data in rest {
            output.extend_from_slice(data);
        }

        output
    }

    fn ukify(osrel: &[u8]) -> Vec<u8> {
        let osrel_offset = data_offset(1);
        peify(
            b"",
            &[SectionHeader {
                name: *b".osrel\0\0",
                virtual_size: U32::new(osrel.len() as u32),
                pointer_to_raw_data: U32::new(osrel_offset as u32),
                ..Default::default()
            }],
            &[osrel],
        )
    }

    #[test]
    fn test_simple() {
        let uki = ukify(
            br#"
PRETTY_NAME='prettyOS'
VERSION_ID="Rocky Racoon"
VERSION=42
ID=pretty-os
"#,
        );

        assert_eq!(
            get_boot_label(uki.as_ref()).unwrap(),
            "prettyOS Rocky Racoon"
        );
    }

    #[test]
    fn test_bad_pe() {
        fn pe_err(img: &[u8]) {
            assert!(matches!(
                get_boot_label(img),
                Err(UkiError::PortableExecutableError)
            ));
        }
        fn no_sec(img: &[u8]) {
            assert!(matches!(
                get_boot_label(img),
                Err(UkiError::MissingSection(s)) if s == ".osrel"
            ));
        }

        pe_err(b"");
        pe_err(b"This is definitely not an EFI executable, but it's big enough to pass the first step...");

        pe_err(
            DosStub {
                pe_offset: U32::new(0),
                ..Default::default()
            }
            .as_bytes(),
        );

        // no section headers
        no_sec(&peify(b"", &[], &[]));
        // no .osrel section
        no_sec(&peify(
            b"",
            &[
                SectionHeader {
                    name: *b".text\0\0\0",
                    ..Default::default()
                },
                SectionHeader {
                    name: *b".rodata\0",
                    ..Default::default()
                },
            ],
            &[],
        ));

        // .osrel points to invalid offset
        pe_err(&peify(
            b"",
            &[SectionHeader {
                name: *b".osrel\0\0",
                pointer_to_raw_data: U32::new(1234567),
                ..Default::default()
            }],
            &[],
        ));
    }
}
