//! The WIM file header and the resource headers.

use crate::error::{Error, ErrorKind, Result};

/// The size of the WIM header, in bytes.
pub(crate) const HEADER_SIZE: usize = 0xD0;

/// The signature of a WIM file.
const SIGNATURE: [u8; 8] = *b"MSWIM\0\0\0";

/// The signature of a pipable WIM file.
const PIPABLE_SIGNATURE: [u8; 8] = *b"WLPWM\0\0\0";

/// The header flag for compressed resources.
const FLAG_COMPRESSION: u32 = 0x2;
/// The header flag for XPRESS compression.
const FLAG_XPRESS: u32 = 0x2_0000;
/// The header flag for LZX compression.
const FLAG_LZX: u32 = 0x4_0000;
/// The header flag for LZMS compression.
const FLAG_LZMS: u32 = 0x8_0000;

/// The resource flag for a metadata resource.
pub(crate) const RESOURCE_METADATA: u8 = 0x02;
/// The resource flag for a compressed resource.
pub(crate) const RESOURCE_COMPRESSED: u8 = 0x04;
/// The resource flag for a resource that spans parts of a split WIM.
pub(crate) const RESOURCE_SPANNED: u8 = 0x08;
/// The resource flag for a solid resource, or a stream in a solid resource.
pub(crate) const RESOURCE_SOLID: u8 = 0x10;

/// The compression format of the resources.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    /// No compression.
    None,
    /// XPRESS (not supported).
    Xpress,
    /// LZX (not supported).
    Lzx,
    /// LZMS.
    Lzms,
}

impl Compression {
    /// Return the compression of a solid resource from its format number.
    pub(crate) fn from_solid_format(format: u32) -> Result<Self> {
        match format {
            1 => Ok(Self::Xpress),
            2 => Ok(Self::Lzx),
            3 => Ok(Self::Lzms),
            _ => Err(Error::unsupported(format!(
                "solid resource compression format {format}"
            ))),
        }
    }
}

/// The location and size of a resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ResourceHeader {
    /// The size of the resource in the file, in bytes.
    pub(crate) size_in_wim: u64,
    /// The resource flags.
    pub(crate) flags: u8,
    /// The offset of the resource in the file.
    pub(crate) offset: u64,
    /// The uncompressed size of the resource, in bytes.
    pub(crate) original_size: u64,
}

impl ResourceHeader {
    /// Parse a resource header. `bytes` has at least 24 bytes.
    pub(crate) fn parse(bytes: &[u8]) -> Self {
        let mut size = [0; 8];
        size[..7].copy_from_slice(&bytes[..7]);
        Self {
            size_in_wim: u64::from_le_bytes(size),
            flags: bytes[7],
            offset: u64_at(bytes, 8),
            original_size: u64_at(bytes, 16),
        }
    }

    /// Return `true` if the resource has the flag.
    pub(crate) fn has(&self, flag: u8) -> bool {
        self.flags & flag != 0
    }
}

/// The fields of the WIM header that the reader uses.
#[derive(Debug, Clone)]
pub(crate) struct Header {
    /// The compression format of the resources that are not solid.
    pub(crate) compression: Compression,
    /// The uncompressed size of each chunk of a compressed resource that is not solid.
    pub(crate) chunk_size: u32,
    /// The number of images.
    pub(crate) image_count: u32,
    /// The lookup table resource.
    pub(crate) lookup_table: ResourceHeader,
    /// The XML data resource.
    pub(crate) xml: ResourceHeader,
}

impl Header {
    /// Parse the 208-byte header.
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_SIZE {
            return Err(Error::unexpected_end().in_structure("WIM header"));
        }
        if bytes[..8] == PIPABLE_SIGNATURE {
            return Err(Error::unsupported("pipable WIM file"));
        }
        if bytes[..8] != SIGNATURE {
            return Err(ErrorKind::InvalidSignature(bytes[..8].to_vec()).into());
        }
        let header_size = u32_at(bytes, 8);
        if header_size as usize != HEADER_SIZE {
            return Err(Error::unsupported(format!(
                "WIM header size {header_size:#x}"
            )));
        }
        let version = u32_at(bytes, 12);
        if version != 0x10D00 && version != 0xE00 {
            return Err(Error::unsupported(format!("WIM version {version:#x}")));
        }
        let flags = u32_at(bytes, 16);
        let chunk_size = u32_at(bytes, 20);
        let part = u16_at(bytes, 40);
        let total_parts = u16_at(bytes, 42);
        if part != 1 || total_parts != 1 {
            return Err(Error::unsupported(format!(
                "split WIM file (part {part} of {total_parts})"
            )));
        }
        let compression = Self::compression(flags)?;
        if compression != Compression::None && !(1..=1 << 26).contains(&chunk_size) {
            return Err(Error::unsupported(format!("WIM chunk size {chunk_size}")));
        }
        Ok(Self {
            compression,
            chunk_size,
            image_count: u32_at(bytes, 44),
            lookup_table: ResourceHeader::parse(&bytes[48..72]),
            xml: ResourceHeader::parse(&bytes[72..96]),
        })
    }

    /// Return the compression format from the header flags.
    fn compression(flags: u32) -> Result<Compression> {
        if flags & FLAG_COMPRESSION == 0 {
            return Ok(Compression::None);
        }
        match flags & (FLAG_XPRESS | FLAG_LZX | FLAG_LZMS) {
            FLAG_XPRESS => Ok(Compression::Xpress),
            FLAG_LZX => Ok(Compression::Lzx),
            FLAG_LZMS => Ok(Compression::Lzms),
            _ => Err(Error::unsupported(format!("WIM header flags {flags:#x}"))),
        }
    }
}

/// Return the UTF-16LE code units of `bytes`. A last odd byte is not used.
pub(crate) fn utf16_units(bytes: &[u8]) -> Vec<u16> {
    let (pairs, _) = bytes.as_chunks::<2>();
    pairs.iter().map(|&pair| u16::from_le_bytes(pair)).collect()
}

/// Read a little-endian `u16` at `offset`. The caller checks the length.
pub(crate) fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

/// Read a little-endian `u32` at `offset`. The caller checks the length.
pub(crate) fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    let mut value = [0; 4];
    value.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_le_bytes(value)
}

/// Read a little-endian `u64` at `offset`. The caller checks the length.
pub(crate) fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    let mut value = [0; 8];
    value.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(value)
}
