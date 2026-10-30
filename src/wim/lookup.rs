//! The lookup table: the list of streams and the resources that hold them.
//!
//! Each entry has 50 bytes: a resource header, a part number, a reference count and the
//! SHA-1 hash of the stream. An entry with the solid flag is one of these:
//!
//! - A solid resource, with the uncompressed size `0x1_0000_0000`. Its true uncompressed size
//!   is in the header at the start of the resource.
//! - A stream in the solid resources before it. Its size in the file is the uncompressed size
//!   of the stream, and its offset is the offset in the uncompressed data.
//!
//! The solid resources in a row make a group. The offsets of the streams after a group are
//! offsets in the uncompressed data of all resources of the group, one after the other.

use super::header::{RESOURCE_METADATA, RESOURCE_SOLID, RESOURCE_SPANNED, ResourceHeader, u16_at};
use crate::error::{Error, Result};
use std::collections::HashMap;

/// The size of a lookup table entry, in bytes.
pub(crate) const ENTRY_SIZE: usize = 50;

/// The uncompressed size in the lookup table entry of a solid resource.
const SOLID_RESOURCE_MAGIC: u64 = 0x1_0000_0000;

/// The location of the bytes of a stream.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Location {
    /// A whole resource that is not solid.
    Resource(ResourceHeader),
    /// A range in the uncompressed data of a group of solid resources.
    Solid {
        /// The index of the group.
        group: usize,
        /// The offset in the uncompressed data of the group.
        offset: u64,
    },
}

/// A stream in the lookup table.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Stream {
    /// The uncompressed size, in bytes.
    pub(crate) size: u64,
    /// The location of the bytes.
    pub(crate) location: Location,
}

/// The parsed lookup table.
#[derive(Debug, Default)]
pub(crate) struct LookupTable {
    /// The streams by SHA-1 hash.
    pub(crate) streams: HashMap<[u8; 20], Stream>,
    /// The metadata resources, one for each image in order.
    pub(crate) metadata: Vec<ResourceHeader>,
    /// The groups of solid resources.
    pub(crate) solid_groups: Vec<Vec<ResourceHeader>>,
}

impl LookupTable {
    /// Parse the uncompressed lookup table.
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
        if !bytes.len().is_multiple_of(ENTRY_SIZE) {
            return Err(Error::invalid_data(format!(
                "the lookup table size {} is not a multiple of {ENTRY_SIZE}",
                bytes.len()
            )));
        }
        let mut table = Self::default();
        let mut after_resource = false;
        let (entries, _) = bytes.as_chunks::<ENTRY_SIZE>();
        for (index, entry) in entries.iter().enumerate() {
            let context = |e: Error| {
                e.in_structure("lookup table")
                    .at_offset((index * ENTRY_SIZE) as u64)
            };
            let header = ResourceHeader::parse(&entry[..24]);
            let part = u16_at(entry, 24);
            let mut hash = [0; 20];
            hash.copy_from_slice(&entry[30..50]);
            if part != 1 {
                return Err(context(Error::invalid_data(format!("part number {part}"))));
            }
            if header.has(RESOURCE_SPANNED) {
                return Err(context(Error::unsupported(
                    "a resource in more than one part",
                )));
            }
            let solid = header.has(RESOURCE_SOLID);
            if solid && header.original_size == SOLID_RESOURCE_MAGIC {
                if !after_resource {
                    table.solid_groups.push(Vec::new());
                }
                if let Some(group) = table.solid_groups.last_mut() {
                    group.push(header);
                }
                after_resource = true;
                continue;
            }
            after_resource = false;
            if header.has(RESOURCE_METADATA) {
                if solid {
                    return Err(context(Error::unsupported("a solid metadata resource")));
                }
                table.metadata.push(header);
                continue;
            }
            let stream = if solid {
                let Some(group) = table.solid_groups.len().checked_sub(1) else {
                    return Err(context(Error::invalid_data(
                        "a solid stream before the first solid resource",
                    )));
                };
                Stream {
                    size: header.size_in_wim,
                    location: Location::Solid {
                        group,
                        offset: header.offset,
                    },
                }
            } else {
                Stream {
                    size: header.original_size,
                    location: Location::Resource(header),
                }
            };
            table.streams.entry(hash).or_insert(stream);
        }
        Ok(table)
    }
}
