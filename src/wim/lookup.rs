//! The lookup table: the list of streams and the resources that hold them.
//!
//! Each entry has 50 bytes: a resource header, a part number, a reference count and the
//! SHA-1 hash of the stream. An entry with the solid flag is one of these:
//!
//! - A solid resource, with the uncompressed size `0x1_0000_0000`. Its true uncompressed size
//!   is in the header at the start of the resource.
//! - A stream in a solid resource. Its size in the file is the uncompressed size of the
//!   stream, and its offset is an offset in the uncompressed data of all solid resources, one
//!   after the other in the order of the lookup table.
//!
//! A stream entry can come before the entry of its solid resource. Real ESD files with three
//! solid resources have one sequence of stream offsets through all three resources.

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
    /// A range in the uncompressed data of all solid resources.
    Solid {
        /// The offset in the uncompressed data of all solid resources.
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
    /// The solid resources, in the order of the lookup table.
    pub(crate) solid_resources: Vec<ResourceHeader>,
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
                table.solid_resources.push(header);
                continue;
            }
            if header.has(RESOURCE_METADATA) {
                if solid {
                    return Err(context(Error::unsupported("a solid metadata resource")));
                }
                table.metadata.push(header);
                continue;
            }
            let stream = if solid {
                Stream {
                    size: header.size_in_wim,
                    location: Location::Solid {
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
        let solid_stream = table
            .streams
            .values()
            .any(|stream| matches!(stream.location, Location::Solid { .. }));
        if solid_stream && table.solid_resources.is_empty() {
            return Err(Error::invalid_data("a solid stream, but no solid resource")
                .in_structure("lookup table"));
        }
        Ok(table)
    }
}
