//! The metadata resource of an image: the security data and the directory tree.
//!
//! The security data starts with its total length (`u32`). The root directory entry starts at
//! that length, aligned to 8 bytes. Each directory entry (dentry) has these fields:
//!
//! | Offset | Size | Field |
//! | --- | --- | --- |
//! | 0 | 8 | Length of the entry, without its stream entries |
//! | 8 | 4 | File attributes |
//! | 16 | 8 | Offset of the first child, for a directory |
//! | 64 | 20 | SHA-1 hash of the unnamed data stream (zero for no data) |
//! | 96 | 2 | Number of stream entries after the entry |
//! | 98 | 2 | Size of the short name, in bytes |
//! | 100 | 2 | Size of the file name, in bytes |
//! | 102 | n | File name (UTF-16LE) |
//!
//! Each stream entry has its length (`u64`), 8 reserved bytes, the SHA-1 hash, the name size
//! (`u16`) and the name. All entries start at a multiple of 8 bytes. A child list ends with a
//! length of zero.

use super::header::{u16_at, u32_at, u64_at, utf16_units};
use crate::error::{Error, Result};
use std::collections::HashSet;

/// The attribute of a directory.
pub(crate) const ATTRIBUTE_DIRECTORY: u32 = 0x10;

/// The attribute of a reparse point.
const ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

/// The smallest directory entry, in bytes.
const DENTRY_SIZE: u64 = 102;

/// The smallest stream entry, in bytes.
const STREAM_ENTRY_SIZE: u64 = 38;

/// The largest directory depth that the parser accepts.
const MAX_DEPTH: usize = 512;

/// A file or directory in an image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WimFile {
    /// The path from the image root, with `\` between the names.
    pub path: String,
    /// The Windows file attributes.
    pub attributes: u32,
    /// The size of the unnamed data stream, in bytes.
    pub size: u64,
    /// The SHA-1 hash of the unnamed data stream, or `None` for a file with no data.
    pub sha1: Option<[u8; 20]>,
}

impl WimFile {
    /// Return `true` if the entry is a directory.
    #[must_use]
    pub fn is_directory(&self) -> bool {
        self.attributes & ATTRIBUTE_DIRECTORY != 0
    }
}

/// A directory entry before the lookup of its stream size.
pub(crate) struct Entry {
    pub(crate) path: String,
    pub(crate) attributes: u32,
    pub(crate) sha1: Option<[u8; 20]>,
}

/// Parse the metadata resource of an image. Return the entries in tree order, without the
/// root directory.
pub(crate) fn parse(data: &[u8]) -> Result<Vec<Entry>> {
    if data.len() < 8 {
        return Err(Error::unexpected_end().in_structure("security data"));
    }
    let security_len = u64::from(u32_at(data, 0));
    let root = align8(security_len.max(8));
    let mut parser = Parser {
        data,
        entries: Vec::new(),
        visited: HashSet::new(),
    };
    let entry = parser.dentry(root)?;
    let Some(entry) = entry else {
        return Err(Error::invalid_data("the image has no root directory").at_offset(root));
    };
    if entry.attributes & ATTRIBUTE_DIRECTORY == 0 {
        return Err(Error::invalid_data("the root is not a directory").at_offset(root));
    }
    if entry.subdir != 0 {
        parser.children(entry.subdir, "", 1)?;
    }
    Ok(parser.entries)
}

/// Round up to a multiple of 8.
fn align8(value: u64) -> u64 {
    value.div_ceil(8).saturating_mul(8)
}

/// A parsed directory entry.
struct Dentry {
    name: String,
    attributes: u32,
    subdir: u64,
    sha1: Option<[u8; 20]>,
    /// The offset of the next entry in the same directory.
    next: u64,
}

struct Parser<'a> {
    data: &'a [u8],
    entries: Vec<Entry>,
    /// The child lists that the parser read, to find loops.
    visited: HashSet<u64>,
}

impl Parser<'_> {
    /// Return `len` bytes at `offset`.
    fn bytes(&self, offset: u64, len: u64) -> Result<&[u8]> {
        let end = offset.checked_add(len);
        let range = usize::try_from(offset)
            .ok()
            .zip(end.and_then(|end| usize::try_from(end).ok()));
        range
            .and_then(|(start, end)| self.data.get(start..end))
            .ok_or_else(|| {
                Error::unexpected_end()
                    .in_structure("dentry")
                    .at_offset(offset)
            })
    }

    /// Read the entries of the child list at `offset`.
    fn children(&mut self, mut offset: u64, parent: &str, depth: usize) -> Result<()> {
        if depth > MAX_DEPTH {
            return Err(Error::invalid_data("the directory tree is too deep").at_offset(offset));
        }
        if !self.visited.insert(offset) {
            return Err(Error::invalid_data("the directory tree has a loop").at_offset(offset));
        }
        while let Some(entry) = self.dentry(offset)? {
            if entry.name.is_empty() {
                return Err(Error::invalid_data("a dentry has no name").at_offset(offset));
            }
            let path = if parent.is_empty() {
                entry.name
            } else {
                format!("{parent}\\{}", entry.name)
            };
            let directory = entry.attributes & ATTRIBUTE_DIRECTORY != 0;
            self.entries.push(Entry {
                path: path.clone(),
                attributes: entry.attributes,
                sha1: entry.sha1,
            });
            if directory && entry.subdir != 0 {
                self.children(entry.subdir, &path, depth + 1)?;
            }
            offset = entry.next;
        }
        Ok(())
    }

    /// Read the entry at `offset`, or return `None` at the end of a child list.
    fn dentry(&self, offset: u64) -> Result<Option<Dentry>> {
        let length = u64_at(self.bytes(offset, 8)?, 0);
        if length == 0 {
            return Ok(None);
        }
        if length < DENTRY_SIZE {
            return Err(Error::invalid_data(format!("dentry length {length}")).at_offset(offset));
        }
        let bytes = self.bytes(offset, length)?;
        let attributes = u32_at(bytes, 8);
        let subdir = u64_at(bytes, 16);
        let streams = u16_at(bytes, 96);
        let short_name = u64::from(u16_at(bytes, 98));
        let name_len = u16_at(bytes, 100);
        if !name_len.is_multiple_of(2) || DENTRY_SIZE + u64::from(name_len) + short_name > length {
            return Err(Error::invalid_data("the dentry names are too long").at_offset(offset));
        }
        let name_end = 102 + usize::from(name_len);
        let name = String::from_utf16_lossy(&utf16_units(&bytes[102..name_end]));
        let mut sha1 = nonzero_hash(&bytes[64..84]);
        // The stream entries follow the dentry. An unnamed one has the data of a reparse
        // point, or the data when the dentry has no hash.
        let mut next = offset
            .checked_add(align8(length))
            .ok_or_else(Error::unexpected_end)?;
        let reparse = attributes & ATTRIBUTE_REPARSE_POINT != 0;
        if reparse {
            sha1 = None;
        }
        for _ in 0..streams {
            let head = self.bytes(next, STREAM_ENTRY_SIZE)?;
            let entry_len = u64_at(head, 0);
            if entry_len < STREAM_ENTRY_SIZE {
                return Err(Error::invalid_data("stream entry length").at_offset(next));
            }
            let named = u16_at(head, 36) != 0;
            if !named && (reparse || sha1.is_none()) {
                sha1 = nonzero_hash(&head[16..36]);
            }
            next = next
                .checked_add(align8(entry_len))
                .ok_or_else(Error::unexpected_end)?;
        }
        Ok(Some(Dentry {
            name,
            attributes,
            subdir,
            sha1,
            next,
        }))
    }
}

/// Return the hash, or `None` if all its bytes are zero.
fn nonzero_hash(bytes: &[u8]) -> Option<[u8; 20]> {
    let mut hash = [0; 20];
    hash.copy_from_slice(bytes);
    hash.iter().any(|&b| b != 0).then_some(hash)
}
