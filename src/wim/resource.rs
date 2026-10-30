//! Read the uncompressed bytes of resources.
//!
//! A compressed resource is a sequence of chunks. Each chunk has a fixed uncompressed size,
//! but the last chunk can be shorter. A chunk with a compressed size equal to its uncompressed
//! size is stored data. The reader reads only the chunks of the requested range.
//!
//! - A resource that is not solid starts with a chunk table. It has one entry for each chunk
//!   after the first: the offset of the chunk after the table. An entry has 8 bytes if the
//!   uncompressed size is more than 4 GiB, else 4 bytes.
//! - A solid resource starts with a 16-byte header: the uncompressed size (`u64`), the chunk
//!   size (`u32`) and the compression format (`u32`, 3 is LZMS). Then it has one `u32` for each
//!   chunk: the compressed size of the chunk.

use super::header::{Compression, Header, RESOURCE_COMPRESSED, ResourceHeader, u32_at, u64_at};
use super::lookup::Location;
use crate::error::{Error, Result};
use crate::read_at::ReadAt;
use std::sync::{Mutex, PoisonError};

/// The largest chunk size that the reader accepts (64 MiB).
const MAX_CHUNK_SIZE: u64 = 1 << 26;

/// The largest compressed read for a sequence of chunks (32 MiB).
const MAX_BATCH: u64 = 1 << 25;

/// A solid resource, with its chunk offsets.
#[derive(Debug)]
struct SolidResource {
    /// The file offset of the first chunk.
    data_start: u64,
    /// The uncompressed size.
    size: u64,
    chunk_size: u64,
    compression: Compression,
    /// The offset of each chunk after `data_start`, and the end of the last chunk.
    chunk_offsets: Vec<u64>,
}

/// All solid resources of a file. Stream offsets go through all of them, one after the other.
#[derive(Debug, Default)]
struct SolidResources {
    resources: Vec<SolidResource>,
    /// The start of each resource in the uncompressed data of all solid resources, and the
    /// end of the last one.
    starts: Vec<u64>,
}

/// The chunk offsets of a resource.
enum Offsets<'a> {
    /// All offsets, and the end of the last chunk.
    Known(&'a [u64]),
    /// A chunk table in the file, for a resource that is not solid.
    Table {
        /// The file offset of the chunk table.
        start: u64,
        /// The size of an entry, 4 or 8 bytes.
        entry_size: u64,
        /// The number of chunks.
        chunks: u64,
        /// The end of the last chunk, after the chunk table.
        end: u64,
    },
}

/// The layout of a compressed resource.
struct Layout<'a> {
    /// The file offset of the first chunk.
    data_start: u64,
    size: u64,
    chunk_size: u64,
    compression: Compression,
    offsets: Offsets<'a>,
}

/// The last chunk that the reader decompressed for a partial read.
struct Cache {
    decoder: lzms::Decoder,
    /// The file offset of the first chunk of the resource, and the index of the chunk in
    /// `data`.
    key: Option<(u64, u64)>,
    data: Vec<u8>,
}

/// The reader of resources in a WIM file.
pub(crate) struct Store<R> {
    reader: R,
    compression: Compression,
    chunk_size: u32,
    solid: SolidResources,
    cache: Mutex<Cache>,
}

impl<R: ReadAt> Store<R> {
    /// Make a store for the resources of a WIM file.
    pub(crate) fn new(reader: R, header: &Header) -> Self {
        Self {
            reader,
            compression: header.compression,
            chunk_size: header.chunk_size,
            solid: SolidResources::default(),
            cache: Mutex::new(Cache {
                decoder: lzms::Decoder::new(),
                key: None,
                data: Vec::new(),
            }),
        }
    }

    /// Read the headers and the chunk sizes of the solid resources.
    pub(crate) fn load_solid_resources(&mut self, headers: &[ResourceHeader]) -> Result<()> {
        let mut resources = Vec::with_capacity(headers.len());
        let mut starts = vec![0];
        let mut total = 0u64;
        for header in headers {
            let solid = self.solid_resource(header)?;
            total = total
                .checked_add(solid.size)
                .ok_or_else(|| Error::invalid_data("the solid resources are too large"))?;
            starts.push(total);
            resources.push(solid);
        }
        self.solid = SolidResources { resources, starts };
        Ok(())
    }

    /// Return the reader of the WIM file.
    pub(crate) fn reader(&self) -> &R {
        &self.reader
    }

    /// Read the header and the chunk sizes of one solid resource.
    fn solid_resource(&self, resource: &ResourceHeader) -> Result<SolidResource> {
        let context = |e: Error| e.in_structure("solid resource").at_offset(resource.offset);
        let mut head = [0; 16];
        if resource.offset.checked_add(resource.size_in_wim).is_none() {
            return Err(context(Error::invalid_data(
                "the resource goes past the end of the file",
            )));
        }
        if resource.size_in_wim < 16 {
            return Err(context(Error::unexpected_end()));
        }
        self.reader.read_exact_at(resource.offset, &mut head)?;
        let size = u64_at(&head, 0);
        let chunk_size = u64::from(u32_at(&head, 8));
        let compression = Compression::from_solid_format(u32_at(&head, 12)).map_err(context)?;
        if !(1..=MAX_CHUNK_SIZE).contains(&chunk_size) {
            return Err(context(Error::unsupported(format!(
                "chunk size {chunk_size}"
            ))));
        }
        let chunks = size.div_ceil(chunk_size);
        let table_len = chunks
            .checked_mul(4)
            .filter(|&len| len <= resource.size_in_wim - 16)
            .ok_or_else(|| context(Error::invalid_data("the chunk table is too large")))?;
        let mut table = vec![0; to_usize(table_len)?];
        self.reader
            .read_exact_at(resource.offset + 16, &mut table)?;
        let mut chunk_offsets = Vec::with_capacity(table.len() / 4 + 1);
        let mut end = 0u64;
        chunk_offsets.push(end);
        let (entries, _) = table.as_chunks::<4>();
        for &entry in entries {
            end += u64::from(u32::from_le_bytes(entry));
            chunk_offsets.push(end);
        }
        if end > resource.size_in_wim - 16 - table_len {
            return Err(context(Error::invalid_data(
                "the chunks go past the resource",
            )));
        }
        Ok(SolidResource {
            data_start: resource.offset + 16 + table_len,
            size,
            chunk_size,
            compression,
            chunk_offsets,
        })
    }

    /// Read `buf.len()` uncompressed bytes at `offset` of a stream location.
    pub(crate) fn read_location(
        &self,
        location: &Location,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<()> {
        match location {
            Location::Resource(resource) => self.read_resource(resource, offset, buf),
            Location::Solid { offset: base } => {
                let at = base
                    .checked_add(offset)
                    .ok_or_else(|| Error::invalid_data("the stream offset is too large"))?;
                self.read_solid(at, buf)
            }
        }
    }

    /// Read `buf.len()` uncompressed bytes at `offset` of a resource that is not solid.
    pub(crate) fn read_resource(
        &self,
        resource: &ResourceHeader,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<()> {
        let end = offset.checked_add(buf.len() as u64);
        if end.is_none_or(|end| end > resource.original_size) {
            return Err(Error::unexpected_end().in_structure("resource"));
        }
        if !resource.has(RESOURCE_COMPRESSED) {
            if resource.size_in_wim != resource.original_size {
                return Err(
                    Error::invalid_data("an uncompressed resource has two sizes")
                        .at_offset(resource.offset),
                );
            }
            let at = resource
                .offset
                .checked_add(offset)
                .ok_or_else(Error::unexpected_end)?;
            self.reader.read_exact_at(at, buf)?;
            return Ok(());
        }
        if resource.offset.checked_add(resource.size_in_wim).is_none() {
            return Err(Error::invalid_data(
                "the resource goes past the end of the file",
            ));
        }
        let size = resource.original_size;
        let chunk_size = u64::from(self.chunk_size);
        let chunks = size.div_ceil(chunk_size.max(1));
        let entry_size = if size > u64::from(u32::MAX) { 8 } else { 4 };
        let table_len = chunks.saturating_sub(1).saturating_mul(entry_size);
        let Some(end) = resource.size_in_wim.checked_sub(table_len) else {
            return Err(
                Error::invalid_data("the chunk table is larger than the resource")
                    .at_offset(resource.offset),
            );
        };
        let layout = Layout {
            data_start: resource.offset + table_len,
            size,
            chunk_size,
            compression: self.compression,
            offsets: Offsets::Table {
                start: resource.offset,
                entry_size,
                chunks,
                end,
            },
        };
        self.read_chunks(&layout, offset, buf)
    }

    /// Read `buf.len()` uncompressed bytes at `offset` of the solid resources.
    fn read_solid(&self, mut offset: u64, mut buf: &mut [u8]) -> Result<()> {
        let solid = &self.solid;
        while !buf.is_empty() {
            // The resource that has `offset`: the last one that starts at or before it.
            let index = solid.starts.partition_point(|&start| start <= offset);
            let Some(resource) = index.checked_sub(1).and_then(|i| solid.resources.get(i)) else {
                return Err(Error::unexpected_end().in_structure("solid resource"));
            };
            let inner = offset - solid.starts[index - 1];
            let count = buf
                .len()
                .min(to_usize(resource.size - inner).unwrap_or(usize::MAX));
            let (part, rest) = buf.split_at_mut(count);
            let layout = Layout {
                data_start: resource.data_start,
                size: resource.size,
                chunk_size: resource.chunk_size,
                compression: resource.compression,
                offsets: Offsets::Known(&resource.chunk_offsets),
            };
            self.read_chunks(&layout, inner, part)?;
            offset += count as u64;
            buf = rest;
        }
        Ok(())
    }

    /// Return the chunk bounds for the chunks `first..=last`: `last - first + 2` offsets.
    fn chunk_bounds(&self, layout: &Layout<'_>, first: u64, last: u64) -> Result<Vec<u64>> {
        let bounds = match &layout.offsets {
            Offsets::Known(offsets) => {
                let range = to_usize(first)?..=to_usize(last + 1)?;
                offsets
                    .get(range)
                    .ok_or_else(|| Error::invalid_data("no chunk offset"))?
                    .to_vec()
            }
            Offsets::Table {
                start,
                entry_size,
                chunks,
                end,
            } => {
                // Entry `i - 1` is the start of chunk `i`. Chunk 0 starts at 0.
                let from = first.max(1);
                let to = (last + 1).min(chunks - 1);
                let mut bounds = Vec::with_capacity(to_usize(last - first + 2)?);
                if first == 0 {
                    bounds.push(0);
                }
                if from <= to {
                    let mut table = vec![0; to_usize((to - from + 1) * entry_size)?];
                    self.reader
                        .read_exact_at(start + (from - 1) * entry_size, &mut table)?;
                    for entry in table.chunks_exact(to_usize(*entry_size)?) {
                        bounds.push(if *entry_size == 8 {
                            u64_at(entry, 0)
                        } else {
                            u64::from(u32_at(entry, 0))
                        });
                    }
                }
                if last + 1 == *chunks {
                    bounds.push(*end);
                }
                bounds
            }
        };
        let limit = match &layout.offsets {
            Offsets::Known(offsets) => offsets.last().copied().unwrap_or_default(),
            Offsets::Table { end, .. } => *end,
        };
        if bounds.windows(2).any(|pair| pair[0] > pair[1])
            || bounds.iter().any(|&bound| bound > limit)
        {
            return Err(Error::invalid_data("the chunk offsets are not in order"));
        }
        // A compressed chunk is never larger than its uncompressed data.
        for (index, pair) in bounds.windows(2).enumerate() {
            let chunk_start = (first + index as u64) * layout.chunk_size;
            if pair[1] - pair[0] > layout.chunk_size.min(layout.size - chunk_start) {
                return Err(
                    Error::invalid_data("a compressed chunk is larger than its data")
                        .at_offset(layout.data_start + pair[0]),
                );
            }
        }
        Ok(bounds)
    }

    /// Read uncompressed bytes from the chunks of a compressed resource.
    fn read_chunks(&self, layout: &Layout<'_>, offset: u64, buf: &mut [u8]) -> Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        match layout.compression {
            Compression::Lzms => {}
            Compression::None => {
                return Err(Error::invalid_data(
                    "a compressed resource in a WIM without compression",
                ));
            }
            other => return Err(Error::unsupported(format!("{other:?} compression"))),
        }
        let end = offset + buf.len() as u64;
        if end > layout.size {
            return Err(Error::unexpected_end().in_structure("resource"));
        }
        let first = offset / layout.chunk_size;
        let last = (end - 1) / layout.chunk_size;
        let bounds = self.chunk_bounds(layout, first, last)?;
        let mut cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        let count = bounds.len() - 1;
        let mut start = 0;
        while start < count {
            if cache.copy_cached(layout, first + start as u64, offset, buf)? {
                start += 1;
                continue;
            }
            // Read the compressed data of as many chunks as fit in one batch. Stop before a
            // chunk that the cache has.
            let mut end = start + 1;
            while end < count
                && bounds[end + 1] - bounds[start] <= MAX_BATCH
                && !cache.holds(layout, first + end as u64)
            {
                end += 1;
            }
            let mut data = vec![0; to_usize(bounds[end] - bounds[start])?];
            self.reader
                .read_exact_at(layout.data_start + bounds[start], &mut data)?;
            for index in start..end {
                let chunk = first + index as u64;
                let compressed = &data[to_usize(bounds[index] - bounds[start])?
                    ..to_usize(bounds[index + 1] - bounds[start])?];
                cache.copy_chunk(layout, chunk, compressed, offset, buf)?;
            }
            start = end;
        }
        Ok(())
    }
}

/// The part of a chunk in a range of `len` bytes at `offset`.
struct Part {
    /// The uncompressed size of the chunk.
    chunk_len: usize,
    /// The range in the chunk.
    from: usize,
    to: usize,
    /// The position of the part in the range.
    at: usize,
}

impl Part {
    fn new(layout: &Layout<'_>, chunk: u64, offset: u64, len: usize) -> Result<Self> {
        let chunk_start = chunk * layout.chunk_size;
        let chunk_len = to_usize(layout.chunk_size.min(layout.size - chunk_start))?;
        let from = to_usize(offset.saturating_sub(chunk_start))?;
        let to = to_usize((offset + len as u64 - chunk_start).min(chunk_len as u64))?;
        let at = to_usize(chunk_start + from as u64 - offset)?;
        Ok(Self {
            chunk_len,
            from,
            to,
            at,
        })
    }
}

impl Cache {
    /// Return `true` if the cache has the chunk.
    fn holds(&self, layout: &Layout<'_>, chunk: u64) -> bool {
        self.key == Some((layout.data_start, chunk))
    }

    /// Copy the part of the chunk from the cache into `buf`, if the cache has the chunk.
    fn copy_cached(
        &self,
        layout: &Layout<'_>,
        chunk: u64,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<bool> {
        if !self.holds(layout, chunk) {
            return Ok(false);
        }
        let part = Part::new(layout, chunk, offset, buf.len())?;
        buf[part.at..part.at + (part.to - part.from)]
            .copy_from_slice(&self.data[part.from..part.to]);
        Ok(true)
    }

    /// Decompress one chunk and copy its part of the range at `offset` into `buf`.
    fn copy_chunk(
        &mut self,
        layout: &Layout<'_>,
        chunk: u64,
        compressed: &[u8],
        offset: u64,
        buf: &mut [u8],
    ) -> Result<()> {
        let part = Part::new(layout, chunk, offset, buf.len())?;
        let target = &mut buf[part.at..part.at + (part.to - part.from)];
        if part.from == 0 && part.to == part.chunk_len {
            return decompress(&mut self.decoder, compressed, target);
        }
        self.key = None;
        self.data.resize(part.chunk_len, 0);
        decompress(&mut self.decoder, compressed, &mut self.data)?;
        self.key = Some((layout.data_start, chunk));
        target.copy_from_slice(&self.data[part.from..part.to]);
        Ok(())
    }
}

/// Decompress one LZMS chunk, or copy a stored chunk.
fn decompress(decoder: &mut lzms::Decoder, compressed: &[u8], output: &mut [u8]) -> Result<()> {
    if compressed.len() == output.len() {
        output.copy_from_slice(compressed);
        return Ok(());
    }
    decoder.decompress_into(compressed, output)?;
    Ok(())
}

/// Convert a size to `usize`, or return a `LimitExceeded` error.
pub(crate) fn to_usize(value: u64) -> Result<usize> {
    usize::try_from(value).map_err(|_| Error::limit_exceeded(value, usize::MAX as u64))
}
