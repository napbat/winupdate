//! A small WIM writer for the tests.
//!
//! The writer follows the layout of the WIM files in Windows updates: the header, the
//! resources, the metadata resource, the lookup table and the XML data.

use super::data::sha1;

pub const FLAG_COMPRESSION: u32 = 0x2;
pub const FLAG_LZMS: u32 = 0x8_0000;
pub const RESOURCE_METADATA: u8 = 0x02;
pub const RESOURCE_COMPRESSED: u8 = 0x04;
pub const RESOURCE_SOLID: u8 = 0x10;
pub const ATTRIBUTE_DIRECTORY: u32 = 0x10;
pub const ATTRIBUTE_NORMAL: u32 = 0x80;

/// A file or a directory in the image.
pub struct Node {
    pub name: String,
    pub attributes: u32,
    pub hash: [u8; 20],
    pub children: Vec<Node>,
}

impl Node {
    pub fn file(name: &str, data: &[u8]) -> Self {
        Self {
            name: name.to_owned(),
            attributes: ATTRIBUTE_NORMAL,
            hash: if data.is_empty() { [0; 20] } else { sha1(data) },
            children: Vec::new(),
        }
    }

    pub fn directory(name: &str, children: Vec<Node>) -> Self {
        Self {
            name: name.to_owned(),
            attributes: ATTRIBUTE_DIRECTORY,
            hash: [0; 20],
            children,
        }
    }
}

/// A WIM file that the test builds.
pub struct Builder {
    pub bytes: Vec<u8>,
    pub lookup: Vec<u8>,
    pub version: u32,
    pub flags: u32,
    pub chunk_size: u32,
    pub image_count: u32,
}

/// Write a resource header: a 7-byte size, the flags, the offset and the original size.
pub fn resource_header(size: u64, flags: u8, offset: u64, original: u64) -> [u8; 24] {
    let mut out = [0; 24];
    out[..7].copy_from_slice(&size.to_le_bytes()[..7]);
    out[7] = flags;
    out[8..16].copy_from_slice(&offset.to_le_bytes());
    out[16..24].copy_from_slice(&original.to_le_bytes());
    out
}

fn align8(buf: &mut Vec<u8>) {
    while !buf.len().is_multiple_of(8) {
        buf.push(0);
    }
}

fn utf16(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

impl Builder {
    pub fn new(version: u32, flags: u32, chunk_size: u32) -> Self {
        Self {
            bytes: vec![0; 0xD0],
            lookup: Vec::new(),
            version,
            flags,
            chunk_size,
            image_count: 0,
        }
    }

    /// Add a lookup table entry.
    pub fn entry(&mut self, header: [u8; 24], hash: [u8; 20]) {
        self.lookup.extend_from_slice(&header);
        self.lookup.extend_from_slice(&1u16.to_le_bytes());
        self.lookup.extend_from_slice(&1u32.to_le_bytes());
        self.lookup.extend_from_slice(&hash);
    }

    /// Store a stream without compression.
    pub fn plain(&mut self, data: &[u8], flags: u8) -> [u8; 24] {
        let offset = self.bytes.len() as u64;
        self.bytes.extend_from_slice(data);
        let len = data.len() as u64;
        resource_header(len, flags, offset, len)
    }

    /// Store a compressed resource with a chunk table. `None` stores a chunk as it is.
    pub fn chunked(&mut self, data: &[u8], chunks: &[Option<Vec<u8>>], flags: u8) -> [u8; 24] {
        let size = self.chunk_size as usize;
        assert_eq!(chunks.len(), data.len().div_ceil(size));
        let stored: Vec<Vec<u8>> = chunks
            .iter()
            .enumerate()
            .map(|(i, chunk)| {
                chunk
                    .clone()
                    .unwrap_or_else(|| data[i * size..((i + 1) * size).min(data.len())].to_vec())
            })
            .collect();
        let offset = self.bytes.len() as u64;
        let wide = data.len() as u64 > u64::from(u32::MAX);
        let mut position = 0u64;
        for chunk in &stored[..stored.len().saturating_sub(1)] {
            position += chunk.len() as u64;
            if wide {
                self.bytes.extend_from_slice(&position.to_le_bytes());
            } else {
                self.bytes
                    .extend_from_slice(&u32::try_from(position).unwrap().to_le_bytes());
            }
        }
        for chunk in &stored {
            self.bytes.extend_from_slice(chunk);
        }
        let len = self.bytes.len() as u64 - offset;
        resource_header(len, flags | RESOURCE_COMPRESSED, offset, data.len() as u64)
    }

    /// Store a solid LZMS resource from its chunks, and add its lookup table entry.
    pub fn solid(&mut self, size: u64, chunk_size: u32, chunks: &[Vec<u8>]) {
        let offset = self.bytes.len() as u64;
        self.bytes.extend_from_slice(&size.to_le_bytes());
        self.bytes.extend_from_slice(&chunk_size.to_le_bytes());
        self.bytes.extend_from_slice(&3u32.to_le_bytes());
        for chunk in chunks {
            self.bytes
                .extend_from_slice(&u32::try_from(chunk.len()).unwrap().to_le_bytes());
        }
        for chunk in chunks {
            self.bytes.extend_from_slice(chunk);
        }
        let len = self.bytes.len() as u64 - offset;
        self.entry(
            resource_header(len, RESOURCE_SOLID, offset, 0x1_0000_0000),
            [0; 20],
        );
    }

    /// Add the lookup table entry of a stream in the last solid resource group.
    pub fn solid_stream(&mut self, offset: u64, data: &[u8]) {
        self.entry(
            resource_header(data.len() as u64, RESOURCE_SOLID, offset, 0),
            sha1(data),
        );
    }

    /// Store the metadata resource of an image. Compress it with stored chunks if
    /// `chunked` is set.
    pub fn image(&mut self, root: &[Node], chunked: bool) {
        let metadata = metadata(root);
        let header = if chunked {
            let count = metadata.len().div_ceil(self.chunk_size as usize);
            let chunks = vec![None; count];
            self.chunked(&metadata, &chunks, RESOURCE_METADATA)
        } else {
            self.plain(&metadata, RESOURCE_METADATA)
        };
        self.entry(header, sha1(&metadata));
        self.image_count += 1;
    }

    /// Write the lookup table, the XML data and the header, and return the file.
    pub fn finish(mut self) -> Vec<u8> {
        let lookup = std::mem::take(&mut self.lookup);
        let table = self.plain(&lookup, RESOURCE_METADATA);
        let mut xml = vec![0xff, 0xfe];
        xml.extend(utf16(
            "<WIM><IMAGE INDEX=\"1\"><NAME>test</NAME></IMAGE></WIM>",
        ));
        let xml = self.plain(&xml, 0);
        let mut header = Vec::with_capacity(0xD0);
        header.extend_from_slice(b"MSWIM\0\0\0");
        header.extend_from_slice(&0xD0u32.to_le_bytes());
        header.extend_from_slice(&self.version.to_le_bytes());
        header.extend_from_slice(&self.flags.to_le_bytes());
        header.extend_from_slice(&self.chunk_size.to_le_bytes());
        header.extend_from_slice(&[0x11; 16]);
        header.extend_from_slice(&1u16.to_le_bytes());
        header.extend_from_slice(&1u16.to_le_bytes());
        header.extend_from_slice(&self.image_count.to_le_bytes());
        header.extend_from_slice(&table);
        header.extend_from_slice(&xml);
        header.resize(0xD0, 0);
        self.bytes[..0xD0].copy_from_slice(&header);
        self.bytes
    }
}

/// Write one dentry, and return its offset.
fn dentry(buf: &mut Vec<u8>, node: &Node) -> usize {
    let offset = buf.len();
    let name = utf16(&node.name);
    let mut entry = vec![0u8; 102];
    entry[8..12].copy_from_slice(&node.attributes.to_le_bytes());
    entry[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
    entry[64..84].copy_from_slice(&node.hash);
    entry[100..102].copy_from_slice(&u16::try_from(name.len()).unwrap().to_le_bytes());
    entry.extend_from_slice(&name);
    if !name.is_empty() {
        entry.extend_from_slice(&[0, 0]);
    }
    align8(&mut entry);
    let length = entry.len() as u64;
    entry[..8].copy_from_slice(&length.to_le_bytes());
    buf.extend_from_slice(&entry);
    offset
}

/// Write a child list, and set the subdirectory offset of the parent at `parent`.
fn children(buf: &mut Vec<u8>, parent: usize, nodes: &[Node]) {
    let start = buf.len() as u64;
    buf[parent + 16..parent + 24].copy_from_slice(&start.to_le_bytes());
    let offsets: Vec<usize> = nodes.iter().map(|node| dentry(buf, node)).collect();
    buf.extend_from_slice(&[0; 8]);
    for (node, offset) in nodes.iter().zip(offsets) {
        if !node.children.is_empty() {
            children(buf, offset, &node.children);
        }
    }
}

/// Write a metadata resource: empty security data, the root and the tree.
pub fn metadata(root: &[Node]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&8u32.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    let root_offset = dentry(&mut buf, &Node::directory("", Vec::new()));
    buf.extend_from_slice(&[0; 8]);
    children(&mut buf, root_offset, root);
    buf
}
