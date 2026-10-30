//! WIM and ESD files.
//!
//! A WIM file has a header, resources, a lookup table and XML data. The lookup table gives the
//! location of each stream by its SHA-1 hash. Each image has a metadata resource with its
//! directory tree. [`Wim`] reads only the byte ranges that it needs from a [`ReadAt`] source:
//!
//! - [`Wim::open`] reads the header, the lookup table and the headers of the solid resources.
//! - [`Wim::image`] reads the metadata resource of one image.
//! - [`Wim::read`] and [`Wim::open_file`] read the chunks of one stream.
//!
//! The reader supports resources without compression, LZMS resources with chunk tables, and
//! LZMS solid resources (as in ESD files and in Windows 11 update packages). It returns an
//! `Unsupported` error for XPRESS and LZX resources, and for split WIM files.
//!
//! # Example
//!
//! ```no_run
//! use winupdate::Wim;
//!
//! let wim = Wim::open(std::fs::File::open("update.wim")?)?;
//! let image = wim.image(1)?;
//! for file in image.files() {
//!     println!("{} {}", file.size, file.path);
//! }
//! let index = image.find("express.psf.cix.xml").expect("no index");
//! let xml = wim.read(index)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod header;
mod lookup;
mod metadata;
mod resource;

pub use header::Compression;
pub use metadata::WimFile;

use crate::error::{Error, ErrorKind, Result};
use crate::read_at::ReadAt;
use header::{HEADER_SIZE, Header, RESOURCE_SOLID, ResourceHeader};
use lookup::{LookupTable, Stream};
use resource::{Store, to_usize};
use sha1::{Digest, Sha1};
use std::io;

/// The largest metadata resource, lookup table or XML resource that the reader reads
/// (512 MiB).
const MAX_TABLE_SIZE: u64 = 1 << 29;

/// A WIM or ESD file.
pub struct Wim<R> {
    store: Store<R>,
    header: Header,
    lookup: LookupTable,
}

impl<R: ReadAt> Wim<R> {
    /// Open a WIM file. Read the header, the lookup table and the solid resource headers.
    ///
    /// # Errors
    ///
    /// Return an error if the reader fails, if the file is not a valid WIM file, or if the
    /// file uses a feature that the crate does not support.
    pub fn open(reader: R) -> Result<Self> {
        let mut head = [0; HEADER_SIZE];
        reader.read_exact_at(0, &mut head)?;
        let header = Header::parse(&head)?;
        let mut store = Store::new(reader, &header);
        let table = read_table(&store, &header.lookup_table, "lookup table")?;
        let lookup = LookupTable::parse(&table)?;
        store.load_solid_groups(&lookup.solid_groups)?;
        if lookup.metadata.len() < header.image_count as usize {
            return Err(Error::invalid_data(format!(
                "the header has {} images, but the lookup table has {} metadata resources",
                header.image_count,
                lookup.metadata.len()
            )));
        }
        Ok(Self {
            store,
            header,
            lookup,
        })
    }

    /// Return the number of images.
    #[must_use]
    pub fn image_count(&self) -> u32 {
        self.header.image_count
    }

    /// Return the compression format of the resources that are not solid.
    #[must_use]
    pub fn compression(&self) -> Compression {
        self.header.compression
    }

    /// Return the source of the WIM file.
    #[must_use]
    pub fn reader(&self) -> &R {
        self.store.reader()
    }

    /// Read the XML data of the file.
    ///
    /// # Errors
    ///
    /// Return an error if the reader fails or if the XML data is not valid UTF-16.
    pub fn xml(&self) -> Result<String> {
        let bytes = read_table(&self.store, &self.header.xml, "XML data")?;
        if !bytes.len().is_multiple_of(2) {
            return Err(Error::invalid_data("the XML data has an odd size"));
        }
        let text = String::from_utf16(&header::utf16_units(&bytes))
            .map_err(|_| Error::invalid_data("the XML data is not valid UTF-16"))?;
        Ok(text.trim_start_matches('\u{feff}').to_owned())
    }

    /// Read the directory tree of an image. The first image has the index 1.
    ///
    /// # Errors
    ///
    /// Return an error if the image does not exist, if the reader fails, or if the metadata
    /// is not valid.
    pub fn image(&self, index: u32) -> Result<Image> {
        let resource = index
            .checked_sub(1)
            .filter(|&i| i < self.header.image_count)
            .and_then(|i| self.lookup.metadata.get(i as usize))
            .ok_or_else(|| Error::not_found(format!("image {index}")))?;
        let data = read_table(&self.store, resource, "metadata resource")?;
        let entries = metadata::parse(&data)?;
        let mut files = Vec::with_capacity(entries.len());
        for entry in entries {
            let size = match &entry.sha1 {
                None => 0,
                Some(hash) => {
                    self.lookup
                        .streams
                        .get(hash)
                        .ok_or_else(|| {
                            Error::invalid_data(
                                "a file has a stream that is not in the lookup table",
                            )
                            .with_details(entry.path.clone())
                        })?
                        .size
                }
            };
            files.push(WimFile {
                path: entry.path,
                attributes: entry.attributes,
                size,
                sha1: entry.sha1,
            });
        }
        Ok(Image { files })
    }

    /// Return the stream of a file.
    fn stream(&self, file: &WimFile) -> Result<Option<Stream>> {
        match &file.sha1 {
            None => Ok(None),
            Some(hash) => self
                .lookup
                .streams
                .get(hash)
                .copied()
                .map(Some)
                .ok_or_else(|| Error::not_found(file.path.clone())),
        }
    }

    /// Read the data of a file, and check its SHA-1 hash.
    ///
    /// # Errors
    ///
    /// Return an error if the reader fails, if the data is not valid, or if the hash of the
    /// data is not equal to the hash in the lookup table.
    pub fn read(&self, file: &WimFile) -> Result<Vec<u8>> {
        let Some(stream) = self.stream(file)? else {
            return Ok(Vec::new());
        };
        let mut data = vec![0; to_usize(stream.size)?];
        self.store.read_location(&stream.location, 0, &mut data)?;
        if Some(<[u8; 20]>::from(Sha1::digest(&data))) != file.sha1 {
            return Err(Error::new(ErrorKind::HashMismatch { algorithm: "SHA-1" })
                .with_details(file.path.clone()));
        }
        Ok(data)
    }

    /// Open the data of a file as a [`ReadAt`] source, for example to read a nested WIM or CAB
    /// file. The source reads only the chunks of each range. It does not check the hash.
    ///
    /// # Errors
    ///
    /// Return an error if the stream of the file is not in the lookup table.
    pub fn open_file(&self, file: &WimFile) -> Result<WimStream<'_, R>> {
        Ok(WimStream {
            store: &self.store,
            stream: self.stream(file)?,
        })
    }
}

/// Read a whole resource that is not solid, with a size limit.
fn read_table<R: ReadAt>(
    store: &Store<R>,
    resource: &ResourceHeader,
    name: &str,
) -> Result<Vec<u8>> {
    if resource.has(RESOURCE_SOLID) {
        return Err(Error::unsupported(format!("a solid {name}")));
    }
    if resource.original_size > MAX_TABLE_SIZE {
        return Err(
            Error::limit_exceeded(resource.original_size, MAX_TABLE_SIZE)
                .in_structure(name.to_owned()),
        );
    }
    let mut data = vec![0; to_usize(resource.original_size)?];
    store
        .read_resource(resource, 0, &mut data)
        .map_err(|e| e.in_structure(name.to_owned()))?;
    Ok(data)
}

/// The files and directories of one image.
#[derive(Debug, Clone)]
pub struct Image {
    files: Vec<WimFile>,
}

impl Image {
    /// Return the files and directories in tree order.
    #[must_use]
    pub fn files(&self) -> &[WimFile] {
        &self.files
    }

    /// Return the files and directories.
    #[must_use]
    pub fn into_files(self) -> Vec<WimFile> {
        self.files
    }

    /// Find a file by its path from the image root.
    ///
    /// The path can use `\` or `/` between names. The comparison ignores ASCII case, as
    /// Windows does for these names.
    #[must_use]
    pub fn find(&self, path: &str) -> Option<&WimFile> {
        let path = path.replace('/', "\\");
        let path = path.trim_start_matches('\\');
        self.files
            .iter()
            .find(|file| file.path == path)
            .or_else(|| {
                self.files
                    .iter()
                    .find(|file| file.path.eq_ignore_ascii_case(path))
            })
    }
}

/// The data of one file in a WIM file, as a [`ReadAt`] source.
pub struct WimStream<'a, R> {
    store: &'a Store<R>,
    stream: Option<Stream>,
}

impl<R: ReadAt> ReadAt for WimStream<'_, R> {
    fn size(&self) -> io::Result<u64> {
        Ok(self.stream.map_or(0, |stream| stream.size))
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let size = self.size()?;
        if offset
            .checked_add(buf.len() as u64)
            .is_none_or(|end| end > size)
        {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the range goes past the end of the file",
            ));
        }
        let Some(stream) = &self.stream else {
            return Ok(());
        };
        self.store
            .read_location(&stream.location, offset, buf)
            .map_err(io::Error::other)
    }
}
