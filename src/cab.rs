//! Cabinet files (`.cab`).
//!
//! Windows 10 cumulative updates come as cabinet files, sometimes in an other cabinet or MSU
//! file. [`Cab`] reads them with the `cab` crate, through a [`Cursor`] over a [`ReadAt`]
//! source. Thus it reads only the byte ranges that it needs, for example over HTTP or from a
//! file in a WIM file.
//!
//! The `cab` crate supports folders without compression, with MSZIP and with LZX.
//!
//! # Cost of a read
//!
//! A folder is one compressed stream for all of its files. To read a file, the reader
//! decompresses the folder from its start to the end of the file. Thus a file late in a large
//! folder costs the read and the decompression of all files before it in the folder.
//!
//! # Example
//!
//! ```no_run
//! use winupdate::Cab;
//!
//! let mut cab = Cab::open(std::fs::File::open("Windows10.0-KB5035845-x64.cab")?)?;
//! for entry in cab.entries() {
//!     println!("{} {}", entry.size, entry.name);
//! }
//! let manifest = cab.read("update.mum")?;
//! # Ok::<(), winupdate::Error>(())
//! ```

use crate::error::{Error, Result};
use crate::read_at::{Cursor, ReadAt};
use std::io::{self, Read};

/// A file in a cabinet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CabEntry {
    /// The name, with `\` between directory names.
    pub name: String,
    /// The uncompressed size, in bytes.
    pub size: u64,
    /// The index of the folder that holds the file.
    pub folder: usize,
}

/// A cabinet file.
pub struct Cab<R> {
    cabinet: cab::Cabinet<Cursor<R>>,
    entries: Vec<CabEntry>,
}

impl<R: ReadAt> Cab<R> {
    /// Open a cabinet file, and read its file list.
    ///
    /// # Errors
    ///
    /// Return an error if the reader fails or if the file is not a valid cabinet file.
    pub fn open(reader: R) -> Result<Self> {
        let cabinet = cab::Cabinet::new(Cursor::new(reader)).map_err(cab_error)?;
        let mut entries = Vec::new();
        for (folder, entry) in cabinet.folder_entries().enumerate() {
            for file in entry.file_entries() {
                entries.push(CabEntry {
                    name: file.name().to_owned(),
                    size: u64::from(file.uncompressed_size()),
                    folder,
                });
            }
        }
        Ok(Self { cabinet, entries })
    }

    /// Return the files in the order of the cabinet.
    #[must_use]
    pub fn entries(&self) -> &[CabEntry] {
        &self.entries
    }

    /// Find a file by its name. The comparison ignores ASCII case if no name is equal.
    #[must_use]
    pub fn find(&self, name: &str) -> Option<&CabEntry> {
        self.entries
            .iter()
            .find(|entry| entry.name == name)
            .or_else(|| {
                self.entries
                    .iter()
                    .find(|entry| entry.name.eq_ignore_ascii_case(name))
            })
    }

    /// Open a file as a stream of its uncompressed bytes.
    ///
    /// # Errors
    ///
    /// Return an error if the cabinet has no file with this name, or if the reader fails.
    pub fn open_file(&mut self, name: &str) -> Result<impl Read + '_> {
        let name = self
            .find(name)
            .ok_or_else(|| Error::not_found(name))?
            .name
            .clone();
        self.cabinet.read_file(&name).map_err(cab_error)
    }

    /// Read the uncompressed bytes of a file.
    ///
    /// # Errors
    ///
    /// Return an error if the cabinet has no file with this name, if the reader fails, or if
    /// the compressed data is not valid.
    pub fn read(&mut self, name: &str) -> Result<Vec<u8>> {
        let size = self.find(name).ok_or_else(|| Error::not_found(name))?.size;
        let mut data = Vec::with_capacity(usize::try_from(size).unwrap_or(0));
        self.open_file(name)?
            .read_to_end(&mut data)
            .map_err(cab_error)?;
        if data.len() as u64 != size {
            return Err(Error::unexpected_end()
                .in_structure("cabinet")
                .with_details(name.to_owned()));
        }
        Ok(data)
    }
}

/// Convert an error of the `cab` crate.
fn cab_error(error: io::Error) -> Error {
    if error.kind() == io::ErrorKind::InvalidData {
        Error::invalid_data(error.to_string()).in_structure("cabinet")
    } else {
        Error::from(error)
    }
}
