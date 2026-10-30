//! # winupdate
//!
//! Read Windows update packages on each platform, with no Windows API. The readers read only
//! the byte ranges that they need through the [`ReadAt`] trait, so a caller can read a
//! multi-gigabyte package over HTTP with range requests.
//!
//! ## Support
//!
//! - [`Wim`]: WIM and ESD files (`.wim`, `.esd`, and `.msu` files, which are WIM files). The
//!   reader supports resources without compression, LZMS resources and LZMS solid resources.
//! - [`Cab`]: cabinet files (`.cab`), with MSZIP and LZX compression.
//! - [`cix::PsfIndex`]: the PSF index (`express.psf.cix.xml`) of a PSF payload file.
//! - [`psf::strip_crc`]: the CRC-32 prefix of a forward delta in a PSF payload.
//!
//! ## Example
//!
//! ```no_run
//! use winupdate::{Wim, cix::PsfIndex};
//!
//! let wim = Wim::open(std::fs::File::open("Windows11.0-KB5043080-x64.wim")?)?;
//! let image = wim.image(1)?;
//! let file = image.find("express.psf.cix.xml").expect("no PSF index");
//! let index = PsfIndex::parse(std::str::from_utf8(&wim.read(file)?)?)?;
//! for file in index.files.iter().filter(|f| f.name.ends_with("\\apisetschema.dll")) {
//!     println!("{} {} bytes", file.name, file.length);
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

pub mod cab;
pub mod cix;
pub mod error;
pub mod psf;
pub mod read_at;
pub mod wim;

pub use cab::{Cab, CabEntry};
pub use error::{Error, ErrorContext, ErrorKind, Result};
pub use read_at::{Cursor, ReadAt, Slice};
pub use wim::{Compression, Image, Wim, WimFile, WimStream};

/// The examples of the README file, compiled as documentation tests.
#[doc = include_str!("../README.md")]
#[cfg(doctest)]
pub struct ReadmeDoctests;
