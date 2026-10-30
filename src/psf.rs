//! PSF payload files.
//!
//! A PSF file (`*.psf`) holds the payloads of an update, one after the other. The PSF index
//! ([`PsfIndex`](crate::cix::PsfIndex)) gives the offset and the length of each payload.
//!
//! A forward delta (a name with `\f\`) with a `RAW` source starts with a 4-byte prefix: the
//! CRC-32 of the rest of the payload, little-endian. The rest is a PA31 delta. Use
//! [`strip_crc`] to check and remove the prefix.

use crate::cix::Source;
use crate::error::{Error, ErrorKind, Result};
use crate::read_at::ReadAt;
use sha2::{Digest, Sha256};

/// Check the CRC-32 prefix of a payload, and return the payload without it.
///
/// # Errors
///
/// Return an error if the payload has less than 4 bytes, or if the CRC-32 of the rest is not
/// equal to the prefix.
///
/// # Example
///
/// ```
/// // The CRC-32 of "123456789" is 0xCBF43926.
/// let payload = b"\x26\x39\xf4\xcb123456789";
/// assert_eq!(winupdate::psf::strip_crc(payload)?, b"123456789");
/// # Ok::<(), winupdate::Error>(())
/// ```
pub fn strip_crc(payload: &[u8]) -> Result<&[u8]> {
    let Some((prefix, rest)) = payload.split_first_chunk::<4>() else {
        return Err(Error::unexpected_end().in_structure("CRC-32 prefix"));
    };
    if u32::from_le_bytes(*prefix) != crc32fast::hash(rest) {
        return Err(ErrorKind::HashMismatch {
            algorithm: "CRC-32",
        }
        .into());
    }
    Ok(rest)
}

/// Read the bytes of a source from a PSF file, and check their SHA-256 hash.
///
/// The function checks the hash only if the source has a SHA-256 hash.
///
/// # Errors
///
/// Return an error if the reader fails, or if the hash of the bytes is not equal to the hash
/// of the source.
pub fn read_source<R: ReadAt + ?Sized>(psf: &R, source: &Source) -> Result<Vec<u8>> {
    let len = usize::try_from(source.length)
        .map_err(|_| Error::limit_exceeded(source.length, usize::MAX as u64))?;
    let mut data = vec![0; len];
    psf.read_exact_at(source.offset, &mut data)
        .map_err(|e| Error::from(e).at_offset(source.offset))?;
    if let Some(expected) = source.sha256()
        && <[u8; 32]>::from(Sha256::digest(&data)) != expected
    {
        return Err(Error::new(ErrorKind::HashMismatch {
            algorithm: "SHA-256",
        })
        .at_offset(source.offset));
    }
    Ok(data)
}
