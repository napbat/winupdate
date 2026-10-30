//! Positional reads.
//!
//! The readers in this crate read only the byte ranges that they need. They read through the
//! [`ReadAt`] trait. Implement it for a source of bytes, for example an HTTP client that sends
//! range requests, to read a multi-gigabyte package without a download of the full file.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::sync::Arc;

/// A source of bytes that can read a range at an offset.
///
/// The methods take `&self`, so one source can serve many readers.
pub trait ReadAt {
    /// Return the total size of the source, in bytes.
    ///
    /// # Errors
    ///
    /// Return an error if the source cannot get its size.
    fn size(&self) -> io::Result<u64>;

    /// Read exactly `buf.len()` bytes at `offset`.
    ///
    /// # Errors
    ///
    /// Return an error of the kind [`io::ErrorKind::UnexpectedEof`] if the range goes past the
    /// end of the source. Return other errors from the source.
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()>;
}

/// Make the error for a range that goes past the end of a source.
fn past_end() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "the range goes past the end")
}

impl ReadAt for [u8] {
    fn size(&self) -> io::Result<u64> {
        Ok(self.len() as u64)
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let start = usize::try_from(offset).map_err(|_| past_end())?;
        let end = start.checked_add(buf.len()).ok_or_else(past_end)?;
        let bytes = self.get(start..end).ok_or_else(past_end)?;
        buf.copy_from_slice(bytes);
        Ok(())
    }
}

impl ReadAt for Vec<u8> {
    fn size(&self) -> io::Result<u64> {
        self.as_slice().size()
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        self.as_slice().read_exact_at(offset, buf)
    }
}

impl<T: ReadAt + ?Sized> ReadAt for &T {
    fn size(&self) -> io::Result<u64> {
        (**self).size()
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        (**self).read_exact_at(offset, buf)
    }
}

impl<T: ReadAt + ?Sized> ReadAt for Box<T> {
    fn size(&self) -> io::Result<u64> {
        (**self).size()
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        (**self).read_exact_at(offset, buf)
    }
}

impl<T: ReadAt + ?Sized> ReadAt for Arc<T> {
    fn size(&self) -> io::Result<u64> {
        (**self).size()
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        (**self).read_exact_at(offset, buf)
    }
}

#[cfg(any(unix, windows))]
impl ReadAt for File {
    fn size(&self) -> io::Result<u64> {
        Ok(self.metadata()?.len())
    }

    #[cfg(unix)]
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        std::os::unix::fs::FileExt::read_exact_at(self, buf, offset)
    }

    #[cfg(windows)]
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let mut done = 0;
        while done < buf.len() {
            let at = offset.checked_add(done as u64).ok_or_else(past_end)?;
            match std::os::windows::fs::FileExt::seek_read(self, &mut buf[done..], at) {
                Ok(0) => return Err(past_end()),
                Ok(n) => done += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

/// A part of a [`ReadAt`] source: `len` bytes from `start`.
#[derive(Debug, Clone)]
pub struct Slice<R> {
    inner: R,
    start: u64,
    len: u64,
}

impl<R: ReadAt> Slice<R> {
    /// Make a source that has the bytes `start..start + len` of `inner`.
    pub fn new(inner: R, start: u64, len: u64) -> Self {
        Self { inner, start, len }
    }
}

impl<R: ReadAt> ReadAt for Slice<R> {
    fn size(&self) -> io::Result<u64> {
        Ok(self.len)
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let end = offset.checked_add(buf.len() as u64).ok_or_else(past_end)?;
        if end > self.len {
            return Err(past_end());
        }
        let at = self.start.checked_add(offset).ok_or_else(past_end)?;
        self.inner.read_exact_at(at, buf)
    }
}

/// A [`Read`] and [`Seek`] adapter for a [`ReadAt`] source.
///
/// Use it to give a [`ReadAt`] source to an API that needs a stream, for example the `cab`
/// crate. Such an API often reads a few bytes at a time. Thus the cursor reads ahead into a
/// buffer, and serves small reads from the buffer. A read that is larger than the buffer goes
/// directly to the source.
#[derive(Debug, Clone)]
pub struct Cursor<R> {
    inner: R,
    position: u64,
    /// The bytes that the cursor read ahead, from `buffer_start`.
    buffer: Vec<u8>,
    buffer_start: u64,
    buffer_size: usize,
}

impl<R: ReadAt> Cursor<R> {
    /// The default read-ahead size (64 KiB).
    pub const DEFAULT_BUFFER_SIZE: usize = 64 * 1024;

    /// Make a stream at position 0, with the default read-ahead size.
    pub fn new(inner: R) -> Self {
        Self::with_buffer_size(inner, Self::DEFAULT_BUFFER_SIZE)
    }

    /// Make a stream at position 0 that reads ahead `buffer_size` bytes. Zero reads no more
    /// than each call asks for.
    pub fn with_buffer_size(inner: R, buffer_size: usize) -> Self {
        Self {
            inner,
            position: 0,
            buffer: Vec::new(),
            buffer_start: 0,
            buffer_size,
        }
    }

    /// Return the source.
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: ReadAt> Read for Cursor<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let size = self.inner.size()?;
        let left = size.saturating_sub(self.position);
        let count = usize::try_from(left).map_or(buf.len(), |left| left.min(buf.len()));
        if count == 0 {
            return Ok(0);
        }
        let in_buffer = self
            .position
            .checked_sub(self.buffer_start)
            .and_then(|skip| usize::try_from(skip).ok())
            .filter(|&skip| skip < self.buffer.len());
        let count = if let Some(skip) = in_buffer {
            let count = count.min(self.buffer.len() - skip);
            buf[..count].copy_from_slice(&self.buffer[skip..skip + count]);
            count
        } else if count >= self.buffer_size {
            self.inner.read_exact_at(self.position, &mut buf[..count])?;
            count
        } else {
            let ahead =
                usize::try_from(left).map_or(self.buffer_size, |left| left.min(self.buffer_size));
            self.buffer.resize(ahead, 0);
            self.buffer_start = self.position;
            if let Err(error) = self.inner.read_exact_at(self.position, &mut self.buffer) {
                self.buffer.clear();
                return Err(error);
            }
            buf[..count].copy_from_slice(&self.buffer[..count]);
            count
        };
        self.position += count as u64;
        Ok(count)
    }
}

impl<R: ReadAt> Seek for Cursor<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let invalid = || io::Error::new(io::ErrorKind::InvalidInput, "invalid seek position");
        let position = match pos {
            SeekFrom::Start(offset) => Some(offset),
            SeekFrom::End(delta) => self.inner.size()?.checked_add_signed(delta),
            SeekFrom::Current(delta) => self.position.checked_add_signed(delta),
        };
        self.position = position.ok_or_else(invalid)?;
        Ok(self.position)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_slice_reads_only_its_range() {
        let data: Vec<u8> = (0..100).collect();
        let slice = Slice::new(&data, 10, 20);
        let mut buf = [0; 5];
        slice.read_exact_at(15, &mut buf).unwrap();
        assert_eq!(buf, [25, 26, 27, 28, 29]);
        assert!(slice.read_exact_at(16, &mut buf).is_err());
    }

    /// A source that counts its reads.
    struct Counting(Vec<u8>, std::cell::Cell<usize>);

    impl ReadAt for Counting {
        fn size(&self) -> io::Result<u64> {
            self.0.size()
        }

        fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
            self.1.set(self.1.get() + 1);
            self.0.read_exact_at(offset, buf)
        }
    }

    #[test]
    fn a_cursor_serves_small_reads_from_its_buffer() {
        let source = Counting((0..=255).collect(), std::cell::Cell::new(0));
        let mut cursor = Cursor::with_buffer_size(&source, 100);
        let mut byte = [0; 1];
        for expected in 0..=255u8 {
            cursor.read_exact(&mut byte).unwrap();
            assert_eq!(byte[0], expected);
        }
        assert_eq!(source.1.get(), 3);
        cursor.seek(SeekFrom::Start(50)).unwrap();
        cursor.read_exact(&mut byte).unwrap();
        assert_eq!(byte[0], 50);
        let mut large = [0; 120];
        cursor.seek(SeekFrom::Start(10)).unwrap();
        cursor.read_exact(&mut large).unwrap();
        assert_eq!(large[119], 129);
    }

    #[test]
    fn a_cursor_reads_and_seeks() {
        let data: Vec<u8> = (0..10).collect();
        let mut cursor = Cursor::new(data);
        let mut buf = [0; 4];
        assert_eq!(cursor.seek(SeekFrom::End(-3)).unwrap(), 7);
        assert_eq!(cursor.read(&mut buf).unwrap(), 3);
        assert_eq!(&buf[..3], &[7, 8, 9]);
        assert_eq!(cursor.read(&mut buf).unwrap(), 0);
        assert!(cursor.seek(SeekFrom::Current(-20)).is_err());
    }
}
