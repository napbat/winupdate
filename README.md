# winupdate

winupdate reads Windows update packages on each platform, with no Windows API. It reads only
the byte ranges that it needs through the `ReadAt` trait. Thus a caller can read a
multi-gigabyte package over HTTP with range requests.

## Status

| Feature | Status |
| --- | --- |
| WIM and ESD files, and MSU files (which are WIM files) | Supported |
| Resources without compression | Supported |
| LZMS resources with chunk tables (CBS package WIM files) | Supported |
| LZMS solid resources (ESD files, Windows 11 CBS package WIM files) | Supported |
| XPRESS and LZX resources | `Unsupported` error |
| Split WIM files and pipable WIM files | `Unsupported` error |
| Cabinet files (`.cab`) with MSZIP and LZX, through the `cab` crate | Supported |
| PSF indexes (`express.psf.cix.xml`) | Supported |
| The CRC-32 prefix of forward deltas in PSF files | Supported |

winupdate checks the SHA-1 hash of each file that `Wim::read` reads.

## Usage

```rust,no_run
use winupdate::{Cab, Wim, cix::PsfIndex, psf};

// An MSU file is a WIM file without compression. Its CBS package is an LZMS WIM file.
let msu = Wim::open(std::fs::File::open("Windows11.0-KB5043080-x64.msu")?)?;
let msu_image = msu.image(1)?;
let package = msu_image.find("Windows11.0-KB5043080-x64.wim").expect("no package");
let wim = Wim::open(msu.open_file(package)?)?;

// The PSF index of the package gives the location of each payload in the PSF file.
let image = wim.image(1)?;
let index = image.find("express.psf.cix.xml").expect("no index");
let index = PsfIndex::parse(std::str::from_utf8(&wim.read(index)?)?)?;
let psf_file = msu_image.find("Windows11.0-KB5043080-x64.psf").expect("no payload");
let psf_reader = msu.open_file(psf_file)?;
for file in index.files.iter().filter(|f| f.name.ends_with("\\f\\apisetschema.dll")) {
    let payload = psf::read_source(&psf_reader, &file.sources[0])?;
    let delta = psf::strip_crc(&payload)?;
    println!("{}: PA31 delta of {} bytes", file.name, delta.len());
}

// A Windows 10 update is a cabinet file.
let mut cab = Cab::open(std::fs::File::open("Windows10.0-KB5035845-x64.cab")?)?;
let manifest = cab.read("update.mum")?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Implement `ReadAt` for an HTTP client to read a package without a full download. `Slice`
gives a part of a source, and `Cursor` gives a `Read + Seek` stream for a source. `Cursor`
reads ahead 64 KiB, so that the many small reads of the `cab` crate become few range
requests.

## Cost of reads

- `Wim::open` reads the header, the lookup table and the headers of the solid resources.
- `Wim::image` reads and decompresses the metadata resource of the image.
- A read of a file decompresses only the chunks of the range. The chunks of a solid resource
  in an ESD file are 64 MiB each. The reader keeps the last chunk, so read many files in the
  order of `Wim::storage_order` to decompress each chunk only once.
- A cabinet folder is one compressed stream. A read of a file late in a large folder
  decompresses all files before it in the folder.

## Format notes

WIM resources are chunks of a fixed size, each compressed alone. A resource that is not solid
starts with a table of chunk offsets. A solid resource starts with its uncompressed size, its
chunk size, its compression format and the compressed size of each chunk. The lookup table
gives the location of each stream: a whole resource, or an offset in the solid resources
before the entry.

The [lzms](https://github.com/napbat/lzms) crate decompresses the LZMS chunks.

## Tests

`scripts/make-fixtures.py` compresses the LZMS chunks with `cabinet.dll` on Windows. The tests
build WIM files and cabinet files around fixed-seed data. The repository has no Microsoft
files.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.
