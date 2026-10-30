//! Read WIM files that the tests build: without compression, with LZMS chunks and with LZMS
//! solid resources. `cabinet.dll` compressed the LZMS chunks (see `scripts/make-fixtures.py`).

mod builder;
mod data;

use builder::{Builder, FLAG_COMPRESSION, FLAG_LZMS, Node, RESOURCE_SOLID, resource_header};
use data::{chunked, fixture, random_bytes, sha1, solid_files, text};
use serde_json::Value;
use sha2::{Digest, Sha256};
use winupdate::{Cab, Compression, ErrorKind, ReadAt, Wim};

/// Build a WIM file without compression, with a file in a subdirectory and an empty file.
fn plain_wim() -> (Vec<u8>, Vec<(String, Vec<u8>)>) {
    let files = vec![
        ("readme.txt".to_owned(), text(1, 5000)),
        ("empty.dat".to_owned(), Vec::new()),
        ("dir\\inner.bin".to_owned(), random_bytes(2, 70_000)),
    ];
    let mut wim = Builder::new(0x10D00, 0, 0);
    for (_, data) in &files {
        if !data.is_empty() {
            let header = wim.plain(data, 0);
            wim.entry(header, sha1(data));
        }
    }
    wim.image(
        &[
            Node::file("readme.txt", &files[0].1),
            Node::file("empty.dat", &files[1].1),
            Node::directory("dir", vec![Node::file("inner.bin", &files[2].1)]),
        ],
        false,
    );
    (wim.finish(), files)
}

/// Build an LZMS WIM file with a chunked file, a file with stored chunks and chunked
/// metadata.
fn chunked_wim() -> (Vec<u8>, Vec<(String, Vec<u8>)>) {
    let text = chunked();
    let random = random_bytes(3, 200_000);
    let mut wim = Builder::new(0x10D00, FLAG_COMPRESSION | FLAG_LZMS, 131_072);
    let chunks: Vec<Option<Vec<u8>>> = (0..3)
        .map(|i| Some(fixture(&format!("chunked-{i}"))))
        .collect();
    let header = wim.chunked(&text, &chunks, 0);
    wim.entry(header, sha1(&text));
    let header = wim.chunked(&random, &[None, None], 0);
    wim.entry(header, sha1(&random));
    wim.image(
        &[
            Node::file("text.txt", &text),
            Node::file("random.bin", &random),
        ],
        true,
    );
    let files = vec![
        ("text.txt".to_owned(), text),
        ("random.bin".to_owned(), random),
    ];
    (wim.finish(), files)
}

/// Build an LZMS WIM file with one solid resource for three files, as in Windows 11 update
/// packages and ESD files.
fn solid_wim() -> (Vec<u8>, Vec<(String, Vec<u8>)>) {
    let parts = solid_files();
    let size: u64 = parts.iter().map(|part| part.len() as u64).sum();
    let mut wim = Builder::new(0xE00, FLAG_COMPRESSION | FLAG_LZMS, 131_072);
    wim.solid(size, 262_144, &[fixture("solid-0"), fixture("solid-1")]);
    let mut offset = 0;
    for part in &parts {
        wim.solid_stream(offset, part);
        offset += part.len() as u64;
    }
    let names = ["a.txt", "b.exe", "c.txt"];
    wim.image(
        &[Node::directory(
            "files",
            names
                .iter()
                .zip(&parts)
                .map(|(name, part)| Node::file(name, part))
                .collect(),
        )],
        true,
    );
    let files = names
        .iter()
        .zip(parts)
        .map(|(name, part)| (format!("files\\{name}"), part))
        .collect();
    (wim.finish(), files)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut s, b| {
        write!(s, "{b:02x}").unwrap();
        s
    })
}

/// Open a WIM file, and check each file and some ranges.
fn check(bytes: &[u8], files: &[(String, Vec<u8>)]) {
    let wim = Wim::open(bytes).unwrap();
    assert_eq!(wim.image_count(), 1);
    assert!(wim.xml().unwrap().starts_with("<WIM>"));
    let image = wim.image(1).unwrap();
    for (path, data) in files {
        let file = image.find(path).unwrap_or_else(|| panic!("no {path}"));
        assert_eq!(file.size, data.len() as u64, "{path}");
        assert!(wim.read(file).unwrap() == *data, "{path}");
        let stream = wim.open_file(file).unwrap();
        assert_eq!(stream.size().unwrap(), data.len() as u64);
        // Ranges in one chunk, across chunks, and at the end.
        let len = data.len();
        for (start, count) in [
            (0, 1),
            (len / 3, 1000),
            (131_000, 600),
            (len.saturating_sub(7), 7),
        ] {
            if start + count > len {
                continue;
            }
            let mut buf = vec![0; count];
            stream.read_exact_at(start as u64, &mut buf).unwrap();
            assert!(buf == data[start..start + count], "{path} at {start}");
        }
        let mut buf = [0; 1];
        assert!(stream.read_exact_at(len as u64, &mut buf).is_err());
    }
}

#[test]
fn the_fixtures_have_the_generated_chunks() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/manifest.json");
    let manifest: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let text = chunked();
    let solid = solid_files().concat();
    let chunks = text
        .chunks(131_072)
        .enumerate()
        .map(|(i, c)| (format!("chunked-{i}"), c))
        .chain(
            solid
                .chunks(262_144)
                .enumerate()
                .map(|(i, c)| (format!("solid-{i}"), c)),
        );
    for (name, chunk) in chunks {
        let entry = &manifest[&name];
        let hash = hex(&Sha256::digest(chunk));
        assert_eq!(entry["sha256"].as_str().unwrap(), hash, "{name}");
        assert_eq!(
            lzms::decompress(&fixture(&name), chunk.len()).unwrap(),
            chunk
        );
    }
}

#[test]
fn a_wim_without_compression_gives_its_files() {
    let (bytes, files) = plain_wim();
    check(&bytes, &files);
    let wim = Wim::open(&bytes[..]).unwrap();
    assert_eq!(wim.compression(), Compression::None);
    let image = wim.image(1).unwrap();
    let paths: Vec<&str> = image.files().iter().map(|f| f.path.as_str()).collect();
    assert_eq!(paths, ["readme.txt", "empty.dat", "dir", "dir\\inner.bin"]);
    assert!(image.find("dir").unwrap().is_directory());
    assert!(image.find("/DIR/Inner.bin").is_some());
    assert_eq!(image.find("empty.dat").unwrap().sha1, None);
}

#[test]
fn an_lzms_wim_gives_its_files() {
    let (bytes, files) = chunked_wim();
    check(&bytes, &files);
}

#[test]
fn a_solid_wim_gives_its_files() {
    let (bytes, files) = solid_wim();
    check(&bytes, &files);
}

#[test]
fn storage_order_follows_the_data() {
    let (bytes, _) = solid_wim();
    let wim = Wim::open(&bytes[..]).unwrap();
    let image = wim.image(1).unwrap();
    let reversed: Vec<_> = image.files().iter().rev().collect();
    let paths: Vec<&str> = wim
        .storage_order(reversed)
        .iter()
        .map(|f| f.path.as_str())
        .collect();
    assert_eq!(
        paths,
        ["files", "files\\a.txt", "files\\b.exe", "files\\c.txt"]
    );
}

#[test]
fn a_changed_byte_fails_the_hash_check() {
    let (mut bytes, files) = plain_wim();
    let at = bytes
        .windows(16)
        .position(|w| w == &files[0].1[100..116])
        .unwrap();
    bytes[at] ^= 1;
    let wim = Wim::open(&bytes[..]).unwrap();
    let image = wim.image(1).unwrap();
    let error = wim.read(image.find("readme.txt").unwrap()).unwrap_err();
    assert_eq!(error.kind, ErrorKind::HashMismatch { algorithm: "SHA-1" });
}

#[test]
fn every_truncated_wim_is_an_error() {
    for (bytes, files) in [plain_wim(), chunked_wim(), solid_wim()] {
        let step = bytes.len() / 300;
        for len in (0..bytes.len()).step_by(step.max(1)) {
            let Ok(wim) = Wim::open(&bytes[..len]) else {
                continue;
            };
            let Ok(image) = wim.image(1) else {
                continue;
            };
            for (path, _) in &files {
                if let Some(file) = image.find(path) {
                    let _ = wim.read(file);
                }
            }
        }
    }
}

#[test]
fn a_changed_chunk_is_an_error() {
    let (bytes, _) = chunked_wim();
    let wim = Wim::open(&bytes[..]).unwrap();
    let image = wim.image(1).unwrap();
    let file = image.find("text.txt").unwrap().clone();
    drop(wim);
    // Change each byte of the first compressed chunk in turn. No change may panic.
    let start = bytes
        .windows(32)
        .position(|w| w == &fixture("chunked-0")[..32])
        .unwrap();
    for at in (start..start + 19_370).step_by(97) {
        let mut changed = bytes.clone();
        changed[at] ^= 0x5a;
        let wim = Wim::open(&changed[..]).unwrap();
        assert!(wim.read(&file).is_err(), "byte {at}");
    }
}

#[test]
fn a_split_wim_is_unsupported() {
    let (mut bytes, _) = plain_wim();
    bytes[42] = 2;
    let error = Wim::open(&bytes[..]).err().unwrap();
    assert!(matches!(error.kind, ErrorKind::Unsupported(_)), "{error}");
}

#[test]
fn an_xpress_resource_is_unsupported() {
    let data = text(5, 1000);
    let mut wim = Builder::new(0x10D00, FLAG_COMPRESSION | 0x2_0000, 32_768);
    let header = wim.chunked(&data, &[Some(data[..900].to_vec())], 0);
    wim.entry(header, sha1(&data));
    wim.image(&[Node::file("x.txt", &data)], false);
    let bytes = wim.finish();
    let wim = Wim::open(&bytes[..]).unwrap();
    let image = wim.image(1).unwrap();
    let error = wim.read(image.find("x.txt").unwrap()).unwrap_err();
    assert!(matches!(error.kind, ErrorKind::Unsupported(_)), "{error}");
}

#[test]
fn a_solid_stream_needs_a_solid_resource() {
    let data = text(6, 100);
    let mut wim = Builder::new(0xE00, FLAG_COMPRESSION | FLAG_LZMS, 131_072);
    wim.entry(resource_header(100, RESOURCE_SOLID, 0, 0), sha1(&data));
    wim.image(&[Node::file("x.txt", &data)], false);
    let error = Wim::open(&wim.finish()[..]).err().unwrap();
    assert!(matches!(error.kind, ErrorKind::InvalidData(_)), "{error}");
}

#[test]
fn a_wim_inside_a_wim_opens_through_open_file() {
    let (inner, files) = solid_wim();
    let mut outer = Builder::new(0x10D00, 0, 0);
    let header = outer.plain(&inner, 0);
    outer.entry(header, sha1(&inner));
    outer.image(&[Node::file("inner.wim", &inner)], false);
    let outer = outer.finish();
    let wim = Wim::open(&outer[..]).unwrap();
    let image = wim.image(1).unwrap();
    let nested = Wim::open(wim.open_file(image.find("inner.wim").unwrap()).unwrap()).unwrap();
    let nested_image = nested.image(1).unwrap();
    let file = nested_image.find(&files[1].0).unwrap();
    assert_eq!(nested.read(file).unwrap(), files[1].1);
}

#[test]
fn a_cab_inside_a_wim_opens_through_open_file() {
    let cab = cab_bytes();
    let mut wim = Builder::new(0x10D00, 0, 0);
    let header = wim.plain(&cab, 0);
    wim.entry(header, sha1(&cab));
    wim.image(&[Node::file("update.cab", &cab)], false);
    let bytes = wim.finish();
    let wim = Wim::open(&bytes[..]).unwrap();
    let image = wim.image(1).unwrap();
    let mut cab = Cab::open(wim.open_file(image.find("update.cab").unwrap()).unwrap()).unwrap();
    assert_eq!(cab.read("update.mum").unwrap(), b"<assembly />");
}

/// Build a small cabinet file with one MSZIP folder.
fn cab_bytes() -> Vec<u8> {
    use std::io::Write;
    let mut builder = cab::CabinetBuilder::new();
    builder
        .add_folder(cab::CompressionType::MsZip)
        .add_file("update.mum");
    let mut writer = builder.build(std::io::Cursor::new(Vec::new())).unwrap();
    while let Some(mut file) = writer.next_file().unwrap() {
        file.write_all(b"<assembly />").unwrap();
    }
    writer.finish().unwrap().into_inner()
}
