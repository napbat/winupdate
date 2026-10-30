//! Read cabinet files that the `cab` crate writes.

use std::io::{Read, Write};
use winupdate::{Cab, ErrorKind};

/// The `SplitMix64` generator.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

fn data(seed: u64, n: usize) -> Vec<u8> {
    let mut rng = Rng(seed);
    // Half random bytes and half repeated text, so that MSZIP has work to do.
    (0..n)
        .map(|i| {
            if (i / 4096) % 2 == 0 {
                rng.next().to_le_bytes()[0]
            } else {
                b"cabinet folder "[i % 15]
            }
        })
        .collect()
}

type Files = Vec<(String, Vec<u8>)>;

/// Build a cabinet with one folder for each item of `folders`.
fn build(folders: &[(cab::CompressionType, Files)]) -> Vec<u8> {
    let mut builder = cab::CabinetBuilder::new();
    for (kind, files) in folders {
        let folder = builder.add_folder(*kind);
        for (name, _) in files {
            folder.add_file(name.clone());
        }
    }
    let mut writer = builder.build(std::io::Cursor::new(Vec::new())).unwrap();
    let mut contents = folders.iter().flat_map(|(_, files)| files.iter());
    while let Some(mut file) = writer.next_file().unwrap() {
        let (_, content) = contents.next().unwrap();
        file.write_all(content).unwrap();
    }
    writer.finish().unwrap().into_inner()
}

fn sample() -> Vec<(cab::CompressionType, Files)> {
    vec![
        (
            cab::CompressionType::MsZip,
            vec![
                ("update.mum".into(), b"<assembly />".to_vec()),
                ("amd64_x\\f\\apisetschema.dll".into(), data(1, 300_000)),
                ("late.bin".into(), data(2, 100_000)),
            ],
        ),
        (
            cab::CompressionType::None,
            vec![("stored.txt".into(), data(3, 5000))],
        ),
    ]
}

#[test]
fn a_cabinet_lists_and_reads_its_files() {
    let folders = sample();
    let bytes = build(&folders);
    let mut cab = Cab::open(&bytes[..]).unwrap();
    let names: Vec<(&str, u64, usize)> = cab
        .entries()
        .iter()
        .map(|e| (e.name.as_str(), e.size, e.folder))
        .collect();
    assert_eq!(
        names,
        [
            ("update.mum", 12, 0),
            ("amd64_x\\f\\apisetschema.dll", 300_000, 0),
            ("late.bin", 100_000, 0),
            ("stored.txt", 5000, 1)
        ]
    );
    for (_, files) in &folders {
        for (name, content) in files {
            assert!(cab.read(name).unwrap() == *content, "{name}");
        }
    }
    assert_eq!(cab.read("LATE.BIN").unwrap(), folders[0].1[2].1);
    let mut stream = cab.open_file("update.mum").unwrap();
    let mut text = String::new();
    stream.read_to_string(&mut text).unwrap();
    assert_eq!(text, "<assembly />");
}

#[test]
fn a_cabinet_inside_a_cabinet_opens_from_its_bytes() {
    let inner = build(&sample());
    let outer = build(&[(
        cab::CompressionType::MsZip,
        vec![("Windows10.0-KB1-x64.cab".into(), inner)],
    )]);
    let mut cab = Cab::open(&outer[..]).unwrap();
    let inner = cab.read("Windows10.0-KB1-x64.cab").unwrap();
    let mut nested = Cab::open(inner).unwrap();
    assert_eq!(nested.read("update.mum").unwrap(), b"<assembly />");
}

#[test]
fn a_missing_file_is_not_found() {
    let mut cab = Cab::open(build(&sample())).unwrap();
    let error = cab.read("missing.txt").unwrap_err();
    assert!(matches!(error.kind, ErrorKind::NotFound(_)), "{error}");
}

#[test]
fn an_other_file_is_not_a_cabinet() {
    let error = Cab::open(&b"MSWIM\0\0\0 not a cabinet file"[..])
        .err()
        .unwrap();
    assert!(matches!(error.kind, ErrorKind::InvalidData(_)), "{error}");
}

#[test]
fn every_truncated_cabinet_is_an_error() {
    let bytes = build(&sample());
    for len in (0..bytes.len()).step_by(997) {
        if let Ok(mut cab) = Cab::open(&bytes[..len]) {
            // The last file ends at the end of the cabinet, so the read must fail.
            assert!(cab.read("stored.txt").is_err(), "{len} bytes");
        }
    }
}
