//! The fixed-seed data of the WIM tests, and the LZMS chunks that `cabinet.dll` made.
//!
//! `scripts/make-fixtures.py` has the same generator.

use sha1::{Digest, Sha1};
use std::path::Path;

/// The `SplitMix64` generator, the same as in `scripts/make-fixtures.py`.
pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    pub fn index(&mut self, n: usize) -> usize {
        usize::try_from(self.below(n as u64)).unwrap()
    }
}

const WORDS: [&[u8]; 16] = [
    b"the",
    b"image",
    b"stream",
    b"resource",
    b"chunk",
    b"lookup",
    b"table",
    b"solid",
    b"header",
    b"dentry",
    b"update",
    b"package",
    b"payload",
    b"delta",
    b"index",
    b"file",
];

pub fn text(seed: u64, n: usize) -> Vec<u8> {
    let mut rng = Rng(seed);
    let mut out = Vec::with_capacity(n + 16);
    while out.len() < n {
        out.extend_from_slice(WORDS[rng.index(WORDS.len())]);
        out.push(if rng.below(8) == 0 { b'\n' } else { b' ' });
    }
    out.truncate(n);
    out
}

pub fn calls(seed: u64, n: usize) -> Vec<u8> {
    let mut rng = Rng(seed);
    let targets: Vec<u64> = (0..32).map(|_| rng.below(1 << 20)).collect();
    let mut out = Vec::with_capacity(n + 8);
    while out.len() < n {
        if rng.below(3) == 0 {
            let target = targets[rng.index(targets.len())];
            let relative = target.wrapping_sub(out.len() as u64).wrapping_sub(5);
            out.push(0xe8);
            out.extend_from_slice(&relative.to_le_bytes()[..4]);
        } else {
            let count = 1 + rng.index(5);
            out.extend_from_slice(&b"\x90\x55\x48\x89\xe5"[..count]);
        }
    }
    out.truncate(n);
    out
}

pub fn random_bytes(seed: u64, n: usize) -> Vec<u8> {
    let mut rng = Rng(seed);
    (0..n).map(|_| rng.next().to_le_bytes()[0]).collect()
}

/// The file of the chunked LZMS resource.
pub fn chunked() -> Vec<u8> {
    text(31, 300_000)
}

/// The three files of the solid resource.
pub fn solid_files() -> [Vec<u8>; 3] {
    [text(32, 200_000), calls(33, 150_000), text(34, 50_000)]
}

/// Read a compressed chunk from `tests/fixtures/`.
pub fn fixture(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(format!("{name}.lzms"));
    std::fs::read(path).unwrap()
}

pub fn sha1(data: &[u8]) -> [u8; 20] {
    Sha1::digest(data).into()
}
