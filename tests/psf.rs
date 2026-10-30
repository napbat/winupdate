//! Parse PSF indexes, and read and check PSF payloads.

use winupdate::cix::{Hash, PsfIndex, SourceKind};
use winupdate::{ErrorKind, psf};

const INDEX: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<Container name="kb1-baseless.psf" type="PSF" length="300" version="1" xmlns="urn:ContainerIndex">
  <Description />
  <DeltaBasisSearch>
    <Location id="0" path="{windir}\servicing\packages" flags="2000001" />
  </DeltaBasisSearch>
  <Files>
    <File id="1" name="amd64_a_31bf3856ad364e35_10.0.26100.1_none_0\f\apisetschema.dll" length="17" time="134342095980000000" attr="128">
      <Hash alg="SHA256" value="5C4ECEF1ED3FC08DB3BC1B0D8C1D1B39A8B9F7E7E4C3D6E0A5B8A0F5D7E4C3B2" />
      <Delta>
        <Source type="RAW" offset="0" length="17">
          <Hash alg="SHA256" value="00112233445566778899AABBCCDDEEFF00112233445566778899aabbccddeeff" />
        </Source>
      </Delta>
    </File>
    <File id="2" name="x86_b_31bf3856ad364e35_10.0.26100.1_none_0\b.dll" length="69632">
      <Hash alg="SHA256" value="337EBBA7629E627215C9D2FCBC3D92AC4EAD1B710219FA96692FF8F9E0BB4894" />
      <Delta>
        <Source type="PA30" offset="17" length="283" />
      </Delta>
    </File>
    <File id="3" name="c &amp; d.txt" length="0" />
  </Files>
</Container>
"#;

#[test]
fn an_index_gives_its_files_and_sources() {
    let index = PsfIndex::parse(INDEX).unwrap();
    assert_eq!(index.name, "kb1-baseless.psf");
    assert_eq!(index.container_type, "PSF");
    assert_eq!(index.length, 300);
    assert_eq!(index.files.len(), 3);
    let first = &index.files[0];
    assert_eq!(first.id, Some(1));
    assert!(first.name.ends_with("\\f\\apisetschema.dll"));
    assert_eq!(first.length, 17);
    assert_eq!(first.time, Some(134_342_095_980_000_000));
    assert_eq!(first.attributes, Some(128));
    assert_eq!(first.sha256().unwrap()[..2], [0x5c, 0x4e]);
    assert_eq!(first.sources.len(), 1);
    let source = &first.sources[0];
    assert_eq!(source.kind, SourceKind::Raw);
    assert_eq!((source.offset, source.length), (0, 17));
    assert_eq!(source.sha256().unwrap()[31], 0xff);
    let second = &index.files[1];
    assert_eq!(second.time, None);
    assert_eq!(second.sources[0].kind, SourceKind::Pa30);
    assert_eq!(second.sources[0].hash, None);
    assert_eq!(index.files[2].name, "c & d.txt");
    assert_eq!(index.files[2].sources, []);
}

#[test]
fn a_hash_of_an_other_algorithm_is_not_sha256() {
    let hash = Hash {
        algorithm: "SHA1".into(),
        value: vec![0; 20],
    };
    assert_eq!(hash.sha256(), None);
}

#[test]
fn a_bad_index_is_an_error() {
    for (xml, what) in [
        (
            INDEX.replace(r#"length="17" time"#, r#"length="x" time"#),
            "number",
        ),
        (INDEX.replace(r#"offset="17" "#, ""), "missing offset"),
        (INDEX.replace("5C4ECEF1", "5C4ECEFZ"), "hex"),
        (INDEX.replace("</Files>", ""), "XML"),
        ("<Files />".to_owned(), "no container"),
    ] {
        let error = PsfIndex::parse(&xml)
            .err()
            .unwrap_or_else(|| panic!("{what}"));
        assert!(
            matches!(error.kind, ErrorKind::InvalidData(_)),
            "{what}: {error}"
        );
    }
}

#[test]
fn strip_crc_checks_and_removes_the_prefix() {
    let delta = b"PA31 and the rest of a delta";
    let mut payload = crc32fast::hash(delta).to_le_bytes().to_vec();
    payload.extend_from_slice(delta);
    assert_eq!(psf::strip_crc(&payload).unwrap(), delta);
    payload[10] ^= 1;
    let error = psf::strip_crc(&payload).unwrap_err();
    assert_eq!(
        error.kind,
        ErrorKind::HashMismatch {
            algorithm: "CRC-32"
        }
    );
    assert_eq!(
        psf::strip_crc(b"abc").unwrap_err().kind,
        ErrorKind::UnexpectedEnd
    );
}

#[test]
fn read_source_checks_the_sha256_hash() {
    use sha2::{Digest, Sha256};
    let payload = b"0123456789abcdefg-the-pa30-delta-bytes".to_vec();
    let hash = Sha256::digest(&payload[..17])
        .iter()
        .fold(String::new(), |mut s, b| {
            use std::fmt::Write;
            write!(s, "{b:02X}").unwrap();
            s
        });
    let xml = INDEX.replace(
        "00112233445566778899AABBCCDDEEFF00112233445566778899aabbccddeeff",
        &hash,
    );
    let index = PsfIndex::parse(&xml).unwrap();
    let source = &index.files[0].sources[0];
    assert_eq!(psf::read_source(&payload, source).unwrap(), &payload[..17]);
    let mut changed = payload.clone();
    changed[3] ^= 1;
    let error = psf::read_source(&changed, source).unwrap_err();
    assert_eq!(
        error.kind,
        ErrorKind::HashMismatch {
            algorithm: "SHA-256"
        }
    );
    let error = psf::read_source(&payload[..10].to_vec(), source).unwrap_err();
    assert_eq!(error.kind, ErrorKind::UnexpectedEnd);
}
