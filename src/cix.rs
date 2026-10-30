//! The PSF index (`express.psf.cix.xml`).
//!
//! The CBS package of an update has an index of its PSF payload file. The index has one
//! `File` element for each payload, with the name, the length and the SHA-256 hash of the
//! target, and one or more `Source` elements with the type, the offset and the length of the
//! bytes in the PSF file:
//!
//! ```xml
//! <Container name="kb5043080-baseless.psf" type="PSF" length="..." xmlns="urn:ContainerIndex">
//!   <Files>
//!     <File id="1" name="amd64_..._10.0.26100.1591_none_...\f\apisetschema.dll" length="4538"
//!           time="133700000000000000" attr="128">
//!       <Hash alg="SHA256" value="..." />
//!       <Delta>
//!         <Source type="RAW" offset="1540743007" length="4538">
//!           <Hash alg="SHA256" value="..." />
//!         </Source>
//!       </Delta>
//!     </File>
//!   </Files>
//! </Container>
//! ```
//!
//! The offsets are from the start of the PSF file.

use crate::error::{Error, Result};
use quick_xml::XmlVersion;
use quick_xml::events::{BytesStart, Event};
use quick_xml::reader::Reader;

/// A parsed PSF index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PsfIndex {
    /// The name of the PSF file (the `name` attribute of `Container`).
    pub name: String,
    /// The container type (`PSF`).
    pub container_type: String,
    /// The size of the PSF file, in bytes.
    pub length: u64,
    /// The payload files in document order.
    pub files: Vec<PsfFile>,
}

/// A payload file in a PSF index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PsfFile {
    /// The `id` attribute.
    pub id: Option<u64>,
    /// The name, for example `amd64_..._none_...\f\apisetschema.dll`.
    pub name: String,
    /// The size of the file, in bytes.
    pub length: u64,
    /// The file time (`FILETIME`), if the index has it.
    pub time: Option<u64>,
    /// The Windows file attributes, if the index has them.
    pub attributes: Option<u32>,
    /// The hash of the file.
    pub hash: Option<Hash>,
    /// The sources of the bytes in the PSF file.
    pub sources: Vec<Source>,
}

impl PsfFile {
    /// Return the SHA-256 hash of the file, if the index has one.
    #[must_use]
    pub fn sha256(&self) -> Option<[u8; 32]> {
        self.hash.as_ref().and_then(Hash::sha256)
    }
}

/// The location of the bytes of a payload in the PSF file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    /// The format of the bytes.
    pub kind: SourceKind,
    /// The offset in the PSF file.
    pub offset: u64,
    /// The size, in bytes.
    pub length: u64,
    /// The hash of the bytes in the PSF file.
    pub hash: Option<Hash>,
}

impl Source {
    /// Return the SHA-256 hash of the bytes, if the index has one.
    #[must_use]
    pub fn sha256(&self) -> Option<[u8; 32]> {
        self.hash.as_ref().and_then(Hash::sha256)
    }
}

/// The format of a source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceKind {
    /// The bytes as they are. A forward delta (`f\`) has a CRC-32 prefix and a PA31 delta.
    Raw,
    /// A PA30 delta.
    Pa30,
    /// An other type.
    Other(String),
}

/// A hash value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hash {
    /// The algorithm name, for example `SHA256`.
    pub algorithm: String,
    /// The hash value.
    pub value: Vec<u8>,
}

impl Hash {
    /// Return the value if the algorithm is SHA-256.
    #[must_use]
    pub fn sha256(&self) -> Option<[u8; 32]> {
        if self.algorithm.eq_ignore_ascii_case("SHA256") {
            self.value.as_slice().try_into().ok()
        } else {
            None
        }
    }
}

impl PsfIndex {
    /// Parse the XML text of a PSF index.
    ///
    /// # Errors
    ///
    /// Return an error if the XML is not well-formed, if a required attribute is missing, or
    /// if a number or a hash value is not valid.
    pub fn parse(xml: &str) -> Result<Self> {
        let mut reader = Reader::from_str(xml.trim_start_matches('\u{feff}'));
        let mut index: Option<Self> = None;
        let mut file: Option<PsfFile> = None;
        let mut source: Option<Source> = None;
        loop {
            let position = reader.buffer_position();
            let event = reader.read_event().map_err(|e| {
                Error::invalid_data("the PSF index is not well-formed XML")
                    .at_offset(position)
                    .with_details(e.to_string())
            })?;
            let context = |e: Error| e.in_structure("PSF index").at_offset(position);
            match event {
                Event::Start(element) => {
                    handle_start(&element, &mut index, &mut file, &mut source).map_err(context)?;
                }
                Event::Empty(element) => {
                    handle_start(&element, &mut index, &mut file, &mut source).map_err(context)?;
                    let name = element.local_name();
                    handle_end(name.as_ref(), &mut index, &mut file, &mut source)
                        .map_err(context)?;
                }
                Event::End(element) => {
                    handle_end(
                        element.local_name().as_ref(),
                        &mut index,
                        &mut file,
                        &mut source,
                    )
                    .map_err(context)?;
                }
                Event::Eof => break,
                _ => {}
            }
        }
        index.ok_or_else(|| Error::invalid_data("the XML has no Container element"))
    }
}

/// Handle a start tag or an empty tag.
fn handle_start(
    element: &BytesStart<'_>,
    index: &mut Option<PsfIndex>,
    file: &mut Option<PsfFile>,
    source: &mut Option<Source>,
) -> Result<()> {
    match element.local_name().as_ref() {
        "Container" => {
            *index = Some(PsfIndex {
                name: required(element, "name")?,
                container_type: required(element, "type")?,
                length: number(element, "length")?.ok_or_else(|| missing("Container", "length"))?,
                files: Vec::new(),
            });
        }
        "File" => {
            *file = Some(PsfFile {
                id: number(element, "id")?,
                name: required(element, "name")?,
                length: number(element, "length")?.ok_or_else(|| missing("File", "length"))?,
                time: number(element, "time")?,
                attributes: number(element, "attr")?
                    .map(u32::try_from)
                    .transpose()
                    .map_err(|_| Error::invalid_data("the attr value is too large"))?,
                hash: None,
                sources: Vec::new(),
            });
        }
        "Source" => {
            let kind = match required(element, "type")?.as_str() {
                "RAW" => SourceKind::Raw,
                "PA30" => SourceKind::Pa30,
                other => SourceKind::Other(other.to_owned()),
            };
            *source = Some(Source {
                kind,
                offset: number(element, "offset")?.ok_or_else(|| missing("Source", "offset"))?,
                length: number(element, "length")?.ok_or_else(|| missing("Source", "length"))?,
                hash: None,
            });
        }
        "Hash" => {
            let hash = Hash {
                algorithm: required(element, "alg")?,
                value: hex(&required(element, "value")?)?,
            };
            if let Some(source) = source {
                source.hash = Some(hash);
            } else if let Some(file) = file {
                file.hash = Some(hash);
            }
        }
        _ => {}
    }
    Ok(())
}

/// Handle an end tag.
fn handle_end(
    name: &str,
    index: &mut Option<PsfIndex>,
    file: &mut Option<PsfFile>,
    source: &mut Option<Source>,
) -> Result<()> {
    match name {
        "Source" => {
            if let (Some(done), Some(file)) = (source.take(), file.as_mut()) {
                file.sources.push(done);
            }
        }
        "File" => {
            let Some(done) = file.take() else {
                return Ok(());
            };
            let Some(index) = index.as_mut() else {
                return Err(Error::invalid_data(
                    "a File element is outside the Container",
                ));
            };
            index.files.push(done);
        }
        _ => {}
    }
    Ok(())
}

/// Make the error for a missing attribute.
fn missing(element: &str, attribute: &str) -> Error {
    Error::invalid_data(format!(
        "the {element} element has no {attribute} attribute"
    ))
}

/// Return the value of an attribute, if the element has it.
fn attribute(element: &BytesStart<'_>, name: &str) -> Result<Option<String>> {
    for attr in element.attributes() {
        let attr = attr.map_err(|e| Error::invalid_data(format!("attribute: {e}")))?;
        if attr.key.local_name().as_ref() == name {
            let value = attr
                .normalized_value(XmlVersion::Implicit1_0)
                .map_err(|e| Error::invalid_data(format!("attribute {name}: {e}")))?;
            return Ok(Some(value.into_owned()));
        }
    }
    Ok(None)
}

/// Return the value of a required attribute.
fn required(element: &BytesStart<'_>, name: &str) -> Result<String> {
    let local = element.local_name();
    attribute(element, name)?.ok_or_else(|| missing(local.as_ref(), name))
}

/// Return the value of a decimal attribute, if the element has it.
fn number(element: &BytesStart<'_>, name: &str) -> Result<Option<u64>> {
    attribute(element, name)?
        .map(|value| {
            value.parse().map_err(|_| {
                Error::invalid_data(format!("the {name} value {value:?} is not a number"))
            })
        })
        .transpose()
}

/// Decode a hexadecimal string.
fn hex(text: &str) -> Result<Vec<u8>> {
    let digit = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(Error::invalid_data(format!(
            "the hash value {text:?} is not hexadecimal"
        )));
    }
    let (pairs, _) = bytes.as_chunks::<2>();
    pairs
        .iter()
        .map(|pair| match (digit(pair[0]), digit(pair[1])) {
            (Some(high), Some(low)) => Ok(high << 4 | low),
            _ => Err(Error::invalid_data(format!(
                "the hash value {text:?} is not hexadecimal"
            ))),
        })
        .collect()
}
