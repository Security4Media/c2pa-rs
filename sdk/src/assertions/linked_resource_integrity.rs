// Copyright 2026 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

// Unless required by applicable law or agreed to in writing,
// this software is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR REPRESENTATIONS OF ANY KIND, either express or
// implied. See the LICENSE-MIT and LICENSE-APACHE files for the
// specific language governing permissions and limitations under
// each license.

//! The linked resource integrity assertion (`c2pa.linked-resource-integrity`, C2PA 2.5).
//!
//! The assertion hash-binds resources that an asset references but does not contain, such
//! as the scripts and stylesheets of an HTML page or the textures of a MaterialX scene. It is
//! the C2PA counterpart of W3C Subresource Integrity for formats without such a mechanism.
//!
//! Besides the public types, this module holds the structural checks of the spec's
//! validation procedure ([`LinkedResourceIntegrity::check`]). They work on the raw CBOR
//! rather than on the typed struct so that one bad entry does not hide the others, and so
//! that the typed decoder's leniency (it accepts base64 text for hashes) never weakens
//! validation.

use std::{
    collections::BTreeMap,
    fmt,
    io::{self, Read, Write},
};

use c2pa_cbor::Value;
use serde::{
    de::{self, SeqAccess, Visitor},
    ser::SerializeMap,
    Deserialize, Deserializer, Serialize, Serializer,
};

use crate::{
    assertion::{Assertion, AssertionBase, AssertionCbor, AssertionData},
    assertions::{labels, AssertionMetadata, AssetType, UriHashedDataMap},
    crypto::base64,
    error::{Error, Result},
    utils::{
        hash_utils::{hash_size_by_alg, Hasher},
        uri_utils::has_parent_segment,
    },
    validation_status,
};

const EXTERNAL_RESOURCES: &str = "externalResources";
const RELATIVE_RESOURCES: &str = "relativeResources";

/// Hash algorithms on the deprecated list of the spec's Hashing section. The list is
/// empty in C2PA 2.5.
const DEPRECATED_HASH_ALGORITHMS: &[&str] = &[];

/// A linked resource integrity assertion: hashes of resources that an asset references by
/// URI, recorded at signing time.
///
/// The resources are either all referenced by absolute URL ([`LinkedResources::External`])
/// or all by a URI relative to the asset ([`LinkedResources::Relative`]). The
/// [`Builder`](crate::Builder) always adds this assertion to `created_assertions`, the only
/// place the spec allows it.
///
/// See [Linked resource integrity - C2PA Technical Specification](https://spec.c2pa.org/specifications/specifications/2.5/specs/C2PA_Specification.html#linked_resource_integrity_assertion).
///
/// # Examples
///
/// An HTML page that loads a script and a stylesheet from absolute URLs:
///
/// ```
/// # use c2pa::{assertions::{ExternalResource, LinkedResourceIntegrity}, Builder, Result};
/// # fn main() -> Result<()> {
/// let script = b"console.log('hello');";
/// let style = b"body { margin: 0 }";
///
/// let lri = LinkedResourceIntegrity::external(vec![
///     ExternalResource::from_bytes("https://example.com/assets/main.js", "sha256", script)?
///         .set_dc_format("text/javascript"),
///     ExternalResource::from_bytes("https://example.com/assets/style.css", "sha256", style)?
///         .set_dc_format("text/css"),
/// ])
/// .set_all_uris_included(true);
///
/// let mut builder = Builder::default();
/// builder.add_assertion(LinkedResourceIntegrity::LABEL, &lri)?;
/// # Ok(())
/// # }
/// ```
///
/// A scene that references a texture relative to its own location. Start from an empty list
/// and let [`add_relative_from_bytes`](Self::add_relative_from_bytes) hash each resource with
/// the shared algorithm:
///
/// ```
/// # use c2pa::{assertions::LinkedResourceIntegrity, Result};
/// # fn main() -> Result<()> {
/// let albedo = b"texture bytes";
///
/// let mut lri =
///     LinkedResourceIntegrity::relative("sha256", Vec::new()).set_all_uris_included(false);
/// lri.add_relative_from_bytes("./scenes/albedo.png", albedo)?
///     .dc_format = Some("image/png".to_owned());
/// # Ok(())
/// # }
/// ```
///
/// In a JSON manifest definition, give each `hash` as plain base64 or as a `b64'<base64>'`
/// string; either way it is stored as a CBOR byte string:
///
/// ```json
/// {
///   "label": "c2pa.linked-resource-integrity",
///   "data": {
///     "resources": {
///       "relativeResources": [
///         {
///           "uri": "./scenes/albedo.png",
///           "hash": "kQ7J3p+xYL8mHkR4Y0vKDg2aWHC5cGxDJSFj5oozmQI=",
///           "dc:format": "image/png"
///         }
///       ],
///       "alg": "sha256"
///     },
///     "allURIsIncluded": false
///   }
/// }
/// ```
///
/// # Validation
///
/// Reading an asset applies the spec's validation procedure to this assertion, with two
/// readings worth knowing:
///
/// - The `alg` of every `externalResources` entry is checked whether or not the resource is
///   retrieved, and an unsupported one rejects the claim with `algorithm.unsupported`. The spec
///   requires the check only for entries that a validator retrieves. Because its list of
///   allowed algorithms is closed, an entry with any other algorithm is non-conforming anyway.
/// - An `alg` next to `externalResources` makes the assertion malformed, like a `resources`
///   map with both lists, because it matches neither shape the spec allows. Other unknown keys
///   are ignored.
///
/// <div class="warning">
///
/// **Experimental.** This type is available only with the `unstable_linked_resource_integrity`
/// feature enabled. It is exempt from this crate's usual semantic-versioning stability
/// guarantees and may change in a backward-incompatible way, or be removed entirely, in any
/// release.
///
/// </div>
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct LinkedResourceIntegrity {
    /// The hashed resources.
    pub resources: LinkedResources,

    /// `true` when every URI that the container format makes the processor fetch or embed has
    /// an entry in [`resources`](Self::resources). Navigational links do not count.
    ///
    /// Absent or `false` means the asset may reference other resources.
    #[serde(
        rename = "allURIsIncluded",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub all_uris_included: Option<bool>,

    /// Optional metadata about the assertion.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<AssertionMetadata>,
}

impl LinkedResourceIntegrity {
    /// Label of the linked resource integrity assertion.
    pub const LABEL: &'static str = labels::LINKED_RESOURCE_INTEGRITY;

    /// Creates an assertion for resources referenced by absolute URL.
    ///
    /// The spec requires at least one resource; an empty list fails when the
    /// [`Builder`](crate::Builder) signs.
    pub fn external(resources: Vec<ExternalResource>) -> Self {
        Self::new(LinkedResources::External(resources))
    }

    /// Creates an assertion for resources referenced relative to the asset, all hashed with
    /// `alg`.
    ///
    /// The usual call passes an empty list, then adds each resource with
    /// [`add_relative_from_bytes`](Self::add_relative_from_bytes) or
    /// [`add_relative_from_stream`](Self::add_relative_from_stream), which hash it with `alg`.
    /// Entries passed here must already hold a hash computed with `alg`; an entry without a
    /// `hash` makes the [`Builder`](crate::Builder) fail to sign.
    pub fn relative(alg: impl Into<String>, resources: Vec<UriHashedDataMap>) -> Self {
        Self::new(LinkedResources::Relative {
            alg: alg.into(),
            resources,
        })
    }

    fn new(resources: LinkedResources) -> Self {
        Self {
            resources,
            all_uris_included: None,
            metadata: None,
        }
    }

    /// Hashes `data` with the shared `alg` of the relative resources and adds an entry for
    /// `uri` with that hash and the data size.
    ///
    /// Returns the new entry so that its optional fields, such as `dc_format`, can be set.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BadParam`] if this assertion lists external resources, or
    /// [`Error::UnsupportedType`] if `alg` is not a supported hash algorithm.
    pub fn add_relative_from_bytes(
        &mut self,
        uri: impl Into<String>,
        mut data: &[u8],
    ) -> Result<&mut UriHashedDataMap> {
        self.add_relative_from_stream(uri, &mut data)
    }

    /// Hashes everything read from `stream` with the shared `alg` of the relative resources
    /// and adds an entry for `uri` with that hash and the number of bytes read.
    ///
    /// Returns the new entry so that its optional fields, such as `dc_format`, can be set.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BadParam`] if this assertion lists external resources,
    /// [`Error::UnsupportedType`] if `alg` is not a supported hash algorithm, or an I/O error
    /// from `stream`.
    pub fn add_relative_from_stream<R: Read + ?Sized>(
        &mut self,
        uri: impl Into<String>,
        stream: &mut R,
    ) -> Result<&mut UriHashedDataMap> {
        let LinkedResources::Relative { alg, resources } = &mut self.resources else {
            return Err(Error::BadParam(
                "relative resources cannot be added to an assertion that lists external resources"
                    .to_owned(),
            ));
        };

        let (hash, size) = hash_resource(alg, stream)?;
        let mut entry = UriHashedDataMap::new(uri.into());
        entry.hash = Some(hash);
        entry.size = Some(size);

        let index = resources.len();
        resources.push(entry);
        Ok(&mut resources[index])
    }

    /// Sets whether every fetched or embedded URI of the asset has an entry.
    pub fn set_all_uris_included(mut self, all_uris_included: bool) -> Self {
        self.all_uris_included = Some(all_uris_included);
        self
    }

    /// Sets optional metadata about the assertion.
    pub fn set_metadata(mut self, metadata: AssertionMetadata) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Applies the structural steps of the spec's validation procedure to `assertion`.
    ///
    /// Checks every entry, so one bad entry does not hide problems in the others, and lists
    /// the well-formed entries, which each need exactly one terminal status. An entry counts
    /// as well-formed when its required fields are present with the right types, even if its
    /// algorithm or URI is then rejected.
    ///
    /// The `alg` of each `externalResources` entry is checked here, without retrieval, and an
    /// `alg` next to `externalResources` is malformed; the type docs explain both choices.
    /// Unknown keys are otherwise ignored.
    ///
    /// Placement in `created_assertions` is not checked here because it depends on the claim.
    pub(crate) fn check(assertion: &Assertion) -> LinkedResourceCheck {
        let mut check = LinkedResourceCheck::default();

        let AssertionData::Cbor(data) = assertion.decode_data() else {
            check.malformed("assertion data is not CBOR", None);
            return check;
        };
        let root = match c2pa_cbor::from_slice::<Value>(data) {
            Ok(Value::Map(root)) => root,
            Ok(_) => {
                check.malformed("assertion is not a CBOR map", None);
                return check;
            }
            Err(err) => {
                check.malformed(format!("assertion could not be decoded: {err}"), None);
                return check;
            }
        };

        let resources = match map_field(&root, "resources") {
            Some(Value::Map(resources)) => resources,
            Some(_) => {
                check.malformed("`resources` is not a map", None);
                return check;
            }
            None => {
                check.malformed("`resources` is missing", None);
                return check;
            }
        };

        match (
            map_field(resources, EXTERNAL_RESOURCES),
            map_field(resources, RELATIVE_RESOURCES),
        ) {
            (Some(_), None) if map_field(resources, "alg").is_some() => check.malformed(
                "`resources` has `externalResources` with an `alg`, which only \
                 `relativeResources` takes",
                None,
            ),
            (Some(external), None) => check.external(external),
            (None, Some(relative)) => check.relative(relative, map_field(resources, "alg")),
            (Some(_), Some(_)) => check.malformed(
                "`resources` has both `externalResources` and `relativeResources`",
                None,
            ),
            (None, None) => check.malformed(
                "`resources` has neither `externalResources` nor `relativeResources`",
                None,
            ),
        }

        check
    }
}

impl AssertionCbor for LinkedResourceIntegrity {}

impl AssertionBase for LinkedResourceIntegrity {
    const LABEL: &'static str = Self::LABEL;

    fn to_assertion(&self) -> Result<Assertion> {
        Self::to_cbor_assertion(self)
    }

    fn from_assertion(assertion: &Assertion) -> Result<Self> {
        Self::from_cbor_assertion(assertion)
    }
}

/// The `resources` field of a [`LinkedResourceIntegrity`] assertion.
///
/// It is serialized as a map with either an `externalResources` array, or a
/// `relativeResources` array and an `alg`. Deserialization rejects any other shape, empty
/// arrays, and an empty `data_types` list on an entry.
///
/// <div class="warning">
///
/// **Experimental.** This type is available only with the `unstable_linked_resource_integrity`
/// feature enabled. It is exempt from this crate's usual semantic-versioning stability
/// guarantees and may change in a backward-incompatible way, or be removed entirely, in any
/// release.
///
/// </div>
#[derive(Debug, PartialEq, Eq)]
pub enum LinkedResources {
    /// Resources referenced by absolute URL, each with its own hash algorithm
    /// (`externalResources`).
    External(Vec<ExternalResource>),

    /// Resources referenced by a URI relative to the asset, all hashed with one algorithm
    /// (`relativeResources` and `alg`).
    ///
    /// A validator resolves each `uri` against the location of the asset, following the
    /// container format's rules. When reading, give that location with
    /// [`Reader::with_linked_resource_base`](crate::Reader::with_linked_resource_base).
    Relative {
        /// Hash algorithm identifier for every entry, such as `"sha256"`.
        alg: String,

        /// The resources. Each entry needs a `hash`.
        resources: Vec<UriHashedDataMap>,
    },
}

impl Serialize for LinkedResources {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        match self {
            Self::External(resources) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry(EXTERNAL_RESOURCES, resources)?;
                map.end()
            }
            Self::Relative { alg, resources } => {
                let mut map = serializer.serialize_map(Some(2))?;
                map.serialize_entry(RELATIVE_RESOURCES, resources)?;
                map.serialize_entry("alg", alg)?;
                map.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for LinkedResources {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Wire {
            #[serde(rename = "externalResources")]
            external: Option<Vec<ExternalResource>>,
            #[serde(rename = "relativeResources")]
            relative: Option<Vec<RelativeResourceWire>>,
            alg: Option<String>,
        }

        let wire = Wire::deserialize(deserializer)?;
        match (wire.external, wire.relative, wire.alg) {
            (Some(_), None, Some(_)) => Err(de::Error::custom(
                "alg belongs with relativeResources, not externalResources",
            )),
            (Some(external), None, None) if !external.is_empty() => Ok(Self::External(external)),
            (None, Some(relative), Some(alg)) if !relative.is_empty() => Ok(Self::Relative {
                alg,
                resources: relative.into_iter().map(UriHashedDataMap::from).collect(),
            }),
            (Some(_), Some(_), _) => Err(de::Error::custom(
                "resources must not have both externalResources and relativeResources",
            )),
            (Some(_), None, None) | (None, Some(_), Some(_)) => Err(de::Error::custom(
                "resources must list at least one resource",
            )),
            (None, Some(_), None) => Err(de::Error::custom("relativeResources requires alg")),
            (None, None, _) => Err(de::Error::custom(
                "resources must have externalResources or relativeResources",
            )),
        }
    }
}

/// A `relativeResources` entry as decoded. Unlike [`UriHashedDataMap`], its `hash` is
/// required, as in the spec's `uri-hashed-data-map`, and may be given as base64 text.
#[derive(Deserialize)]
struct RelativeResourceWire {
    uri: String,
    #[serde(deserialize_with = "deserialize_hash")]
    hash: Vec<u8>,
    size: Option<u64>,
    #[serde(rename = "dc:format")]
    dc_format: Option<String>,
    #[serde(default, deserialize_with = "deserialize_data_types")]
    data_types: Option<Vec<AssetType>>,
}

impl From<RelativeResourceWire> for UriHashedDataMap {
    fn from(wire: RelativeResourceWire) -> Self {
        Self {
            uri: wire.uri,
            hash: Some(wire.hash),
            size: wire.size,
            dc_format: wire.dc_format,
            data_types: wire.data_types,
        }
    }
}

/// An `externalResources` entry: a resource referenced by absolute URL and hashed with its
/// own algorithm (the spec's `hashed-ext-uri-map`).
///
/// Unlike [`HashedExtUri`](crate::assertions::HashedExtUri), which serves cloud data, this
/// type keeps the `dc:format` and `size` fields.
///
/// <div class="warning">
///
/// **Experimental.** This type is available only with the `unstable_linked_resource_integrity`
/// feature enabled. It is exempt from this crate's usual semantic-versioning stability
/// guarantees and may change in a backward-incompatible way, or be removed entirely, in any
/// release.
///
/// </div>
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalResource {
    /// Absolute `http` or `https` URL of the resource, as the asset references it.
    pub url: String,

    /// Hash algorithm identifier, such as `"sha256"`.
    pub alg: String,

    /// Hash of the resource content, serialized as a CBOR byte string.
    ///
    /// Deserialization also accepts base64 text, plain or as `b64'<base64>'`.
    #[serde(
        serialize_with = "serde_bytes::serialize",
        deserialize_with = "deserialize_hash"
    )]
    pub hash: Vec<u8>,

    /// IANA media type of the resource.
    #[serde(rename = "dc:format", default, skip_serializing_if = "Option::is_none")]
    pub dc_format: Option<String>,

    /// Size of the resource in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,

    /// Additional information about the kind of data in the resource. When present, the list
    /// must not be empty.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_data_types"
    )]
    pub data_types: Option<Vec<AssetType>>,
}

impl ExternalResource {
    /// Creates an entry from a precomputed hash.
    pub fn new(url: impl Into<String>, alg: impl Into<String>, hash: Vec<u8>) -> Self {
        Self {
            url: url.into(),
            alg: alg.into(),
            hash,
            dc_format: None,
            size: None,
            data_types: None,
        }
    }

    /// Creates an entry by hashing `data` with `alg`, and records the data size.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedType`] if `alg` is not a supported hash algorithm.
    pub fn from_bytes(
        url: impl Into<String>,
        alg: impl Into<String>,
        mut data: &[u8],
    ) -> Result<Self> {
        Self::from_stream(url, alg, &mut data)
    }

    /// Creates an entry by hashing everything read from `stream` with `alg`, and records the
    /// number of bytes read as the size.
    ///
    /// The bytes must be the resource as delivered, after any transfer or content encoding is
    /// removed, because that is what a validator hashes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedType`] if `alg` is not a supported hash algorithm, or an
    /// I/O error from `stream`.
    pub fn from_stream<R: Read + ?Sized>(
        url: impl Into<String>,
        alg: impl Into<String>,
        stream: &mut R,
    ) -> Result<Self> {
        let alg = alg.into();
        let (hash, size) = hash_resource(&alg, stream)?;
        Ok(Self::new(url, alg, hash).set_size(size))
    }

    /// Sets the IANA media type of the resource.
    pub fn set_dc_format(mut self, dc_format: impl Into<String>) -> Self {
        self.dc_format = Some(dc_format.into());
        self
    }

    /// Sets the size of the resource in bytes.
    pub fn set_size(mut self, size: u64) -> Self {
        self.size = Some(size);
        self
    }

    /// Sets additional information about the kind of data in the resource.
    ///
    /// The spec requires at least one type; an empty list fails when the
    /// [`Builder`](crate::Builder) signs.
    pub fn set_data_types(mut self, data_types: Vec<AssetType>) -> Self {
        self.data_types = Some(data_types);
        self
    }
}

/// Hashes everything `stream` yields with `alg` and counts the bytes.
///
/// Uses the [`Hasher`] directly rather than `hash_stream_by_alg`, which needs `Seek` and
/// refuses empty input; an empty stylesheet is still a valid resource.
pub(crate) fn hash_resource<R: Read + ?Sized>(alg: &str, stream: &mut R) -> Result<(Vec<u8>, u64)> {
    struct HashWriter(Hasher);

    impl Write for HashWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.update(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let mut writer = HashWriter(Hasher::new(alg)?);
    let size = io::copy(stream, &mut writer)?;
    Ok((Hasher::finalize(writer.0), size))
}

/// Deserializes a hash from a byte string, a sequence of bytes, or base64 text.
///
/// Text is accepted so that JSON manifest definitions can give hashes as base64, either
/// plain or as a `b64'<base64>'` string.
fn deserialize_hash<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Vec<u8>, D::Error> {
    struct HashVisitor;

    impl<'de> Visitor<'de> for HashVisitor {
        type Value = Vec<u8>;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("a byte string or a base64 string")
        }

        fn visit_bytes<E: de::Error>(self, v: &[u8]) -> std::result::Result<Self::Value, E> {
            Ok(v.to_vec())
        }

        fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> std::result::Result<Self::Value, E> {
            Ok(v)
        }

        fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Self::Value, E> {
            match base64::decode_b64_wrapped(v) {
                Some(bytes) => Ok(bytes),
                None => base64::decode(v)
                    .map_err(|err| E::custom(format!("hash is not valid base64: {err}"))),
            }
        }

        fn visit_seq<A: SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> std::result::Result<Self::Value, A::Error> {
            let mut bytes = Vec::with_capacity(seq.size_hint().unwrap_or(0));
            while let Some(byte) = seq.next_element::<u8>()? {
                bytes.push(byte);
            }
            Ok(bytes)
        }
    }

    deserializer.deserialize_any(HashVisitor)
}

/// Deserializes an optional `data_types` list, which the spec requires to be non-empty when
/// present.
fn deserialize_data_types<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<Vec<AssetType>>, D::Error> {
    match Option::<Vec<AssetType>>::deserialize(deserializer)? {
        Some(data_types) if data_types.is_empty() => {
            Err(de::Error::custom("data_types must list at least one type"))
        }
        data_types => Ok(data_types),
    }
}

/// The outcome of [`LinkedResourceIntegrity::check`].
#[derive(Debug, Default, PartialEq)]
pub(crate) struct LinkedResourceCheck {
    /// Problems found, in the order the procedure finds them.
    pub(crate) findings: Vec<LinkedResourceFinding>,

    /// Entries whose required fields are present, in assertion order.
    pub(crate) entries: Vec<LinkedResourceEntry>,
}

impl LinkedResourceCheck {
    fn malformed(&mut self, explanation: impl Into<String>, resource_url: Option<&str>) {
        self.findings.push(LinkedResourceFinding::Malformed {
            explanation: explanation.into(),
            resource_url: resource_url.map(str::to_owned),
        });
    }

    fn algorithm(&mut self, alg: &str, resource_url: Option<&str>) {
        // The allowed list is exactly the set of algorithms the SDK can compute.
        if hash_size_by_alg(alg).is_ok() {
            return;
        }
        let alg = alg.to_owned();
        let resource_url = resource_url.map(str::to_owned);
        self.findings
            .push(if DEPRECATED_HASH_ALGORITHMS.contains(&alg.as_str()) {
                LinkedResourceFinding::DeprecatedAlgorithm { alg, resource_url }
            } else {
                LinkedResourceFinding::UnsupportedAlgorithm { alg, resource_url }
            });
    }

    fn external(&mut self, list: &Value) {
        let Some(items) = self.non_empty_array(list, EXTERNAL_RESOURCES) else {
            return;
        };

        for (index, item) in items.iter().enumerate() {
            let Some(entry) =
                self.decode_entry::<ExternalResource>(item, EXTERNAL_RESOURCES, index, "url")
            else {
                continue;
            };
            self.algorithm(&entry.alg, Some(&entry.url));
            self.entries.push(LinkedResourceEntry::External(entry));
        }
    }

    fn relative(&mut self, list: &Value, alg: Option<&Value>) {
        let Some(items) = self.non_empty_array(list, RELATIVE_RESOURCES) else {
            return;
        };
        let Some(Value::Text(alg)) = alg else {
            self.malformed(
                format!("`{RELATIVE_RESOURCES}` requires a text `alg` alongside it"),
                None,
            );
            return;
        };
        self.algorithm(alg, None);

        for (index, item) in items.iter().enumerate() {
            let Some(wire) =
                self.decode_entry::<RelativeResourceWire>(item, RELATIVE_RESOURCES, index, "uri")
            else {
                continue;
            };
            if has_parent_segment(&wire.uri) {
                self.findings.push(LinkedResourceFinding::InvalidUri {
                    uri: wire.uri.clone(),
                });
            }
            self.entries.push(LinkedResourceEntry::Relative {
                alg: alg.clone(),
                resource: UriHashedDataMap::from(wire),
            });
        }
    }

    fn non_empty_array<'a>(&mut self, value: &'a Value, name: &str) -> Option<&'a [Value]> {
        match value {
            Value::Array(items) if !items.is_empty() => Some(items),
            Value::Array(_) => {
                self.malformed(format!("`{name}` is empty"), None);
                None
            }
            _ => {
                self.malformed(format!("`{name}` is not an array"), None);
                None
            }
        }
    }

    /// Decodes one entry, or records it as malformed.
    ///
    /// `url_key` names the entry's location field (`url` or `uri`), whose value becomes the
    /// `resourceUrl` of a finding. The typed decoders accept base64 text for `hash`, so the
    /// byte-string requirement is checked on the raw value before decoding.
    fn decode_entry<T: de::DeserializeOwned>(
        &mut self,
        item: &Value,
        list: &str,
        index: usize,
        url_key: &str,
    ) -> Option<T> {
        let Value::Map(map) = item else {
            self.malformed(format!("{list}[{index}] is not a map"), None);
            return None;
        };

        let resource_url = match map_field(map, url_key) {
            Some(Value::Text(url)) if !url.is_empty() => Some(url.as_str()),
            _ => None,
        };
        let problem = if resource_url.is_none() {
            Some(format!("`{url_key}` is missing, empty, or not text"))
        } else if !matches!(map_field(map, "hash"), Some(Value::Bytes(_))) {
            Some("`hash` is missing or not a byte string".to_owned())
        } else {
            None
        };
        if let Some(problem) = problem {
            self.malformed(format!("{list}[{index}]: {problem}"), resource_url);
            return None;
        }

        match c2pa_cbor::value::from_value(item.clone()) {
            Ok(entry) => Some(entry),
            Err(err) => {
                self.malformed(format!("{list}[{index}]: {err}"), resource_url);
                None
            }
        }
    }
}

/// A problem that [`LinkedResourceIntegrity::check`] found, mapped to its status code.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum LinkedResourceFinding {
    /// The assertion or one entry does not have the required shape.
    Malformed {
        explanation: String,
        /// The entry's `url` or `uri`, when the problem is in an entry that has one.
        resource_url: Option<String>,
    },

    /// A `relativeResources` URI that could step outside the base location.
    InvalidUri { uri: String },

    /// An algorithm on neither the allowed nor the deprecated list.
    UnsupportedAlgorithm {
        alg: String,
        /// The entry's `url` for an `externalResources` entry; `None` for the shared
        /// `relativeResources` algorithm.
        resource_url: Option<String>,
    },

    /// An algorithm on the deprecated list.
    DeprecatedAlgorithm {
        alg: String,
        /// As for [`UnsupportedAlgorithm`](Self::UnsupportedAlgorithm).
        resource_url: Option<String>,
    },
}

impl LinkedResourceFinding {
    /// The validation status code for this finding.
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::Malformed { .. } => {
                validation_status::ASSERTION_LINKED_RESOURCE_INTEGRITY_MALFORMED
            }
            Self::InvalidUri { .. } => {
                validation_status::ASSERTION_LINKED_RESOURCE_INTEGRITY_INVALID_URI
            }
            Self::UnsupportedAlgorithm { .. } => validation_status::ALGORITHM_UNSUPPORTED,
            Self::DeprecatedAlgorithm { .. } => validation_status::ALGORITHM_DEPRECATED,
        }
    }

    /// Whether the finding rejects the claim. Only a deprecated algorithm is informational.
    pub(crate) fn is_failure(&self) -> bool {
        !matches!(self, Self::DeprecatedAlgorithm { .. })
    }

    /// The `url` or `uri` of the entry the finding is about, if any.
    pub(crate) fn resource_url(&self) -> Option<&str> {
        match self {
            Self::Malformed { resource_url, .. }
            | Self::UnsupportedAlgorithm { resource_url, .. }
            | Self::DeprecatedAlgorithm { resource_url, .. } => resource_url.as_deref(),
            Self::InvalidUri { uri } => Some(uri),
        }
    }

    /// A human-readable description of the finding.
    pub(crate) fn explanation(&self) -> String {
        match self {
            Self::Malformed { explanation, .. } => {
                format!("linked resource integrity assertion is malformed: {explanation}")
            }
            Self::InvalidUri { uri } => {
                format!("linked resource URI has a `..` path segment: {uri}")
            }
            Self::UnsupportedAlgorithm { alg, .. } => {
                format!("unsupported linked resource hash algorithm: {alg}")
            }
            Self::DeprecatedAlgorithm { alg, .. } => {
                format!("deprecated linked resource hash algorithm: {alg}")
            }
        }
    }
}

/// A well-formed entry of a linked resource integrity assertion.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum LinkedResourceEntry {
    /// An `externalResources` entry.
    External(ExternalResource),
    /// A `relativeResources` entry, with the shared `alg` of the list. Its `hash` is always set.
    Relative {
        alg: String,
        resource: UriHashedDataMap,
    },
}

impl LinkedResourceEntry {
    /// The entry's `url` or `uri`, which its statuses carry as `resourceUrl`.
    pub(crate) fn resource_url(&self) -> &str {
        match self {
            Self::External(entry) => &entry.url,
            Self::Relative { resource, .. } => &resource.uri,
        }
    }

    /// The hash algorithm: the entry's own `alg`, or the shared one of `relativeResources`.
    pub(crate) fn alg(&self) -> &str {
        match self {
            Self::External(entry) => &entry.alg,
            Self::Relative { alg, .. } => alg,
        }
    }

    /// The hash recorded at signing time.
    pub(crate) fn hash(&self) -> &[u8] {
        match self {
            Self::External(entry) => &entry.hash,
            Self::Relative { resource, .. } => resource.hash.as_deref().unwrap_or_default(),
        }
    }

    /// The declared size in bytes, if any.
    pub(crate) fn size(&self) -> Option<u64> {
        match self {
            Self::External(entry) => entry.size,
            Self::Relative { resource, .. } => resource.size,
        }
    }

    /// The declared media type (`dc:format`), if any.
    pub(crate) fn dc_format(&self) -> Option<&str> {
        match self {
            Self::External(entry) => entry.dc_format.as_deref(),
            Self::Relative { resource, .. } => resource.dc_format.as_deref(),
        }
    }
}

/// Returns the value for a text `key` of a CBOR map.
fn map_field<'a>(map: &'a BTreeMap<Value, Value>, key: &str) -> Option<&'a Value> {
    map.iter()
        .find_map(|(k, v)| matches!(k, Value::Text(text) if text == key).then_some(v))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use std::{assert_matches, io::Cursor};

    use serde_json::json;

    use super::*;
    use crate::utils::{hash_utils::hash_by_alg, json_b64::from_json_b64};

    const MAIN_JS_HASH: &str = "Hf0IgeqbL0m+FTTLpUWwsDGR8pvhUR1AlwvaXjQ0qGY=";
    const STYLE_CSS_HASH: &str = "zP84FPSremIrAQHlhw+hRYQdZp/+KggnD0W8opXlIQQ=";
    const ALBEDO_PNG_HASH: &str = "kQ7J3p+xYL8mHkR4Y0vKDg2aWHC5cGxDJSFj5oozmQI=";

    /// SHA-256 of zero bytes.
    const EMPTY_SHA256: &str = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";

    fn b64(hash: &str) -> String {
        format!("b64'{hash}'")
    }

    /// The HTML example of the spec, in json_b64 form.
    fn html_example() -> serde_json::Value {
        json!({
            "resources": {
                "externalResources": [
                    {
                        "url": "https://northwindtraders.com/assets/main.js",
                        "alg": "sha256",
                        "hash": b64(MAIN_JS_HASH),
                        "dc:format": "text/javascript"
                    },
                    {
                        "url": "https://northwindtraders.com/assets/style.css",
                        "alg": "sha256",
                        "hash": b64(STYLE_CSS_HASH),
                        "dc:format": "text/css"
                    }
                ]
            },
            "allURIsIncluded": true
        })
    }

    /// The MaterialX example of the spec, in json_b64 form.
    fn materialx_example() -> serde_json::Value {
        json!({
            "resources": {
                "relativeResources": [
                    {
                        "uri": "./scenes/albedo.png",
                        "hash": b64(ALBEDO_PNG_HASH),
                        "dc:format": "image/png"
                    }
                ],
                "alg": "sha256"
            },
            "allURIsIncluded": false
        })
    }

    /// A relative-resources assertion listing `uris`, in json_b64 form.
    fn relative_with_uris(uris: &[&str]) -> serde_json::Value {
        let entries: Vec<_> = uris
            .iter()
            .map(|uri| json!({ "uri": uri, "hash": b64(ALBEDO_PNG_HASH) }))
            .collect();
        json!({ "resources": { "relativeResources": entries, "alg": "sha256" } })
    }

    fn cbor_value(json: serde_json::Value) -> Value {
        from_json_b64(json).unwrap()
    }

    fn cbor(json: serde_json::Value) -> Vec<u8> {
        c2pa_cbor::to_vec(&cbor_value(json)).unwrap()
    }

    fn check(json: serde_json::Value) -> LinkedResourceCheck {
        LinkedResourceIntegrity::check(&Assertion::from_data_cbor(
            LinkedResourceIntegrity::LABEL,
            &cbor(json),
        ))
    }

    fn malformed(resource_url: Option<&str>) -> impl Fn(&LinkedResourceFinding) -> bool + '_ {
        move |finding| {
            matches!(
                finding,
                LinkedResourceFinding::Malformed { resource_url: url, .. } if url.as_deref() == resource_url
            )
        }
    }

    fn resource_urls(check: &LinkedResourceCheck) -> Vec<&str> {
        check
            .entries
            .iter()
            .map(LinkedResourceEntry::resource_url)
            .collect()
    }

    fn decode(hash: &str) -> Vec<u8> {
        base64::decode(hash).unwrap()
    }

    #[test]
    fn html_example_round_trips_through_cbor() {
        let lri: LinkedResourceIntegrity = c2pa_cbor::from_slice(&cbor(html_example())).unwrap();

        let LinkedResources::External(resources) = &lri.resources else {
            panic!("expected external resources, got {:?}", lri.resources);
        };
        assert_eq!(
            resources,
            &vec![
                ExternalResource::new(
                    "https://northwindtraders.com/assets/main.js",
                    "sha256",
                    decode(MAIN_JS_HASH),
                )
                .set_dc_format("text/javascript"),
                ExternalResource::new(
                    "https://northwindtraders.com/assets/style.css",
                    "sha256",
                    decode(STYLE_CSS_HASH),
                )
                .set_dc_format("text/css"),
            ]
        );
        assert_eq!(lri.all_uris_included, Some(true));
        assert_eq!(lri.metadata, None);

        let assertion = lri.to_assertion().unwrap();
        assert_eq!(assertion.label(), LinkedResourceIntegrity::LABEL);
        assert_eq!(assertion.mime_type(), "application/cbor");
        let encoded: Value = c2pa_cbor::from_slice(assertion.data()).unwrap();
        assert_eq!(encoded, cbor_value(html_example()));
        assert_eq!(
            LinkedResourceIntegrity::from_assertion(&assertion).unwrap(),
            lri
        );
    }

    #[test]
    fn materialx_example_round_trips_through_cbor() {
        let lri: LinkedResourceIntegrity =
            c2pa_cbor::from_slice(&cbor(materialx_example())).unwrap();

        let LinkedResources::Relative { alg, resources } = &lri.resources else {
            panic!("expected relative resources, got {:?}", lri.resources);
        };
        assert_eq!(alg, "sha256");
        let mut albedo = UriHashedDataMap::new("./scenes/albedo.png".to_owned());
        albedo.hash = Some(decode(ALBEDO_PNG_HASH));
        albedo.dc_format = Some("image/png".to_owned());
        assert_eq!(resources, &vec![albedo]);
        assert_eq!(lri.all_uris_included, Some(false));

        let assertion = lri.to_assertion().unwrap();
        let encoded: Value = c2pa_cbor::from_slice(assertion.data()).unwrap();
        assert_eq!(encoded, cbor_value(materialx_example()));
    }

    #[test]
    fn metadata_round_trips() {
        let lri = LinkedResourceIntegrity::external(vec![ExternalResource::new(
            "https://example.com/app.js",
            "sha256",
            vec![1, 2, 3],
        )])
        .set_metadata(AssertionMetadata::new());

        let assertion = lri.to_assertion().unwrap();
        assert_eq!(
            LinkedResourceIntegrity::from_assertion(&assertion).unwrap(),
            lri
        );
    }

    #[test]
    fn deserialize_rejects_wrong_shapes() {
        let entry = json!({ "url": "https://example.com/a.js", "alg": "sha256", "hash": b64(MAIN_JS_HASH) });
        let relative_entry = json!({ "uri": "a.png", "hash": b64(ALBEDO_PNG_HASH) });
        let cases = [
            ("no resources", json!({ "allURIsIncluded": true })),
            (
                "resources not a map",
                json!({ "resources": [entry.clone()] }),
            ),
            ("neither list", json!({ "resources": {} })),
            (
                "both lists",
                json!({ "resources": {
                    "externalResources": [entry.clone()],
                    "relativeResources": [relative_entry.clone()],
                    "alg": "sha256"
                }}),
            ),
            (
                "empty external list",
                json!({ "resources": { "externalResources": [] } }),
            ),
            (
                "empty relative list",
                json!({ "resources": { "relativeResources": [], "alg": "sha256" } }),
            ),
            (
                "relative list without alg",
                json!({ "resources": { "relativeResources": [relative_entry] } }),
            ),
            (
                "external entry without alg",
                json!({ "resources": { "externalResources": [
                    { "url": "https://example.com/a.js", "hash": b64(MAIN_JS_HASH) }
                ]}}),
            ),
            (
                "external entry without hash",
                json!({ "resources": { "externalResources": [
                    { "url": "https://example.com/a.js", "alg": "sha256" }
                ]}}),
            ),
            (
                "relative entry without hash",
                json!({ "resources": { "relativeResources": [{ "uri": "a.png" }], "alg": "sha256" } }),
            ),
            (
                "alg next to external list",
                json!({ "resources": { "externalResources": [entry.clone()], "alg": "sha256" } }),
            ),
            (
                "external entry with empty data_types",
                json!({ "resources": { "externalResources": [
                    { "url": "https://example.com/a.js", "alg": "sha256", "hash": b64(MAIN_JS_HASH), "data_types": [] }
                ]}}),
            ),
            (
                "relative entry with empty data_types",
                json!({ "resources": {
                    "relativeResources": [{ "uri": "a.png", "hash": b64(ALBEDO_PNG_HASH), "data_types": [] }],
                    "alg": "sha256"
                }}),
            ),
        ];

        for (name, json) in cases {
            assert!(
                c2pa_cbor::from_slice::<LinkedResourceIntegrity>(&cbor(json)).is_err(),
                "{name} should not deserialize"
            );
        }
    }

    #[test]
    fn json_base64_hash_is_stored_as_cbor_byte_string() {
        for hash in [
            json!(MAIN_JS_HASH),
            json!(b64(MAIN_JS_HASH)),
            json!(decode(MAIN_JS_HASH)),
        ] {
            let lri: LinkedResourceIntegrity = serde_json::from_value(json!({
                "resources": { "externalResources": [
                    { "url": "https://example.com/main.js", "alg": "sha256", "hash": hash.clone() }
                ]}
            }))
            .unwrap();

            let assertion = lri.to_assertion().unwrap();
            let encoded: Value = c2pa_cbor::from_slice(assertion.data()).unwrap();
            let expected = cbor_value(json!({
                "resources": { "externalResources": [
                    { "url": "https://example.com/main.js", "alg": "sha256", "hash": b64(MAIN_JS_HASH) }
                ]}
            }));
            assert_eq!(encoded, expected, "hash given as {hash}");
        }

        let relative: LinkedResourceIntegrity = serde_json::from_value(json!({
            "resources": { "relativeResources": [{ "uri": "a.png", "hash": ALBEDO_PNG_HASH }], "alg": "sha256" }
        }))
        .unwrap();
        let encoded: Value =
            c2pa_cbor::from_slice(relative.to_assertion().unwrap().data()).unwrap();
        assert_eq!(
            encoded,
            cbor_value(json!({
                "resources": { "relativeResources": [{ "uri": "a.png", "hash": b64(ALBEDO_PNG_HASH) }], "alg": "sha256" }
            }))
        );
    }

    #[test]
    fn json_hash_must_be_valid_base64() {
        let result = serde_json::from_value::<LinkedResourceIntegrity>(json!({
            "resources": { "externalResources": [
                { "url": "https://example.com/main.js", "alg": "sha256", "hash": "not base64!" }
            ]}
        }));
        assert!(result.is_err());
    }

    #[test]
    fn from_bytes_hashes_data_and_records_size() {
        let data = b"console.log('hello');";
        let resource =
            ExternalResource::from_bytes("https://example.com/app.js", "sha384", data).unwrap();

        assert_eq!(resource.url, "https://example.com/app.js");
        assert_eq!(resource.alg, "sha384");
        assert_eq!(resource.hash, hash_by_alg("sha384", data, None));
        assert_eq!(resource.size, Some(data.len() as u64));
        assert_eq!(resource.dc_format, None);
    }

    #[test]
    fn from_stream_matches_from_bytes() {
        let data = vec![7u8; 200_000];
        let from_stream = ExternalResource::from_stream(
            "https://example.com/big.bin",
            "sha512",
            &mut Cursor::new(&data),
        )
        .unwrap();
        let from_bytes =
            ExternalResource::from_bytes("https://example.com/big.bin", "sha512", &data).unwrap();

        assert_eq!(from_stream, from_bytes);
    }

    #[test]
    fn empty_resource_can_be_hashed() {
        let resource =
            ExternalResource::from_bytes("https://example.com/empty.css", "sha256", b"").unwrap();

        assert_eq!(resource.hash, decode(EMPTY_SHA256));
        assert_eq!(resource.size, Some(0));
    }

    #[test]
    fn unsupported_algorithm_cannot_hash() {
        assert_matches!(
            ExternalResource::from_bytes("https://example.com/app.js", "md5", b"x"),
            Err(Error::UnsupportedType)
        );

        let mut lri = LinkedResourceIntegrity::relative("sha1", Vec::new());
        assert_matches!(
            lri.add_relative_from_bytes("a.png", b"x"),
            Err(Error::UnsupportedType)
        );
    }

    #[test]
    fn set_methods_fill_optional_fields() {
        let data_types = vec![AssetType::new("c2pa.types.dataset", None)];
        let resource = ExternalResource::new("https://example.com/data.bin", "sha256", vec![1])
            .set_dc_format("application/octet-stream")
            .set_size(42)
            .set_data_types(data_types.clone());

        assert_eq!(
            resource.dc_format.as_deref(),
            Some("application/octet-stream")
        );
        assert_eq!(resource.size, Some(42));
        assert_eq!(resource.data_types, Some(data_types));
    }

    #[test]
    fn add_relative_hashes_with_the_shared_algorithm() {
        let texture = b"texture bytes";
        let mut lri = LinkedResourceIntegrity::relative("sha384", Vec::new());
        lri.add_relative_from_bytes("./scenes/albedo.png", texture)
            .unwrap()
            .dc_format = Some("image/png".to_owned());
        lri.add_relative_from_stream("./scenes/normal.png", &mut Cursor::new(b"normal"))
            .unwrap();

        let LinkedResources::Relative { alg, resources } = &lri.resources else {
            panic!("expected relative resources");
        };
        assert_eq!(alg, "sha384");
        assert_eq!(resources.len(), 2);
        assert_eq!(resources[0].uri, "./scenes/albedo.png");
        assert_eq!(
            resources[0].hash,
            Some(hash_by_alg("sha384", texture, None))
        );
        assert_eq!(resources[0].size, Some(texture.len() as u64));
        assert_eq!(resources[0].dc_format.as_deref(), Some("image/png"));
        assert_eq!(
            resources[1].hash,
            Some(hash_by_alg("sha384", b"normal", None))
        );
    }

    #[test]
    fn add_relative_rejects_external_assertion() {
        let mut lri = LinkedResourceIntegrity::external(Vec::new());
        assert_matches!(
            lri.add_relative_from_bytes("a.png", b"x"),
            Err(Error::BadParam(_))
        );
    }

    #[test]
    fn check_accepts_spec_examples() {
        let html = check(html_example());
        assert_eq!(html.findings, Vec::new());
        assert_eq!(
            resource_urls(&html),
            [
                "https://northwindtraders.com/assets/main.js",
                "https://northwindtraders.com/assets/style.css"
            ]
        );

        let materialx = check(materialx_example());
        assert_eq!(materialx.findings, Vec::new());
        assert_eq!(resource_urls(&materialx), ["./scenes/albedo.png"]);
        assert_matches!(
            &materialx.entries[..],
            [LinkedResourceEntry::Relative { alg, resource }]
                if alg == "sha256" && resource.hash == Some(decode(ALBEDO_PNG_HASH))
        );
    }

    #[test]
    fn check_reports_malformed_assertion_shapes() {
        let entry = json!({ "url": "https://example.com/a.js", "alg": "sha256", "hash": b64(MAIN_JS_HASH) });
        let relative_entry = json!({ "uri": "a.png", "hash": b64(ALBEDO_PNG_HASH) });
        let cases = [
            ("not a map", json!([1, 2])),
            ("no resources", json!({ "allURIsIncluded": true })),
            (
                "resources not a map",
                json!({ "resources": [entry.clone()] }),
            ),
            ("neither list", json!({ "resources": {} })),
            (
                "both lists",
                json!({ "resources": {
                    "externalResources": [entry.clone()],
                    "relativeResources": [relative_entry.clone()],
                    "alg": "sha256"
                }}),
            ),
            (
                "empty external list",
                json!({ "resources": { "externalResources": [] } }),
            ),
            (
                "external list not an array",
                json!({ "resources": { "externalResources": entry.clone() } }),
            ),
            (
                "empty relative list",
                json!({ "resources": { "relativeResources": [], "alg": "sha256" } }),
            ),
            (
                "relative list without alg",
                json!({ "resources": { "relativeResources": [relative_entry.clone()] } }),
            ),
            (
                "relative alg not text",
                json!({ "resources": { "relativeResources": [relative_entry], "alg": 256 } }),
            ),
            (
                "alg next to external list",
                json!({ "resources": { "externalResources": [entry], "alg": "sha256" } }),
            ),
        ];

        for (name, json) in cases {
            let check = check(json);
            assert_matches!(&check.findings[..], [finding] if malformed(None)(finding), "{name}");
            assert!(check.entries.is_empty(), "{name} should have no entries");
        }
    }

    #[test]
    fn check_reports_non_cbor_data_as_malformed() {
        let assertion = Assertion::from_data_json(
            LinkedResourceIntegrity::LABEL,
            &serde_json::to_vec(&html_example()).unwrap(),
        )
        .unwrap();
        let check = LinkedResourceIntegrity::check(&assertion);
        assert_matches!(&check.findings[..], [finding] if malformed(None)(finding));

        let garbage =
            Assertion::from_data_cbor(LinkedResourceIntegrity::LABEL, &[0xff, 0x00, 0x13]);
        let check = LinkedResourceIntegrity::check(&garbage);
        assert_matches!(&check.findings[..], [finding] if malformed(None)(finding));
    }

    #[test]
    fn check_reports_malformed_entries_and_keeps_the_others() {
        let url = "https://example.com/a.js";
        let cases = [
            ("not a map", json!("https://example.com/a.js"), None),
            (
                "no url",
                json!({ "alg": "sha256", "hash": b64(MAIN_JS_HASH) }),
                None,
            ),
            (
                "empty url",
                json!({ "url": "", "alg": "sha256", "hash": b64(MAIN_JS_HASH) }),
                None,
            ),
            (
                "no alg",
                json!({ "url": url, "hash": b64(MAIN_JS_HASH) }),
                Some(url),
            ),
            ("no hash", json!({ "url": url, "alg": "sha256" }), Some(url)),
            // Text is not a CBOR byte string, even if it holds base64.
            (
                "text hash",
                json!({ "url": url, "alg": "sha256", "hash": MAIN_JS_HASH }),
                Some(url),
            ),
            (
                "size not a number",
                json!({ "url": url, "alg": "sha256", "hash": b64(MAIN_JS_HASH), "size": "12" }),
                Some(url),
            ),
            (
                "dc:format not text",
                json!({ "url": url, "alg": "sha256", "hash": b64(MAIN_JS_HASH), "dc:format": 1 }),
                Some(url),
            ),
            (
                "empty data_types",
                json!({ "url": url, "alg": "sha256", "hash": b64(MAIN_JS_HASH), "data_types": [] }),
                Some(url),
            ),
        ];
        let good = json!({ "url": "https://example.com/b.css", "alg": "sha256", "hash": b64(STYLE_CSS_HASH) });

        for (name, bad, resource_url) in cases {
            let check = check(json!({ "resources": { "externalResources": [bad, good.clone()] } }));
            assert_matches!(&check.findings[..], [finding] if malformed(resource_url)(finding), "{name}");
            assert_eq!(
                resource_urls(&check),
                ["https://example.com/b.css"],
                "{name}"
            );
        }
    }

    #[test]
    fn check_reports_malformed_relative_entries() {
        let cases = [
            ("no uri", json!({ "hash": b64(ALBEDO_PNG_HASH) }), None),
            (
                "empty uri",
                json!({ "uri": "", "hash": b64(ALBEDO_PNG_HASH) }),
                None,
            ),
            ("no hash", json!({ "uri": "a.png" }), Some("a.png")),
            (
                "text hash",
                json!({ "uri": "a.png", "hash": ALBEDO_PNG_HASH }),
                Some("a.png"),
            ),
            (
                "empty data_types",
                json!({ "uri": "a.png", "hash": b64(ALBEDO_PNG_HASH), "data_types": [] }),
                Some("a.png"),
            ),
        ];

        for (name, bad, resource_url) in cases {
            let check = check(json!({
                "resources": {
                    "relativeResources": [bad, { "uri": "b.png", "hash": b64(ALBEDO_PNG_HASH) }],
                    "alg": "sha256"
                }
            }));
            assert_matches!(&check.findings[..], [finding] if malformed(resource_url)(finding), "{name}");
            assert_eq!(resource_urls(&check), ["b.png"], "{name}");
        }
    }

    #[test]
    fn check_reports_unsupported_entry_algorithm() {
        let check = check(json!({ "resources": { "externalResources": [
            { "url": "https://example.com/a.js", "alg": "md5", "hash": b64(MAIN_JS_HASH) }
        ]}}));

        assert_eq!(
            check.findings,
            [LinkedResourceFinding::UnsupportedAlgorithm {
                alg: "md5".to_owned(),
                resource_url: Some("https://example.com/a.js".to_owned()),
            }]
        );
        // A rejected algorithm does not make the entry malformed.
        assert_eq!(resource_urls(&check), ["https://example.com/a.js"]);
    }

    #[test]
    fn check_reports_unsupported_shared_algorithm() {
        let mut json = relative_with_uris(&["a.png"]);
        json["resources"]["alg"] = json!("sha1");
        let check = check(json);

        assert_eq!(
            check.findings,
            [LinkedResourceFinding::UnsupportedAlgorithm {
                alg: "sha1".to_owned(),
                resource_url: None,
            }]
        );
        assert_eq!(resource_urls(&check), ["a.png"]);
    }

    #[test]
    fn check_reports_parent_segments_after_percent_decoding() {
        let rejected = ["../a.png", "%2e%2e/a.png", "a/..?v=1"];
        let check = check(relative_with_uris(&rejected));

        let invalid: Vec<_> = check
            .findings
            .iter()
            .map(|finding| match finding {
                LinkedResourceFinding::InvalidUri { uri } => uri.as_str(),
                other => panic!("unexpected finding {other:?}"),
            })
            .collect();
        assert_eq!(invalid, rejected);
        // Each entry is still well-formed and needs a terminal status.
        assert_eq!(resource_urls(&check), rejected);
    }

    #[test]
    fn check_accepts_uris_without_parent_segments() {
        // `..%3Fx` names a file called `..?x`: an encoded `?` does not end a segment.
        let accepted = ["./a.png", "..a.png", "..%3Fx", "a.png?v=.."];
        let check = check(relative_with_uris(&accepted));

        assert_eq!(check.findings, Vec::new());
        assert_eq!(resource_urls(&check), accepted);
    }

    #[test]
    fn finding_maps_to_status_code() {
        let url = Some("https://example.com/a.js".to_owned());
        let cases = [
            (
                LinkedResourceFinding::Malformed {
                    explanation: "x".to_owned(),
                    resource_url: None,
                },
                validation_status::ASSERTION_LINKED_RESOURCE_INTEGRITY_MALFORMED,
                true,
                None,
            ),
            (
                LinkedResourceFinding::InvalidUri {
                    uri: "../a.png".to_owned(),
                },
                validation_status::ASSERTION_LINKED_RESOURCE_INTEGRITY_INVALID_URI,
                true,
                Some("../a.png"),
            ),
            (
                LinkedResourceFinding::UnsupportedAlgorithm {
                    alg: "md5".to_owned(),
                    resource_url: url.clone(),
                },
                validation_status::ALGORITHM_UNSUPPORTED,
                true,
                url.as_deref(),
            ),
            (
                LinkedResourceFinding::DeprecatedAlgorithm {
                    alg: "sha1".to_owned(),
                    resource_url: url.clone(),
                },
                validation_status::ALGORITHM_DEPRECATED,
                false,
                url.as_deref(),
            ),
        ];

        for (finding, code, is_failure, resource_url) in &cases {
            assert_eq!(finding.code(), *code);
            assert_eq!(finding.is_failure(), *is_failure, "{finding:?}");
            assert_eq!(finding.resource_url(), *resource_url, "{finding:?}");
            assert!(!finding.explanation().is_empty());
        }
    }
}
