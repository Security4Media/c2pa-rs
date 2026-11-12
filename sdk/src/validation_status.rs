// Copyright 2022 Adobe. All rights reserved.
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

//! Implements validation status for specific parts of a manifest.
//!
//! See [Existing Manifests - C2PA Technical Specification](https://spec.c2pa.org/specifications/specifications/2.3/specs/C2PA_Specification.html#_existing_manifests).

#![deny(missing_docs)]

use log::debug;
#[cfg(feature = "json_schema")]
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub use crate::validation_results::validation_codes::*;
use crate::{
    error::Error,
    jumbf,
    status_tracker::{LogItem, LogKind},
};

/// A `ValidationStatus` struct describes the validation status of a
/// specific part of a manifest.
///
/// See [Existing Manifests - C2PA Technical Specification](https://spec.c2pa.org/specifications/specifications/2.3/specs/C2PA_Specification.html#_existing_manifests).
#[derive(Clone, Debug, Deserialize, Serialize, Eq)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
pub struct ValidationStatus {
    code: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<String>,

    // The spec's `status-map` allows at most one of `url` and `resourceUrl`; the
    // setters keep them exclusive.
    #[cfg(feature = "unstable_linked_resource_integrity")]
    #[serde(rename = "resourceUrl", skip_serializing_if = "Option::is_none")]
    resource_url: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    explanation: Option<String>,

    #[serde(skip_serializing)]
    #[allow(dead_code)]
    success: Option<bool>, // deprecated in 2.x, allow reading for compatibility

    #[serde(skip)]
    #[serde(default = "default_log_kind")]
    kind: LogKind,

    #[serde(skip)]
    ingredient_uri: Option<String>,

    #[serde(skip)]
    trust_list_uri: Option<String>,

    // `resourceUrl` takes the place of the `url` that would name the assertion, and with it
    // its manifest. This keeps that manifest label, so that de-duplication can match the
    // status against what that manifest's ingredient recorded. It is not serialized.
    #[cfg(feature = "unstable_linked_resource_integrity")]
    #[serde(skip)]
    resource_manifest: Option<String>,
}

fn default_log_kind() -> LogKind {
    LogKind::Success
}

impl ValidationStatus {
    pub(crate) fn new<S: Into<String>>(code: S) -> Self {
        Self {
            code: code.into(),
            url: None,
            #[cfg(feature = "unstable_linked_resource_integrity")]
            resource_url: None,
            explanation: None,
            success: None,
            ingredient_uri: None,
            kind: LogKind::Success,
            trust_list_uri: None,
            #[cfg(feature = "unstable_linked_resource_integrity")]
            resource_manifest: None,
        }
    }

    pub(crate) fn new_failure<S: Into<String>>(code: S) -> Self {
        Self::new(code).set_kind(LogKind::Failure)
    }

    /// Returns the validation status code.
    ///
    /// Validation status codes are the labels from the "Value"
    /// column in [Existing Manifests - C2PA Technical Specification](https://spec.c2pa.org/specifications/specifications/2.3/specs/C2PA_Specification.html#_existing_manifests).
    ///
    /// These are also defined as constants in the
    /// [`validation_status`](crate::validation_status) mod.
    pub fn code(&self) -> &str {
        &self.code
    }

    /// Returns the internal JUMBF reference to the entity that was validated.
    pub fn url(&self) -> Option<&str> {
        self.url.as_deref()
    }

    /// Returns the `url` or `uri` of the assertion entry this status applies to, such as
    /// one resource listed in a linked resource integrity assertion.
    ///
    /// A status has at most one of [`url`](Self::url) and `resource_url`. It is serialized
    /// as `resourceUrl`.
    ///
    /// See [Linked resource integrity validation - C2PA Technical Specification](https://spec.c2pa.org/specifications/specifications/2.5/specs/C2PA_Specification.html#_c2pa_linked_resource_integrity_validation).
    ///
    /// <div class="warning">
    ///
    /// **Experimental.** This method is available only with the
    /// `unstable_linked_resource_integrity` feature enabled. It is exempt from this crate's
    /// usual semantic-versioning stability guarantees and may change in a backward-incompatible
    /// way, or be removed entirely, in any release.
    ///
    /// </div>
    #[cfg(feature = "unstable_linked_resource_integrity")]
    pub fn resource_url(&self) -> Option<&str> {
        self.resource_url.as_deref()
    }

    /// Returns the label of the manifest whose assertion a [`resource_url`](Self::resource_url)
    /// status is about, when it was made from a log item.
    #[cfg(feature = "unstable_linked_resource_integrity")]
    pub(crate) fn resource_manifest(&self) -> Option<&str> {
        self.resource_manifest.as_deref()
    }

    /// Returns a human-readable description of the validation that was performed.
    pub fn explanation(&self) -> Option<&str> {
        self.explanation.as_deref()
    }

    /// Returns the internal JUMBF reference to the Ingredient that was validated.
    pub fn ingredient_uri(&self) -> Option<&str> {
        self.ingredient_uri.as_deref()
    }

    /// Returns the internal JUMBF reference to the trust list that was validated.
    pub fn trust_list_uri(&self) -> Option<&str> {
        self.trust_list_uri.as_deref()
    }

    /// Sets the internal JUMBF reference to the entity was validated.
    pub fn set_url<S: Into<String>>(mut self, url: S) -> Self {
        self.url = Some(url.into());
        #[cfg(feature = "unstable_linked_resource_integrity")]
        {
            self.resource_url = None;
        }
        self
    }

    /// Sets the `url` or `uri` of the assertion entry this status applies to and clears
    /// [`url`](Self::url), which the spec does not allow alongside it.
    #[cfg(feature = "unstable_linked_resource_integrity")]
    pub(crate) fn set_resource_url<S: Into<String>>(mut self, resource_url: S) -> Self {
        self.resource_url = Some(resource_url.into());
        self.url = None;
        self
    }

    /// Sets the LogKind for this validation status.
    pub fn set_kind(mut self, kind: LogKind) -> Self {
        self.kind = kind;
        self
    }

    /// Sets the internal JUMBF reference to the Ingredient that was validated.
    pub fn set_ingredient_uri<S: Into<String>>(mut self, uri: S) -> Self {
        self.ingredient_uri = Some(uri.into());
        self
    }

    /// Sets the human-readable description of the validation that was performed.
    pub(crate) fn set_explanation(mut self, explanation: String) -> Self {
        self.explanation = Some(explanation);
        self
    }

    /// Sets the internal JUMBF reference to the trust list that was validated this item.
    pub fn set_trust_list_uri<S: Into<String>>(mut self, uri: S) -> Self {
        self.trust_list_uri = Some(uri.into());
        self
    }

    /// Returns `true` if this has a successful validation code.
    pub fn passed(&self) -> bool {
        self.kind != LogKind::Failure
    }

    /// Returns the LogKind for this validation status.
    pub fn kind(&self) -> &LogKind {
        &self.kind
    }

    // Maps errors into validation_status codes.
    fn code_from_error_str(error: &str) -> &str {
        match error {
            "ClaimMissing" => CLAIM_MISSING,
            e if e.starts_with("AssertionMissing") => ASSERTION_MISSING,
            e if e.starts_with("AssertionDecoding") => ASSERTION_REQUIRED_MISSING,
            e if e.starts_with("HashMismatch") => ASSERTION_DATAHASH_MISMATCH,
            e if e.starts_with("RemoteManifestFetch") => MANIFEST_INACCESSIBLE,
            e if e.starts_with("PrereleaseError") => STATUS_PRERELEASE,
            _ => GENERAL_ERROR,
        }
    }

    // Maps errors into validation_status codes.
    pub(crate) fn code_from_error(error: &Error) -> &'static str {
        match error {
            Error::ClaimMissing { .. } => CLAIM_MISSING,
            Error::AssertionMissing { .. } => ASSERTION_MISSING,
            Error::AssertionDecoding(_code) => ASSERTION_REQUIRED_MISSING, /* todo detect json/cbor errors */
            Error::HashMismatch(_) => ASSERTION_DATAHASH_MISMATCH,
            Error::RemoteManifestFetch(_) => MANIFEST_INACCESSIBLE,
            Error::PrereleaseError => STATUS_PRERELEASE,
            _ => GENERAL_ERROR,
        }
    }

    /// Creates a ValidationStatus from an error code.
    #[allow(dead_code)]
    pub(crate) fn from_error(error: &Error) -> Self {
        // We need to create error codes here for client processing.
        let code = Self::code_from_error(error);
        debug!("ValidationStatus {code} from error {error:#?}");
        Self::new_failure(code.to_string()).set_explanation(error.to_string())
    }

    /// Creates a ValidationStatus from a validation_log item.
    pub(crate) fn from_log_item(item: &LogItem) -> Option<Self> {
        match item.validation_status.as_ref() {
            Some(status) => Some({
                let mut vi = Self::new(status.to_string())
                    .set_url(item.label.to_string())
                    .set_kind(item.kind.clone())
                    .set_explanation(item.description.to_string());

                if let Some(ingredient_uri) = &item.ingredient_uri {
                    vi = vi.set_ingredient_uri(ingredient_uri.to_string());
                }

                if let Some(trust_list_uri) = &item.trust_list_uri {
                    vi = vi.set_trust_list_uri(trust_list_uri.to_string());
                }

                #[cfg(feature = "unstable_linked_resource_integrity")]
                if let Some(resource_url) = &item.resource_url {
                    vi.resource_manifest = jumbf::labels::manifest_label_from_uri(&item.label);
                    vi = vi.set_resource_url(resource_url.to_string());
                }

                vi
            }),
            // If we don't have a validation_status, then make one from the err_val
            // using the description plus error text explanation.
            None => item.err_val.as_ref().map(|e| {
                let code = Self::code_from_error_str(e);
                Self::new_failure(code.to_string())
                    .set_url(item.label.to_string())
                    .set_explanation(format!("{}: {}", item.description, e))
            }),
        }
    }

    // converts a validation status url into and absolute URI given the manifest label.
    pub(crate) fn make_absolute(&mut self, manifest_label: &str) {
        if let Some(url) = &self.url {
            if url.starts_with("self#jumbf") {
                // Some are just labels (i.e. "Cose_Sign1")
                self.url = Some(jumbf::labels::to_absolute_uri(manifest_label, url));
            }
        }
    }
}

impl PartialEq for ValidationStatus {
    fn eq(&self, other: &Self) -> bool {
        // Statuses about different entries of one assertion differ only in `resourceUrl`, so
        // it must take part for de-duplication to keep them apart.
        #[cfg(feature = "unstable_linked_resource_integrity")]
        if self.resource_url != other.resource_url {
            return false;
        }
        self.code == other.code && self.url == other.url && self.kind == other.kind
    }
}

// -- unofficial status code --

pub(crate) const STATUS_PRERELEASE: &str = "com.adobe.prerelease";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_mismatch_error_maps_to_mismatch_code() {
        // Error::HashMismatch must produce the failure code, not the success code.
        assert_eq!(
            ValidationStatus::code_from_error(&Error::HashMismatch("digest differs".to_string())),
            ASSERTION_DATAHASH_MISMATCH,
        );
    }

    #[test]
    fn hash_mismatch_error_str_maps_to_mismatch_code() {
        // The string-based path (used when mapping log items without a typed error) must
        // also produce the failure code.
        assert_eq!(
            ValidationStatus::code_from_error_str("HashMismatch(digest differs)"),
            ASSERTION_DATAHASH_MISMATCH,
        );
    }

    #[test]
    fn hash_mismatch_from_error_is_failure_status() {
        let status = ValidationStatus::from_error(&Error::HashMismatch("bad hash".to_string()));
        assert_eq!(status.code(), ASSERTION_DATAHASH_MISMATCH);
        assert!(
            !status.passed(),
            "hash mismatch must not be a passing status"
        );
    }

    #[cfg(feature = "unstable_linked_resource_integrity")]
    mod resource_url {
        #![allow(clippy::unwrap_used)]

        use serde_json::json;

        use super::*;
        use crate::log_item;

        const RESOURCE_URL: &str = "https://example.com/assets/main.js";
        const ASSERTION_URL: &str = "self#jumbf=c2pa.assertions/c2pa.linked-resource-integrity";

        #[test]
        fn url_and_resource_url_are_exclusive() {
            let status = ValidationStatus::new(ASSERTION_LINKED_RESOURCE_INTEGRITY_SKIPPED)
                .set_url(ASSERTION_URL)
                .set_resource_url(RESOURCE_URL);
            assert_eq!(status.url(), None);
            assert_eq!(status.resource_url(), Some(RESOURCE_URL));

            let status = status.set_url(ASSERTION_URL);
            assert_eq!(status.url(), Some(ASSERTION_URL));
            assert_eq!(status.resource_url(), None);
        }

        #[test]
        fn log_item_resource_url_replaces_url() {
            let item = log_item!(ASSERTION_URL, "not retrieved", "test")
                .set_resource_url(RESOURCE_URL)
                .validation_status(ASSERTION_LINKED_RESOURCE_INTEGRITY_SKIPPED);

            let status = ValidationStatus::from_log_item(&item).unwrap();

            assert_eq!(status.url(), None);
            assert_eq!(status.resource_url(), Some(RESOURCE_URL));
        }

        #[test]
        fn log_item_resource_url_keeps_the_manifest_of_its_assertion() {
            let assertion = crate::jumbf::labels::to_assertion_uri(
                "urn:c2pa:manifest",
                "c2pa.linked-resource-integrity",
            );
            let item = log_item!(assertion, "not retrieved", "test")
                .set_resource_url(RESOURCE_URL)
                .validation_status(ASSERTION_LINKED_RESOURCE_INTEGRITY_SKIPPED);

            let status = ValidationStatus::from_log_item(&item).unwrap();

            assert_eq!(status.resource_manifest(), Some("urn:c2pa:manifest"));
            let json = serde_json::to_value(&status).unwrap();
            assert_eq!(
                json.as_object().unwrap().keys().collect::<Vec<_>>(),
                ["code", "resourceUrl", "explanation"]
            );
        }

        #[test]
        fn resource_url_serializes_as_resource_url() {
            let status = ValidationStatus::new(ASSERTION_LINKED_RESOURCE_INTEGRITY_SKIPPED)
                .set_resource_url(RESOURCE_URL);

            let json = serde_json::to_value(&status).unwrap();
            assert_eq!(
                json,
                json!({
                    "code": ASSERTION_LINKED_RESOURCE_INTEGRITY_SKIPPED,
                    "resourceUrl": RESOURCE_URL
                })
            );

            let parsed: ValidationStatus = serde_json::from_value(json).unwrap();
            assert_eq!(parsed.resource_url(), Some(RESOURCE_URL));
            assert_eq!(parsed.url(), None);
        }

        #[test]
        fn statuses_for_different_resources_differ() {
            let skipped = |url: &str| {
                ValidationStatus::new(ASSERTION_LINKED_RESOURCE_INTEGRITY_SKIPPED)
                    .set_kind(LogKind::Informational)
                    .set_resource_url(url)
            };

            assert_eq!(skipped(RESOURCE_URL), skipped(RESOURCE_URL));
            assert_ne!(
                skipped(RESOURCE_URL),
                skipped("https://example.com/assets/style.css")
            );
        }

        #[test]
        fn linked_resource_codes_have_their_log_kind() {
            assert_eq!(
                log_kind(ASSERTION_LINKED_RESOURCE_INTEGRITY_MATCH),
                LogKind::Success
            );
            for code in [
                ASSERTION_LINKED_RESOURCE_INTEGRITY_SKIPPED,
                ASSERTION_LINKED_RESOURCE_INTEGRITY_INACCESSIBLE,
                ASSERTION_LINKED_RESOURCE_INTEGRITY_SIZE_MISMATCH,
                ASSERTION_LINKED_RESOURCE_INTEGRITY_FORMAT_MISMATCH,
                ASSERTION_LINKED_RESOURCE_INTEGRITY_HASH_MISMATCH,
            ] {
                assert_eq!(log_kind(code), LogKind::Informational, "{code}");
            }
            for code in [
                ASSERTION_LINKED_RESOURCE_INTEGRITY_MALFORMED,
                ASSERTION_LINKED_RESOURCE_INTEGRITY_NOT_CREATED,
                ASSERTION_LINKED_RESOURCE_INTEGRITY_INVALID_URI,
            ] {
                assert_eq!(log_kind(code), LogKind::Failure, "{code}");
            }
        }
    }
}
