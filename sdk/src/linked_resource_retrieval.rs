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

//! Retrieval of the resources listed in `c2pa.linked-resource-integrity` assertions.
//!
//! Claim verification reports every listed resource as
//! `assertion.linkedResourceIntegrity.skipped`, because it never retrieves anything. When
//! `verify.fetch_linked_resources` is on, the [`Reader`](crate::Reader) then calls
//! [`retrieve_linked_resources`] once the store is verified and its manifests are loaded. It
//! retrieves the resources of the active manifest, provided its claim is not rejected, and
//! replaces each `skipped` status with the outcome. Running this late is what lets retrieval
//! wait for the whole claim, hard binding included, as the spec requires before any external
//! data is retrieved.
//!
//! Each outcome follows the order of the spec procedure: the resource is retrieved
//! (`inaccessible` on failure), then its size, media type and hash are compared with the
//! declared values (`sizeMismatch`, `formatMismatch`, `hashMismatch`), and `match` reports that
//! every check passed. All of them are informational except `match`, so none rejects the claim.
//!
//! See [`c2pa.linked-resource-integrity` validation - C2PA Technical Specification](https://spec.c2pa.org/specifications/specifications/2.5/specs/C2PA_Specification.html#_c2pa_linked_resource_integrity_validation).

#[cfg(feature = "file_io")]
use std::{
    fs::{self, File},
    path::{Component, Path, PathBuf},
};
use std::{io::Read, time::Duration};

use async_generic::async_generic;
use http::{header, HeaderMap, Request, Response, StatusCode};
use url::Url;

#[cfg(feature = "file_io")]
use crate::utils::uri_utils::percent_decode;
use crate::{
    assertions::{hash_resource, LinkedResourceEntry, LinkedResourceIntegrity},
    claim::Claim,
    context::{Context, ProgressPhase},
    http::{restricted::HttpsRedirectsOnly, sanitize_for_log, RequestTimeout},
    jumbf::labels::to_assertion_uri,
    log_item,
    status_tracker::{LogItem, LogKind, StatusTracker},
    store::Store,
    utils::uri_utils::{has_parent_segment, path_component},
    validation_results::{ValidationResults, ValidationState},
    validation_status, Result,
};

// The docs of `Verify::fetch_linked_resources` and docs/context-settings.md state the values
// of the next four limits.

/// Maximum number of resources retrieved per manifest. Entries past it stay `skipped`, so that
/// one manifest cannot make the validator issue an unbounded number of requests.
const MAX_RETRIEVALS: usize = 100;

/// Largest resource read, in bytes. A declared `size` above it makes the resource
/// `inaccessible` without any request. A resource without a declared size is `inaccessible`
/// once it turns out larger.
const MAX_RESOURCE_SIZE: u64 = 256 * 1024 * 1024; // 256 MiB

/// Time limit for one network retrieval, redirects and body included. The built-in `ureq` and
/// native `reqwest` resolvers apply it through [`RequestTimeout`].
const RETRIEVAL_TIMEOUT: Duration = Duration::from_secs(60);

/// Time limit for all the retrievals of one manifest. Retrievals run one after another, so
/// without it a manifest listing [`MAX_RETRIEVALS`] slow resources could hold a read for
/// [`MAX_RETRIEVALS`] times [`RETRIEVAL_TIMEOUT`]. Entries not attempted in time stay
/// `skipped`.
const RETRIEVAL_BUDGET: Duration = Duration::from_secs(5 * 60);

/// Media type of an HTTP response without `Content-Type` (RFC 9110, section 8.3).
const DEFAULT_MEDIA_TYPE: &str = "application/octet-stream";

/// Whether the platform removes any content coding before the body reaches the resolver, as
/// `fetch` does in a browser, whatever the `Content-Encoding` header says.
const BODY_DECODED_BY_PLATFORM: bool = cfg!(all(target_arch = "wasm32", not(target_os = "wasi")));

/// Where the `relativeResources` of a linked resource integrity assertion are found.
///
/// A relative URI resolves against the location of the asset. The application gives that
/// location with [`Reader::with_linked_resource_base`](crate::Reader::with_linked_resource_base),
/// because resolving it reads files or URLs that the manifest names. The SDK never derives a
/// base from the asset, not even when reading a file, and never falls back to the working
/// directory: without a base, relative resources are reported as
/// `assertion.linkedResourceIntegrity.inaccessible` when retrieval is on.
///
/// With either base, a URI that has a scheme or an authority (`//host`), or that contains a
/// backslash, a space or a control character, is not resolved.
///
/// See [Linked resource integrity - C2PA Technical Specification](https://spec.c2pa.org/specifications/specifications/2.5/specs/C2PA_Specification.html#linked_resource_integrity_assertion).
///
/// <div class="warning">
///
/// **Experimental.** This type is available only with the `unstable_linked_resource_integrity`
/// feature enabled. It is exempt from this crate's usual semantic-versioning stability
/// guarantees and may change in a backward-incompatible way, or be removed entirely, in any
/// release.
///
/// </div>
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum LinkedResourceBase {
    /// A local directory, normally the one that holds the asset.
    ///
    /// URIs resolve to regular files inside it. A URI with a leading `/` is refused, and so
    /// is any path that leads outside the directory, including through a symbolic link. Each
    /// `/`-delimited segment is percent-decoded on its own, so an encoded `/` (`%2F`) is
    /// refused rather than taken as a separator; it is data, as in a URL.
    ///
    /// A file has no media type, so a declared `dc:format` is not compared, and the
    /// explanation of a `match` says so. Size and hash are still compared.
    ///
    /// Requires the `file_io` feature.
    #[cfg(feature = "file_io")]
    Directory(PathBuf),

    /// The absolute `https` URL of the asset, such as `https://example.com/scenes/scene.mtlx`.
    ///
    /// URIs resolve against it as RFC 3986 relative references: `./textures/albedo.png` gives
    /// `https://example.com/scenes/textures/albedo.png`, and `/albedo.png` gives
    /// `https://example.com/albedo.png`. A URL of a directory needs a trailing `/`. A resolved
    /// URL must keep the scheme, host and port of the base. It is then retrieved like an
    /// `externalResources` URL, under the same rules.
    Url(String),
}

/// Retrieves the linked resources of the active manifest of `store` and records the outcome
/// for each in place of its `skipped` status in `validation_log`.
///
/// Does nothing unless `verify.fetch_linked_resources` is on, and nothing when the active
/// claim is rejected (see `active_claim_rejected`): the spec forbids retrieving external data
/// for a rejected claim. Resources of ingredient manifests are never retrieved, since `base`
/// locates the asset being read, not its ingredients.
///
/// # Errors
///
/// Returns [`Error::OperationCancelled`](crate::Error::OperationCancelled) if the progress
/// callback or the cancel flag of `context` stops the operation.
#[async_generic]
pub(crate) fn retrieve_linked_resources(
    store: &Store,
    validation_log: &mut StatusTracker,
    context: &Context,
    base: Option<&LinkedResourceBase>,
) -> Result<()> {
    if !context.settings().verify.fetch_linked_resources {
        return Ok(());
    }
    let Some(claim) = store.provenance_claim() else {
        return Ok(());
    };
    let pending = pending_retrievals(claim, validation_log);
    if pending.is_empty() || active_claim_rejected(store, validation_log) {
        return Ok(());
    }

    let base = Base::new(base);
    let deadline = Deadline::start(RETRIEVAL_BUDGET);
    let total = u32::try_from(pending.len()).unwrap_or(u32::MAX);
    for (step, PendingRetrieval { index, entry }) in (1..).zip(pending) {
        context.check_progress(ProgressPhase::FetchingLinkedResource, step, total)?;
        let Some(timeout) = deadline.next_timeout() else {
            break;
        };

        let outcome = if _sync {
            retrieve(&entry, &base, context, timeout)
        } else {
            retrieve_async(&entry, &base, context, timeout).await
        };

        let skipped = &mut validation_log.logged_items_mut()[index];
        *skipped = outcome.into_log_item(skipped.label.to_string(), entry.resource_url());
    }
    Ok(())
}

/// Whether the active claim of `store` is rejected, judging by `validation_log`.
///
/// It is when the [`ValidationResults`] that the [`Reader`](crate::Reader) reports are
/// `Invalid`. That covers a failure logged for the active manifest, one logged while checking
/// its ingredient assertions, a manifest that failed to load, and a store that was never
/// verified. It is also when the signing credential is untrusted: the spec rejects such a
/// claim, although [`ValidationResults::validation_state`] tolerates
/// `signingCredential.untrusted` and reports `Valid`. CAWG identity failures, which the state
/// tolerates as well, do not reject the claim.
fn active_claim_rejected(store: &Store, validation_log: &StatusTracker) -> bool {
    let results = ValidationResults::from_store(store, validation_log);
    results.validation_state() == ValidationState::Invalid
        || results.active_manifest().is_some_and(|active| {
            active
                .failure()
                .iter()
                .any(|status| status.code() == validation_status::SIGNING_CREDENTIAL_UNTRUSTED)
        })
}

/// A `skipped` status that retrieval replaces, with the entry it reports on.
struct PendingRetrieval {
    /// Index of the `skipped` item in the validation log.
    index: usize,
    entry: LinkedResourceEntry,
}

/// Pairs each `skipped` status of the active manifest of `claim` with its entry, up to
/// [`MAX_RETRIEVALS`].
///
/// Claim verification logs one `skipped` per well-formed entry, in entry order, so the
/// statuses of an assertion pair up with the entries of a fresh structural check. An
/// assertion whose statuses do not line up with its entries is left alone.
fn pending_retrievals(claim: &Claim, validation_log: &StatusTracker) -> Vec<PendingRetrieval> {
    let mut pending = Vec::new();
    for assertion in claim.linked_resource_integrity_assertions() {
        let label = to_assertion_uri(claim.label(), &assertion.label());
        let skipped: Vec<usize> = validation_log
            .logged_items()
            .iter()
            .enumerate()
            .filter(|(_, item)| is_skipped_status(item, &label))
            .map(|(index, _)| index)
            .collect();
        let entries = LinkedResourceIntegrity::check(assertion.assertion()).entries;
        let lined_up = skipped.len() == entries.len()
            && skipped.iter().zip(&entries).all(|(&index, entry)| {
                validation_log.logged_items()[index].resource_url.as_deref()
                    == Some(entry.resource_url())
            });
        if lined_up {
            pending.extend(
                skipped
                    .into_iter()
                    .zip(entries)
                    .map(|(index, entry)| PendingRetrieval { index, entry }),
            );
        } else {
            log::debug!(
                "linked resource statuses of {} do not line up with its entries, so its \
                 resources are not retrieved",
                sanitize_for_log(&label)
            );
        }
    }
    pending.truncate(MAX_RETRIEVALS);
    pending
}

/// Whether `item` is a `skipped` status of the active manifest for the assertion at `label`.
fn is_skipped_status(item: &LogItem, label: &str) -> bool {
    item.ingredient_uri.is_none()
        && item.label == label
        && item.validation_status.as_deref()
            == Some(validation_status::ASSERTION_LINKED_RESOURCE_INTEGRITY_SKIPPED)
}

/// What is left of the time budget for the retrievals of one manifest.
struct Deadline {
    started: web_time::Instant,
    budget: Duration,
}

impl Deadline {
    fn start(budget: Duration) -> Self {
        Self {
            started: web_time::Instant::now(),
            budget,
        }
    }

    /// The time limit for the next retrieval: [`RETRIEVAL_TIMEOUT`], or what is left of the
    /// budget if that is less. `None` once the budget is spent.
    fn next_timeout(&self) -> Option<Duration> {
        self.budget
            .checked_sub(self.started.elapsed())
            .filter(|left| !left.is_zero())
            .map(|left| left.min(RETRIEVAL_TIMEOUT))
    }
}

/// The terminal outcome of retrieving one entry.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// Every applicable check passed. `dc_format_skipped` is set when the entry declares a
    /// `dc:format` that could not be compared, because the resource has no media type.
    Match { dc_format_skipped: bool },
    /// The resource could not be located or obtained; the reason says why.
    Inaccessible(String),
    /// The retrieved size differs from the declared `size`.
    SizeMismatch(String),
    /// The retrieved media type differs from the declared `dc:format`.
    FormatMismatch(String),
    /// The hash of the retrieved bytes differs from the declared `hash`.
    HashMismatch,
}

impl Outcome {
    fn code(&self) -> &'static str {
        match self {
            Self::Match { .. } => validation_status::ASSERTION_LINKED_RESOURCE_INTEGRITY_MATCH,
            Self::Inaccessible(_) => {
                validation_status::ASSERTION_LINKED_RESOURCE_INTEGRITY_INACCESSIBLE
            }
            Self::SizeMismatch(_) => {
                validation_status::ASSERTION_LINKED_RESOURCE_INTEGRITY_SIZE_MISMATCH
            }
            Self::FormatMismatch(_) => {
                validation_status::ASSERTION_LINKED_RESOURCE_INTEGRITY_FORMAT_MISMATCH
            }
            Self::HashMismatch => {
                validation_status::ASSERTION_LINKED_RESOURCE_INTEGRITY_HASH_MISMATCH
            }
        }
    }

    /// `match` is a success code; every other outcome is informational.
    fn kind(&self) -> LogKind {
        match self {
            Self::Match { .. } => LogKind::Success,
            Self::Inaccessible(_)
            | Self::SizeMismatch(_)
            | Self::FormatMismatch(_)
            | Self::HashMismatch => LogKind::Informational,
        }
    }

    fn explanation(&self) -> String {
        match self {
            Self::Match {
                dc_format_skipped: false,
            } => "linked resource matches the values declared in the assertion".into(),
            Self::Match {
                dc_format_skipped: true,
            } => "linked resource matches the size and hash declared in the assertion; its \
                  media type was not compared with `dc:format` because a file has none"
                .into(),
            Self::Inaccessible(reason) => format!("linked resource is inaccessible: {reason}"),
            Self::SizeMismatch(detail) => format!("linked resource size does not match: {detail}"),
            Self::FormatMismatch(detail) => {
                format!("linked resource media type does not match: {detail}")
            }
            Self::HashMismatch => "linked resource hash does not match".into(),
        }
    }

    /// The status that reports this outcome for the entry at `resource_url` of the assertion
    /// at `label`.
    fn into_log_item(self, label: String, resource_url: &str) -> LogItem {
        let mut item = log_item!(label, self.explanation(), "retrieve_linked_resources")
            .validation_status(self.code())
            .set_resource_url(resource_url.to_owned());
        item.kind = self.kind();
        item
    }
}

/// The [`LinkedResourceBase`] of a read, checked once for all of its entries.
#[derive(Debug)]
enum Base {
    /// No base was set, so relative resources cannot be resolved.
    Missing,
    /// A base was set but cannot be used; the reason says why.
    Unusable(String),
    /// The `https` URL of the asset.
    Url(Url),
    /// The canonical path of the base directory.
    #[cfg(feature = "file_io")]
    Directory(PathBuf),
}

impl Base {
    fn new(base: Option<&LinkedResourceBase>) -> Self {
        match base {
            None => Self::Missing,
            Some(LinkedResourceBase::Url(url)) => match remote_url(url) {
                Ok(url) => Self::Url(url),
                Err(reason) => Self::Unusable(format!("base URL is not usable: {reason}")),
            },
            // Canonicalized once, so that each resolved path can be checked against it.
            #[cfg(feature = "file_io")]
            Some(LinkedResourceBase::Directory(directory)) => match directory.canonicalize() {
                Ok(root) => Self::Directory(root),
                Err(err) => Self::Unusable(format!("base directory cannot be opened: {err}")),
            },
        }
    }
}

/// Retrieves the resource of `entry` within `timeout` and compares it with the declared
/// values.
#[async_generic]
fn retrieve(
    entry: &LinkedResourceEntry,
    base: &Base,
    context: &Context,
    timeout: Duration,
) -> Outcome {
    let retrieved = match locate(entry, base) {
        Ok(Location::Remote(url)) => {
            if _sync {
                fetch(&url, entry, context, timeout)
            } else {
                fetch_async(&url, entry, context, timeout).await
            }
        }
        #[cfg(feature = "file_io")]
        Ok(Location::File(path)) => read_file(&path, entry),
        Err(reason) => Err(Outcome::Inaccessible(reason)),
    };
    match retrieved {
        Ok(retrieved) => compare(entry, &retrieved),
        Err(outcome) => outcome,
    }
}

/// Where the resource of an entry is retrieved from.
#[derive(Debug, PartialEq, Eq)]
enum Location {
    Remote(Url),
    #[cfg(feature = "file_io")]
    File(PathBuf),
}

/// Finds where the resource of `entry` is, or says why it cannot be retrieved.
fn locate(entry: &LinkedResourceEntry, base: &Base) -> Result<Location, String> {
    let uri = match entry {
        LinkedResourceEntry::External(resource) => {
            return remote_url(&resource.url).map(Location::Remote)
        }
        LinkedResourceEntry::Relative { resource, .. } => &resource.uri,
    };
    check_relative_reference(uri)?;
    match base {
        Base::Missing => Err("no base location is set for relative resources".into()),
        Base::Unusable(reason) => Err(reason.clone()),
        Base::Url(base) => resolve_url(base, uri).map(Location::Remote),
        #[cfg(feature = "file_io")]
        Base::Directory(root) => resolve_file(root, uri).map(Location::File),
    }
}

/// Parses `raw` as a URL to retrieve: `https` only, with no userinfo part.
fn remote_url(raw: &str) -> Result<Url, String> {
    check_characters(raw)?;
    let url = Url::parse(raw).map_err(|err| format!("URL cannot be parsed: {err}"))?;
    if url.scheme() != "https" {
        return Err(format!(
            "only `https` URLs are retrieved, not `{}`",
            url.scheme()
        ));
    }
    // The parsed URL drops an empty userinfo (`https://@host`), so the raw authority, after
    // the scheme and its slashes, is checked as well.
    let raw_authority = raw
        .split_once(':')
        .and_then(|(_, rest)| rest.trim_start_matches('/').split(['/', '?', '#']).next())
        .unwrap_or_default();
    if !url.username().is_empty() || url.password().is_some() || raw_authority.contains('@') {
        return Err("URL has a userinfo part".into());
    }
    if url.host().is_none() {
        return Err("URL has no host".into());
    }
    Ok(url)
}

/// Refuses characters that URL parsers drop or reinterpret, so the resource retrieved is the
/// one the URI names as signed: a backslash can stand for `/`, and tabs, line breaks and
/// leading spaces are removed.
fn check_characters(value: &str) -> Result<(), String> {
    if value
        .chars()
        .any(|ch| ch == '\\' || ch.is_whitespace() || ch.is_control())
    {
        return Err("URI contains a backslash, a space or a control character".into());
    }
    Ok(())
}

/// Checks that `uri` is a relative reference, with no scheme or authority.
fn check_relative_reference(uri: &str) -> Result<(), String> {
    check_characters(uri)?;
    if uri.starts_with("//") {
        return Err("URI has an authority, so it is not relative".into());
    }
    // A colon in the first segment would end a scheme (RFC 3986, section 4.2).
    let first_segment = path_component(uri).split('/').next().unwrap_or_default();
    if first_segment.contains(':') {
        return Err("URI has a scheme, so it is not relative".into());
    }
    Ok(())
}

/// Resolves `reference` against the URL `base`, keeping the origin of the base.
fn resolve_url(base: &Url, reference: &str) -> Result<Url, String> {
    if has_parent_segment(reference) {
        return Err("URI has a `..` segment".into());
    }
    let resolved = base
        .join(reference)
        .map_err(|err| format!("URI cannot be resolved against the base URL: {err}"))?;
    if resolved.origin() != base.origin() {
        return Err("URI resolves outside the origin of the base URL".into());
    }
    Ok(resolved)
}

/// Resolves the path of the relative reference `uri` to a regular file inside `root`, the
/// canonical base directory.
///
/// Each segment is percent-decoded on its own and joined to the path, then the result is
/// canonicalized, which follows symbolic links, and must still be inside `root`.
#[cfg(feature = "file_io")]
fn resolve_file(root: &Path, uri: &str) -> Result<PathBuf, String> {
    let path = path_component(uri);
    if path.starts_with('/') {
        return Err("URI starts with `/`, which leads outside the base directory".into());
    }

    let mut candidate = root.to_path_buf();
    for raw_segment in path.split('/') {
        let segment = String::from_utf8(percent_decode(raw_segment))
            .map_err(|_| "URI path is not UTF-8 once percent-decoded".to_owned())?;
        match segment.as_str() {
            "" | "." => continue,
            ".." => return Err("URI has a `..` segment".into()),
            _ => {}
        }
        // A decoded `/` or `\` would split the segment, and `\` is a separator on Windows. A
        // decoded space is a valid file name character, unlike a raw one.
        if segment.contains(['/', '\\']) || segment.chars().any(char::is_control) {
            return Err(
                "URI path has an encoded separator or a control character once percent-decoded"
                    .into(),
            );
        }
        // A segment must name one entry of its parent. This also refuses a Windows prefix
        // such as `C:`, which would replace the whole path when pushed.
        let mut components = Path::new(&segment).components();
        if !matches!(
            (components.next(), components.next()),
            (Some(Component::Normal(_)), None)
        ) {
            return Err("URI has a segment that is not a plain file name".into());
        }
        candidate.push(segment);
    }

    let resolved = candidate
        .canonicalize()
        .map_err(|err| format!("file cannot be opened: {err}"))?;
    if !resolved.starts_with(root) {
        return Err("URI leads outside the base directory".into());
    }
    // Checked before opening, because opening a FIFO blocks until a writer appears.
    let metadata =
        fs::metadata(&resolved).map_err(|err| format!("file cannot be inspected: {err}"))?;
    if !metadata.is_file() {
        return Err("URI does not name a regular file".into());
    }
    Ok(resolved)
}

/// A retrieved representation, reduced to what the checks compare.
#[derive(Debug)]
struct Retrieved {
    size: u64,
    hash: Vec<u8>,
    /// `None` when the resource has no media type, which skips the `dc:format` check.
    media_type: Option<String>,
}

/// Retrieves `url` through the HTTP resolver of `context`, within `timeout`.
///
/// A failed retrieval, or one that is too large, is returned as the terminal outcome.
#[async_generic]
fn fetch(
    url: &Url,
    entry: &LinkedResourceEntry,
    context: &Context,
    timeout: Duration,
) -> Result<Retrieved, Outcome> {
    let limit = read_limit(entry)?;
    // Without content coding the body is the representation the spec has us hash; the
    // built-in clients do not decode `gzip` or other codings.
    let request = Request::get(url.as_str())
        .header(header::ACCEPT_ENCODING, "identity")
        .extension(RequestTimeout(timeout))
        .extension(HttpsRedirectsOnly)
        .body(Vec::new())
        .map_err(|err| Outcome::Inaccessible(format!("request cannot be built: {err}")))?;

    let response = if _sync {
        context.resolver().http_resolve(request)
    } else {
        context.resolver_async().http_resolve_async(request).await
    }
    .map_err(|err| Outcome::Inaccessible(format!("request failed: {err}")))?;

    read_response(response, entry, limit)
}

/// Reads the body of `response`, hashing it with the algorithm of `entry`.
fn read_response(
    response: Response<Box<dyn Read>>,
    entry: &LinkedResourceEntry,
    limit: u64,
) -> Result<Retrieved, Outcome> {
    let status = response.status();
    if status != StatusCode::OK {
        return Err(Outcome::Inaccessible(format!(
            "server answered with status {status}"
        )));
    }
    let headers = response.headers();
    // When the platform has decoded the body, `Content-Encoding` no longer applies to it and
    // `Content-Length` counts the coded bytes, so neither says anything about the
    // representation; the bounded read below still applies.
    if !BODY_DECODED_BY_PLATFORM {
        if let Some(coding) = content_coding(headers) {
            return Err(Outcome::Inaccessible(format!(
                "response has content coding `{}`, which is not removed",
                sanitize_for_log(&coding)
            )));
        }
        let advertised_length = headers
            .get(header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok());
        if advertised_length.is_some_and(|length| length > limit) {
            return Err(exceeds_limit(entry));
        }
    }
    let media_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or(DEFAULT_MEDIA_TYPE)
        .to_owned();

    let (size, hash) = read_representation(response.into_body(), entry, limit)?;
    Ok(Retrieved {
        size,
        hash,
        media_type: Some(media_type),
    })
}

/// Returns the content coding that `headers` declare, if any other than `identity`.
fn content_coding(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::CONTENT_ENCODING)?;
    let Ok(value) = value.to_str() else {
        return Some("unreadable".into());
    };
    value
        .split(',')
        .map(str::trim)
        .find(|coding| !coding.is_empty() && !coding.eq_ignore_ascii_case("identity"))
        .map(str::to_owned)
}

/// Reads the file at `path`, hashing it with the algorithm of `entry`.
#[cfg(feature = "file_io")]
fn read_file(path: &Path, entry: &LinkedResourceEntry) -> Result<Retrieved, Outcome> {
    let limit = read_limit(entry)?;
    let file = File::open(path)
        .map_err(|err| Outcome::Inaccessible(format!("file cannot be opened: {err}")))?;
    // `resolve_file` checked the path already; this checks the file actually opened.
    let metadata = file
        .metadata()
        .map_err(|err| Outcome::Inaccessible(format!("file cannot be inspected: {err}")))?;
    if !metadata.is_file() {
        return Err(Outcome::Inaccessible(
            "URI does not name a regular file".into(),
        ));
    }
    if metadata.len() > limit {
        return Err(exceeds_limit(entry));
    }

    let (size, hash) = read_representation(file, entry, limit)?;
    Ok(Retrieved {
        size,
        hash,
        media_type: None,
    })
}

/// The most bytes to read for `entry`: its declared size, or [`MAX_RESOURCE_SIZE`].
fn read_limit(entry: &LinkedResourceEntry) -> Result<u64, Outcome> {
    match entry.size() {
        Some(size) if size > MAX_RESOURCE_SIZE => Err(Outcome::Inaccessible(format!(
            "declared size of {size} bytes exceeds the retrieval limit of {MAX_RESOURCE_SIZE} bytes"
        ))),
        Some(size) => Ok(size),
        None => Ok(MAX_RESOURCE_SIZE),
    }
}

/// The outcome for a resource found to be larger than [`read_limit`].
fn exceeds_limit(entry: &LinkedResourceEntry) -> Outcome {
    match entry.size() {
        Some(size) => {
            Outcome::SizeMismatch(format!("resource is larger than the declared {size} bytes"))
        }
        None => Outcome::Inaccessible(format!(
            "resource exceeds the retrieval limit of {MAX_RESOURCE_SIZE} bytes"
        )),
    }
}

/// Hashes up to `limit` bytes of `reader` and returns their count and hash.
///
/// Reads at most one byte past `limit`, enough to tell that the resource is larger. That
/// bounds what is read from `reader`; an HTTP resolver may have buffered more before
/// returning it.
fn read_representation(
    reader: impl Read,
    entry: &LinkedResourceEntry,
    limit: u64,
) -> Result<(u64, Vec<u8>), Outcome> {
    let (hash, size) = hash_resource(entry.alg(), &mut reader.take(limit + 1))
        .map_err(|err| Outcome::Inaccessible(format!("resource cannot be read: {err}")))?;
    if size > limit {
        return Err(exceeds_limit(entry));
    }
    Ok((size, hash))
}

/// Compares `retrieved` with the declared size, media type and hash of `entry`, in this order.
fn compare(entry: &LinkedResourceEntry, retrieved: &Retrieved) -> Outcome {
    if let Some(size) = entry.size() {
        if retrieved.size != size {
            return Outcome::SizeMismatch(format!(
                "retrieved {} bytes, declared {size}",
                retrieved.size
            ));
        }
    }
    if let (Some(declared), Some(actual)) = (entry.dc_format(), retrieved.media_type.as_deref()) {
        if media_type_essence(declared) != media_type_essence(actual) {
            return Outcome::FormatMismatch(format!(
                "retrieved `{}`, declared `{}`",
                sanitize_for_log(actual),
                sanitize_for_log(declared)
            ));
        }
    }
    if retrieved.hash != entry.hash() {
        return Outcome::HashMismatch;
    }
    Outcome::Match {
        dc_format_skipped: entry.dc_format().is_some() && retrieved.media_type.is_none(),
    }
}

/// The `type/subtype` of a media type, lowercased and without parameters.
///
/// Type and subtype are case-insensitive (RFC 9110, section 8.3.1). Parameters such as
/// `charset` describe how to decode the bytes, not what they are, so they are not compared.
fn media_type_essence(media_type: &str) -> String {
    media_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use std::{
        assert_matches,
        collections::HashMap,
        io::{self, Cursor},
        sync::{Arc, Mutex},
    };

    use async_trait::async_trait;
    #[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
    use wasm_bindgen_test::wasm_bindgen_test;

    use super::*;
    use crate::{
        assertions::{ExternalResource, UriHashedDataMap},
        http::{AsyncHttpResolver, HttpResolverError, SyncHttpResolver},
    };

    const SCRIPT_URL: &str = "https://example.com/assets/main.js";
    const SCRIPT: &[u8] = b"console.log('hello');";

    /// A match whose every declared value was compared.
    const MATCH: Outcome = Outcome::Match {
        dc_format_skipped: false,
    };

    /// A canned HTTP response.
    #[derive(Clone)]
    struct Canned {
        status: u16,
        headers: Vec<(&'static str, String)>,
        body: Vec<u8>,
        /// Fail on the first read of the body, to show that it is never read.
        broken_body: bool,
    }

    impl Canned {
        fn ok(content_type: &'static str, body: &[u8]) -> Self {
            Self {
                status: 200,
                headers: vec![("content-type", content_type.to_owned())],
                body: body.to_vec(),
                broken_body: false,
            }
        }

        fn redirect(location: &str) -> Self {
            Self {
                status: 302,
                headers: vec![("location", location.to_owned())],
                body: Vec::new(),
                broken_body: false,
            }
        }

        fn header(mut self, name: &'static str, value: impl Into<String>) -> Self {
            self.headers.push((name, value.into()));
            self
        }
    }

    struct BrokenBody;

    impl Read for BrokenBody {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("the body must not be read"))
        }
    }

    /// Answers requests from canned responses keyed by URL, and records each request. An
    /// unknown URL fails as a connection error would.
    #[derive(Clone, Default)]
    struct MockResolver {
        responses: Arc<HashMap<String, Canned>>,
        requests: Arc<Mutex<Vec<Request<Vec<u8>>>>>,
    }

    impl MockResolver {
        fn new<const N: usize>(responses: [(&str, Canned); N]) -> Self {
            Self {
                responses: Arc::new(
                    responses
                        .into_iter()
                        .map(|(url, canned)| (url.to_owned(), canned))
                        .collect(),
                ),
                requests: Arc::default(),
            }
        }

        fn context(&self) -> Context {
            Context::new()
                .with_resolver(self.clone())
                .with_resolver_async(self.clone())
        }

        fn requested_urls(&self) -> Vec<String> {
            self.requests
                .lock()
                .unwrap()
                .iter()
                .map(|request| request.uri().to_string())
                .collect()
        }
    }

    impl SyncHttpResolver for MockResolver {
        fn http_resolve(
            &self,
            request: Request<Vec<u8>>,
        ) -> Result<Response<Box<dyn Read>>, HttpResolverError> {
            let canned = self.responses.get(&request.uri().to_string()).cloned();
            self.requests.lock().unwrap().push(request);
            let canned =
                canned.ok_or_else(|| HttpResolverError::Other("connection refused".into()))?;

            let mut response = Response::builder().status(canned.status);
            for (name, value) in canned.headers {
                response = response.header(name, value);
            }
            let body: Box<dyn Read> = if canned.broken_body {
                Box::new(BrokenBody)
            } else {
                Box::new(Cursor::new(canned.body))
            };
            Ok(response.body(body).unwrap())
        }
    }

    #[cfg_attr(not(target_arch = "wasm32"), async_trait)]
    #[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
    impl AsyncHttpResolver for MockResolver {
        async fn http_resolve_async(
            &self,
            request: Request<Vec<u8>>,
        ) -> Result<Response<Box<dyn Read>>, HttpResolverError> {
            self.http_resolve(request)
        }
    }

    /// The script at [`SCRIPT_URL`], with its size and `dc:format`.
    fn script() -> ExternalResource {
        ExternalResource::from_bytes(SCRIPT_URL, "sha256", SCRIPT)
            .unwrap()
            .set_dc_format("text/javascript")
    }

    /// A `relativeResources` entry for `body` at `uri`, with its size and no `dc:format`.
    fn relative(uri: &str, body: &[u8]) -> LinkedResourceEntry {
        let (hash, size) = hash_resource("sha256", &mut &body[..]).unwrap();
        let mut resource = UriHashedDataMap::new(uri.to_owned());
        resource.hash = Some(hash);
        resource.size = Some(size);
        LinkedResourceEntry::Relative {
            alg: "sha256".to_owned(),
            resource,
        }
    }

    fn without_size(mut entry: LinkedResourceEntry) -> LinkedResourceEntry {
        match &mut entry {
            LinkedResourceEntry::External(resource) => resource.size = None,
            LinkedResourceEntry::Relative { resource, .. } => resource.size = None,
        }
        entry
    }

    fn retrieve_with(resolver: &MockResolver, entry: &LinkedResourceEntry) -> Outcome {
        retrieve(
            entry,
            &Base::Missing,
            &resolver.context(),
            RETRIEVAL_TIMEOUT,
        )
    }

    #[test]
    fn matching_external_resource_is_a_match() {
        let resolver = MockResolver::new([(
            SCRIPT_URL,
            Canned::ok("text/javascript; charset=utf-8", SCRIPT),
        )]);

        let outcome = retrieve_with(&resolver, &LinkedResourceEntry::External(script()));

        assert_eq!(outcome, MATCH);
        let requests = resolver.requests.lock().unwrap();
        let [request] = &requests[..] else {
            panic!("expected one request, got {}", requests.len());
        };
        assert_eq!(request.method(), http::Method::GET);
        assert_eq!(request.headers()[header::ACCEPT_ENCODING], "identity");
        assert_eq!(
            request.extensions().get::<RequestTimeout>(),
            Some(&RequestTimeout(RETRIEVAL_TIMEOUT))
        );
        assert_eq!(
            request.extensions().get::<HttpsRedirectsOnly>(),
            Some(&HttpsRedirectsOnly)
        );
    }

    #[c2pa_macros::c2pa_test_async]
    async fn matching_external_resource_is_a_match_async() {
        let resolver = MockResolver::new([(SCRIPT_URL, Canned::ok("text/javascript", SCRIPT))]);
        let entry = LinkedResourceEntry::External(script());

        let outcome = retrieve_async(
            &entry,
            &Base::Missing,
            &resolver.context(),
            RETRIEVAL_TIMEOUT,
        )
        .await;

        assert_eq!(outcome, MATCH);
        assert_eq!(resolver.requested_urls(), [SCRIPT_URL]);
    }

    #[test]
    fn checks_run_in_spec_order() {
        let entry = LinkedResourceEntry::External(script());
        let outcome_for = |content_type, body: &[u8]| {
            let resolver = MockResolver::new([(SCRIPT_URL, Canned::ok(content_type, body))]);
            retrieve_with(&resolver, &entry)
        };
        let shorter = b"console.log(1);";
        let same_size = b"console.log('HELLO');";

        // Size, media type and hash all differ: the size is reported.
        assert_matches!(
            outcome_for("text/plain", shorter),
            Outcome::SizeMismatch(detail) if detail == "retrieved 15 bytes, declared 21"
        );
        // Media type and hash differ: the media type is reported.
        assert_matches!(
            outcome_for("text/plain", same_size),
            Outcome::FormatMismatch(detail)
                if detail == "retrieved `text/plain`, declared `text/javascript`"
        );
        assert_eq!(
            outcome_for("text/javascript", same_size),
            Outcome::HashMismatch
        );
    }

    #[test]
    fn media_types_compare_without_case_or_parameters() {
        assert_eq!(
            media_type_essence(" Text/JavaScript ; charset=UTF-8"),
            "text/javascript"
        );
        assert_eq!(media_type_essence("image/png"), "image/png");

        for content_type in ["TEXT/JAVASCRIPT", "text/javascript;charset=utf-8"] {
            let resolver = MockResolver::new([(SCRIPT_URL, Canned::ok(content_type, SCRIPT))]);
            let outcome = retrieve_with(&resolver, &LinkedResourceEntry::External(script()));
            assert_eq!(outcome, MATCH, "{content_type}");
        }
    }

    #[test]
    fn missing_content_type_is_octet_stream() {
        let mut canned = Canned::ok("unused", SCRIPT);
        canned.headers.clear();
        let resolver = MockResolver::new([(SCRIPT_URL, canned)]);

        let outcome = retrieve_with(&resolver, &LinkedResourceEntry::External(script()));
        assert_matches!(outcome, Outcome::FormatMismatch(detail) if detail.contains(DEFAULT_MEDIA_TYPE));

        let mut without_format = script();
        without_format.dc_format = None;
        let outcome = retrieve_with(&resolver, &LinkedResourceEntry::External(without_format));
        assert_eq!(outcome, MATCH);
    }

    #[test]
    fn failed_retrievals_are_inaccessible() {
        let entry = LinkedResourceEntry::External(script());
        let mut not_found = Canned::ok("text/javascript", SCRIPT);
        not_found.status = 404;
        let cases = [
            ("connection error", None, "request failed"),
            ("status", Some(not_found), "404"),
            (
                "content coding",
                Some(Canned::ok("text/javascript", SCRIPT).header("content-encoding", "gzip")),
                "gzip",
            ),
        ];

        for (case, canned, reason) in cases {
            let resolver = match canned {
                Some(canned) => MockResolver::new([(SCRIPT_URL, canned)]),
                None => MockResolver::default(),
            };
            let outcome = retrieve_with(&resolver, &entry);
            assert_matches!(&outcome, Outcome::Inaccessible(detail) if detail.contains(reason), "{case}: {outcome:?}");
        }
    }

    #[test]
    fn identity_content_coding_is_accepted() {
        let canned = Canned::ok("text/javascript", SCRIPT).header("content-encoding", "identity");
        let resolver = MockResolver::new([(SCRIPT_URL, canned)]);

        let outcome = retrieve_with(&resolver, &LinkedResourceEntry::External(script()));

        assert_eq!(outcome, MATCH);
    }

    #[test]
    fn advertised_length_over_the_declared_size_is_not_read() {
        let mut canned = Canned::ok("text/javascript", SCRIPT).header("content-length", "1000");
        canned.broken_body = true;
        let resolver = MockResolver::new([(SCRIPT_URL, canned)]);

        let outcome = retrieve_with(&resolver, &LinkedResourceEntry::External(script()));

        assert_matches!(outcome, Outcome::SizeMismatch(detail) if detail.contains("larger"));
    }

    #[test]
    fn reading_stops_past_the_declared_size() {
        let mut body = SCRIPT.to_vec();
        body.extend_from_slice(b" // more");
        let resolver = MockResolver::new([(SCRIPT_URL, Canned::ok("text/javascript", &body))]);

        let outcome = retrieve_with(&resolver, &LinkedResourceEntry::External(script()));

        assert_matches!(outcome, Outcome::SizeMismatch(detail) if detail.contains("larger"));
    }

    #[test]
    fn undeclared_size_is_bounded_by_the_limit() {
        let entry = without_size(LinkedResourceEntry::External(script()));
        assert_eq!(read_limit(&entry), Ok(MAX_RESOURCE_SIZE));

        let mut canned = Canned::ok("text/javascript", SCRIPT)
            .header("content-length", (MAX_RESOURCE_SIZE + 1).to_string());
        canned.broken_body = true;
        let resolver = MockResolver::new([(SCRIPT_URL, canned)]);

        let outcome = retrieve_with(&resolver, &entry);

        assert_matches!(outcome, Outcome::Inaccessible(detail) if detail.contains("limit"));
    }

    #[test]
    fn declared_size_over_the_limit_is_not_requested() {
        let entry = LinkedResourceEntry::External(script().set_size(MAX_RESOURCE_SIZE + 1));
        let resolver = MockResolver::new([(SCRIPT_URL, Canned::ok("text/javascript", SCRIPT))]);

        let outcome = retrieve_with(&resolver, &entry);

        assert_matches!(outcome, Outcome::Inaccessible(detail) if detail.contains("limit"));
        assert!(resolver.requested_urls().is_empty());
    }

    #[test]
    fn only_https_urls_without_userinfo_are_retrieved() {
        for url in [
            "https://example.com/a.js",
            "https://example.com:8443/a.js?v=1",
            "HTTPS://Example.COM/a.js",
            "https://example.com/a@b.js",
            "https://[2001:db8::1]/a.js",
        ] {
            assert!(remote_url(url).is_ok(), "{url}");
        }
        for (url, reason) in [
            ("http://example.com/a.js", "`http`"),
            ("ftp://example.com/a.js", "`ftp`"),
            ("file:///etc/hosts", "`file`"),
            ("https://user@example.com/a.js", "userinfo"),
            ("https://user:secret@example.com/a.js", "userinfo"),
            ("https://@example.com/a.js", "userinfo"),
            ("https:user@example.com/a.js", "userinfo"),
            ("https:@example.com/a.js", "userinfo"),
            ("https://example.com\\@evil.example/a.js", "backslash"),
            ("https://exam\tple.com/a.js", "control"),
            ("not a url", "space"),
            ("/a.js", "parsed"),
        ] {
            assert_matches!(remote_url(url), Err(detail) if detail.contains(reason), "{url}");
        }
    }

    #[test]
    fn refused_urls_are_not_requested() {
        let resolver = MockResolver::default();
        for url in ["http://example.com/a.js", "https://user@example.com/a.js"] {
            let entry = LinkedResourceEntry::External(ExternalResource {
                url: url.to_owned(),
                ..script()
            });
            let outcome = retrieve_with(&resolver, &entry);
            assert_matches!(outcome, Outcome::Inaccessible(_), "{url}");
        }
        assert!(resolver.requested_urls().is_empty());
    }

    #[test]
    fn redirects_are_followed_only_to_https_urls_without_userinfo() {
        const MOVED_URL: &str = "https://example.com/assets/moved.js";
        let resolver = MockResolver::new([
            (SCRIPT_URL, Canned::redirect("/assets/moved.js")),
            (MOVED_URL, Canned::ok("text/javascript", SCRIPT)),
            (
                "https://example.com/assets/plain.js",
                Canned::redirect("http://example.com/assets/main.js"),
            ),
            (
                "https://example.com/assets/user.js",
                Canned::redirect("https://user@example.com/assets/main.js"),
            ),
        ]);
        // The built-in resolver stack follows redirects through `RedirectResolver`.
        let redirecting = crate::http::restricted::RedirectResolver::new(resolver.clone(), true);
        let context = Context::new().with_resolver(redirecting);
        let retrieve_url = |url: &str| {
            let entry = LinkedResourceEntry::External(ExternalResource {
                url: url.to_owned(),
                ..script()
            });
            retrieve(&entry, &Base::Missing, &context, RETRIEVAL_TIMEOUT)
        };

        assert_eq!(retrieve_url(SCRIPT_URL), MATCH);
        for url in [
            "https://example.com/assets/plain.js",
            "https://example.com/assets/user.js",
        ] {
            assert_matches!(
                retrieve_url(url),
                Outcome::Inaccessible(detail) if detail.contains("only https targets"),
                "{url}"
            );
        }
        assert_eq!(
            resolver.requested_urls(),
            [
                SCRIPT_URL,
                MOVED_URL,
                "https://example.com/assets/plain.js",
                "https://example.com/assets/user.js"
            ]
        );
    }

    #[test]
    fn relative_references_have_no_scheme_or_authority() {
        for uri in [
            "a.png",
            "./a.png",
            "/a.png",
            "a/b:c.png",
            "a.png?x=1:2#y",
            "%3Aa.png",
        ] {
            assert_eq!(check_relative_reference(uri), Ok(()), "{uri}");
        }
        for uri in [
            "https://example.com/a.png",
            "//example.com/a.png",
            "c:/a.png",
            "a:b",
            "a\\b.png",
            "a b.png",
            "a\n.png",
        ] {
            assert!(check_relative_reference(uri).is_err(), "{uri}");
        }
    }

    #[test]
    fn relative_resource_without_base_is_inaccessible() {
        let resolver = MockResolver::default();

        let outcome = retrieve_with(&resolver, &relative("./a.png", b"png"));

        assert_matches!(outcome, Outcome::Inaccessible(detail) if detail.contains("base"));
        assert!(resolver.requested_urls().is_empty());
    }

    #[test]
    fn url_base_resolves_as_rfc_3986() {
        let base = remote_url("https://example.com/scenes/scene.mtlx").unwrap();
        for (reference, resolved) in [
            (
                "./textures/albedo.png",
                "https://example.com/scenes/textures/albedo.png",
            ),
            (
                "albedo.png?v=2",
                "https://example.com/scenes/albedo.png?v=2",
            ),
            (
                "/shared/albedo.png",
                "https://example.com/shared/albedo.png",
            ),
            ("a.png#part", "https://example.com/scenes/a.png#part"),
        ] {
            assert_eq!(
                resolve_url(&base, reference).map(String::from),
                Ok(resolved.to_owned()),
                "{reference}"
            );
        }

        assert_matches!(resolve_url(&base, "../a.png"), Err(detail) if detail.contains(".."));
        assert_matches!(resolve_url(&base, "%2e%2e/a.png"), Err(detail) if detail.contains(".."));
    }

    #[test]
    fn unusable_url_base_makes_relative_resources_inaccessible() {
        let resolver = MockResolver::default();
        for base in [
            "http://example.com/scene.mtlx",
            "https://user@example.com/",
            "scene.mtlx",
        ] {
            let base = Base::new(Some(&LinkedResourceBase::Url(base.to_owned())));
            assert_matches!(&base, Base::Unusable(reason) if reason.contains("base URL"), "{base:?}");

            let outcome = retrieve(
                &relative("a.png", b"png"),
                &base,
                &resolver.context(),
                RETRIEVAL_TIMEOUT,
            );
            assert_matches!(outcome, Outcome::Inaccessible(detail) if detail.contains("base URL"));
        }
        assert!(resolver.requested_urls().is_empty());
    }

    #[test]
    fn url_base_retrieves_the_resolved_url() {
        const ALBEDO: &[u8] = b"albedo texture";
        let resolver = MockResolver::new([(
            "https://example.com/scenes/textures/albedo.png",
            Canned::ok("image/png", ALBEDO),
        )]);
        let base = Base::new(Some(&LinkedResourceBase::Url(
            "https://example.com/scenes/scene.mtlx".to_owned(),
        )));

        let outcome = retrieve(
            &relative("./textures/albedo.png", ALBEDO),
            &base,
            &resolver.context(),
            RETRIEVAL_TIMEOUT,
        );

        assert_eq!(outcome, MATCH);
        assert_eq!(
            resolver.requested_urls(),
            ["https://example.com/scenes/textures/albedo.png"]
        );
    }

    #[cfg(all(feature = "file_io", not(target_arch = "wasm32")))]
    mod directory {
        use tempfile::TempDir;

        use super::*;

        const ALBEDO: &[u8] = b"albedo texture";

        /// A base directory `base` with `textures/albedo.png` inside, and `secret.txt` next to
        /// it, outside the base. Returns the canonical path of the base.
        fn fixture() -> (TempDir, PathBuf) {
            let root = tempfile::tempdir().unwrap();
            let base = root.path().join("base");
            fs::create_dir_all(base.join("textures")).unwrap();
            fs::write(base.join("textures/albedo.png"), ALBEDO).unwrap();
            fs::write(base.join("textures/albedo.dat"), ALBEDO).unwrap();
            fs::write(root.path().join("secret.txt"), b"secret").unwrap();
            let base = base.canonicalize().unwrap();
            (root, base)
        }

        fn retrieve_in(base: &Path, entry: &LinkedResourceEntry) -> Outcome {
            let base = Base::new(Some(&LinkedResourceBase::Directory(base.to_path_buf())));
            retrieve(entry, &base, &Context::new(), RETRIEVAL_TIMEOUT)
        }

        fn with_dc_format(mut entry: LinkedResourceEntry, dc_format: &str) -> LinkedResourceEntry {
            if let LinkedResourceEntry::Relative { resource, .. } = &mut entry {
                resource.dc_format = Some(dc_format.to_owned());
            }
            entry
        }

        #[test]
        fn file_inside_the_directory_resolves() {
            let (_root, base) = fixture();
            let expected = base.join("textures/albedo.png");

            for path in [
                "textures/albedo.png",
                "./textures/./albedo.png",
                "textures//albedo.png",
                "textures/albedo%2Epng",
                "%74extures/albedo.png?v=1#top",
            ] {
                assert_eq!(resolve_file(&base, path).as_ref(), Ok(&expected), "{path}");
            }

            fs::write(base.join("textures/base color.png"), ALBEDO).unwrap();
            assert_eq!(
                retrieve_in(&base, &relative("textures/base%20color.png", ALBEDO)),
                MATCH
            );
        }

        #[test]
        fn paths_leaving_the_directory_are_refused() {
            let (_root, base) = fixture();
            for (path, reason) in [
                ("/textures/albedo.png", "starts with `/`"),
                ("../secret.txt", ".."),
                ("textures/../../secret.txt", ".."),
                ("%2e%2e/secret.txt", ".."),
                // An encoded `/` is data within one segment, as in a URL.
                ("textures%2Falbedo.png", "encoded separator"),
                ("textures%5c..%5csecret.txt", "encoded separator"),
                ("textures%00albedo.png", "control character"),
                ("missing.png", "cannot be opened"),
            ] {
                assert_matches!(resolve_file(&base, path), Err(detail) if detail.contains(reason), "{path}");
            }
        }

        #[test]
        fn unusable_base_directory_makes_every_entry_inaccessible() {
            let (root, _base) = fixture();
            let missing = root.path().join("missing");

            assert_matches!(
                retrieve_in(&missing, &relative("textures/albedo.png", ALBEDO)),
                Outcome::Inaccessible(detail) if detail.contains("base directory cannot be opened")
            );
        }

        #[cfg(unix)]
        #[test]
        fn symbolic_links_are_followed_only_inside_the_directory() {
            let (root, base) = fixture();
            std::os::unix::fs::symlink(root.path().join("secret.txt"), base.join("escape.txt"))
                .unwrap();
            std::os::unix::fs::symlink(base.join("textures"), base.join("alias")).unwrap();

            assert_matches!(
                resolve_file(&base, "escape.txt"),
                Err(detail) if detail.contains("outside the base directory")
            );
            assert_eq!(
                retrieve_in(&base, &relative("escape.txt", b"secret")),
                Outcome::Inaccessible("URI leads outside the base directory".to_owned())
            );
            assert_eq!(
                retrieve_in(&base, &relative("alias/albedo.png", ALBEDO)),
                MATCH
            );
        }

        #[cfg(unix)]
        #[test]
        fn special_files_are_refused_before_they_are_opened() {
            // Opening a FIFO would block, and a socket cannot be read as a file; both are
            // refused from their metadata. A socket stands in for both here, as std can make
            // one without extra dependencies.
            let (_root, base) = fixture();
            let _listener = std::os::unix::net::UnixListener::bind(base.join("socket")).unwrap();

            assert_matches!(
                resolve_file(&base, "socket"),
                Err(detail) if detail == "URI does not name a regular file"
            );
        }

        #[test]
        fn file_outcomes() {
            let (_root, base) = fixture();
            let albedo = relative("textures/albedo.png", ALBEDO);
            let format_skipped = Outcome::Match {
                dc_format_skipped: true,
            };

            assert_eq!(retrieve_in(&base, &albedo), MATCH);
            // A file has no media type, so a declared `dc:format` is never compared.
            for (path, dc_format) in [
                ("textures/albedo.png", "image/png"),
                ("textures/albedo.png", "image/jpeg"),
                ("textures/albedo.dat", "image/png"),
            ] {
                assert_eq!(
                    retrieve_in(&base, &with_dc_format(relative(path, ALBEDO), dc_format)),
                    format_skipped,
                    "{path} as {dc_format}"
                );
            }
            assert_eq!(
                retrieve_in(&base, &relative("textures/albedo.png", b"other texture!")),
                Outcome::HashMismatch
            );
            assert_matches!(
                retrieve_in(&base, &relative("textures/albedo.png", b"short")),
                Outcome::SizeMismatch(_)
            );
            assert_eq!(
                retrieve_in(&base, &relative("textures/", ALBEDO)),
                Outcome::Inaccessible("URI does not name a regular file".to_owned())
            );
        }
    }

    mod rejection {
        use super::*;
        use crate::utils::test::create_test_store;

        fn log(validation_log: &mut StatusTracker, label: &str, code: &'static str, kind: LogKind) {
            let item = log_item!(label.to_owned(), "test status", "test").validation_status(code);
            match kind {
                LogKind::Success => item.success(validation_log),
                LogKind::Informational => item.informational(validation_log),
                LogKind::Failure => {
                    item.failure_no_throw(validation_log, crate::Error::ValidationRule(code.into()))
                }
            }
        }

        /// A store with one claim, and the success statuses of a claim that validated.
        fn validated_store() -> (Store, StatusTracker, String) {
            let store = create_test_store().unwrap();
            let manifest = store.provenance_label().unwrap();
            let signature = crate::jumbf::labels::to_signature_uri(&manifest);
            let mut validation_log = StatusTracker::default();
            for code in [
                validation_status::CLAIM_SIGNATURE_VALIDATED,
                validation_status::CLAIM_SIGNATURE_INSIDE_VALIDITY,
            ] {
                log(&mut validation_log, &signature, code, LogKind::Success);
            }
            (store, validation_log, manifest)
        }

        #[test]
        fn validated_claim_is_not_rejected() {
            let (store, mut validation_log, manifest) = validated_store();
            log(
                &mut validation_log,
                &to_assertion_uri(&manifest, LinkedResourceIntegrity::LABEL),
                validation_status::ASSERTION_LINKED_RESOURCE_INTEGRITY_SKIPPED,
                LogKind::Informational,
            );

            assert!(!active_claim_rejected(&store, &validation_log));
        }

        #[test]
        fn unverified_claim_is_rejected() {
            let store = create_test_store().unwrap();

            assert!(active_claim_rejected(&store, &StatusTracker::default()));
        }

        #[test]
        fn active_manifest_failure_rejects_the_claim() {
            let (store, mut validation_log, manifest) = validated_store();
            log(
                &mut validation_log,
                &to_assertion_uri(&manifest, "c2pa.hash.data"),
                validation_status::ASSERTION_DATAHASH_MISMATCH,
                LogKind::Failure,
            );

            assert!(active_claim_rejected(&store, &validation_log));
        }

        #[test]
        fn failure_about_an_ingredient_assertion_of_the_active_manifest_rejects_the_claim() {
            // Ingredient checks log failures about the active manifest's own ingredient
            // assertions in the ingredient scope, such as a v3 ingredient without
            // validation results.
            let (store, mut validation_log, manifest) = validated_store();
            let ingredient = to_assertion_uri(&manifest, "c2pa.ingredient.v3");
            validation_log.push_ingredient_uri(ingredient.clone());
            log(
                &mut validation_log,
                &ingredient,
                validation_status::ASSERTION_INGREDIENT_MALFORMED,
                LogKind::Failure,
            );
            validation_log.pop_ingredient_uri();

            assert!(active_claim_rejected(&store, &validation_log));
        }

        #[test]
        fn untrusted_signing_credential_rejects_the_claim() {
            let (store, mut validation_log, manifest) = validated_store();
            log(
                &mut validation_log,
                &crate::jumbf::labels::to_signature_uri(&manifest),
                validation_status::SIGNING_CREDENTIAL_UNTRUSTED,
                LogKind::Failure,
            );

            assert!(active_claim_rejected(&store, &validation_log));
        }

        #[test]
        fn tolerated_failures_elsewhere_do_not_reject_the_claim() {
            let (store, mut validation_log, manifest) = validated_store();
            // A CAWG identity failure is about one identity assertion, not the claim.
            log(
                &mut validation_log,
                &to_assertion_uri(&manifest, "cawg.identity"),
                "cawg.identity.well-formed",
                LogKind::Failure,
            );
            // An untrusted signer of an ingredient manifest does not reject this claim.
            let ingredient = to_assertion_uri(&manifest, "c2pa.ingredient.v3");
            validation_log.push_ingredient_uri(ingredient);
            log(
                &mut validation_log,
                &crate::jumbf::labels::to_signature_uri("urn:c2pa:ingredient"),
                validation_status::SIGNING_CREDENTIAL_UNTRUSTED,
                LogKind::Failure,
            );
            validation_log.pop_ingredient_uri();

            assert!(!active_claim_rejected(&store, &validation_log));
        }
    }

    mod pending {
        use super::*;
        use crate::{
            assertions::LinkedResourceIntegrity, claim::Claim, utils::test::create_test_claim,
        };

        fn script_entries(count: usize) -> Vec<ExternalResource> {
            (0..count)
                .map(|index| {
                    ExternalResource::from_bytes(
                        format!("https://example.com/assets/{index}.js"),
                        "sha256",
                        SCRIPT,
                    )
                    .unwrap()
                })
                .collect()
        }

        /// A claim with one external assertion, and the `skipped` statuses that claim
        /// verification logs for it.
        fn claim_and_log(resources: Vec<ExternalResource>) -> (Claim, StatusTracker) {
            let mut claim = create_test_claim().unwrap();
            claim
                .add_created_assertion(&LinkedResourceIntegrity::external(resources.clone()))
                .unwrap();
            let label = to_assertion_uri(claim.label(), LinkedResourceIntegrity::LABEL);

            let mut validation_log = StatusTracker::default();
            for resource in resources {
                log_item!(label.clone(), "linked resource was not retrieved", "test")
                    .set_resource_url(resource.url)
                    .validation_status(
                        validation_status::ASSERTION_LINKED_RESOURCE_INTEGRITY_SKIPPED,
                    )
                    .informational(&mut validation_log);
            }
            (claim, validation_log)
        }

        #[test]
        fn skipped_statuses_pair_with_entries_in_order() {
            let (claim, validation_log) = claim_and_log(script_entries(3));

            let pending = pending_retrievals(&claim, &validation_log);

            let pairs: Vec<_> = pending
                .iter()
                .map(|pending| (pending.index, pending.entry.resource_url()))
                .collect();
            assert_eq!(
                pairs,
                [
                    (0, "https://example.com/assets/0.js"),
                    (1, "https://example.com/assets/1.js"),
                    (2, "https://example.com/assets/2.js"),
                ]
            );
        }

        #[test]
        fn retrievals_per_manifest_are_bounded() {
            let (claim, validation_log) = claim_and_log(script_entries(MAX_RETRIEVALS + 1));

            assert_eq!(
                pending_retrievals(&claim, &validation_log).len(),
                MAX_RETRIEVALS
            );
        }

        #[test]
        fn statuses_that_do_not_line_up_are_left_alone() {
            let (claim, mut validation_log) = claim_and_log(script_entries(2));
            validation_log.logged_items_mut()[1].resource_url =
                Some("https://example.com/other.js".into());

            assert!(pending_retrievals(&claim, &validation_log).is_empty());

            let (claim, _) = claim_and_log(script_entries(2));
            assert!(pending_retrievals(&claim, &StatusTracker::default()).is_empty());
        }

        #[test]
        fn ingredient_statuses_are_not_retrieved() {
            let (claim, mut validation_log) = claim_and_log(script_entries(1));
            validation_log.logged_items_mut()[0].ingredient_uri = Some("ingredient".into());

            assert!(pending_retrievals(&claim, &validation_log).is_empty());
        }
    }

    #[test]
    fn deadline_caps_each_retrieval_and_runs_out() {
        assert_eq!(
            Deadline::start(RETRIEVAL_BUDGET).next_timeout(),
            Some(RETRIEVAL_TIMEOUT)
        );
        assert_matches!(
            Deadline::start(Duration::from_secs(10)).next_timeout(),
            Some(timeout) if timeout <= Duration::from_secs(10)
        );
        assert_eq!(Deadline::start(Duration::ZERO).next_timeout(), None);
    }

    #[test]
    fn outcome_statuses_carry_resource_url_and_kind() {
        let item = MATCH.into_log_item("assertion".to_owned(), SCRIPT_URL);
        assert_eq!(item.kind, LogKind::Success);
        assert_eq!(
            item.validation_status.as_deref(),
            Some(validation_status::ASSERTION_LINKED_RESOURCE_INTEGRITY_MATCH)
        );
        assert_eq!(item.resource_url.as_deref(), Some(SCRIPT_URL));
        assert_eq!(item.label, "assertion");

        let item = Outcome::Match {
            dc_format_skipped: true,
        }
        .into_log_item("assertion".to_owned(), SCRIPT_URL);
        assert_eq!(item.kind, LogKind::Success);
        assert!(item.description.contains("not compared"));

        let item = Outcome::HashMismatch.into_log_item("assertion".to_owned(), SCRIPT_URL);
        assert_eq!(item.kind, LogKind::Informational);
        assert!(item.err_val.is_none());
    }
}
