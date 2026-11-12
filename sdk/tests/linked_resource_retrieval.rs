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

//! Signs assets with `c2pa.linked-resource-integrity` assertions and reads them back with
//! `verify.fetch_linked_resources` on. Network retrievals go to a mock HTTP resolver, so these
//! tests never touch the network; the signer needs no time-stamp service either.

#![cfg(feature = "unstable_linked_resource_integrity")]

use std::{
    collections::HashMap,
    io::{Cursor, Read},
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use c2pa::{
    assertions::{ExternalResource, LinkedResourceIntegrity},
    http::{
        http::{Request, Response},
        AsyncHttpResolver, HttpResolverError, SyncHttpResolver,
    },
    validation_status::{
        ASSERTION_LINKED_RESOURCE_INTEGRITY_FORMAT_MISMATCH as FORMAT_MISMATCH,
        ASSERTION_LINKED_RESOURCE_INTEGRITY_HASH_MISMATCH as HASH_MISMATCH,
        ASSERTION_LINKED_RESOURCE_INTEGRITY_INACCESSIBLE as INACCESSIBLE,
        ASSERTION_LINKED_RESOURCE_INTEGRITY_INVALID_URI as INVALID_URI,
        ASSERTION_LINKED_RESOURCE_INTEGRITY_MATCH as MATCH,
        ASSERTION_LINKED_RESOURCE_INTEGRITY_SIZE_MISMATCH as SIZE_MISMATCH,
        ASSERTION_LINKED_RESOURCE_INTEGRITY_SKIPPED as SKIPPED, SIGNING_CREDENTIAL_UNTRUSTED,
    },
    Builder, BuilderIntent, Context, LinkedResourceBase, Reader, Result, ValidationState,
};
use c2pa_macros::c2pa_test_async;
#[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
use wasm_bindgen_test::wasm_bindgen_test;

mod common;
use common::{test_context, test_signer};

const FORMAT: &str = "image/jpeg";

const SCRIPT_URL: &str = "https://example.com/assets/main.js";
const SCRIPT: &[u8] = b"console.log('hello');";
const STYLE_URL: &str = "https://example.com/assets/style.css";
const STYLE: &[u8] = b"body { margin: 0 }";
const ALBEDO: &[u8] = b"albedo texture";

/// Answers requests from fixed `(content type, body)` responses keyed by URL and records each
/// requested URL. An unknown URL fails as a refused connection would.
#[derive(Clone, Default)]
struct MockResolver {
    responses: Arc<HashMap<String, (&'static str, Vec<u8>)>>,
    requests: Arc<Mutex<Vec<String>>>,
}

impl MockResolver {
    fn new<const N: usize>(responses: [(&str, &'static str, &[u8]); N]) -> Self {
        Self {
            responses: Arc::new(
                responses
                    .into_iter()
                    .map(|(url, content_type, body)| {
                        (url.to_owned(), (content_type, body.to_vec()))
                    })
                    .collect(),
            ),
            requests: Arc::default(),
        }
    }

    fn requested_urls(&self) -> Vec<String> {
        self.requests.lock().expect("requests lock").clone()
    }
}

impl SyncHttpResolver for MockResolver {
    fn http_resolve(
        &self,
        request: Request<Vec<u8>>,
    ) -> std::result::Result<Response<Box<dyn Read>>, HttpResolverError> {
        let url = request.uri().to_string();
        self.requests
            .lock()
            .expect("requests lock")
            .push(url.clone());
        let (content_type, body) = self
            .responses
            .get(&url)
            .cloned()
            .ok_or_else(|| HttpResolverError::Other("connection refused".into()))?;
        Ok(Response::builder()
            .status(200)
            .header("content-type", content_type)
            .body(Box::new(Cursor::new(body)) as Box<dyn Read>)?)
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl AsyncHttpResolver for MockResolver {
    async fn http_resolve_async(
        &self,
        request: Request<Vec<u8>>,
    ) -> std::result::Result<Response<Box<dyn Read>>, HttpResolverError> {
        self.http_resolve(request)
    }
}

/// The standard test context with linked resource retrieval on.
fn fetching_context() -> Context {
    test_context()
        .with_settings_value("verify.fetch_linked_resources", true)
        .expect("valid setting")
}

/// [`fetching_context`] with every HTTP request answered by `resolver`.
fn mock_context(resolver: &MockResolver) -> Context {
    fetching_context()
        .with_resolver(resolver.clone())
        .with_resolver_async(resolver.clone())
}

/// An `externalResources` entry for the test script at `url`.
fn script(url: &str) -> Result<ExternalResource> {
    Ok(ExternalResource::from_bytes(url, "sha256", SCRIPT)?.set_dc_format("text/javascript"))
}

/// An assertion with one `relativeResources` entry, for `body` at `uri`.
fn relative(uri: &str, body: &[u8]) -> Result<LinkedResourceIntegrity> {
    let mut lri = LinkedResourceIntegrity::relative("sha256", Vec::new());
    lri.add_relative_from_bytes(uri, body)?;
    Ok(lri)
}

fn sign_with(context: Context, lri: &LinkedResourceIntegrity) -> Result<Vec<u8>> {
    let mut builder = Builder::from_context(context);
    builder.set_intent(BuilderIntent::Edit);
    builder.add_assertion(LinkedResourceIntegrity::LABEL, lri)?;

    let mut source = Cursor::new(include_bytes!("fixtures/no_manifest.jpg"));
    let mut dest = Cursor::new(Vec::new());
    builder.sign(&test_signer(), FORMAT, &mut source, &mut dest)?;
    Ok(dest.into_inner())
}

/// Signs the test JPEG with `lri`. The callback test signer needs no network.
fn sign(lri: &LinkedResourceIntegrity) -> Result<Vec<u8>> {
    sign_with(test_context(), lri)
}

fn read(reader: Reader, asset: &[u8]) -> Result<Reader> {
    reader.with_stream(FORMAT, Cursor::new(asset))
}

/// The code and `resourceUrl` of every linked resource integrity status of the active
/// manifest, successes first, then informational codes, then failures.
fn lri_statuses(reader: &Reader) -> Vec<(&str, &str)> {
    let active = reader
        .validation_results()
        .and_then(|results| results.active_manifest())
        .expect("active manifest results");
    active
        .success()
        .iter()
        .chain(active.informational())
        .chain(active.failure())
        .filter(|status| {
            status
                .code()
                .starts_with("assertion.linkedResourceIntegrity.")
        })
        .map(|status| (status.code(), status.resource_url().unwrap_or_default()))
        .collect()
}

#[test]
fn retrieved_resources_that_match_are_reported_as_match() -> Result<()> {
    let lri = LinkedResourceIntegrity::external(vec![
        script(SCRIPT_URL)?,
        ExternalResource::from_bytes(STYLE_URL, "sha256", STYLE)?.set_dc_format("text/css"),
    ]);
    let asset = sign(&lri)?;
    let resolver = MockResolver::new([
        (SCRIPT_URL, "text/javascript", SCRIPT),
        (STYLE_URL, "text/css; charset=utf-8", STYLE),
    ]);

    let reader = read(Reader::from_context(mock_context(&resolver)), &asset)?;

    assert_eq!(
        lri_statuses(&reader),
        [(MATCH, SCRIPT_URL), (MATCH, STYLE_URL)]
    );
    assert_eq!(resolver.requested_urls(), [SCRIPT_URL, STYLE_URL]);
    assert_ne!(reader.validation_state(), ValidationState::Invalid);
    Ok(())
}

#[c2pa_test_async]
async fn retrieved_resources_that_match_are_reported_as_match_async() -> Result<()> {
    let asset = sign(&LinkedResourceIntegrity::external(vec![script(
        SCRIPT_URL,
    )?]))?;
    let resolver = MockResolver::new([(SCRIPT_URL, "text/javascript", SCRIPT)]);

    let reader = Reader::from_context(mock_context(&resolver))
        .with_stream_async(FORMAT, Cursor::new(&asset))
        .await?;

    assert_eq!(lri_statuses(&reader), [(MATCH, SCRIPT_URL)]);
    assert_eq!(resolver.requested_urls(), [SCRIPT_URL]);
    Ok(())
}

#[test]
fn each_retrieval_outcome_is_reported_without_rejecting_the_manifest() -> Result<()> {
    const TAMPERED_URL: &str = "https://example.com/assets/tampered.js";
    const RESIZED_URL: &str = "https://example.com/assets/resized.js";
    const RETYPED_URL: &str = "https://example.com/assets/retyped.js";
    const MISSING_URL: &str = "https://example.com/assets/missing.js";
    const HTTP_URL: &str = "http://example.com/assets/plain.js";
    const USERINFO_URL: &str = "https://user@example.com/assets/main.js";
    let lri = LinkedResourceIntegrity::external(vec![
        script(SCRIPT_URL)?,
        script(TAMPERED_URL)?,
        script(RESIZED_URL)?,
        script(RETYPED_URL)?,
        script(MISSING_URL)?,
        script(HTTP_URL)?,
        script(USERINFO_URL)?,
    ]);
    let asset = sign(&lri)?;
    let resolver = MockResolver::new([
        (SCRIPT_URL, "text/javascript", SCRIPT),
        (TAMPERED_URL, "text/javascript", b"console.log('HELLO');"),
        (
            RESIZED_URL,
            "text/javascript",
            b"console.log('hello, world');",
        ),
        (RETYPED_URL, "text/plain", SCRIPT),
    ]);

    let reader = read(Reader::from_context(mock_context(&resolver)), &asset)?;

    assert_eq!(
        lri_statuses(&reader),
        [
            (MATCH, SCRIPT_URL),
            (HASH_MISMATCH, TAMPERED_URL),
            (SIZE_MISMATCH, RESIZED_URL),
            (FORMAT_MISMATCH, RETYPED_URL),
            (INACCESSIBLE, MISSING_URL),
            (INACCESSIBLE, HTTP_URL),
            (INACCESSIBLE, USERINFO_URL),
        ]
    );
    // The `http` and userinfo URLs are refused before any request.
    assert_eq!(
        resolver.requested_urls(),
        [
            SCRIPT_URL,
            TAMPERED_URL,
            RESIZED_URL,
            RETYPED_URL,
            MISSING_URL
        ]
    );
    assert_ne!(reader.validation_state(), ValidationState::Invalid);
    Ok(())
}

#[test]
fn hosts_outside_the_allow_list_are_inaccessible() -> Result<()> {
    let asset = sign(&LinkedResourceIntegrity::external(vec![script(
        SCRIPT_URL,
    )?]))?;
    // The default resolver refuses the host before opening any connection.
    let context = fetching_context()
        .with_settings_value("core.allowed_network_hosts", ["assets.example.net"])?;

    let reader = read(Reader::from_context(context), &asset)?;

    assert_eq!(lri_statuses(&reader), [(INACCESSIBLE, SCRIPT_URL)]);
    Ok(())
}

#[test]
fn resources_of_a_rejected_manifest_stay_skipped() -> Result<()> {
    let mut asset = sign(&LinkedResourceIntegrity::external(vec![script(
        SCRIPT_URL,
    )?]))?;
    // Change a byte of the image data so the hard binding fails.
    let index = asset.len() - 10;
    asset[index] ^= 0x01;
    let resolver = MockResolver::new([(SCRIPT_URL, "text/javascript", SCRIPT)]);

    let reader = read(Reader::from_context(mock_context(&resolver)), &asset)?;

    assert_eq!(reader.validation_state(), ValidationState::Invalid);
    assert_eq!(lri_statuses(&reader), [(SKIPPED, SCRIPT_URL)]);
    assert!(resolver.requested_urls().is_empty());
    Ok(())
}

#[test]
fn resources_of_an_untrusted_signer_stay_skipped() -> Result<()> {
    let asset = sign(&LinkedResourceIntegrity::external(vec![script(
        SCRIPT_URL,
    )?]))?;
    let resolver = MockResolver::new([(SCRIPT_URL, "text/javascript", SCRIPT)]);
    // The default settings configure no trust list, so the test signer is untrusted.
    let context = Context::new()
        .with_settings_value("verify.fetch_linked_resources", true)?
        .with_resolver(resolver.clone())
        .with_resolver_async(resolver.clone());

    let reader = read(Reader::from_context(context), &asset)?;

    let untrusted = reader
        .validation_results()
        .and_then(|results| results.active_manifest())
        .is_some_and(|active| {
            active
                .failure()
                .iter()
                .any(|status| status.code() == SIGNING_CREDENTIAL_UNTRUSTED)
        });
    assert!(untrusted);
    assert_eq!(reader.validation_state(), ValidationState::Valid);
    assert_eq!(lri_statuses(&reader), [(SKIPPED, SCRIPT_URL)]);
    assert!(resolver.requested_urls().is_empty());
    Ok(())
}

#[test]
fn nothing_is_retrieved_when_the_manifest_is_not_verified() -> Result<()> {
    let asset = sign(&LinkedResourceIntegrity::external(vec![script(
        SCRIPT_URL,
    )?]))?;
    let resolver = MockResolver::new([(SCRIPT_URL, "text/javascript", SCRIPT)]);
    let context = fetching_context()
        .with_settings_value("verify.verify_after_reading", false)?
        .with_resolver(resolver.clone())
        .with_resolver_async(resolver.clone());

    read(Reader::from_context(context), &asset)?;

    assert!(resolver.requested_urls().is_empty());
    Ok(())
}

#[test]
fn parent_segment_rejects_the_manifest_and_nothing_is_retrieved() -> Result<()> {
    // Verification after signing would refuse this assertion, so it is turned off here.
    let signing_context = test_context().with_settings_value("verify.verify_after_sign", false)?;
    let asset = sign_with(signing_context, &relative("../secret.txt", b"secret")?)?;
    let resolver = MockResolver::default();
    let base = LinkedResourceBase::Url("https://example.com/scenes/scene.mtlx".to_owned());

    let reader = read(
        Reader::from_context(mock_context(&resolver)).with_linked_resource_base(base),
        &asset,
    )?;

    assert_eq!(reader.validation_state(), ValidationState::Invalid);
    assert_eq!(
        lri_statuses(&reader),
        [(SKIPPED, "../secret.txt"), (INVALID_URI, "../secret.txt")]
    );
    assert!(resolver.requested_urls().is_empty());
    Ok(())
}

#[test]
fn resources_stay_skipped_when_retrieval_is_off() -> Result<()> {
    let asset = sign(&LinkedResourceIntegrity::external(vec![script(
        SCRIPT_URL,
    )?]))?;
    let resolver = MockResolver::new([(SCRIPT_URL, "text/javascript", SCRIPT)]);
    let context = test_context()
        .with_resolver(resolver.clone())
        .with_resolver_async(resolver.clone());

    let reader = read(Reader::from_context(context), &asset)?;

    assert_eq!(lri_statuses(&reader), [(SKIPPED, SCRIPT_URL)]);
    assert!(resolver.requested_urls().is_empty());
    Ok(())
}

#[test]
fn relative_resources_resolve_against_a_url_base() -> Result<()> {
    let mut lri = relative("./textures/albedo.png", ALBEDO)?;
    lri.add_relative_from_bytes("/shared/style.css", STYLE)?;
    let asset = sign(&lri)?;
    let resolver = MockResolver::new([
        (
            "https://example.com/scenes/textures/albedo.png",
            "image/png",
            ALBEDO,
        ),
        ("https://example.com/shared/style.css", "text/css", STYLE),
    ]);
    let base = LinkedResourceBase::Url("https://example.com/scenes/scene.mtlx".to_owned());

    let reader = read(
        Reader::from_context(mock_context(&resolver)).with_linked_resource_base(base),
        &asset,
    )?;

    assert_eq!(
        lri_statuses(&reader),
        [
            (MATCH, "./textures/albedo.png"),
            (MATCH, "/shared/style.css")
        ]
    );
    assert_eq!(
        resolver.requested_urls(),
        [
            "https://example.com/scenes/textures/albedo.png",
            "https://example.com/shared/style.css"
        ]
    );
    Ok(())
}

#[c2pa_test_async]
async fn relative_resources_without_a_base_are_inaccessible_async() -> Result<()> {
    let asset = sign(&relative("./textures/albedo.png", ALBEDO)?)?;
    let resolver = MockResolver::default();

    let reader = Reader::from_context(mock_context(&resolver))
        .with_stream_async(FORMAT, Cursor::new(&asset))
        .await?;

    assert_eq!(
        lri_statuses(&reader),
        [(INACCESSIBLE, "./textures/albedo.png")]
    );
    assert!(resolver.requested_urls().is_empty());
    Ok(())
}

#[cfg(all(feature = "file_io", not(target_arch = "wasm32")))]
#[test]
fn relative_resources_resolve_inside_a_directory_base() -> Result<()> {
    use std::fs;

    let root = tempfile::tempdir()?;
    let base = root.path().join("scene");
    fs::create_dir_all(base.join("textures"))?;
    fs::write(base.join("textures/albedo.png"), ALBEDO)?;
    fs::write(base.join("textures/normal.png"), b"NORMAL MAP")?;
    fs::write(base.join("textures/height.png"), b"edited height map")?;
    fs::write(root.path().join("secret.txt"), b"secret")?;
    #[cfg(unix)]
    std::os::unix::fs::symlink(root.path().join("secret.txt"), base.join("escape.txt"))?;

    let mut lri = relative("./textures/albedo.png", ALBEDO)?;
    lri.add_relative_from_bytes("textures/normal.png", b"normal map")?;
    lri.add_relative_from_bytes("textures/height.png", b"height map")?;
    lri.add_relative_from_bytes("textures/missing.png", ALBEDO)?;
    lri.add_relative_from_bytes("/textures/albedo.png", ALBEDO)?;
    lri.add_relative_from_bytes("escape.txt", b"secret")?;
    let asset = sign(&lri)?;

    let reader = read(
        Reader::from_context(fetching_context())
            .with_linked_resource_base(LinkedResourceBase::Directory(base)),
        &asset,
    )?;

    assert_eq!(
        lri_statuses(&reader),
        [
            (MATCH, "./textures/albedo.png"),
            (HASH_MISMATCH, "textures/normal.png"),
            (SIZE_MISMATCH, "textures/height.png"),
            (INACCESSIBLE, "textures/missing.png"),
            (INACCESSIBLE, "/textures/albedo.png"),
            (INACCESSIBLE, "escape.txt"),
        ]
    );
    Ok(())
}

#[test]
fn resource_url_appears_in_the_reader_json() -> Result<()> {
    let asset = sign(&LinkedResourceIntegrity::external(vec![script(
        SCRIPT_URL,
    )?]))?;
    let resolver = MockResolver::new([(SCRIPT_URL, "text/javascript", SCRIPT)]);

    let reader = read(Reader::from_context(mock_context(&resolver)), &asset)?;
    let json: serde_json::Value = serde_json::from_str(&reader.json())?;

    let success = json["validation_results"]["activeManifest"]["success"]
        .as_array()
        .expect("success statuses");
    let matched: Vec<_> = success
        .iter()
        .filter(|status| status["code"] == MATCH)
        .collect();
    assert_eq!(matched.len(), 1);
    assert_eq!(matched[0]["resourceUrl"], SCRIPT_URL);
    assert!(matched[0].get("url").is_none(), "{}", matched[0]);
    Ok(())
}
