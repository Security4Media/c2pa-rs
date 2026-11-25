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

//! Signs an asset with a `c2pa.linked-resource-integrity` assertion and reads it back, on
//! both the sync and the async validation paths.

#![cfg(feature = "unstable_linked_resource_integrity")]

use std::io::Cursor;

use c2pa::{
    assertions::{ExternalResource, LinkedResourceIntegrity},
    validation_status::{ValidationStatus, ASSERTION_LINKED_RESOURCE_INTEGRITY_SKIPPED},
    Builder, BuilderIntent, Reader, Result, ValidationState,
};
use c2pa_macros::c2pa_test_async;
#[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
use wasm_bindgen_test::wasm_bindgen_test;

mod common;
use common::test_context;

const FORMAT: &str = "image/jpeg";
const SCRIPT_URL: &str = "https://example.com/assets/main.js";
const STYLE_URL: &str = "https://example.com/assets/style.css";

fn linked_resources() -> Result<LinkedResourceIntegrity> {
    Ok(LinkedResourceIntegrity::external(vec![
        ExternalResource::from_bytes(SCRIPT_URL, "sha256", b"console.log('hello');")?
            .set_dc_format("text/javascript"),
        ExternalResource::from_bytes(STYLE_URL, "sha256", b"body { margin: 0 }")?
            .set_dc_format("text/css"),
    ])
    .set_all_uris_included(true))
}

/// Signs the test JPEG with [`linked_resources`] and returns the signed bytes.
fn signed_asset() -> Result<Vec<u8>> {
    signed_asset_with(&linked_resources()?)
}

/// Signs the test JPEG with `lri` and returns the signed bytes.
fn signed_asset_with(lri: &LinkedResourceIntegrity) -> Result<Vec<u8>> {
    let context = test_context().into_shared();
    let mut builder = Builder::from_shared_context(&context);
    builder.set_intent(BuilderIntent::Edit);
    builder.add_assertion(LinkedResourceIntegrity::LABEL, lri)?;

    let mut source = Cursor::new(include_bytes!("fixtures/CA.jpg"));
    let mut dest = Cursor::new(Vec::new());
    builder.sign(context.signer()?, FORMAT, &mut source, &mut dest)?;
    Ok(dest.into_inner())
}

/// Reads `asset` back as crJSON and checks it against the crJSON schema.
fn crjson_matching_the_schema(asset: &[u8]) -> Result<serde_json::Value> {
    let reader = Reader::from_context(test_context()).with_stream(FORMAT, Cursor::new(asset))?;
    let crjson = reader.to_crjson_value()?;

    let schema: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/schemas/crJSON-schema.json"))?;
    let validator = jsonschema::validator_for(&schema).expect("crJSON schema compiles");
    let errors: Vec<String> = validator
        .iter_errors(&crjson)
        .map(|err| format!("[{}] {err}", err.instance_path()))
        .collect();
    assert!(errors.is_empty(), "{errors:#?}");
    Ok(crjson)
}

fn assert_each_resource_skipped(reader: &Reader) {
    assert_ne!(reader.validation_state(), ValidationState::Invalid);

    let active = reader
        .validation_results()
        .and_then(|results| results.active_manifest())
        .expect("active manifest results");
    let skipped: Vec<_> = active
        .informational()
        .iter()
        .filter(|status| status.code() == ASSERTION_LINKED_RESOURCE_INTEGRITY_SKIPPED)
        .map(|status| (status.url(), status.resource_url()))
        .collect();
    assert_eq!(skipped, [(None, Some(SCRIPT_URL)), (None, Some(STYLE_URL))]);

    let lri_failures: Vec<&ValidationStatus> = active
        .failure()
        .iter()
        .filter(|status| status.code().contains("linkedResourceIntegrity"))
        .collect();
    assert!(lri_failures.is_empty(), "{lri_failures:?}");
}

#[test]
fn signed_assertion_reports_each_resource_as_skipped() -> Result<()> {
    let asset = signed_asset()?;

    let reader = Reader::from_context(test_context()).with_stream(FORMAT, Cursor::new(&asset))?;

    assert_each_resource_skipped(&reader);
    Ok(())
}

#[c2pa_test_async]
async fn signed_assertion_reports_each_resource_as_skipped_async() -> Result<()> {
    let asset = signed_asset()?;

    let reader = Reader::from_context(test_context())
        .with_stream_async(FORMAT, Cursor::new(&asset))
        .await?;

    assert_each_resource_skipped(&reader);
    Ok(())
}

#[test]
fn signed_assertion_reads_back_unchanged() -> Result<()> {
    let asset = signed_asset()?;

    let reader = Reader::from_context(test_context()).with_stream(FORMAT, Cursor::new(&asset))?;
    let manifest = reader.active_manifest().expect("active manifest");
    let read_back: LinkedResourceIntegrity =
        manifest.find_assertion(LinkedResourceIntegrity::LABEL)?;

    assert_eq!(read_back, linked_resources()?);
    Ok(())
}

#[test]
fn resource_url_appears_in_reader_json() -> Result<()> {
    let asset = signed_asset()?;

    let reader = Reader::from_context(test_context()).with_stream(FORMAT, Cursor::new(&asset))?;
    let json: serde_json::Value = serde_json::from_str(&reader.json())?;

    let informational = json["validation_results"]["activeManifest"]["informational"]
        .as_array()
        .expect("informational statuses");
    let skipped: Vec<_> = informational
        .iter()
        .filter(|status| status["code"] == ASSERTION_LINKED_RESOURCE_INTEGRITY_SKIPPED)
        .collect();
    assert_eq!(skipped.len(), 2);
    for status in skipped {
        assert!(status.get("url").is_none(), "{status}");
        assert!(status["resourceUrl"].is_string(), "{status}");
    }
    Ok(())
}

#[test]
fn crjson_with_resource_url_matches_the_schema() -> Result<()> {
    let crjson = crjson_matching_the_schema(&signed_asset()?)?.to_string();

    assert!(crjson.contains(&format!("\"resourceUrl\":\"{SCRIPT_URL}\"")));
    assert!(crjson.contains(&format!("\"resourceUrl\":\"{STYLE_URL}\"")));
    Ok(())
}

#[test]
fn crjson_of_relative_resources_matches_the_schema() -> Result<()> {
    let mut lri = LinkedResourceIntegrity::relative("sha256", Vec::new());
    lri.add_relative_from_bytes("./scenes/albedo.png", b"albedo texture")?
        .dc_format = Some("image/png".to_owned());

    let crjson = crjson_matching_the_schema(&signed_asset_with(&lri)?)?.to_string();

    assert!(crjson.contains("\"resourceUrl\":\"./scenes/albedo.png\""));
    Ok(())
}

#[test]
fn signed_asset_as_parent_ingredient_stays_valid() -> Result<()> {
    let parent = signed_asset()?;
    let context = test_context().into_shared();
    let mut builder = Builder::from_shared_context(&context);
    builder.set_intent(BuilderIntent::Edit);
    let mut dest = Cursor::new(Vec::new());
    builder.sign(
        context.signer()?,
        FORMAT,
        &mut Cursor::new(&parent),
        &mut dest,
    )?;

    let reader =
        Reader::from_context(test_context()).with_stream(FORMAT, Cursor::new(dest.get_ref()))?;

    assert_ne!(reader.validation_state(), ValidationState::Invalid);
    let results = reader.validation_results().expect("validation results");
    let failures: Vec<&ValidationStatus> = results
        .active_manifest()
        .into_iter()
        .chain(
            results
                .ingredient_deltas()
                .into_iter()
                .flatten()
                .map(|delta| delta.validation_deltas()),
        )
        .flat_map(|codes| codes.failure())
        .collect();
    assert!(failures.is_empty(), "{failures:?}");
    Ok(())
}

#[test]
fn reader_into_builder_keeps_the_assertion() -> Result<()> {
    let asset = signed_asset()?;
    let reader = Reader::from_context(test_context()).with_stream(FORMAT, Cursor::new(&asset))?;
    let mut builder = reader.into_builder()?;

    let context = test_context();
    let mut source = Cursor::new(include_bytes!("fixtures/CA.jpg"));
    let mut dest = Cursor::new(Vec::new());
    builder.sign(context.signer()?, FORMAT, &mut source, &mut dest)?;

    let reader =
        Reader::from_context(test_context()).with_stream(FORMAT, Cursor::new(dest.get_ref()))?;
    assert_each_resource_skipped(&reader);
    let read_back: LinkedResourceIntegrity = reader
        .active_manifest()
        .expect("active manifest")
        .find_assertion(LinkedResourceIntegrity::LABEL)?;
    assert_eq!(read_back, linked_resources()?);
    Ok(())
}
