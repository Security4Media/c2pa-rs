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

//! URI helpers for the URIs listed in linked resource integrity assertions.
//!
//! Validation uses [`has_parent_segment`] on every `relativeResources` URI; retrieval uses the
//! same helpers to resolve those URIs against a base location.

/// The path of the URI reference `uri`: everything before the first raw `?` or `#`.
pub(crate) fn path_component(uri: &str) -> &str {
    uri.find(['?', '#']).map_or(uri, |end| &uri[..end])
}

/// Returns `true` if `uri` has a path segment that is exactly `..` once percent-decoded.
///
/// The spec's rule decodes the whole URI and looks for a `/`-delimited piece that is exactly
/// `..`. That alone accepts `a/..?v=1`, whose path still ends in `..`, so the path without its
/// raw query and fragment is checked the same way. An encoded `%3F` or `%23` is part of a
/// segment, so `..%3Fx` names a file called `..?x` and is accepted.
pub(crate) fn has_parent_segment(uri: &str) -> bool {
    let has_dot_dot = |decoded: Vec<u8>| {
        decoded
            .split(|&byte| byte == b'/')
            .any(|segment| segment == b"..")
    };
    has_dot_dot(percent_decode(uri)) || has_dot_dot(percent_decode(path_component(uri)))
}

/// Decodes `%XX` escapes once. A `%` that does not start a valid escape is kept as is.
pub(crate) fn percent_decode(input: &str) -> Vec<u8> {
    fn hex_digit(byte: u8) -> Option<u8> {
        char::from(byte)
            .to_digit(16)
            .and_then(|digit| u8::try_from(digit).ok())
    }

    let mut decoded = Vec::with_capacity(input.len());
    let mut rest = input.as_bytes();
    while let Some((&byte, tail)) = rest.split_first() {
        if byte == b'%' {
            if let [high, low, after @ ..] = tail {
                if let (Some(high), Some(low)) = (hex_digit(*high), hex_digit(*low)) {
                    decoded.push((high << 4) | low);
                    rest = after;
                    continue;
                }
            }
        }
        decoded.push(byte);
        rest = tail;
    }
    decoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_component_stops_at_the_first_query_or_fragment() {
        assert_eq!(path_component("a/b.png?x#y"), "a/b.png");
        assert_eq!(path_component("a/b.png#y?x"), "a/b.png");
        assert_eq!(path_component("a/b.png"), "a/b.png");
        assert_eq!(path_component("a%3Fb.png"), "a%3Fb.png");
    }

    #[test]
    fn parent_segments_are_found_after_percent_decoding() {
        for uri in [
            "../a.png",
            "a/..",
            "a/../b.png",
            "%2e%2e/a.png",
            "%2E%2e/a.png",
            ".%2e/a.png",
            "a%2f..%2fb.png",
            "/../a.png",
            "a/..?v=1",
            "a/..#frag",
            // The spec's rule covers the whole decoded URI, query included.
            "a.png?x=/../y",
        ] {
            assert!(has_parent_segment(uri), "{uri}");
        }
    }

    #[test]
    fn other_dots_are_not_parent_segments() {
        for uri in [
            "./a.png",
            "a/./b.png",
            "..a.png",
            "a...png",
            ".../a.png",
            "%2e/a.png",
            // Decoded once, this is the literal name `%2e%2e`.
            "%252e%252e/a.png",
            "%zz/a.png",
            "a.png%",
            "/textures/a.png",
            "a.png?v=..",
            // Encoded delimiters are part of the segment: these name `..?x` and `..#x`.
            "..%3Fx",
            "a/..%23x",
        ] {
            assert!(!has_parent_segment(uri), "{uri}");
        }
    }

    #[test]
    fn percent_decode_decodes_valid_escapes_once() {
        assert_eq!(percent_decode("a%2Fb%2fc"), b"a/b/c");
        assert_eq!(percent_decode("%252e"), b"%2e");
        assert_eq!(percent_decode("%e2%82%ac"), "\u{20ac}".as_bytes());
        assert_eq!(percent_decode("%g1%1"), b"%g1%1");
        assert_eq!(percent_decode("%+1"), b"%+1");
        assert_eq!(percent_decode("%"), b"%");
    }
}
