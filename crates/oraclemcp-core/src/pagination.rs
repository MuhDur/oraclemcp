//! Opaque, tamper-evident `nextCursor` pagination for the served MCP list
//! endpoints (WP-E E2).
//!
//! MCP `tools/list`, `resources/list`, and `resources/templates/list` may carry
//! a `nextCursor`; a client replays it as `params.cursor` to fetch the next
//! page. The spec treats the cursor as opaque, and we keep it genuinely so: the
//! cursor is a [`crate::tamper_token`]-signed handle that binds the *listing
//! kind* and the *next offset*, so a client cannot forge or edit it to page a
//! different list or jump past the offset it was handed. A tampered or
//! cross-endpoint cursor fails closed (treated as an invalid argument), never
//! silently reads a different slice.
//!
//! These lists are small and static per process, so server-side slicing on a
//! signed offset is the simplest correct model; there is no server-side cursor
//! state to leak or exhaust.

use oraclemcp_error::{ErrorClass, ErrorEnvelope};
use serde_json::Value;

use crate::tamper_token::{sign_token, verify_token};

/// Bounded page size for the static list endpoints. Large enough that the
/// default tool/resource catalogs return in one page (so existing clients see
/// no behavior change), but a real cap so an unbounded future catalog still
/// paginates.
pub const LIST_PAGE_SIZE: usize = 100;

/// The shared tamper-token scope prefix for list cursors. The per-list `kind`
/// is appended so a `tools` cursor never verifies against `resources`.
const CURSOR_SCOPE: &str = "cursor:list";

fn scope_for(kind: &str) -> String {
    format!("{CURSOR_SCOPE}:{kind}")
}

/// Encode an opaque, tamper-evident cursor pointing at `next_offset` of the
/// `kind` listing. The offset is the signed payload, so editing it invalidates
/// the cursor.
#[must_use]
pub fn encode_cursor(kind: &str, next_offset: usize) -> String {
    sign_token(&scope_for(kind), &next_offset.to_string(), &[kind])
}

/// Decode a client-supplied cursor for the `kind` listing back to an offset.
/// `None` (absent cursor) starts at offset 0. A present-but-invalid cursor —
/// forged, edited, or minted for a different list — is a hard
/// `InvalidArguments` error (fail closed), never a silent reset to 0.
pub fn decode_cursor(kind: &str, cursor: Option<&str>) -> Result<usize, ErrorEnvelope> {
    let Some(cursor) = cursor else {
        return Ok(0);
    };
    let cursor = cursor.trim();
    if cursor.is_empty() {
        return Ok(0);
    }
    let payload = verify_token(&scope_for(kind), cursor, &[kind]).ok_or_else(|| {
        ErrorEnvelope::new(
            ErrorClass::InvalidArguments,
            format!("invalid or tampered {kind} pagination cursor"),
        )
        .with_next_step("drop the cursor to restart from the first page")
    })?;
    payload.parse::<usize>().map_err(|_| {
        ErrorEnvelope::new(
            ErrorClass::InvalidArguments,
            format!("invalid {kind} pagination cursor payload"),
        )
    })
}

/// One bounded page of `items` plus the opaque `nextCursor` (if more remain).
#[derive(Debug)]
pub struct Page {
    /// The items in this page.
    pub items: Vec<Value>,
    /// The opaque cursor for the next page, or `None` when the list is
    /// exhausted.
    pub next_cursor: Option<String>,
}

/// Slice `items` into a bounded page starting at the offset encoded in
/// `cursor`. Out-of-range offsets (a stale cursor pointing past a now-shorter
/// list) yield an empty final page with no `nextCursor`, which is a valid
/// terminal page.
pub fn paginate(kind: &str, items: &[Value], cursor: Option<&str>) -> Result<Page, ErrorEnvelope> {
    let offset = decode_cursor(kind, cursor)?.min(items.len());
    let end = offset.saturating_add(LIST_PAGE_SIZE).min(items.len());
    let next_cursor = (end < items.len()).then(|| encode_cursor(kind, end));
    Ok(Page {
        items: items[offset..end].to_vec(),
        next_cursor,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn items(n: usize) -> Vec<Value> {
        (0..n).map(|i| json!({ "i": i })).collect()
    }

    #[test]
    fn single_page_when_under_the_cap_has_no_cursor() {
        let page = paginate("tools", &items(3), None).expect("page");
        assert_eq!(page.items.len(), 3);
        assert!(page.next_cursor.is_none());
    }

    #[test]
    fn round_trips_across_multiple_pages_covering_every_item_once() {
        let all = items(LIST_PAGE_SIZE * 2 + 7);
        let mut seen = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let page = paginate("tools", &all, cursor.as_deref()).expect("page");
            seen.extend(page.items.iter().map(|v| v["i"].as_u64().unwrap()));
            match page.next_cursor {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }
        let expected: Vec<u64> = (0..all.len() as u64).collect();
        assert_eq!(seen, expected, "every item returned exactly once, in order");
    }

    #[test]
    fn a_forged_cursor_offset_is_rejected_not_silently_followed() {
        let all = items(LIST_PAGE_SIZE * 2);
        let page = paginate("tools", &all, None).expect("first page");
        let real = page.next_cursor.expect("more pages");
        // Attacker edits the signed offset payload to jump the boundary.
        let forged = real.replacen(&LIST_PAGE_SIZE.to_string(), "9999", 1);
        let err = paginate("tools", &all, Some(&forged)).expect_err("forged cursor rejected");
        assert_eq!(err.error_class, ErrorClass::InvalidArguments);
    }

    #[test]
    fn a_cursor_minted_for_another_list_is_rejected() {
        let all = items(LIST_PAGE_SIZE * 2);
        let resources_cursor = paginate("resources", &all, None)
            .expect("first page")
            .next_cursor
            .expect("more pages");
        // Replaying a resources cursor against tools/list must fail closed.
        let err = paginate("tools", &all, Some(&resources_cursor))
            .expect_err("cross-list cursor rejected");
        assert_eq!(err.error_class, ErrorClass::InvalidArguments);
    }

    #[test]
    fn a_stale_cursor_past_the_end_yields_an_empty_terminal_page() {
        let cursor = encode_cursor("tools", 9999);
        let page = paginate("tools", &items(3), Some(&cursor)).expect("page");
        assert!(page.items.is_empty());
        assert!(page.next_cursor.is_none());
    }
}
