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
//! Server-side slicing on a signed offset is the simplest correct model; there
//! is no server-side cursor state to leak or exhaust. The cursor also binds a
//! digest of the exact ordered, visible list it was issued against (its
//! *revision*), so replaying a cursor after the catalog's names, order,
//! descriptors, or visibility change is rejected as stale rather than silently
//! paging an inconsistent snapshot.

use oraclemcp_error::{ErrorClass, ErrorEnvelope};
use serde_json::Value;
use sha2::{Digest, Sha256};

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

/// A digest of the exact ordered, visible list a cursor was issued against.
///
/// Any change to item names, order, descriptor contents, or visibility changes
/// the serialized bytes and therefore this revision, so a cursor minted against
/// an older catalog is detected as stale on replay. It rides inside the
/// MAC-signed cursor, so it only needs to change when the list changes — it does
/// not itself need to resist forgery (the tamper token does that).
fn list_revision(items: &[Value]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(serde_json::to_vec(items).unwrap_or_default());
    hasher
        .finalize()
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Encode an opaque, tamper-evident cursor pointing at `next_offset` of the
/// `kind` listing at `revision`. The `revision:offset` payload is signed, so
/// editing either field invalidates the cursor.
#[must_use]
pub fn encode_cursor(kind: &str, revision: &str, next_offset: usize) -> String {
    sign_token(
        &scope_for(kind),
        &format!("{revision}:{next_offset}"),
        &[kind],
    )
}

/// Decode a client-supplied cursor for the `kind` listing at `current_revision`
/// back to an offset. `None` (absent cursor) starts at offset 0. A
/// present-but-invalid cursor — forged, edited, or minted for a different list —
/// is a hard `InvalidArguments` error (fail closed), never a silent reset to 0.
/// A cursor whose embedded revision no longer matches `current_revision` (the
/// list changed since it was issued) is rejected as stale.
pub fn decode_cursor(
    kind: &str,
    current_revision: &str,
    cursor: Option<&str>,
) -> Result<usize, ErrorEnvelope> {
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
    let (revision, offset) = payload.split_once(':').ok_or_else(|| {
        ErrorEnvelope::new(
            ErrorClass::InvalidArguments,
            format!("invalid {kind} pagination cursor payload"),
        )
    })?;
    if revision != current_revision {
        return Err(ErrorEnvelope::new(
            ErrorClass::InvalidArguments,
            format!("stale {kind} pagination cursor: the list changed since this page was issued"),
        )
        .with_next_step("drop the cursor and restart from the first page"));
    }
    offset.parse::<usize>().map_err(|_| {
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
/// `cursor`. The cursor is bound to a revision digest of `items`, so a cursor
/// issued against a since-changed list is rejected as stale (`InvalidArguments`)
/// rather than paging an inconsistent snapshot. A within-revision offset past
/// the end yields an empty terminal page with no `nextCursor`.
pub fn paginate(kind: &str, items: &[Value], cursor: Option<&str>) -> Result<Page, ErrorEnvelope> {
    let revision = list_revision(items);
    let offset = decode_cursor(kind, &revision, cursor)?.min(items.len());
    let end = offset.saturating_add(LIST_PAGE_SIZE).min(items.len());
    let next_cursor = (end < items.len()).then(|| encode_cursor(kind, &revision, end));
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
    fn a_within_revision_offset_past_the_end_yields_an_empty_terminal_page() {
        let all = items(3);
        // A cursor carrying the CURRENT list revision but an offset past the end
        // (list unchanged) clamps to an empty terminal page rather than erroring.
        let cursor = encode_cursor("tools", &list_revision(&all), 9999);
        let page = paginate("tools", &all, Some(&cursor)).expect("page");
        assert!(page.items.is_empty());
        assert!(page.next_cursor.is_none());
    }

    #[test]
    fn a_cursor_is_rejected_once_the_list_changes_under_it() {
        let v1 = items(LIST_PAGE_SIZE * 2);
        let cursor = paginate("tools", &v1, None)
            .expect("first page")
            .next_cursor
            .expect("more pages");
        // The catalog changes (an item appended) between page 1 and page 2: the
        // revision no longer matches, so the cursor is rejected as stale instead
        // of paging an inconsistent snapshot.
        let mut v2 = v1.clone();
        v2.push(json!({ "i": 9_999 }));
        let err = paginate("tools", &v2, Some(&cursor)).expect_err("stale cursor rejected");
        assert_eq!(err.error_class, ErrorClass::InvalidArguments);
        // A reordering (same length, same set) is also detected.
        let mut v3 = v1.clone();
        v3.swap(0, 1);
        let err = paginate("tools", &v3, Some(&cursor)).expect_err("reorder rejected");
        assert_eq!(err.error_class, ErrorClass::InvalidArguments);
    }

    #[test]
    fn a_cursor_replays_cleanly_while_the_list_is_unchanged() {
        let all = items(LIST_PAGE_SIZE * 2);
        let cursor = paginate("tools", &all, None)
            .expect("first page")
            .next_cursor
            .expect("more pages");
        // Same list, same revision -> the second page is served.
        let page = paginate("tools", &all, Some(&cursor)).expect("second page");
        assert_eq!(page.items.len(), LIST_PAGE_SIZE);
        assert_eq!(page.items[0]["i"].as_u64().unwrap(), LIST_PAGE_SIZE as u64);
    }
}
