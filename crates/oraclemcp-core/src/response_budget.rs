//! One whole-MCP-response byte budget, charged across every transport (QA100
//! bead `oraclemcp-qa100-post-v080-audit-5u1n.116`).
//!
//! `oraclemcp-db`'s `max_result_bytes` is only enforceable as the sum of the
//! *compact row-object payloads* of one query page (bead `.89`). Everything the
//! response gains afterwards escapes that cap:
//!
//! - column metadata, array separators, and pagination/cursor fields;
//! - sealed/nested cursor serialization;
//! - the MCP `tools/call` result envelope — which embeds the structured payload
//!   **twice**, once fenced as `content[0].text` and once as
//!   `structuredContent`, so a 25 MiB row payload alone becomes ~50 MiB;
//! - the JSON-RPC frame and the per-transport SSE / chunked framing;
//! - stateful replay-store cloning.
//!
//! A single authenticated caller could therefore drive a response many times
//! larger than the advertised row cap onto the wire and into the replay store.
//! This module defines [`ResponseByteBudget`]: one budget that charges the whole
//! serialized response — measured at the actual wire boundary — before it is
//! written to any transport or inserted into the stateful replay store. An
//! oversized response is replaced by a bounded, typed "response too large"
//! JSON-RPC error whose own serialized size is guaranteed to fit the budget, so
//! we never advertise a cap smaller than the unavoidable error envelope.
//!
//! This composes with bead `.52`, which separately bounds how much of an
//! in-budget response the stateful replay store *retains*: `.116` refuses to
//! ever build/deliver an unbounded response; `.52` bounds retention of the
//! bounded ones.

use serde_json::{Value, json};

/// Hard ceiling on the whole serialized MCP response placed on the wire for one
/// JSON-RPC request: JSON-RPC frame + tool/result envelope + DB row payload +
/// column metadata + pagination cursor + per-transport (SSE / chunked) framing.
///
/// Sized above the largest response the downstream caps permit: the
/// `oracle_query` row-payload page cap is 25 MiB, and the `tools/call` envelope
/// embeds that payload twice (fenced text + structured content), so a legitimate
/// maximum page is ~50 MiB at the wire. 64 MiB leaves headroom for column
/// metadata, fencing, and framing while still refusing an unbounded response.
pub const MAX_MCP_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

/// Maximum per-response transport framing charged on top of the serialized
/// JSON-RPC bytes. The SSE keep-alive/`event:`/`id:`/`data:` lines and the
/// chunked-transfer wrapping are the largest framing we add around one response;
/// reserving a fixed allowance keeps the on-wire total within the ceiling.
pub const RESPONSE_FRAMING_ALLOWANCE: usize = 1024;

/// Proven upper bound on the serialized size of the bounded oversized-response
/// substitution ([`oversized_response`]). The request id echoed into it is
/// capped at [`MAX_ECHOED_ID_BYTES`], so the substitution size is bounded
/// regardless of caller input. A budget's usable ceiling is never allowed below
/// this, so the substitution always fits — i.e. we never advertise a cap
/// smaller than the unavoidable error envelope.
pub const OVERSIZED_RESPONSE_MAX_BYTES: usize = 1024;

/// Maximum serialized bytes of the request id echoed into an oversized-response
/// substitution. A larger id (an adversarial or accidental giant id) is replaced
/// by `null` so the bounded error stays bounded.
pub const MAX_ECHOED_ID_BYTES: usize = 256;

/// JSON-RPC error code for a refused oversized response. Sits in the
/// implementation-defined server-error band (`-32000..=-32099`), distinct from
/// the generic `-32000` server error.
pub const RESPONSE_TOO_LARGE_CODE: i64 = -32001;

// The default ceiling must leave room for both the framing allowance and the
// unavoidable error envelope, or an oversized substitution could not itself be
// delivered. Verified at compile time.
const _: () =
    assert!(MAX_MCP_RESPONSE_BYTES >= OVERSIZED_RESPONSE_MAX_BYTES + RESPONSE_FRAMING_ALLOWANCE);

/// The whole-response byte budget for one JSON-RPC response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResponseByteBudget {
    /// On-wire ceiling: serialized JSON bytes plus reserved transport framing.
    ceiling: usize,
    /// Transport framing charged on top of the serialized JSON bytes.
    framing_allowance: usize,
}

/// The outcome of charging one finalized response against the budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResponseAdmission {
    /// The whole response fits; `total_bytes` is the charged on-wire size.
    Fits { total_bytes: usize },
    /// The whole response is over budget and must be refused; `measured_bytes`
    /// is the charged on-wire size and `limit` is the ceiling it exceeded.
    Oversized { measured_bytes: usize, limit: usize },
}

impl Default for ResponseByteBudget {
    fn default() -> Self {
        Self::new(MAX_MCP_RESPONSE_BYTES, RESPONSE_FRAMING_ALLOWANCE)
    }
}

impl ResponseByteBudget {
    /// Build a budget with an on-wire `ceiling` and a per-response
    /// `framing_allowance`.
    ///
    /// The ceiling is clamped up so the reserved framing and the unavoidable
    /// oversized-response substitution always fit — a budget can never be
    /// constructed that would advertise a cap smaller than the error envelope it
    /// would need to report.
    #[must_use]
    pub fn new(ceiling: usize, framing_allowance: usize) -> Self {
        let framing_allowance = framing_allowance.min(ceiling);
        // Usable payload room must cover at least the substitution error, on top
        // of the reserved framing.
        let floor = OVERSIZED_RESPONSE_MAX_BYTES.saturating_add(framing_allowance);
        let ceiling = ceiling.max(floor);
        Self {
            ceiling,
            framing_allowance,
        }
    }

    /// The on-wire ceiling (serialized JSON bytes plus reserved framing).
    #[must_use]
    pub fn ceiling(&self) -> usize {
        self.ceiling
    }

    /// The reserved per-response transport framing allowance.
    #[must_use]
    pub fn framing_allowance(&self) -> usize {
        self.framing_allowance
    }

    /// The budget available to the serialized JSON payload alone (the ceiling
    /// minus the reserved transport framing).
    #[must_use]
    pub fn payload_ceiling(&self) -> usize {
        self.ceiling.saturating_sub(self.framing_allowance)
    }

    /// Sum charged byte components with checked arithmetic. Returns `None` on
    /// integer overflow **or** as soon as the running total exceeds the ceiling
    /// — the accumulator never silently wraps and never reports an over-ceiling
    /// total as admissible. This is the shared primitive for charging a
    /// response's parts (payload, metadata, cursor, envelope, framing, retained
    /// copy) as one budget.
    #[must_use]
    pub fn checked_total<I>(&self, components: I) -> Option<usize>
    where
        I: IntoIterator<Item = usize>,
    {
        let mut total: usize = 0;
        for component in components {
            total = total.checked_add(component)?;
            if total > self.ceiling {
                return None;
            }
        }
        Some(total)
    }

    /// Charge one finalized response's serialized JSON bytes plus the reserved
    /// transport framing and decide whether the whole response fits on the wire.
    #[must_use]
    pub fn admit_serialized(&self, response_json_bytes: usize) -> ResponseAdmission {
        match self.checked_total([response_json_bytes, self.framing_allowance]) {
            Some(total_bytes) => ResponseAdmission::Fits { total_bytes },
            None => ResponseAdmission::Oversized {
                measured_bytes: response_json_bytes.saturating_add(self.framing_allowance),
                limit: self.ceiling,
            },
        }
    }

    /// Enforce the whole-response budget on a finalized JSON-RPC response value
    /// **before** it is written to any transport or inserted into the stateful
    /// replay store.
    ///
    /// The response is measured by serializing exactly the bytes a transport
    /// would put on the wire. An in-budget response is returned unchanged
    /// (byte-identical); an oversized one — or one that fails to serialize — is
    /// replaced by the bounded, typed oversized-response substitution carrying
    /// the (bounded) original request id.
    #[must_use]
    pub fn enforce(&self, response: Value) -> Value {
        let response_json_bytes = serde_json::to_vec(&response)
            .map(|bytes| bytes.len())
            // A non-serializable value can never be delivered; treat as unbounded
            // and fail closed onto the bounded substitution.
            .unwrap_or(usize::MAX);
        match self.admit_serialized(response_json_bytes) {
            ResponseAdmission::Fits { .. } => response,
            ResponseAdmission::Oversized {
                measured_bytes,
                limit,
            } => {
                let id = bounded_response_id(response.get("id"));
                oversized_response(id, measured_bytes, limit)
            }
        }
    }
}

/// Echo the request id into a substitution only if it is small; otherwise use
/// `null` so the bounded error stays bounded regardless of caller input.
fn bounded_response_id(id: Option<&Value>) -> Value {
    match id {
        Some(id)
            if serde_json::to_vec(id)
                .map(|bytes| bytes.len())
                .unwrap_or(usize::MAX)
                <= MAX_ECHOED_ID_BYTES =>
        {
            id.clone()
        }
        _ => Value::Null,
    }
}

/// The bounded, typed "response too large" JSON-RPC error substituted for an
/// oversized response. Fixed small structure with a length-capped id, so its
/// serialized size is always well under [`OVERSIZED_RESPONSE_MAX_BYTES`].
#[must_use]
pub fn oversized_response(id: Value, measured_bytes: usize, limit: usize) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": RESPONSE_TOO_LARGE_CODE,
            "message": "the MCP response exceeded the whole-response byte budget and was not delivered",
            "data": {
                "reason": "response_too_large",
                "measured_bytes": measured_bytes,
                "max_response_bytes": limit,
                "next_step": "request fewer rows or columns (lower max_rows/max_result_bytes), page or stream the query, or use a bounded export resource for large durable delivery",
            },
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_total_refuses_overflow_and_over_ceiling_without_wrapping() {
        let budget = ResponseByteBudget::new(4_000, 0);
        assert_eq!(budget.checked_total([1_500, 2_000]), Some(3_500));
        assert_eq!(
            budget.checked_total([2_500, 2_000]),
            None,
            "over ceiling => None"
        );
        // A component that would overflow usize must not wrap to a small total.
        assert_eq!(
            budget.checked_total([usize::MAX, 1]),
            None,
            "integer overflow must fail closed, never wrap"
        );
    }

    #[test]
    fn admit_serialized_fits_at_exact_ceiling_and_refuses_cap_plus_one() {
        // Zero framing so the payload ceiling equals the ceiling exactly.
        let budget = ResponseByteBudget::new(2_048, 0);
        assert_eq!(budget.payload_ceiling(), 2_048);
        assert_eq!(
            budget.admit_serialized(2_048),
            ResponseAdmission::Fits { total_bytes: 2_048 },
            "exact page fits"
        );
        assert_eq!(
            budget.admit_serialized(2_049),
            ResponseAdmission::Oversized {
                measured_bytes: 2_049,
                limit: 2_048,
            },
            "cap + 1 is refused"
        );
    }

    #[test]
    fn framing_allowance_reduces_the_payload_ceiling() {
        let budget = ResponseByteBudget::new(4_096, 512);
        assert_eq!(budget.payload_ceiling(), 3_584);
        assert_eq!(
            budget.admit_serialized(3_584),
            ResponseAdmission::Fits { total_bytes: 4_096 },
            "payload exactly filling the framing-reduced ceiling fits"
        );
        assert!(matches!(
            budget.admit_serialized(3_585),
            ResponseAdmission::Oversized { .. }
        ));
    }

    #[test]
    fn ceiling_is_never_below_the_error_envelope_it_must_report() {
        // Even asking for a nonsensically tiny budget yields a usable ceiling
        // that can hold the oversized substitution plus reserved framing.
        for (requested_ceiling, framing) in [(0, 0), (1, 0), (10, 4), (500, 512)] {
            let budget = ResponseByteBudget::new(requested_ceiling, framing);
            assert!(
                budget.payload_ceiling() >= OVERSIZED_RESPONSE_MAX_BYTES,
                "usable ceiling {} must hold the substitution ({} bytes)",
                budget.payload_ceiling(),
                OVERSIZED_RESPONSE_MAX_BYTES
            );
        }
    }

    #[test]
    fn enforce_returns_in_budget_response_byte_identical() {
        let budget = ResponseByteBudget::default();
        let response = json!({
            "jsonrpc": "2.0",
            "id": 7,
            "result": { "structuredContent": { "rows": [[1, "a"], [2, "b"]] } },
        });
        let before = serde_json::to_vec(&response).unwrap();
        let after = budget.enforce(response);
        assert_eq!(
            serde_json::to_vec(&after).unwrap(),
            before,
            "an in-budget response passes through byte-identical"
        );
    }

    #[test]
    fn enforce_replaces_oversized_response_with_bounded_typed_error() {
        // A response whose *envelope/metadata*, not just row payload, pushes it
        // over a small budget. The single wide `columns`/`text` string models the
        // tool-result envelope + wide metadata + fenced text duplication.
        let wide_text = "x".repeat(8_192);
        let response = json!({
            "jsonrpc": "2.0",
            "id": "req-42",
            "result": {
                "content": [{ "type": "text", "text": wide_text.clone() }],
                "structuredContent": {
                    "columns": ["c0", "c1", "c2"],
                    "rows": [[1, 2, 3]],
                    "next_cursor": "sealed-cursor",
                    "wide": wide_text,
                },
            },
        });
        let measured = serde_json::to_vec(&response).unwrap().len();
        let budget = ResponseByteBudget::new(4_096, 0);
        assert!(measured > budget.ceiling());

        let enforced = budget.enforce(response);
        // The request id is preserved for JSON-RPC correlation.
        assert_eq!(enforced["id"], json!("req-42"));
        assert_eq!(enforced["error"]["code"], json!(RESPONSE_TOO_LARGE_CODE));
        assert_eq!(
            enforced["error"]["data"]["reason"],
            json!("response_too_large")
        );
        assert_eq!(
            enforced["error"]["data"]["max_response_bytes"],
            json!(budget.ceiling())
        );
        assert!(
            enforced.get("result").is_none(),
            "the payload is not delivered"
        );
        // The substitution actually fits — measured at the wire boundary.
        let substitution_bytes = serde_json::to_vec(&enforced).unwrap().len();
        assert!(
            substitution_bytes <= OVERSIZED_RESPONSE_MAX_BYTES,
            "substitution {substitution_bytes} must stay within the proven bound"
        );
        assert!(matches!(
            budget.admit_serialized(substitution_bytes),
            ResponseAdmission::Fits { .. }
        ));
    }

    #[test]
    fn enforce_at_the_measured_wire_boundary_is_exact() {
        // Comfortably above the structural floor so the tested ceilings are not
        // clamped up by `new`.
        let response = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": { "structuredContent": { "blob": "y".repeat(4_000) } },
        });
        let measured = serde_json::to_vec(&response).unwrap().len();

        // Ceiling one byte above the measured size: delivered unchanged.
        let fits = ResponseByteBudget::new(measured + 1, 0);
        assert_eq!(
            serde_json::to_vec(&fits.enforce(response.clone()))
                .unwrap()
                .len(),
            measured
        );

        // Ceiling exactly at the measured size: still fits (inclusive boundary).
        let exact = ResponseByteBudget::new(measured, 0);
        assert!(
            exact.enforce(response.clone()).get("result").is_some(),
            "a response exactly at the ceiling is delivered"
        );

        // Ceiling one byte below the measured size: refused.
        let over = ResponseByteBudget::new(measured - 1, 0);
        assert_eq!(
            over.enforce(response)["error"]["data"]["reason"],
            json!("response_too_large")
        );
    }

    #[test]
    fn oversized_substitution_stays_bounded_for_a_giant_request_id() {
        // An adversarial giant id must not blow the bounded error's own budget.
        let giant_id = json!("i".repeat(50_000));
        let response = json!({
            "jsonrpc": "2.0",
            "id": giant_id,
            "result": { "structuredContent": { "blob": "z".repeat(20_000) } },
        });
        let budget = ResponseByteBudget::new(4_096, 0);
        let enforced = budget.enforce(response);
        assert_eq!(
            enforced["id"],
            Value::Null,
            "an over-long id is dropped to null to keep the error bounded"
        );
        let substitution_bytes = serde_json::to_vec(&enforced).unwrap().len();
        assert!(
            substitution_bytes <= OVERSIZED_RESPONSE_MAX_BYTES,
            "substitution {substitution_bytes} must stay bounded regardless of id"
        );
    }

    #[test]
    fn default_budget_admits_a_legitimate_maximum_query_page() {
        // ~50 MiB models a maximum 25 MiB row payload embedded twice by the
        // tool-result envelope (fenced text + structuredContent). It must remain
        // deliverable under the default whole-response ceiling.
        let budget = ResponseByteBudget::default();
        let legit = 50 * 1024 * 1024;
        assert!(matches!(
            budget.admit_serialized(legit),
            ResponseAdmission::Fits { .. }
        ));
        // But an unbounded response beyond the ceiling is refused.
        assert!(matches!(
            budget.admit_serialized(MAX_MCP_RESPONSE_BYTES + 1),
            ResponseAdmission::Oversized { .. }
        ));
    }
}
