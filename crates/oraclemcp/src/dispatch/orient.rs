//! C2 orientation + fleet-orientation tool family, extracted isomorphically
//! from `dispatch/mod.rs` (C6 de-monolith). Every item is `pub(super)` and
//! re-imported into the parent with `use orient::*;`, so the effective
//! visibility inside the `dispatch` module is unchanged and no call site,
//! tool surface, or behavior moves. The registry (34 tools + 25 aliases) and
//! the classifier are untouched.

use asupersync::Cx;
use oraclemcp_audit::AuditSubject;
use oraclemcp_core::RequestBudget;
use oraclemcp_db::{
    DbError, OracleCell, OracleConnection, OracleConnectionInfo, OracleRow, OrientForeignKey,
    OrientHotObject, OrientRecentDdlObject, OrientSchemaObject, ResultMaskingCertificate,
    ResultMaskingPolicy, SearchObject, SerializeOptions, orient_fks_page, orient_hot_objects_page,
    orient_recent_ddl_page, orient_schema_page, serialize_row,
};
use oraclemcp_error::ErrorEnvelope;
use serde::Serialize;
use serde_json::{Value, json};

use super::{invalid_args, non_empty_arg};

/// The cache identity for one C2 orientation snapshot.
///
/// `catalog_revision` is the resolver cache's monotonic generation. It advances
/// before DDL, session context changes, and reconnects, so it is impossible to
/// retrieve a snapshot from an older catalog as though it were current.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) struct OrientSnapshotCacheKey {
    pub(super) profile: Option<String>,
    pub(super) catalog_revision: u64,
    pub(super) owner: Option<String>,
    pub(super) max_rows: usize,
    pub(super) offset: usize,
}

/// The complete internal orientation snapshot. Selectors project this single
/// value after it is cached; they never create independently stale fragments.
#[derive(Clone, Debug)]
pub(super) struct OrientSnapshot {
    pub(super) owner: Option<String>,
    pub(super) catalog_revision: u64,
    pub(super) schema: Vec<OrientSchemaObject>,
    pub(super) fks: Vec<OrientForeignKey>,
    pub(super) hot_objects: Vec<OrientHotObject>,
    pub(super) freshness: OrientFreshness,
    pub(super) recent_ddl: Vec<OrientRecentDdlObject>,
    pub(super) schema_truncated: bool,
    pub(super) fks_truncated: bool,
    pub(super) hot_truncated: bool,
    pub(super) ddl_truncated: bool,
}

/// One profile's result while assembling a federated orientation snapshot.
///
/// This deliberately keeps successful evidence separate from terminal lane
/// status until every agent-visible profile has been attempted. A fleet call
/// must never turn one unavailable database into either a whole-call failure
/// or an absent profile that looks like a clean result.
#[derive(Clone, Debug)]
pub(super) struct FleetOrientEvidence {
    pub(super) connection: OracleConnectionInfo,
    pub(super) snapshot: OrientSnapshot,
}

/// Terminal result for one profile while assembling fleet orientation.
#[derive(Clone, Debug)]
pub(super) enum FleetOrientLane {
    Reachable {
        profile: String,
        evidence: Box<FleetOrientEvidence>,
    },
    Unreachable {
        profile: String,
    },
    FailClosed {
        profile: String,
        reason: &'static str,
    },
}

/// One profile's egress-filtered contribution to the merged fleet object
/// index. This is intentionally not a lane-status enum: a catalog response
/// must not expose a roster, a reachable-count, or a missing-profile signal.
/// The caller sees only object rows it is authorized to receive.
#[derive(Clone, Debug)]
pub(super) struct FleetCatalogProfileResult {
    pub(super) profile: String,
    pub(super) results: Vec<Value>,
    pub(super) mask_certificate: Option<ResultMaskingCertificate>,
    pub(super) truncated: bool,
}

/// Inputs for one source-profile read while building the egress-safe catalog.
/// Keeping this request together makes it harder to accidentally use an active
/// session's filter, budget, or subject for a transient fleet connection.
pub(super) struct FleetCatalogRequest<'a> {
    pub(super) profile: String,
    pub(super) owner: Option<&'a str>,
    pub(super) object_type: Option<&'a str>,
    pub(super) name_like: Option<&'a str>,
    pub(super) max_rows: usize,
    pub(super) request_budget: &'a RequestBudget,
    pub(super) subject: &'a AuditSubject,
}

/// Deterministic freshness summary derived from the bounded dictionary reads.
#[derive(Clone, Debug, Serialize)]
pub(super) struct OrientFreshness {
    pub(super) catalog_revision: u64,
    pub(super) latest_dml_time: Option<String>,
    pub(super) latest_ddl_time: Option<String>,
    pub(super) hot_object_count: usize,
}

/// C2 output selector. The default is intentionally the complete snapshot.
#[derive(Clone, Copy, Debug)]
pub(super) struct OrientInclude {
    pub(super) schema: bool,
    pub(super) fks: bool,
    pub(super) hot: bool,
    pub(super) freshness: bool,
    pub(super) ddl: bool,
}

impl OrientInclude {
    pub(super) const fn all() -> Self {
        Self {
            schema: true,
            fks: true,
            hot: true,
            freshness: true,
            ddl: true,
        }
    }

    pub(super) fn parse(include: &[String]) -> Result<Self, ErrorEnvelope> {
        if include.is_empty() {
            return Ok(Self::all());
        }
        let mut selected = Self {
            schema: false,
            fks: false,
            hot: false,
            freshness: false,
            ddl: false,
        };
        for section in include {
            match section.to_ascii_lowercase().as_str() {
                "schema" => selected.schema = true,
                "fks" => selected.fks = true,
                "hot" => selected.hot = true,
                "freshness" => selected.freshness = true,
                "ddl" => selected.ddl = true,
                _ => {
                    return Err(invalid_args(
                        "include entries must be one of: schema, fks, hot, freshness, ddl",
                    ));
                }
            }
        }
        Ok(selected)
    }

    /// Stable, non-secret selector material for an opaque orient cursor.
    pub(super) fn cursor_selector(self, fleet: bool) -> String {
        format!(
            "schema={};fks={};hot={};freshness={};ddl={};fleet={fleet}",
            self.schema, self.fks, self.hot, self.freshness, self.ddl
        )
    }
}

pub(super) fn orient_owner_arg(owner: Option<String>) -> Result<Option<String>, ErrorEnvelope> {
    match non_empty_arg(owner).as_deref() {
        None | Some("*") => Ok(None),
        Some(owner) => Ok(Some(owner.to_ascii_uppercase())),
    }
}

pub(super) async fn load_orient_snapshot(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: Option<&str>,
    catalog_revision: u64,
    offset: usize,
    max_rows: usize,
) -> Result<OrientSnapshot, DbError> {
    // Fetch one sentinel row per component. That proves a following page exists
    // before we mint a cursor, avoiding a silent or speculative continuation.
    let fetch_rows = max_rows.saturating_add(1);
    let mut schema = orient_schema_page(cx, conn, owner, offset, fetch_rows).await?;
    let mut fks = orient_fks_page(cx, conn, owner, offset, fetch_rows).await?;
    let mut hot_objects = orient_hot_objects_page(cx, conn, owner, offset, fetch_rows).await?;
    let mut recent_ddl = orient_recent_ddl_page(cx, conn, owner, offset, fetch_rows).await?;
    let schema_truncated = truncate_orient_page(&mut schema, max_rows);
    let fks_truncated = truncate_orient_page(&mut fks, max_rows);
    let hot_truncated = truncate_orient_page(&mut hot_objects, max_rows);
    let ddl_truncated = truncate_orient_page(&mut recent_ddl, max_rows);
    let freshness = OrientFreshness {
        catalog_revision,
        latest_dml_time: hot_objects
            .iter()
            .filter_map(|object| object.last_modified.clone())
            .max(),
        latest_ddl_time: recent_ddl
            .iter()
            .filter_map(|object| object.last_ddl_time.clone())
            .max(),
        hot_object_count: hot_objects.len(),
    };
    Ok(OrientSnapshot {
        owner: owner.map(str::to_owned),
        catalog_revision,
        schema,
        fks,
        hot_objects,
        freshness,
        recent_ddl,
        schema_truncated,
        fks_truncated,
        hot_truncated,
        ddl_truncated,
    })
}

pub(super) fn truncate_orient_page<T>(rows: &mut Vec<T>, max_rows: usize) -> bool {
    let truncated = rows.len() > max_rows;
    rows.truncate(max_rows);
    truncated
}

pub(super) fn orient_snapshot_response(
    snapshot: &OrientSnapshot,
    include: &OrientInclude,
    max_rows: usize,
) -> Value {
    let mut response = serde_json::Map::from_iter([
        (
            "owner".to_owned(),
            json!(snapshot.owner.as_deref().unwrap_or("*")),
        ),
        (
            "catalog_revision".to_owned(),
            json!(snapshot.catalog_revision),
        ),
    ]);
    if include.schema {
        response.insert("schema".to_owned(), json!(&snapshot.schema));
    }
    if include.fks {
        response.insert("fks".to_owned(), json!(&snapshot.fks));
    }
    if include.hot {
        response.insert("hot_objects".to_owned(), json!(&snapshot.hot_objects));
    }
    if include.freshness {
        response.insert("freshness".to_owned(), json!(&snapshot.freshness));
    }
    if include.ddl {
        response.insert("recent_ddl".to_owned(), json!(&snapshot.recent_ddl));
    }
    response.insert("max_rows".to_owned(), json!(max_rows));
    let schema_truncated = include.schema && snapshot.schema_truncated;
    let fks_truncated = include.fks && snapshot.fks_truncated;
    let hot_truncated = include.hot && snapshot.hot_truncated;
    let ddl_truncated = include.ddl && snapshot.ddl_truncated;
    response.insert(
        "truncation".to_owned(),
        json!({
            "schema": schema_truncated,
            "fks": fks_truncated,
            "hot": hot_truncated,
            "ddl": ddl_truncated,
        }),
    );
    response.insert(
        "truncated".to_owned(),
        json!(schema_truncated || fks_truncated || hot_truncated || ddl_truncated),
    );
    Value::Object(response)
}

pub(super) fn fleet_orient_component_matches<T: Serialize>(left: &T, right: &T) -> bool {
    serde_json::to_value(left).ok() == serde_json::to_value(right).ok()
}

pub(super) fn fleet_orient_drift(
    profile: &str,
    snapshot: &OrientSnapshot,
    connection: &OracleConnectionInfo,
    baseline: Option<(&str, &OrientSnapshot, &OracleConnectionInfo)>,
) -> Value {
    let Some((baseline_profile, baseline_snapshot, baseline_connection)) = baseline else {
        return json!({
            "baseline_profile": profile,
            "schema_changed": false,
            "foreign_keys_changed": false,
            "freshness_changed": false,
            "recent_ddl_changed": false,
            "server_version_changed": false,
        });
    };

    json!({
        "baseline_profile": baseline_profile,
        "schema_changed": !fleet_orient_component_matches(&snapshot.schema, &baseline_snapshot.schema),
        "foreign_keys_changed": !fleet_orient_component_matches(&snapshot.fks, &baseline_snapshot.fks),
        "freshness_changed": !fleet_orient_component_matches(&snapshot.freshness, &baseline_snapshot.freshness),
        "recent_ddl_changed": !fleet_orient_component_matches(&snapshot.recent_ddl, &baseline_snapshot.recent_ddl),
        "server_version_changed": connection.server_version != baseline_connection.server_version,
    })
}

pub(super) fn fleet_orient_response(
    lanes: Vec<FleetOrientLane>,
    include: &OrientInclude,
    max_rows: usize,
) -> Value {
    let total_profiles = lanes.len();
    let mut reachable = 0_usize;
    let mut unreachable = 0_usize;
    let mut fail_closed = 0_usize;
    let mut truncated = false;
    let mut baseline: Option<(String, OrientSnapshot, OracleConnectionInfo)> = None;
    let mut profiles = Vec::with_capacity(total_profiles);

    for lane in lanes {
        match lane {
            FleetOrientLane::Reachable { profile, evidence } => {
                let FleetOrientEvidence {
                    connection,
                    snapshot,
                } = *evidence;
                let drift = fleet_orient_drift(
                    &profile,
                    &snapshot,
                    &connection,
                    baseline
                        .as_ref()
                        .map(|(name, snapshot, connection)| (name.as_str(), snapshot, connection)),
                );
                if baseline.is_none() {
                    baseline = Some((profile.clone(), snapshot.clone(), connection.clone()));
                }
                reachable = reachable.saturating_add(1);
                let orient = orient_snapshot_response(&snapshot, include, max_rows);
                truncated |= orient
                    .get("truncated")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                profiles.push(json!({
                    "profile": profile,
                    "status": "REACHABLE",
                    "connection": connection.redacted(),
                    "orient": orient,
                    "drift": drift,
                }));
            }
            FleetOrientLane::Unreachable { profile } => {
                unreachable = unreachable.saturating_add(1);
                profiles.push(json!({
                    "profile": profile,
                    "status": "UNREACHABLE",
                    "error": {
                        "code": "UNREACHABLE",
                        "message": "profile connection or orientation metadata is unavailable",
                    },
                }));
            }
            FleetOrientLane::FailClosed { profile, reason } => {
                fail_closed = fail_closed.saturating_add(1);
                profiles.push(json!({
                    "profile": profile,
                    "status": "FAIL_CLOSED",
                    "error": {
                        "code": "FAIL_CLOSED",
                        "message": reason,
                    },
                }));
            }
        }
    }

    json!({
        "profiles": profiles,
        "truncated": truncated,
        "summary": {
            "profile_count": total_profiles,
            "reachable_count": reachable,
            "unreachable_count": unreachable,
            "fail_closed_count": fail_closed,
        },
    })
}

/// Build the fixed, names-only dictionary result shape that crosses the fleet
/// aggregation boundary. Applying Arc M here (rather than after the JSON has
/// been merged) keeps every source row under the policy of the profile that
/// produced it.
pub(super) fn fleet_catalog_source_row(object: &SearchObject) -> OracleRow {
    OracleRow {
        columns: vec![
            (
                "OWNER".to_owned(),
                OracleCell::new("VARCHAR2", Some(object.owner.clone())),
            ),
            (
                "OBJECT_NAME".to_owned(),
                OracleCell::new("VARCHAR2", Some(object.object_name.clone())),
            ),
            (
                "OBJECT_TYPE".to_owned(),
                OracleCell::new("VARCHAR2", Some(object.object_type.clone())),
            ),
            (
                "STATUS".to_owned(),
                OracleCell::new("VARCHAR2", object.status.clone()),
            ),
        ],
    }
}

pub(super) fn fleet_catalog_result_row(
    profile: &str,
    object: &SearchObject,
    result_masking: Option<&ResultMaskingPolicy>,
) -> Value {
    let row = fleet_catalog_source_row(object);
    let serialized = serialize_row(
        &row,
        &SerializeOptions {
            result_masking: result_masking.cloned(),
            ..Default::default()
        },
    );
    json!({
        "profile": profile,
        "owner": serialized["OWNER"].clone(),
        "object_name": serialized["OBJECT_NAME"].clone(),
        "object_type": serialized["OBJECT_TYPE"].clone(),
        "status": serialized["STATUS"].clone(),
    })
}

pub(super) fn fleet_catalog_response(
    lanes: Vec<FleetCatalogProfileResult>,
    owner: Option<&str>,
    object_type: Option<&str>,
    name_like: Option<&str>,
    max_rows: usize,
) -> Value {
    let mut results = Vec::new();
    let mut mask_certificates = Vec::new();
    let mut truncated = false;
    for lane in lanes {
        truncated |= lane.truncated;
        if !lane.results.is_empty() {
            if let Some(certificate) = lane.mask_certificate {
                mask_certificates.push(json!({
                    "profile": lane.profile,
                    "certificate": certificate,
                }));
            }
            results.extend(lane.results);
        }
    }

    json!({
        "fleet": true,
        "owner": owner.unwrap_or("*"),
        "object_type": object_type,
        "name_like": name_like,
        "detail_level": "names",
        "count": results.len(),
        "results": results,
        "mask_certificates": mask_certificates,
        "max_rows": max_rows,
        "truncated": truncated,
    })
}
