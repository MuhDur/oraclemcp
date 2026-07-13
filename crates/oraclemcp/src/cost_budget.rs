//! Durable, fail-closed cumulative optimizer-cost budgets.
//!
//! The query dispatcher provides the active profile and authenticated
//! [`DispatchContext`](oraclemcp_core::DispatchContext) principal; neither is
//! derived from request arguments. Records are keyed with [`StoreId`] content
//! hashes, so the state directory never exposes a raw profile or principal.

use std::fs;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use oraclemcp_config::CumulativeQueryCostBudgetConfig;
use oraclemcp_core::{FileStore, ServiceOwner, StoreId};
use serde::{Deserialize, Serialize};

const COLLECTION: &str = "query-cost-budgets";
const RECORD_VERSION: u8 = 1;

/// Durable cumulative-budget state store. Every successful admission writes
/// before the corresponding target query is executed.
#[derive(Clone)]
pub struct QueryCostBudgetStore {
    store: Arc<FileStore>,
    owner: ServiceOwner,
    /// `FileStore` serializes writes but not this read/modify/write operation.
    /// This process-local gate preserves accounting monotonicity between query
    /// lanes that share a service owner.
    mutation_gate: Arc<Mutex<()>>,
}

/// Result of attempting to charge one pre-execution optimizer estimate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueryCostBudgetAdmission {
    /// The estimate was durably charged before execution.
    Admitted {
        /// Cost consumed in the active accounting window after this charge.
        consumed_cost: u64,
        /// Whether this admission began a new rolled-over window.
        reset_window: bool,
    },
    /// The active window has no budget for another target query.
    Exhausted {
        /// Cost already consumed in the active window.
        consumed_cost: u64,
        /// Configured cumulative budget for the window.
        max_cost: u64,
    },
}

/// State failures that deliberately refuse a query rather than risk an
/// unaccounted execution. Variants expose no paths, profile names, principals,
/// or record bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueryCostBudgetStoreError {
    /// Durable service state could not be opened, locked, read, or written.
    StateUnavailable,
    /// An existing state record is not a supported complete budget record.
    InvalidState,
    /// The server clock could not be represented as a Unix timestamp.
    ClockUnavailable,
    /// The server clock moved before a persisted window start.
    ClockRegression,
    /// Adding a cost estimate overflowed the durable counter.
    CounterOverflow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BudgetRecord {
    version: u8,
    window_started_at_unix_seconds: u64,
    consumed_cost: u64,
}

impl QueryCostBudgetStore {
    /// Open a budget store under the service-owned state root.
    ///
    /// Acquiring the [`ServiceOwner`] is intentionally outside this type: the
    /// server owns the one process-wide lock and shares it with other durable
    /// state domains. Failure to establish that ownership prevents budgeted
    /// serving at startup.
    pub fn open_with_owner(owner: ServiceOwner) -> Result<Self, QueryCostBudgetStoreError> {
        let store = FileStore::open(owner.root())
            .map_err(|_| QueryCostBudgetStoreError::StateUnavailable)?;
        Ok(Self {
            store: Arc::new(store),
            owner,
            mutation_gate: Arc::new(Mutex::new(())),
        })
    }

    /// Charge an estimate using the server's current time.
    ///
    /// The `profile` and `principal` arguments must come from server-owned
    /// dispatch state. No request argument can select either identifier or a
    /// clock/reset value.
    pub fn reserve(
        &self,
        profile: &str,
        principal: &str,
        policy: &CumulativeQueryCostBudgetConfig,
        estimated_cost: u64,
    ) -> Result<QueryCostBudgetAdmission, QueryCostBudgetStoreError> {
        self.reserve_at(
            profile,
            principal,
            policy,
            estimated_cost,
            SystemTime::now(),
        )
    }

    fn reserve_at(
        &self,
        profile: &str,
        principal: &str,
        policy: &CumulativeQueryCostBudgetConfig,
        estimated_cost: u64,
        now: SystemTime,
    ) -> Result<QueryCostBudgetAdmission, QueryCostBudgetStoreError> {
        let now = now
            .duration_since(UNIX_EPOCH)
            .map_err(|_| QueryCostBudgetStoreError::ClockUnavailable)?
            .as_secs();
        let _gate = self
            .mutation_gate
            .lock()
            .map_err(|_| QueryCostBudgetStoreError::StateUnavailable)?;
        let id = StoreId::content_hashed("principal", &[profile, principal])
            .map_err(|_| QueryCostBudgetStoreError::StateUnavailable)?;
        let path = self
            .store
            .path_for(COLLECTION, &id, "json")
            .map_err(|_| QueryCostBudgetStoreError::StateUnavailable)?;
        let mut record = match fs::read(&path) {
            Ok(bytes) => parse_record(&bytes)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => BudgetRecord {
                version: RECORD_VERSION,
                window_started_at_unix_seconds: now,
                consumed_cost: 0,
            },
            Err(_) => return Err(QueryCostBudgetStoreError::StateUnavailable),
        };

        if now < record.window_started_at_unix_seconds {
            return Err(QueryCostBudgetStoreError::ClockRegression);
        }
        let reset_window =
            now.saturating_sub(record.window_started_at_unix_seconds) >= policy.window_seconds;
        if reset_window {
            record.window_started_at_unix_seconds = now;
            record.consumed_cost = 0;
        }

        // An at-budget principal is refused even for a zero optimizer estimate:
        // exhausted state never falls open because a cost was rounded to zero.
        if record.consumed_cost >= policy.max_cost {
            return Ok(QueryCostBudgetAdmission::Exhausted {
                consumed_cost: record.consumed_cost,
                max_cost: policy.max_cost,
            });
        }
        let Some(next_cost) = record.consumed_cost.checked_add(estimated_cost) else {
            return Err(QueryCostBudgetStoreError::CounterOverflow);
        };
        if next_cost > policy.max_cost {
            return Ok(QueryCostBudgetAdmission::Exhausted {
                consumed_cost: record.consumed_cost,
                max_cost: policy.max_cost,
            });
        }

        record.consumed_cost = next_cost;
        let bytes =
            serde_json::to_vec(&record).map_err(|_| QueryCostBudgetStoreError::InvalidState)?;
        self.store
            .write_atomic(&self.owner, COLLECTION, &id, "json", &bytes)
            .map_err(|_| QueryCostBudgetStoreError::StateUnavailable)?;
        Ok(QueryCostBudgetAdmission::Admitted {
            consumed_cost: next_cost,
            reset_window,
        })
    }
}

fn parse_record(bytes: &[u8]) -> Result<BudgetRecord, QueryCostBudgetStoreError> {
    let record: BudgetRecord =
        serde_json::from_slice(bytes).map_err(|_| QueryCostBudgetStoreError::InvalidState)?;
    if record.version != RECORD_VERSION {
        return Err(QueryCostBudgetStoreError::InvalidState);
    }
    Ok(record)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn policy(max_cost: u64, window_seconds: u64) -> CumulativeQueryCostBudgetConfig {
        CumulativeQueryCostBudgetConfig {
            max_cost,
            window_seconds,
        }
    }

    fn at(seconds: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(seconds)
    }

    #[test]
    fn durable_budget_accrues_refuses_at_limit_and_rolls_its_window() {
        let temp = tempfile::tempdir().expect("temporary state root");
        let file_store = FileStore::open(temp.path()).expect("open state root");
        let owner = file_store
            .acquire_service_owner("query-cost-budget-test")
            .expect("own state root");
        let store =
            QueryCostBudgetStore::open_with_owner(owner.clone()).expect("open budget store");
        let policy = policy(10, 60);

        assert_eq!(
            store
                .reserve_at("profile-a", "oauth:principal-a", &policy, 4, at(100))
                .expect("first charge"),
            QueryCostBudgetAdmission::Admitted {
                consumed_cost: 4,
                reset_window: false,
            }
        );

        // Reopening through the same server owner proves the state is durable,
        // not a per-dispatch in-memory counter.
        let reopened = QueryCostBudgetStore::open_with_owner(owner).expect("reopen budget store");
        assert_eq!(
            reopened
                .reserve_at("profile-a", "oauth:principal-a", &policy, 6, at(110))
                .expect("second charge"),
            QueryCostBudgetAdmission::Admitted {
                consumed_cost: 10,
                reset_window: false,
            }
        );
        assert_eq!(
            reopened
                .reserve_at("profile-a", "oauth:principal-a", &policy, 0, at(111))
                .expect("at-budget refusal"),
            QueryCostBudgetAdmission::Exhausted {
                consumed_cost: 10,
                max_cost: 10,
            }
        );
        assert_eq!(
            reopened
                .reserve_at("profile-a", "oauth:principal-a", &policy, 3, at(160))
                .expect("rolled-window charge"),
            QueryCostBudgetAdmission::Admitted {
                consumed_cost: 3,
                reset_window: true,
            }
        );
    }

    #[test]
    fn budget_state_never_resets_for_a_backward_clock_or_invalid_record() {
        let temp = tempfile::tempdir().expect("temporary state root");
        let file_store = FileStore::open(temp.path()).expect("open state root");
        let owner = file_store
            .acquire_service_owner("query-cost-budget-test")
            .expect("own state root");
        let store = QueryCostBudgetStore::open_with_owner(owner).expect("open budget store");
        let policy = policy(10, 60);
        store
            .reserve_at("profile-a", "oauth:principal-a", &policy, 5, at(100))
            .expect("seed charge");

        assert_eq!(
            store.reserve_at("profile-a", "oauth:principal-a", &policy, 1, at(99)),
            Err(QueryCostBudgetStoreError::ClockRegression)
        );

        let id = StoreId::content_hashed("principal", &["profile-a", "oauth:principal-a"])
            .expect("safe hashed state id");
        store
            .store
            .write_atomic(&store.owner, COLLECTION, &id, "json", br#"{"version":99}"#)
            .expect("seed unsupported record");
        assert_eq!(
            store.reserve_at("profile-a", "oauth:principal-a", &policy, 1, at(101)),
            Err(QueryCostBudgetStoreError::InvalidState),
            "corrupt or unsupported state must refuse instead of starting a new budget"
        );
    }
}
