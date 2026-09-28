//! Exact, built-in eligibility for Oracle dictionary views.
//!
//! Eligibility is deliberately not a safety verdict.  A caller must still
//! establish the full view closure before it may treat a relation as read-only.

/// Returns whether an exact `SYS` dictionary view is eligible for closure
/// proof.
///
/// This list is intentionally limited to the user/all dictionary surface.
/// `DBA_*` views and every application view remain ineligible unless a
/// database-facing consumer supplies a separately configured, exact identity.
#[must_use]
pub fn is_builtin_dictionary_view(owner: &str, name: &str) -> bool {
    owner == "SYS"
        && matches!(
            name,
            "USER_OBJECTS"
                | "ALL_OBJECTS"
                | "USER_TAB_COLUMNS"
                | "ALL_TAB_COLUMNS"
                | "USER_TABLES"
                | "ALL_TABLES"
                | "USER_VIEWS"
                | "ALL_VIEWS"
                | "USER_SEQUENCES"
                | "ALL_SEQUENCES"
                | "USER_ARGUMENTS"
                | "ALL_ARGUMENTS"
                | "USER_SOURCE"
                | "ALL_SOURCE"
                | "USER_CONSTRAINTS"
                | "ALL_CONSTRAINTS"
                | "USER_CONS_COLUMNS"
                | "ALL_CONS_COLUMNS"
                | "USER_INDEXES"
                | "ALL_INDEXES"
                | "USER_IND_COLUMNS"
                | "ALL_IND_COLUMNS"
                | "USER_SYNONYMS"
                | "ALL_SYNONYMS"
                | "USER_DEPENDENCIES"
                | "ALL_DEPENDENCIES"
                | "USER_ERRORS"
                | "ALL_ERRORS"
                | "USER_PROCEDURES"
                | "ALL_PROCEDURES"
                | "USER_TRIGGERS"
                | "ALL_TRIGGERS"
        )
}

#[cfg(test)]
mod tests {
    use super::is_builtin_dictionary_view;

    #[test]
    fn issue35_dictionary_allowlist_is_exact_sys_only() {
        assert!(is_builtin_dictionary_view("SYS", "USER_OBJECTS"));
        assert!(is_builtin_dictionary_view("SYS", "ALL_TAB_COLUMNS"));
        assert!(is_builtin_dictionary_view("SYS", "USER_SEQUENCES"));
        assert!(!is_builtin_dictionary_view("APP", "USER_OBJECTS"));
        assert!(!is_builtin_dictionary_view("SYS", "DBA_OBJECTS"));
        assert!(!is_builtin_dictionary_view("sys", "USER_OBJECTS"));
        assert!(!is_builtin_dictionary_view("SYS", "user_objects"));
    }
}
