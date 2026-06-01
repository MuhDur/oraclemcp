//! Actionable-error enrichment + fuzzy schema suggestions (plan §8.2; bead
//! P1-ERR). Additive over the P0-1 [`ErrorEnvelope`]: maps a raw `ORA-` error
//! plus the agent's referenced object name and the cached schema object list to
//! a structured envelope with `suggested_tool`, near-miss `fuzzy_matches`, and a
//! concrete next step. Pure (the candidate list is passed in) — no DB / engine
//! dependency.

use crate::{ErrorClass, ErrorEnvelope, classify_ora_code, parse_ora_code};

/// Levenshtein edit distance (case-insensitive), bounded for short identifiers.
#[must_use]
pub fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.to_ascii_uppercase().chars().collect();
    let b: Vec<char> = b.to_ascii_uppercase().chars().collect();
    if a.is_empty() {
        return b.len();
    }
    if b.is_empty() {
        return a.len();
    }
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0usize; b.len() + 1];
    for (i, &ca) in a.iter().enumerate() {
        cur[0] = i + 1;
        for (j, &cb) in b.iter().enumerate() {
            let cost = usize::from(ca != cb);
            cur[j + 1] = (prev[j + 1] + 1).min(cur[j] + 1).min(prev[j] + cost);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()]
}

/// Up to `max` near-miss candidates for `needle`, ranked by edit distance then
/// name. Only candidates within a sensible distance (≤ ⌈len/2⌉+1) are returned,
/// so unrelated names are not suggested.
#[must_use]
pub fn fuzzy_suggest(needle: &str, candidates: &[&str], max: usize) -> Vec<String> {
    let threshold = needle.chars().count() / 2 + 1;
    let mut scored: Vec<(usize, &str)> = candidates
        .iter()
        .map(|c| (levenshtein(needle, c), *c))
        .filter(|(d, _)| *d <= threshold)
        .collect();
    scored.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(b.1)));
    scored
        .into_iter()
        .take(max)
        .map(|(_, c)| c.to_owned())
        .collect()
}

/// Enrich a raw Oracle error into an actionable envelope. `referenced` is the
/// object name the agent used (for `ORA-00942` fuzzy matching); `known_objects`
/// is the cached schema snapshot (empty ⇒ suggest a re-capture).
#[must_use]
pub fn enrich_oracle_error(
    message: &str,
    referenced: Option<&str>,
    known_objects: &[&str],
) -> ErrorEnvelope {
    let Some(code) = parse_ora_code(message) else {
        return ErrorEnvelope::new(ErrorClass::Internal, message.to_owned());
    };
    let class = classify_ora_code(code);
    let mut env = ErrorEnvelope::new(class, message.to_owned()).with_ora_code(code);
    match class {
        ErrorClass::ObjectNotFound => {
            if let Some(name) = referenced {
                if known_objects.is_empty() {
                    env = env.with_next_step(
                        "no cached schema snapshot — run oracle_schema_inspect(depth=full) then retry",
                    );
                } else {
                    let matches = fuzzy_suggest(name, known_objects, 5);
                    if matches.is_empty() {
                        env = env.with_next_step(format!(
                            "object `{name}` not found and no near match in the cached schema"
                        ));
                    } else {
                        env = env
                            .with_next_step(format!(
                                "`{name}` not found — did you mean one of these?"
                            ))
                            .with_fuzzy_matches(matches);
                    }
                }
            }
        }
        ErrorClass::InsufficientPrivilege => {
            env = env.with_next_step(
                "insufficient privilege — check oracle_capabilities for the account's tier; the operator must grant the needed privilege",
            );
        }
        _ => {}
    }
    env
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levenshtein_basics() {
        assert_eq!(levenshtein("employes", "employees"), 1);
        assert_eq!(levenshtein("abc", "abc"), 0);
        assert_eq!(levenshtein("", "abc"), 3);
        assert_eq!(levenshtein("EMP", "emp"), 0); // case-insensitive
    }

    #[test]
    fn fuzzy_suggest_ranks_near_misses() {
        let cands = ["EMPLOYEES", "EMPLOYEE", "DEPARTMENTS", "ORDERS"];
        let s = fuzzy_suggest("EMPLOYES", &cands, 3);
        assert_eq!(s[0], "EMPLOYEE"); // distance 1 (drop trailing S)... EMPLOYEES is dist 1 too
        assert!(s.contains(&"EMPLOYEES".to_owned()));
        assert!(
            !s.contains(&"ORDERS".to_owned()),
            "unrelated name not suggested"
        );
    }

    #[test]
    fn enrich_object_not_found_with_fuzzy_hit() {
        let env = enrich_oracle_error(
            "ORA-00942: table or view does not exist",
            Some("EMPLOYES"),
            &["EMPLOYEES", "DEPARTMENTS"],
        );
        assert_eq!(env.error_class, ErrorClass::ObjectNotFound);
        assert_eq!(env.suggested_tool.as_deref(), Some("oracle_schema_inspect"));
        assert!(env.fuzzy_matches.contains(&"EMPLOYEES".to_owned()));
    }

    #[test]
    fn enrich_object_not_found_no_match() {
        let env = enrich_oracle_error(
            "ORA-00942: table or view does not exist",
            Some("ZZZQQQ"),
            &["EMPLOYEES"],
        );
        assert!(env.fuzzy_matches.is_empty());
        assert!(env.next_steps.iter().any(|s| s.contains("no near match")));
    }

    #[test]
    fn enrich_object_not_found_stale_snapshot() {
        let env = enrich_oracle_error(
            "ORA-00942: table or view does not exist",
            Some("EMPLOYEES"),
            &[],
        );
        assert!(
            env.next_steps
                .iter()
                .any(|s| s.contains("oracle_schema_inspect"))
        );
    }

    #[test]
    fn enrich_insufficient_privilege() {
        let env = enrich_oracle_error("ORA-01031: insufficient privileges", None, &[]);
        assert_eq!(env.error_class, ErrorClass::InsufficientPrivilege);
        assert!(env.next_steps.iter().any(|s| s.contains("privilege")));
    }
}
