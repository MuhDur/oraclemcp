use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

const DIRECT_RELEASE_PUBLISH_JOBS: &[&str] = &[
    "release",
    "publish-crates",
    "docker",
    "publish-mcp-registry",
];
const TRANSITIVE_RELEASE_PUBLISH_JOBS: &[&str] = &["verify-mcp-registry"];
const RELEASE_PUBLISH_JOBS: &[&str] = &[
    "release",
    "publish-crates",
    "docker",
    "publish-mcp-registry",
    "verify-mcp-registry",
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .to_path_buf()
}

fn load_workflow(path: &str) -> Value {
    let full_path = workspace_root().join(path);
    let text = std::fs::read_to_string(&full_path)
        .unwrap_or_else(|err| panic!("read {}: {err}", full_path.display()));
    serde_saphyr::from_str(&text)
        .unwrap_or_else(|err| panic!("parse {}: {err}", full_path.display()))
}

fn as_mapping<'a>(value: &'a Value, label: &str) -> &'a Map<String, Value> {
    value
        .as_object()
        .unwrap_or_else(|| panic!("{label} must be a YAML mapping"))
}

fn mapping_get<'a>(mapping: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    mapping.get(key)
}

fn mapping_get_mut<'a>(mapping: &'a mut Map<String, Value>, key: &str) -> Option<&'a mut Value> {
    mapping.get_mut(key)
}

fn workflow_jobs(workflow: &Value) -> &Map<String, Value> {
    let root = as_mapping(workflow, "workflow");
    as_mapping(
        mapping_get(root, "jobs").expect("workflow must define jobs"),
        "workflow jobs",
    )
}

fn job_mapping<'a>(jobs: &'a Map<String, Value>, job_id: &str) -> Option<&'a Map<String, Value>> {
    mapping_get(jobs, job_id).map(|job| as_mapping(job, job_id))
}

fn job_mapping_mut<'a>(
    jobs: &'a mut Map<String, Value>,
    job_id: &str,
) -> &'a mut Map<String, Value> {
    mapping_get_mut(jobs, job_id)
        .and_then(Value::as_object_mut)
        .unwrap_or_else(|| panic!("workflow job {job_id} must be a mapping"))
}

fn workflow_event_names(workflow: &Value) -> BTreeSet<String> {
    let root = as_mapping(workflow, "workflow");
    let on = mapping_get(root, "on").expect("workflow must define `on` triggers");
    match on {
        Value::String(name) => BTreeSet::from([name.clone()]),
        Value::Array(names) => names
            .iter()
            .map(|name| {
                name.as_str()
                    .unwrap_or_else(|| panic!("workflow event name must be a string: {name:?}"))
                    .to_owned()
            })
            .collect(),
        Value::Object(events) => events.keys().cloned().collect(),
        other => panic!("workflow `on` must be a string, sequence, or mapping: {other:?}"),
    }
}

fn push_trigger_mapping(workflow: &Value) -> Option<&Map<String, Value>> {
    let root = as_mapping(workflow, "workflow");
    let on = mapping_get(root, "on")?;
    match on {
        Value::Object(events) => mapping_get(events, "push").and_then(Value::as_object),
        _ => None,
    }
}

fn trigger_allows_branch_push(workflow: &Value) -> bool {
    if !workflow_event_names(workflow).contains("push") {
        return false;
    }
    let Some(push) = push_trigger_mapping(workflow) else {
        return true;
    };
    !push.contains_key("tags")
        || push.contains_key("branches")
        || push.contains_key("branches-ignore")
}

fn non_tag_events(workflow: &Value) -> BTreeSet<String> {
    let events = workflow_event_names(workflow);
    let mut non_tag = BTreeSet::new();
    for event in ["workflow_dispatch", "pull_request", "schedule"] {
        if events.contains(event) {
            non_tag.insert(event.to_owned());
        }
    }
    if trigger_allows_branch_push(workflow) {
        non_tag.insert("push".to_owned());
    }
    non_tag
}

fn job_if(job: &Map<String, Value>) -> Option<&str> {
    mapping_get(job, "if").and_then(Value::as_str)
}

fn job_needs(job: &Map<String, Value>) -> Vec<String> {
    let Some(needs) = mapping_get(job, "needs") else {
        return Vec::new();
    };
    match needs {
        Value::String(need) => vec![need.clone()],
        Value::Array(needs) => needs
            .iter()
            .map(|need| {
                need.as_str()
                    .unwrap_or_else(|| panic!("job need must be a string: {need:?}"))
                    .to_owned()
            })
            .collect(),
        other => panic!("job needs must be a string or sequence: {other:?}"),
    }
}

fn compact_expression(expression: &str) -> String {
    expression.chars().filter(|c| !c.is_whitespace()).collect()
}

fn has_positive_tag_ref_guard(condition: Option<&str>) -> bool {
    let Some(condition) = condition else {
        return false;
    };
    let compact = compact_expression(condition);
    for needle in [
        "startsWith(github.ref,'refs/tags/')",
        "startsWith(github.ref,\"refs/tags/\")",
    ] {
        let mut offset = 0;
        while let Some(pos) = compact[offset..].find(needle) {
            let start = offset + pos;
            let before = &compact[..start];
            let after = &compact[start + needle.len()..];
            let negated = before.ends_with('!');
            let compared_false = after.starts_with("==false") || after.starts_with("!=true");
            if !negated && !compared_false {
                return true;
            }
            offset = start + needle.len();
        }
    }
    false
}

fn job_reachable_on_non_tag_ref(
    jobs: &Map<String, Value>,
    job_id: &str,
    memo: &mut HashMap<String, bool>,
    stack: &mut HashSet<String>,
) -> bool {
    if let Some(reachable) = memo.get(job_id) {
        return *reachable;
    }
    assert!(
        stack.insert(job_id.to_owned()),
        "cycle in workflow needs graph at {job_id}"
    );
    let job = job_mapping(jobs, job_id).unwrap_or_else(|| panic!("missing job {job_id}"));
    let reachable = if has_positive_tag_ref_guard(job_if(job)) {
        false
    } else {
        let needs = job_needs(job);
        if needs.is_empty()
            || job_if(job)
                .map(compact_expression)
                .is_some_and(|condition| condition.contains("always()"))
        {
            true
        } else {
            needs
                .iter()
                .all(|need| job_reachable_on_non_tag_ref(jobs, need, memo, stack))
        }
    };
    stack.remove(job_id);
    memo.insert(job_id.to_owned(), reachable);
    reachable
}

fn check_release_publish_tag_gates(workflow: &Value) -> Vec<String> {
    let jobs = workflow_jobs(workflow);
    let events = workflow_event_names(workflow);
    let non_tag_events = non_tag_events(workflow);
    let mut errors = Vec::new();

    if !events.contains("push") {
        errors.push("release.yml must keep its tag push trigger".to_owned());
    }
    if !events.contains("workflow_dispatch") {
        errors.push(
            "release.yml must keep workflow_dispatch as a non-publishing rehearsal".to_owned(),
        );
    }
    if !push_trigger_mapping(workflow).is_some_and(|push| push.contains_key("tags")) {
        errors.push("release.yml push trigger must be constrained by tags".to_owned());
    }
    if !non_tag_events.contains("workflow_dispatch") {
        errors.push("release.yml guard must be exercised against workflow_dispatch".to_owned());
    }

    for job_id in RELEASE_PUBLISH_JOBS {
        if !jobs.contains_key(*job_id) {
            errors.push(format!("release.yml must define publishing job {job_id}"));
        }
    }

    for job_id in DIRECT_RELEASE_PUBLISH_JOBS {
        if let Some(job) = job_mapping(jobs, job_id)
            && !has_positive_tag_ref_guard(job_if(job))
        {
            errors.push(format!(
                "{job_id} must carry its own positive startsWith(github.ref, 'refs/tags/') guard"
            ));
        }
    }

    if let Some(job) = job_mapping(jobs, "verify-mcp-registry") {
        let needs = job_needs(job);
        if needs != ["publish-mcp-registry"] {
            errors.push(format!(
                "verify-mcp-registry must be skipped transitively through publish-mcp-registry, got needs={needs:?}"
            ));
        }
        if job_if(job)
            .map(compact_expression)
            .is_some_and(|condition| condition.contains("always()"))
        {
            errors.push(
                "verify-mcp-registry must not override skipped needs with always()".to_owned(),
            );
        }
    }

    if !non_tag_events.is_empty() {
        for job_id in RELEASE_PUBLISH_JOBS {
            let reachable = job_reachable_on_non_tag_ref(
                jobs,
                job_id,
                &mut HashMap::new(),
                &mut HashSet::new(),
            );
            if reachable {
                errors.push(format!(
                    "{job_id} is reachable from non-tag events {non_tag_events:?}"
                ));
            }
        }
    }

    errors
}

fn check_auxiliary_publish_workflow_is_manual_only(path: &str) -> Vec<String> {
    let workflow = load_workflow(path);
    let events = workflow_event_names(&workflow);
    if events == BTreeSet::from(["workflow_dispatch".to_owned()]) {
        Vec::new()
    } else {
        vec![format!(
            "{path} is an auxiliary recovery workflow and must stay workflow_dispatch-only, got events={events:?}"
        )]
    }
}

fn set_job_if(workflow: &mut Value, job_id: &str, condition: &str) {
    let root = workflow
        .as_object_mut()
        .expect("workflow must be a YAML mapping");
    let jobs = mapping_get_mut(root, "jobs")
        .and_then(Value::as_object_mut)
        .expect("workflow must define jobs");
    let job = job_mapping_mut(jobs, job_id);
    job.insert("if".to_owned(), Value::String(condition.to_owned()));
}

fn set_job_needs(workflow: &mut Value, job_id: &str, needs: &[&str]) {
    let root = workflow
        .as_object_mut()
        .expect("workflow must be a YAML mapping");
    let jobs = mapping_get_mut(root, "jobs")
        .and_then(Value::as_object_mut)
        .expect("workflow must define jobs");
    let job = job_mapping_mut(jobs, job_id);
    let needs = needs
        .iter()
        .map(|need| Value::String((*need).to_owned()))
        .collect();
    job.insert("needs".to_owned(), Value::Array(needs));
}

#[test]
fn workflow_yaml_preserves_on_and_rejects_duplicate_publish_conditions() {
    let workflow: Value = serde_saphyr::from_str(
        "on: [push, workflow_dispatch]\njobs:\n  release:\n    if: >-\n      startsWith(github.ref, 'refs/tags/')\n",
    )
    .expect("parse workflow YAML without treating on as a boolean");
    assert_eq!(
        workflow_event_names(&workflow),
        BTreeSet::from(["push".to_owned(), "workflow_dispatch".to_owned()])
    );
    assert!(has_positive_tag_ref_guard(job_if(
        job_mapping(workflow_jobs(&workflow), "release").unwrap()
    )));
    assert!(
        serde_saphyr::from_str::<Value>(
            "jobs:\n  release:\n    if: startsWith(github.ref, 'refs/tags/')\n    if: always()\n"
        )
        .is_err(),
        "a duplicate condition must not silently replace the publishing guard"
    );
}

#[test]
fn release_publishing_jobs_stay_tag_gated_on_actual_workflow_conditions() {
    let workflow = load_workflow(".github/workflows/release.yml");
    let mut errors = check_release_publish_tag_gates(&workflow);
    for path in [
        ".github/workflows/docker.yml",
        ".github/workflows/publish-mcp.yml",
    ] {
        errors.extend(check_auxiliary_publish_workflow_is_manual_only(path));
    }
    assert!(
        errors.is_empty(),
        "release publishing guard violations:\n{}",
        errors.join("\n")
    );
}

#[test]
fn release_publish_guard_mutation_selftest_catches_removed_job_guards() {
    let workflow = load_workflow(".github/workflows/release.yml");
    for job_id in DIRECT_RELEASE_PUBLISH_JOBS {
        let mut mutated = workflow.clone();
        set_job_if(&mut mutated, job_id, "${{ always() }}");
        let errors = check_release_publish_tag_gates(&mutated);
        assert!(
            errors.iter().any(|error| error.contains(job_id)),
            "removing the tag guard from {job_id} must fail loudly, got errors={errors:?}"
        );
    }

    for job_id in TRANSITIVE_RELEASE_PUBLISH_JOBS {
        let mut mutated = workflow.clone();
        set_job_needs(&mut mutated, job_id, &["build"]);
        let errors = check_release_publish_tag_gates(&mutated);
        assert!(
            errors.iter().any(|error| error.contains(job_id)),
            "breaking the transitive skip for {job_id} must fail loudly, got errors={errors:?}"
        );
    }
}

#[test]
fn official_driver_root_data_license_is_distributed_with_every_artifact() {
    let root = workspace_root();
    let workflow = std::fs::read_to_string(root.join(".github/workflows/release.yml"))
        .expect("read release workflow");
    let dockerfile = std::fs::read_to_string(root.join("Dockerfile")).expect("read Dockerfile");
    let deny = std::fs::read_to_string(root.join("deny.toml")).expect("read deny.toml");
    let license = std::fs::read_to_string(root.join("LICENSE-CDLA-Permissive-2.0"))
        .expect("read CDLA redistribution license");

    assert!(
        license.contains("Community Data License Agreement - Permissive - Version 2.0")
            && license.contains(
                "long as the Data Recipient makes available the text of this agreement\nwith the shared Data"
            ),
        "the shipped CDLA file must contain the root-data redistribution condition"
    );
    assert_eq!(
        workflow
            .matches(
                "cp README.md LICENSE-APACHE LICENSE-MIT LICENSE-CDLA-Permissive-2.0 \"$dist/\""
            )
            .count(),
        2,
        "both Unix and Windows release archives must carry the CDLA root-data license"
    );
    assert_eq!(
        dockerfile
            .matches("COPY LICENSE-CDLA-Permissive-2.0 /usr/share/licenses/oraclemcp/LICENSE-CDLA-Permissive-2.0")
            .count(),
        1,
        "the single runtime image must carry the CDLA root-data license"
    );
    assert_eq!(
        dockerfile
            .matches("LABEL org.opencontainers.image.licenses=\"(Apache-2.0 OR MIT) AND CDLA-Permissive-2.0\"")
            .count(),
        1,
        "the single runtime image must disclose the embedded root-data license"
    );
    assert!(
        deny.contains("name = \"webpki-roots\"")
            && deny.contains("allow = [\"CDLA-Permissive-2.0\"]"),
        "the cargo-deny approval must stay package-scoped to webpki-roots"
    );
}
