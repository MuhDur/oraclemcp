//! C6: committed doctor connectivity failure output must stay secret-free.

use asupersync::Cx;
use asupersync::runtime::RuntimeBuilder;
use oraclemcp_core::doctor::{DoctorContext, run_doctor};
use oraclemcp_core::redacted::REDACTED;
use serde_json::json;

#[path = "../../../tests/golden/support.rs"]
mod golden_support;

fn doctor_report(ctx: &DoctorContext<'_>) -> oraclemcp_core::doctor::DoctorReport {
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("current-thread runtime");
    runtime.block_on(async {
        let cx = Cx::current().expect("block_on installs a current Cx");
        run_doctor(&cx, ctx).await
    })
}

#[test]
fn doctor_connectivity_failure_secret_redaction_golden() {
    const WALLET_PW: &str = "WrongWalletPwZ9";
    const IAM_TOKEN: &str = "synthetic-iam-refresh-token-golden";

    let ctx = DoctorContext {
        connection_error: Some(format!(
            "wallet PKCS12 decrypt failed (password was {WALLET_PW}); IAM TokenSource refresh returned {IAM_TOKEN}"
        )),
        sensitive_values: vec![WALLET_PW.to_owned(), IAM_TOKEN.to_owned()],
        ..DoctorContext::default()
    };

    let report = doctor_report(&ctx);
    let connectivity = report
        .checks
        .iter()
        .find(|check| check.id == 3)
        .expect("connectivity check");

    let serialized = serde_json::to_string(connectivity).expect("check json");
    for forbidden in [WALLET_PW, IAM_TOKEN] {
        assert!(
            !serialized.contains(forbidden),
            "doctor check leaked secret: {serialized}"
        );
        assert!(connectivity.detail.contains(REDACTED));
    }

    let actual = json!({
        "fixture": "doctor_connectivity_failure_secret_redaction",
        "check": connectivity,
    });
    golden_support::assert_golden("doctor/connectivity_failure_secret_redaction", &actual);
}
