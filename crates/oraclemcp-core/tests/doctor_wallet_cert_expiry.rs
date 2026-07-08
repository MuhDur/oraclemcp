//! K1 (iec3.6.6) — the `doctor` TNS/wallet check must warn when a wallet
//! certificate is at or within the expiry threshold (or already expired),
//! inferred by a static OFFLINE probe of the wallet files' certificates (never a
//! live DB connection) via the `oraclemcp-db` adapter seam over the driver's
//! `WalletContents::certificate_metadata()`.
//!
//! Fixtures (synthetic, `CN=oracle-test.invalid`; see
//! `tests/fixtures/wallet/PROVENANCE.md`):
//!
//! * `expired_cert/` — a cert-only `ewallet.pem` with an explicitly EXPIRED
//!   validity window (2020-01-01 .. 2020-02-01 UTC) ⇒ WARN.
//! * `good_sso/` — a healthy auto-login `cwallet.sso` whose certificate is
//!   valid far into the future ⇒ no expiry warning.

use std::path::PathBuf;

use asupersync::Cx;
use asupersync::runtime::RuntimeBuilder;
use oraclemcp_core::doctor::{CheckStatus, DoctorContext, run_doctor};

/// The `notAfter` epoch-second the `expired_cert/ewallet.pem` fixture was minted
/// with (`openssl ... -not_after 20200201000000Z`; see PROVENANCE).
const EXPIRED_NOT_AFTER: i64 = 1_580_515_200;
/// A 30-day-or-less window (or an already-expired cert) escalates to WARN — the
/// same threshold `doctor` applies.
const WARN_DAYS: i64 = 30;

fn wallet_fixture_dir(scenario: &str) -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests");
    p.push("fixtures");
    p.push("wallet");
    p.push(scenario);
    p
}

fn now_unix_secs() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_secs(),
    )
    .expect("epoch seconds fit i64")
}

/// The adapter seam maps the driver's `certificate_metadata()` onto the
/// server-owned validity type: the expired fixture yields exactly the minted
/// `notAfter`, and the healthy `good_sso` wallet yields a far-future one.
#[test]
fn seam_reads_wallet_certificate_validity_offline() {
    let expired =
        oraclemcp_db::wallet_certificate_validity(&wallet_fixture_dir("expired_cert"), None);
    assert!(
        expired.iter().any(|c| c.not_after == EXPIRED_NOT_AFTER),
        "expired fixture must expose its minted notAfter (got {expired:?})"
    );

    let healthy = oraclemcp_db::wallet_certificate_validity(&wallet_fixture_dir("good_sso"), None);
    assert!(
        !healthy.is_empty(),
        "good_sso auto-login wallet must expose at least one certificate"
    );
    let now = now_unix_secs();
    let earliest = healthy
        .iter()
        .map(|c| c.not_after)
        .min()
        .expect("good_sso has certs");
    assert!(
        earliest > now + WARN_DAYS * 86_400,
        "good_sso certificate must be comfortably far from expiry (earliest notAfter {earliest}, now {now})"
    );
}

fn run_doctor_blocking(ctx: &DoctorContext<'_>) -> oraclemcp_core::doctor::DoctorReport {
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("current-thread runtime");
    runtime.block_on(async {
        let cx = Cx::current().expect("block_on installs a current Cx");
        run_doctor(&cx, ctx).await
    })
}

/// A wallet whose certificate has expired escalates the TNS/wallet check to
/// WARN, attaches the cert-expiry diagnostic (earliest `notAfter` + negative
/// `days_until_expiry`), and offers a renew/replace fix.
#[test]
fn expired_wallet_certificate_warns() {
    let ctx = DoctorContext {
        wallet_location: Some(wallet_fixture_dir("expired_cert").display().to_string()),
        ..DoctorContext::default()
    };
    let report = run_doctor_blocking(&ctx);
    let tns = report
        .checks
        .iter()
        .find(|c| c.id == 2)
        .expect("TNS/wallet check present");

    assert_eq!(
        tns.status,
        CheckStatus::Warn,
        "an expired wallet cert must WARN (detail = {})",
        tns.detail
    );
    let expiry = tns
        .wallet_cert_expiry
        .as_ref()
        .expect("cert-expiry diagnostic attached");
    assert_eq!(expiry.expires_at, EXPIRED_NOT_AFTER);
    assert!(
        expiry.days_until_expiry < 0,
        "an expired cert reports negative days_until_expiry (got {})",
        expiry.days_until_expiry
    );
    assert!(
        tns.fix.as_deref().is_some_and(|f| f.contains("expired")),
        "an expired cert must carry a renew/replace fix (fix = {:?})",
        tns.fix
    );
    assert!(
        tns.detail.contains("expired"),
        "the WARN detail must mention expiry (detail = {})",
        tns.detail
    );
}

/// A healthy wallet whose certificate is far from expiry does NOT warn: the
/// TNS/wallet check stays a Pass and offers no cert-expiry fix.
#[test]
fn healthy_wallet_certificate_does_not_warn() {
    let ctx = DoctorContext {
        wallet_location: Some(wallet_fixture_dir("good_sso").display().to_string()),
        ..DoctorContext::default()
    };
    let report = run_doctor_blocking(&ctx);
    let tns = report
        .checks
        .iter()
        .find(|c| c.id == 2)
        .expect("TNS/wallet check present");

    assert_eq!(
        tns.status,
        CheckStatus::Pass,
        "a healthy far-from-expiry wallet must not warn (detail = {})",
        tns.detail
    );
    // The cert-expiry diagnostic may be attached (recording the far-future
    // window), but it must not have triggered a warning.
    if let Some(expiry) = tns.wallet_cert_expiry.as_ref() {
        assert!(
            expiry.days_until_expiry >= WARN_DAYS,
            "healthy wallet must be >= {WARN_DAYS} days from expiry (got {})",
            expiry.days_until_expiry
        );
    }
}

/// The rendered doctor output (text + JSON) for the expiry cases must never leak
/// the wallet path or key material.
#[test]
fn cert_expiry_output_never_leaks_a_secret() {
    for scenario in ["expired_cert", "good_sso"] {
        let dir = wallet_fixture_dir(scenario);
        let dir_str = dir.display().to_string();
        let ctx = DoctorContext {
            wallet_location: Some(dir_str.clone()),
            ..DoctorContext::default()
        };
        let report = run_doctor_blocking(&ctx);
        let text = report.to_text();
        let json = serde_json::to_string(&report.to_json()).expect("json");
        for rendered in [&text, &json] {
            assert!(
                !rendered.contains(&dir_str),
                "{scenario}: doctor output leaked the wallet path"
            );
            assert!(
                !rendered.contains("PRIVATE KEY"),
                "{scenario}: doctor output leaked key material"
            );
        }
    }
}
