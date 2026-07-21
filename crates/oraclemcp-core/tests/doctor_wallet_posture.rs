//! B2.1 — the `doctor` TNS/wallet check must tell the TRUTH about Oracle wallet
//! posture, inferred by a static offline probe of the C1 wallet matrix, without
//! opening a live DB connection and without ever leaking a secret.
//!
//! Fixtures (synthetic, `CN=oracle-test.invalid`; see
//! `tests/fixtures/wallet/PROVENANCE.md`):
//!
//! * `good_sso/` — a parseable auto-login `cwallet.sso`.
//! * `undecryptable_with_sso/` — an encrypted `ewallet.pem` (probed with the
//!   WRONG password ⇒ `KeyDecrypt`) + a parseable `cwallet.sso` fallback.
//! * `undecryptable_without_sso/` — the same encrypted `ewallet.pem`, no
//!   `cwallet.sso`.

use std::path::PathBuf;

use asupersync::Cx;
use asupersync::runtime::RuntimeBuilder;
use oraclemcp_core::doctor::{
    CheckStatus, DoctorContext, DoctorWalletErrorKind, DoctorWalletPosture, probe_wallet_posture,
    run_doctor,
};

/// The password the committed encrypted `ewallet.pem` fixtures were sealed with
/// (see PROVENANCE). The probe below deliberately uses the WRONG password to
/// synthesize the `KeyDecrypt` undecryptable posture.
const FIXTURE_RIGHT_PASSWORD: &str = "oracle-test-wallet-16";
/// A deliberately wrong wallet password: decrypting the committed encrypted
/// `ewallet.pem` with it fails PKCS#8 PBES2 padding ⇒ `WalletError::KeyDecrypt`.
const WRONG_WALLET_PASSWORD: &str = "WrongWalletPwZ9";

fn wallet_fixture_dir(scenario: &str) -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests");
    p.push("fixtures");
    p.push("wallet");
    p.push(scenario);
    p
}

/// One C1 truth-table row.
struct Case {
    scenario: &'static str,
    posture: DoctorWalletPosture,
    summary: &'static str,
    error_kind: Option<DoctorWalletErrorKind>,
    fallthrough: bool,
    usable_file: Option<&'static str>,
    failed_file: Option<&'static str>,
    check_status: CheckStatus,
}

fn c1_cases() -> Vec<Case> {
    vec![
        Case {
            scenario: "good_sso",
            posture: DoctorWalletPosture::AutoLoginUsable,
            summary: "auto-login (cwallet.sso) usable",
            error_kind: None,
            fallthrough: false,
            usable_file: Some("cwallet.sso"),
            failed_file: None,
            check_status: CheckStatus::Pass,
        },
        Case {
            scenario: "undecryptable_with_sso",
            posture: DoctorWalletPosture::EwalletUndecryptableSsoFallthrough,
            summary: "ewallet undecryptable (KeyDecrypt) — would fall through to cwallet.sso",
            error_kind: Some(DoctorWalletErrorKind::KeyDecrypt),
            fallthrough: true,
            usable_file: Some("cwallet.sso"),
            failed_file: Some("ewallet.pem"),
            check_status: CheckStatus::Warn,
        },
        Case {
            scenario: "undecryptable_without_sso",
            posture: DoctorWalletPosture::WalletLoadWouldFail,
            summary: "wallet load would fail: KeyDecrypt, no auto-login fallback",
            error_kind: Some(DoctorWalletErrorKind::KeyDecrypt),
            fallthrough: false,
            usable_file: None,
            failed_file: Some("ewallet.pem"),
            check_status: CheckStatus::Fail,
        },
    ]
}

/// The direct probe must render the correct posture for every C1 case.
#[test]
fn wallet_posture_probe_truth_table() {
    for case in c1_cases() {
        let dir = wallet_fixture_dir(case.scenario);
        let report = probe_wallet_posture(&dir, Some(WRONG_WALLET_PASSWORD));
        assert_eq!(
            report.posture, case.posture,
            "{}: posture mismatch (report = {report:?})",
            case.scenario
        );
        assert_eq!(
            report.summary, case.summary,
            "{}: summary mismatch",
            case.scenario
        );
        assert_eq!(
            report.error_kind, case.error_kind,
            "{}: error_kind mismatch",
            case.scenario
        );
        assert_eq!(
            report.fallthrough, case.fallthrough,
            "{}: fallthrough mismatch",
            case.scenario
        );
        assert_eq!(
            report.usable_file, case.usable_file,
            "{}: usable_file mismatch",
            case.scenario
        );
        assert_eq!(
            report.failed_file, case.failed_file,
            "{}: failed_file mismatch",
            case.scenario
        );
    }
}

/// The `good_sso` cwallet.sso genuinely parses (not merely present); probing with
/// the RIGHT wallet password still yields the auto-login posture (there is no
/// ewallet to prefer), confirming the sso usability check is real.
#[test]
fn wallet_posture_good_sso_parses_end_to_end() {
    let report = probe_wallet_posture(
        &wallet_fixture_dir("good_sso"),
        Some(FIXTURE_RIGHT_PASSWORD),
    );
    assert_eq!(report.posture, DoctorWalletPosture::AutoLoginUsable);
    assert!(report.usable_file == Some("cwallet.sso"));
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

/// The doctor's TNS/wallet check (id 2) must render the correct posture string,
/// structured kind, and check status for every C1 case.
#[test]
fn doctor_renders_wallet_posture_for_each_c1_case() {
    for case in c1_cases() {
        let dir = wallet_fixture_dir(case.scenario);
        let ctx = DoctorContext {
            wallet_location: Some(dir.display().to_string()),
            wallet_password: Some(WRONG_WALLET_PASSWORD.to_owned()),
            ..DoctorContext::default()
        };
        let report = run_doctor_blocking(&ctx);
        let tns = report
            .checks
            .iter()
            .find(|c| c.id == 2)
            .expect("TNS/wallet check present");

        assert_eq!(
            tns.status, case.check_status,
            "{}: check status mismatch (detail = {})",
            case.scenario, tns.detail
        );
        assert_eq!(
            tns.detail, case.summary,
            "{}: detail mismatch",
            case.scenario
        );

        let posture = tns
            .wallet_posture
            .as_ref()
            .expect("posture attached to TNS/wallet check");
        assert_eq!(posture.posture, case.posture, "{}: kind", case.scenario);
        assert_eq!(
            posture.error_kind, case.error_kind,
            "{}: kind",
            case.scenario
        );
        assert_eq!(
            posture.fallthrough, case.fallthrough,
            "{}: fallthrough",
            case.scenario
        );
    }
}

/// Secret non-leakage: the rendered doctor output (text + JSON) for every C1 case
/// must contain none of the fixture path, "PRIVATE KEY", or any wallet password.
#[test]
fn doctor_wallet_posture_never_leaks_a_secret() {
    for case in c1_cases() {
        let dir = wallet_fixture_dir(case.scenario);
        let dir_str = dir.display().to_string();
        let ctx = DoctorContext {
            wallet_location: Some(dir_str.clone()),
            wallet_password: Some(WRONG_WALLET_PASSWORD.to_owned()),
            ..DoctorContext::default()
        };
        let report = run_doctor_blocking(&ctx);

        let text = report.to_text();
        let json = serde_json::to_string(&report.to_json()).expect("json");

        for rendered in [&text, &json] {
            assert!(
                !rendered.contains(&dir_str),
                "{}: doctor output leaked the wallet path",
                case.scenario
            );
            assert!(
                !rendered.contains("PRIVATE KEY"),
                "{}: doctor output leaked key material",
                case.scenario
            );
            assert!(
                !rendered.contains(WRONG_WALLET_PASSWORD),
                "{}: doctor output leaked the wallet password",
                case.scenario
            );
            assert!(
                !rendered.contains(FIXTURE_RIGHT_PASSWORD),
                "{}: doctor output leaked the fixture password",
                case.scenario
            );
        }
    }
}

/// P-U4 (D6 rider) — a LEGACY-3DES `ewallet.p12` must decrypt through the SERVER
/// wallet path, not merely be recognised by filename.
///
/// `oci::classify_wallet` only ever sees that a file called `ewallet.p12` exists
/// (`has_p12`); it never opens it. The decryption that matters happens here, in
/// the doctor probe, over the driver's `parse_ewallet_p12`. Oracle wallets in the
/// field are still frequently sealed with PKCS#12's legacy
/// `pbeWithSHA1And3-KeyTripleDES-CBC` (OID 1.2.840.113549.1.12.1.3), which
/// OpenSSL 3 will not even produce without `-legacy`, so a loader that quietly
/// handled only modern PBES2 would pass every other fixture in this file.
///
/// The fixture is synthetic (`CN=oracle-test.invalid`; see PROVENANCE.md) and its
/// committed bytes are authoritative — PKCS#12 is not byte-deterministic, so the
/// test reads them and never regenerates.
#[test]
fn legacy_3des_p12_decrypts_through_the_server_wallet_path() {
    let dir = wallet_fixture_dir("legacy_3des_p12");
    let report = probe_wallet_posture(&dir, Some(FIXTURE_RIGHT_PASSWORD));

    assert_eq!(
        report.posture,
        DoctorWalletPosture::PrimaryUsable,
        "a legacy-3DES ewallet.p12 must be directly usable; got {:?} ({:?})",
        report.posture,
        report.error_kind
    );
    assert_eq!(
        report.usable_file,
        Some("ewallet.p12"),
        "the p12 must be the primary; the fixture directory holds no ewallet.pem"
    );
    assert_eq!(report.error_kind, None, "no error kind on a usable wallet");
}

/// The control for the test above, without which it proves nothing: a probe that
/// merely noticed the FILE would report the same `PrimaryUsable` no matter what
/// the bytes said. Feeding the identical fixture the WRONG password must fail —
/// only real decryption can tell the two runs apart.
#[test]
fn the_legacy_3des_probe_actually_decrypts_rather_than_noticing_the_file() {
    let dir = wallet_fixture_dir("legacy_3des_p12");
    let wrong = probe_wallet_posture(&dir, Some(WRONG_WALLET_PASSWORD));

    assert_ne!(
        wrong.posture,
        DoctorWalletPosture::PrimaryUsable,
        "the wrong password still reported a usable wallet, so the probe is not \
         decrypting the p12 at all and the sibling test passes vacuously"
    );
    assert!(
        wrong.error_kind.is_some(),
        "a failed decrypt must carry a structured error kind"
    );
}
