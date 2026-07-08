//! iec3.2.35 — driver-adoption cross-check: the doctor's offline wallet-posture
//! inference (`probe_wallet_posture`) must not drift from the driver's now-public
//! authoritative precedence resolver (the driver's `resolve_wallet`, exposed
//! through the `oraclemcp-db` adapter seam as `resolve_wallet_choice`).
//!
//! The doctor keeps its OWN posture logic on purpose (option (b)): the driver's
//! `resolve_wallet` deliberately DISCARDS the specific `WalletError` class on a
//! successful fallthrough (it returns `chosen == Sso`, not "the pem failed with
//! KeyDecrypt"), and it reports "no wallet files" as an `Err`, whereas the doctor
//! must surface the exact error class + a distinct `NoWalletFiles` posture and
//! keep its audited secret-free output shape stable. This test pins the two
//! decisions together so the precedence / fallthrough-eligibility inference can
//! never silently drift from the driver.

use std::path::PathBuf;

use oraclemcp_core::doctor::{DoctorWalletPosture, probe_wallet_posture};
use oraclemcp_db::{WalletFileChoice, WalletResolveError, resolve_wallet_choice};

/// Same wrong wallet password the C1 posture fixtures are probed with, so the
/// encrypted `ewallet.pem` fails `KeyDecrypt` in both the doctor probe and the
/// driver resolver.
const WRONG_WALLET_PASSWORD: &str = "WrongWalletPwZ9";

fn wallet_fixture_dir(scenario: &str) -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests");
    p.push("fixtures");
    p.push("wallet");
    p.push(scenario);
    p
}

/// For every C1 fixture, the doctor's posture and the driver's authoritative
/// `resolve_wallet` outcome must AGREE on precedence and fallthrough.
#[test]
fn doctor_posture_agrees_with_driver_resolve_wallet() {
    // good_sso: only an auto-login cwallet.sso → chosen directly, no primary,
    // no fallthrough.
    {
        let dir = wallet_fixture_dir("good_sso");
        let report = probe_wallet_posture(&dir, Some(WRONG_WALLET_PASSWORD));
        let resolved =
            resolve_wallet_choice(&dir, Some(WRONG_WALLET_PASSWORD)).expect("good_sso resolves");
        assert_eq!(report.posture, DoctorWalletPosture::AutoLoginUsable);
        assert_eq!(resolved.chosen, WalletFileChoice::Sso);
        assert_eq!(resolved.attempted_primary, None);
        assert!(!resolved.fell_through);
        assert_eq!(report.fallthrough, resolved.fell_through);
    }

    // undecryptable_with_sso: encrypted ewallet.pem (wrong password ⇒ KeyDecrypt,
    // a fallthrough-eligible class) + a usable cwallet.sso → the driver falls
    // through, and the doctor must classify the SAME fallthrough.
    {
        let dir = wallet_fixture_dir("undecryptable_with_sso");
        let report = probe_wallet_posture(&dir, Some(WRONG_WALLET_PASSWORD));
        let resolved = resolve_wallet_choice(&dir, Some(WRONG_WALLET_PASSWORD))
            .expect("with_sso falls through to a usable sso");
        assert_eq!(
            report.posture,
            DoctorWalletPosture::EwalletUndecryptableSsoFallthrough
        );
        assert_eq!(resolved.chosen, WalletFileChoice::Sso);
        assert_eq!(resolved.attempted_primary, Some(WalletFileChoice::Pem));
        assert!(resolved.fell_through);
        assert!(resolved.fallthrough_eligible);
        // The doctor agrees a fallthrough occurred, and its named failed file
        // matches the driver's attempted primary.
        assert!(report.fallthrough);
        assert_eq!(
            report.failed_file,
            resolved.attempted_primary.map(|f| f.file_name()),
            "doctor's failed_file must match the driver's attempted primary"
        );
    }

    // undecryptable_without_sso: the same encrypted ewallet.pem, no sso → the
    // driver surfaces the typed KeyDecrypt error verbatim (no fallthrough), and
    // the doctor must classify a hard load failure with the SAME error class.
    {
        let dir = wallet_fixture_dir("undecryptable_without_sso");
        let report = probe_wallet_posture(&dir, Some(WRONG_WALLET_PASSWORD));
        let resolved = resolve_wallet_choice(&dir, Some(WRONG_WALLET_PASSWORD));
        assert_eq!(report.posture, DoctorWalletPosture::WalletLoadWouldFail);
        assert!(!report.fallthrough);
        assert_eq!(
            resolved,
            Err(WalletResolveError::KeyDecrypt),
            "the driver surfaces the primary's KeyDecrypt verbatim with no sso fallback"
        );
    }
}
