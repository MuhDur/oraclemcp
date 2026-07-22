use super::*;
use asupersync::runtime::RuntimeBuilder;

/// Run `run_doctor` on a fresh current-thread runtime with an installed `Cx`.
fn doctor(ctx: &DoctorContext<'_>) -> DoctorReport {
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("current-thread runtime");
    runtime.block_on(async {
        let cx = Cx::current().expect("block_on installs a current Cx");
        run_doctor(&cx, ctx).await
    })
}

/// A synthetic, unsigned JWT-shaped token `header.payload.` whose payload is a
/// base64url `{"exp":<exp>}`. NOT a real token; the CN/claims are synthetic
/// and there is no signature.
fn synthetic_jwt_with_exp(exp: i64) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    fn b64url(bytes: &[u8]) -> String {
        let mut out = String::new();
        let (mut buffer, mut bits) = (0u32, 0u32);
        for &b in bytes {
            buffer = (buffer << 8) | u32::from(b);
            bits += 8;
            while bits >= 6 {
                bits -= 6;
                out.push(ALPHABET[((buffer >> bits) & 0x3F) as usize] as char);
            }
        }
        if bits > 0 {
            out.push(ALPHABET[((buffer << (6 - bits)) & 0x3F) as usize] as char);
        }
        out
    }
    format!(
        "{}.{}.",
        b64url(br#"{"alg":"none"}"#),
        b64url(format!(r#"{{"exp":{exp},"sub":"synthetic-subject"}}"#).as_bytes())
    )
}

#[test]
fn iam_token_check_skips_when_no_token_configured() {
    let ctx = DoctorContext::default();
    let report = doctor(&ctx);
    let iam = report
        .checks
        .iter()
        .find(|c| c.id == 14)
        .expect("iam check");
    assert_eq!(iam.status, CheckStatus::Skip);
}

#[test]
fn iam_token_check_passes_when_far_from_expiry() {
    // exp comfortably beyond the 5-minute warning window.
    let token = synthetic_jwt_with_exp(now_unix_seconds() + 3_600);
    let ctx = DoctorContext {
        iam_token: Some(token),
        ..DoctorContext::default()
    };
    let report = doctor(&ctx);
    let iam = report
        .checks
        .iter()
        .find(|c| c.id == 14)
        .expect("iam check");
    assert_eq!(iam.status, CheckStatus::Pass, "{}", iam.detail);
}

#[test]
fn iam_token_check_warns_when_within_five_minutes() {
    // Directly exercise the pure check with a fixed clock: exp is 60s away.
    let now = 1_000_000_000;
    let token = synthetic_jwt_with_exp(now + 60);
    let result = iam_token_expiry_check(Some(&token), now);
    assert_eq!(result.status, CheckStatus::Warn, "{}", result.detail);
    assert!(result.detail.contains("60s"));
    assert!(result.detail.contains("under 5 minutes"));
    assert!(result.fix.is_some());
}

#[test]
fn iam_token_check_warns_when_already_expired() {
    let now = 1_000_000_000;
    let token = synthetic_jwt_with_exp(now - 120);
    let result = iam_token_expiry_check(Some(&token), now);
    assert_eq!(result.status, CheckStatus::Warn, "{}", result.detail);
    assert!(result.detail.contains("expired"));
}

#[test]
fn iam_token_check_warns_when_exp_unreadable() {
    let result = iam_token_expiry_check(Some("not-a-jwt-without-exp"), 1_000_000_000);
    assert_eq!(result.status, CheckStatus::Warn, "{}", result.detail);
    assert!(result.detail.contains("could not be read"));
}

#[test]
fn iam_token_check_never_renders_the_token() {
    // Adversarial non-leak: a sentinel embedded in the JWT header must not
    // reach any rendered doctor surface (detail, fix, or serialized report).
    const SENTINEL: &str = "SECRET_JWT_SENTINEL";
    // Put the sentinel in the header segment so the token is a distinct,
    // greppable string while its payload still carries a readable exp.
    let payload = {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let bytes = format!(r#"{{"exp":{}}}"#, now_unix_seconds() + 30).into_bytes();
        let mut out = String::new();
        let (mut buffer, mut bits) = (0u32, 0u32);
        for b in bytes {
            buffer = (buffer << 8) | u32::from(b);
            bits += 8;
            while bits >= 6 {
                bits -= 6;
                out.push(ALPHABET[((buffer >> bits) & 0x3F) as usize] as char);
            }
        }
        if bits > 0 {
            out.push(ALPHABET[((buffer << (6 - bits)) & 0x3F) as usize] as char);
        }
        out
    };
    let token = format!("{SENTINEL}.{payload}.sig");
    let ctx = DoctorContext {
        iam_token: Some(token.clone()),
        sensitive_values: vec![token],
        ..DoctorContext::default()
    };
    let report = doctor(&ctx);
    let iam = report
        .checks
        .iter()
        .find(|c| c.id == 14)
        .expect("iam check");
    assert_eq!(iam.status, CheckStatus::Warn, "{}", iam.detail);
    assert!(
        !iam.detail.contains(SENTINEL),
        "detail leaked: {}",
        iam.detail
    );
    let serialized = serde_json::to_string(&report.to_json()).expect("json");
    assert!(
        !serialized.contains(SENTINEL),
        "report leaked: {serialized}"
    );
}
