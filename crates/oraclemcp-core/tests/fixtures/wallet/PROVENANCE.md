# Synthetic Oracle wallet fixtures — B2.1 doctor wallet-posture probe (C1 matrix)

**Lab-only, synthetic.** Fictional subject `CN=oracle-test.invalid, O=Oracle
Synthetic Test, C=US`. No real hostnames, OCIDs, or customer identifiers.
**Do not use in production.**

These fixtures drive `tests/doctor_wallet_posture.rs`, which asserts that
`oraclemcp doctor` infers the correct Oracle-wallet posture from a static offline
probe (never a live DB connection) and never leaks a secret.

PKCS#12 / SSO containers are NOT byte-deterministic (salt/IV vary per
generation), so the committed **bytes are authoritative**: the test reads them,
it never regenerates them.

## Scenarios (one resolved wallet directory each)

| Directory                    | Files                          | Doctor posture (probed) |
|------------------------------|--------------------------------|-------------------------|
| `good_sso/`                  | `cwallet.sso`                  | `auto_login_usable` — "auto-login (cwallet.sso) usable" |
| `undecryptable_with_sso/`    | `ewallet.pem` + `cwallet.sso`  | `ewallet_undecryptable_sso_fallthrough` — "ewallet undecryptable (KeyDecrypt) — would fall through to cwallet.sso" |
| `undecryptable_without_sso/` | `ewallet.pem`                  | `wallet_load_would_fail` — "wallet load would fail: KeyDecrypt, no auto-login fallback" |

The `undecryptable_*` postures arise because the test probes the encrypted
`ewallet.pem` with the **wrong** wallet password, so the driver's
`parse_ewallet_pem` returns `WalletError::KeyDecrypt`.

## Passwords

* `ewallet.pem` encrypted-key password (correct): `oracle-test-wallet-16`.
* The doctor/test probes with the WRONG password `WrongWalletPwZ9` to synthesize
  the `KeyDecrypt` posture. (Both constants live in `doctor_wallet_posture.rs`.)

## How the bytes were generated (OpenSSL 3.5.5)

```bash
SUBJ="/CN=oracle-test.invalid/O=Oracle Synthetic Test/C=US"
openssl genrsa -out ca.key 2048
openssl req -new -x509 -days 3650 -key ca.key -out ca.pem -subj "$SUBJ"
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -subj "$SUBJ"
openssl x509 -req -days 3650 -in server.csr -CA ca.pem -CAkey ca.key \
  -CAcreateserial -out server.pem

# Encrypted PKCS#8 (PBES2 / PBKDF2 / AES-256-CBC) private key.
openssl pkcs8 -topk8 -in server.key -out server_enc_pk8.key \
  -passout pass:oracle-test-wallet-16

# ewallet.pem = leaf cert + ENCRYPTED PRIVATE KEY block. Probing it with a wrong
# password fails PKCS#8 PBES2 padding -> WalletError::KeyDecrypt.
cat server.pem server_enc_pk8.key > ewallet.pem
```

`cwallet.sso` is an auto-login SSO container that `orapki` produces; `orapki` is
not available here, so the committed `cwallet.sso` is copied verbatim from the
`oracledb` driver's proven synthetic fixture
`crates/oracledb/tests/fixtures/tls/cwallet_orapki.sso` (a real `orapki wallet
create -auto_login`, synthetic self-signed `CN=oracle-test.invalid`). It parses
end to end through `oracledb_protocol::tls::sso::parse_cwallet_sso`, which is
exactly the usability condition the driver's wallet loader requires before it
will fall through to auto-login.

## Driver API exercised (from `oracledb-protocol =0.7.4`)

* `oracledb_protocol::tls::wallet::{resolve_wallet_dir, pem_wallet_path,
  p12_wallet_path, sso_wallet_path, parse_ewallet_pem, parse_ewallet_p12,
  SSO_WALLET_FILE_NAME}`
* `oracledb_protocol::tls::sso::parse_cwallet_sso`
