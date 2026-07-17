#![forbid(unsafe_code)]

//! Runtime-only setup for the throwaway OCI ADB acceptance database.
//!
//! This is deliberately outside the server's MCP tool surface: it provisions
//! the one-time IAM prerequisite with the ephemeral ADMIN wallet credentials.
//! The signoff then proves the server's own IAM-token path through a governed
//! `oracle_query` at `READ_ONLY`.

use std::{env, error::Error, path::PathBuf, time::Duration};

use asupersync::{Cx, runtime::RuntimeBuilder};
use oraclemcp_db::{OracleConnectOptions, OracleConnection, RustOracleConnection};

fn required_env(name: &str) -> Result<String, Box<dyn Error>> {
    let value = env::var(name)?;
    if value.is_empty() {
        return Err(format!("{name} must not be empty").into());
    }
    Ok(value)
}

fn valid_database_user(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=30).contains(&bytes.len())
        && bytes[0].is_ascii_uppercase()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || *byte == b'_')
}

fn valid_principal(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'_' | b'@' | b':' | b'/' | b'=' | b'-')
        })
}

fn main() -> Result<(), Box<dyn Error>> {
    let connect_string = required_env("ORACLEMCP_ADB_CONNECT_STRING")?;
    let admin_password = required_env("ORACLEMCP_ADB_ADMIN_PASSWORD")?;
    let wallet_location = PathBuf::from(required_env("ORACLEMCP_ADB_WALLET_LOCATION")?);
    let wallet_password = required_env("ORACLEMCP_ADB_WALLET_PASSWORD")?;
    let database_user = required_env("ORACLEMCP_ADB_IAM_DATABASE_USER")?;
    let principal = required_env("ORACLEMCP_ADB_IAM_PRINCIPAL_NAME")?;
    let server_dn = env::var("ORACLEMCP_ADB_SSL_SERVER_CERT_DN")
        .ok()
        .filter(|value| !value.is_empty());

    if !valid_database_user(&database_user) {
        return Err("invalid generated IAM database username".into());
    }
    if !valid_principal(&principal) {
        return Err("invalid IAM principal name".into());
    }

    let options = OracleConnectOptions {
        connect_string,
        username: Some("ADMIN".to_owned()),
        password: Some(admin_password),
        wallet_location: Some(wallet_location),
        wallet_password: Some(wallet_password),
        ssl_server_dn_match: Some(true),
        ssl_server_cert_dn: server_dn,
        use_sni: Some(true),
        call_timeout: Some(Duration::from_secs(30)),
        ..Default::default()
    };
    let enable_iam =
        "BEGIN DBMS_CLOUD_ADMIN.ENABLE_EXTERNAL_AUTHENTICATION(type => 'OCI_IAM'); END;";
    let create_user = format!(
        "CREATE USER {database_user} IDENTIFIED GLOBALLY AS 'IAM_PRINCIPAL_NAME={principal}'"
    );
    let grant_session = format!("GRANT CREATE SESSION TO {database_user}");

    let reactor = asupersync::runtime::reactor::create_reactor()?;
    let runtime = RuntimeBuilder::current_thread()
        .with_reactor(reactor)
        .build()?;
    runtime.block_on(async move {
        let cx = Cx::current().ok_or("OCI IAM bootstrap runtime did not install Cx")?;
        let connection = RustOracleConnection::connect(&cx, options).await?;
        for statement in [enable_iam, create_user.as_str(), grant_session.as_str()] {
            connection.execute(&cx, statement, &[]).await?;
        }

        let provider = connection
            .query_rows(
                &cx,
                "SELECT VALUE FROM V$PARAMETER WHERE NAME = 'identity_provider_type'",
                &[],
            )
            .await?
            .into_iter()
            .next()
            .and_then(|row| row.text("VALUE").map(str::to_owned));
        if provider.as_deref() != Some("OCI_IAM") {
            return Err("OCI IAM external authentication was not enabled".into());
        }

        // `CREATE USER ... IAM_PRINCIPAL_NAME=<token sub>` above is the
        // exact mapping operation. `DBA_USERS.EXTERNAL_NAME` is deliberately
        // not parsed here: OCI canonicalizes that value differently across
        // service versions. The following live IAM-token session and
        // `SELECT USER FROM DUAL` are the behavior-level proof that this exact
        // token resolves to the created global schema.
        Ok::<(), Box<dyn Error>>(())
    })
}
