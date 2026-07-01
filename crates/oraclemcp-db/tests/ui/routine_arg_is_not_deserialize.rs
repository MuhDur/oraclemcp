//! Compile-fail fixture: `OracleRoutineArg` must not implement `Deserialize`.

use oraclemcp_db::OracleRoutineArg;
use serde::Deserialize;

fn assert_deserialize<'de, T>()
where
    T: Deserialize<'de>,
{
}

fn main() {
    assert_deserialize::<OracleRoutineArg>();
}
