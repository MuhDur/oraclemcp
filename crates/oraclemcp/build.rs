use std::path::{Path, PathBuf};

fn version_requirement(manifest: &toml::Value) -> Option<&str> {
    let dependencies = manifest
        .get("dependencies")
        .or_else(|| manifest.get("workspace")?.get("dependencies"))?;
    dependencies.get("plsql-engine")?.get("version")?.as_str()
}

fn exact_version(requirement: &str) -> Result<String, Box<dyn std::error::Error>> {
    let version = requirement
        .strip_prefix('=')
        .ok_or("plsql-engine version must be an exact =X.Y.Z requirement")?;
    if version.split('.').count() != 3
        || version
            .split('.')
            .any(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err("plsql-engine exact version must be plain X.Y.Z".into());
    }
    Ok(version.to_owned())
}

fn manifest_version(path: &Path) -> Result<Option<String>, Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed={}", path.display());
    let manifest: toml::Value = toml::from_str(&std::fs::read_to_string(path)?)?;
    version_requirement(&manifest)
        .map(exact_version)
        .transpose()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let crate_dir = PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR")
            .ok_or("Cargo must set CARGO_MANIFEST_DIR when compiling the oraclemcp binary")?,
    );
    let package_manifest = crate_dir.join("Cargo.toml");
    let version = match manifest_version(&package_manifest)? {
        Some(version) => version,
        None => manifest_version(&crate_dir.join("../../Cargo.toml"))?
            .ok_or("plsql-engine exact version is absent from package and workspace manifests")?,
    };
    println!("cargo:rustc-env=OMCP_BUILD_PLSQL_ENGINE_VERSION={version}");
    Ok(())
}
