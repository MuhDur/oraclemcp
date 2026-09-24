//! Per-profile durable storage for whole-closure Oracle catalog facts.

use std::fs::{self, File};
use std::io::{Read, Take};
use std::path::Path;

use oraclemcp_db::catalog_facts::{
    CLOSURE_FACT_SCHEMA_VERSION, ClosureFactKey, ClosureFactStore, ClosureFacts, fact_record_valid,
};
use serde::{Deserialize, Serialize};

use crate::file_store::{FileStore, FileStoreError, ServiceOwner, StoreId};

const COLLECTION: &str = "catalog-facts";
const EXTENSION: &str = "json";
const MAX_RECORD_BYTES: u64 = 4 * 1024 * 1024;

/// FileStore-backed durable catalog fact repository.
pub struct CatalogFactFileStore {
    store: FileStore,
    owner: ServiceOwner,
}

#[derive(Serialize, Deserialize)]
struct VersionedRecord {
    schema_version: u8,
    facts: ClosureFacts,
}

impl CatalogFactFileStore {
    /// Open the default service state directory and acquire its owner lock.
    pub fn open_default() -> Result<Self, FileStoreError> {
        Self::open(FileStore::default_state_dir()?)
    }

    /// Open a dedicated state directory and acquire its owner lock.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, FileStoreError> {
        let store = FileStore::open(root)?;
        let owner = store.acquire_service_owner("catalog-facts")?;
        Ok(Self { store, owner })
    }

    /// Use the service's already-held file-store ownership capability.
    pub fn open_with_owner(owner: ServiceOwner) -> Result<Self, FileStoreError> {
        let store = FileStore::open(owner.root())?;
        Ok(Self { store, owner })
    }

    fn id(profile: &str, root: &oraclemcp_guard::purity::RoutineRef) -> Result<StoreId, String> {
        let root = serde_json::to_string(root).map_err(|_| "root identity serialization failed")?;
        StoreId::content_hashed("closure", &[profile, &root])
            .map_err(|_| "fact path identity rejected".into())
    }

    fn read_record(&self, id: &StoreId) -> Result<Option<ClosureFacts>, String> {
        let path = self
            .store
            .path_for(COLLECTION, id, EXTENSION)
            .map_err(file_error)?;
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err("fact record metadata unavailable".into()),
        };
        if !metadata.file_type().is_file() || metadata.len() > MAX_RECORD_BYTES {
            return Ok(None);
        }
        let file = File::open(&path).map_err(|_| "fact record unreadable")?;
        let mut limited: Take<File> = file.take(MAX_RECORD_BYTES + 1);
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        limited
            .read_to_end(&mut bytes)
            .map_err(|_| "fact record unreadable")?;
        if bytes.len() as u64 > MAX_RECORD_BYTES {
            return Ok(None);
        }
        let record = match serde_json::from_slice::<VersionedRecord>(&bytes) {
            Ok(record) => record,
            Err(_) => return Ok(None),
        };
        if record.schema_version != CLOSURE_FACT_SCHEMA_VERSION || !fact_record_valid(&record.facts)
        {
            return Ok(None);
        }
        Ok(Some(record.facts))
    }
}

impl ClosureFactStore for CatalogFactFileStore {
    fn load(&self, profile: &str, key: &ClosureFactKey) -> Result<Option<ClosureFacts>, String> {
        let id = Self::id(profile, &key.root)?;
        let Some(facts) = self.read_record(&id)? else {
            return Ok(None);
        };
        if facts.key.root != key.root {
            return Ok(None);
        }
        Ok(Some(facts))
    }

    fn save(&self, profile: &str, facts: &ClosureFacts) -> Result<(), String> {
        if !fact_record_valid(facts) {
            return Err("refusing incomplete or invalid catalog fact record".into());
        }
        let id = Self::id(profile, &facts.key.root)?;
        let record = VersionedRecord {
            schema_version: CLOSURE_FACT_SCHEMA_VERSION,
            facts: facts.clone(),
        };
        let bytes = serde_json::to_vec(&record).map_err(|_| "fact record serialization failed")?;
        self.store
            .write_atomic(&self.owner, COLLECTION, &id, EXTENSION, &bytes)
            .map_err(file_error)?;
        Ok(())
    }
}

fn file_error(error: FileStoreError) -> String {
    let _ = error;
    "catalog fact FileStore operation failed".into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn fact_store_corrupt_record_is_unknown() {
        let dir = tempdir().expect("temp dir");
        let store = CatalogFactFileStore::open(dir.path()).expect("fact store");
        let key = ClosureFactKey {
            dbid: "db".into(),
            container: "pdb".into(),
            edition: "ora$base".into(),
            root: oraclemcp_guard::purity::RoutineRef {
                schema: Some(oraclemcp_guard::purity::RoutineIdentifier::new(
                    "APP", false,
                )),
                package: Some(oraclemcp_guard::purity::RoutineIdentifier::new(
                    "PKG", false,
                )),
                member: oraclemcp_guard::purity::RoutineIdentifier::new("RUN", false),
                overload: None,
            },
            fingerprint: String::new(),
        };
        let id = CatalogFactFileStore::id("profile", &key.root).expect("id");
        let path = store
            .store
            .path_for(COLLECTION, &id, EXTENSION)
            .expect("record path");
        std::fs::create_dir_all(path.parent().expect("parent")).expect("collection");
        let mut file = File::create(path).expect("record file");
        file.write_all(b"{corrupt").expect("corrupt bytes");
        assert!(matches!(store.load("profile", &key), Ok(None)));
    }

    #[test]
    fn fact_store_unknown_schema_is_unknown() {
        let dir = tempdir().expect("temp dir");
        let store = CatalogFactFileStore::open(dir.path()).expect("fact store");
        let root = oraclemcp_guard::purity::RoutineRef {
            schema: Some(oraclemcp_guard::purity::RoutineIdentifier::new(
                "APP", false,
            )),
            package: Some(oraclemcp_guard::purity::RoutineIdentifier::new(
                "PKG", false,
            )),
            member: oraclemcp_guard::purity::RoutineIdentifier::new("RUN", false),
            overload: None,
        };
        let key = ClosureFactKey {
            dbid: "db".into(),
            container: "pdb".into(),
            edition: "ora$base".into(),
            root: root.clone(),
            fingerprint: String::new(),
        };
        let id = CatalogFactFileStore::id("profile", &root).expect("id");
        let record = VersionedRecord {
            schema_version: CLOSURE_FACT_SCHEMA_VERSION + 1,
            facts: ClosureFacts {
                schema_version: CLOSURE_FACT_SCHEMA_VERSION + 1,
                key,
                members: Vec::new(),
                dependencies: Vec::new(),
                triggers: Vec::new(),
                catalog_revision: None,
            },
        };
        let bytes = serde_json::to_vec(&record).expect("encoded unknown schema");
        store
            .store
            .write_atomic(&store.owner, COLLECTION, &id, EXTENSION, &bytes)
            .expect("persist synthetic unknown schema record");
        assert!(matches!(store.load("profile", &record.facts.key), Ok(None)));
    }
}
