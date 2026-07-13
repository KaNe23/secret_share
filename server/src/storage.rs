use anyhow::Result;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use shared::EncryptedData;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

// value = (expires_at unix seconds, payload — serde_json for entries, raw bytes for files)
const ENTRIES: TableDefinition<&str, (u64, &[u8])> = TableDefinition::new("entries");
const FILES: TableDefinition<&str, (u64, &[u8])> = TableDefinition::new("files");

// AES-GCM overhead on top of the declared plaintext size: 12-byte IV + 16-byte tag
const FILE_OVERHEAD: u64 = 28;

#[derive(Serialize, Deserialize, Debug)]
pub struct Entry {
    pub secret: EncryptedData,
    pub password: Option<String>,
    pub file_list: HashMap<String, u64>,
}

pub enum Take {
    Missing,
    Rejected,
    Taken(Entry),
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_secs()
}

fn file_key(uuid: &str, file_name: &str) -> String {
    format!("{}-{}", uuid, file_name)
}

pub fn open(path: &str) -> Result<Database> {
    let db = Database::create(path)?;
    // create the tables so readers never see a missing table
    let txn = db.begin_write()?;
    txn.open_table(ENTRIES)?;
    txn.open_table(FILES)?;
    txn.commit()?;
    Ok(db)
}

pub fn set_entry(db: &Database, key: &str, entry: &Entry, ttl_secs: u64) -> Result<()> {
    let bytes = serde_json::to_vec(entry)?;
    let txn = db.begin_write()?;
    txn.open_table(ENTRIES)?
        .insert(key, (now() + ttl_secs, bytes.as_slice()))?;
    txn.commit()?;
    Ok(())
}

/// Read without consuming (index page preview).
pub fn get_entry(db: &Database, key: &str) -> Result<Option<Entry>> {
    let txn = db.begin_read()?;
    let table = txn.open_table(ENTRIES)?;
    let Some(guard) = table.get(key)? else {
        return Ok(None);
    };
    let (expires_at, bytes) = guard.value();
    if expires_at <= now() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_slice(bytes)?))
}

/// Atomically remove and return the entry, but only if `allowed` accepts it
/// (password check). This is the one-time read: the read, the check and the
/// delete happen in a single write transaction, so two concurrent readers
/// can never both receive the secret.
pub fn take_entry_if(
    db: &Database,
    key: &str,
    allowed: impl FnOnce(&Entry) -> bool,
) -> Result<Take> {
    let txn = db.begin_write()?;
    let take = {
        let mut table = txn.open_table(ENTRIES)?;
        let entry = match table.get(key)? {
            Some(guard) => {
                let (expires_at, bytes) = guard.value();
                if expires_at <= now() {
                    None
                } else {
                    Some(serde_json::from_slice::<Entry>(bytes)?)
                }
            }
            None => None,
        };
        match entry {
            None => Take::Missing,
            Some(entry) if allowed(&entry) => {
                table.remove(key)?;
                Take::Taken(entry)
            }
            Some(_) => Take::Rejected,
        }
    };
    txn.commit()?;
    Ok(take)
}

/// Store an encrypted file blob. Rejects files for unknown secrets, file
/// names that were not declared at creation time, and blobs larger than the
/// declared size (plus crypto overhead); the file inherits the entry's expiry.
pub fn set_file(db: &Database, uuid: &str, file_name: &str, bytes: &[u8]) -> Result<bool> {
    let txn = db.begin_write()?;
    let accepted = {
        let entries = txn.open_table(ENTRIES)?;
        let expires_at = match entries.get(uuid)? {
            Some(guard) => {
                let (expires_at, entry_bytes) = guard.value();
                if expires_at <= now() {
                    None
                } else {
                    serde_json::from_slice::<Entry>(entry_bytes)
                        .ok()
                        .and_then(|entry| entry.file_list.get(file_name).copied())
                        .filter(|declared_size| bytes.len() as u64 <= declared_size + FILE_OVERHEAD)
                        .map(|_| expires_at)
                }
            }
            None => None,
        };
        if let Some(expires_at) = expires_at {
            txn.open_table(FILES)?
                .insert(file_key(uuid, file_name).as_str(), (expires_at, bytes))?;
            true
        } else {
            false
        }
    };
    txn.commit()?;
    Ok(accepted)
}

/// Atomically remove and return a file blob (files are one-time reads too).
pub fn take_file(db: &Database, uuid: &str, file_name: &str) -> Result<Option<Vec<u8>>> {
    let txn = db.begin_write()?;
    let file = {
        let mut table = txn.open_table(FILES)?;
        let removed = table.remove(file_key(uuid, file_name).as_str())?;
        match removed {
            Some(guard) => {
                let (expires_at, bytes) = guard.value();
                if expires_at <= now() {
                    None
                } else {
                    Some(bytes.to_vec())
                }
            }
            None => None,
        }
    };
    txn.commit()?;
    Ok(file)
}

/// Delete expired rows. Called periodically; the tables only ever hold a
/// handful of live secrets, so a full scan is cheap.
pub fn sweep(db: &Database) -> Result<()> {
    let txn = db.begin_write()?;
    let cutoff = now();
    txn.open_table(ENTRIES)?
        .retain(|_, (expires_at, _)| expires_at > cutoff)?;
    txn.open_table(FILES)?
        .retain(|_, (expires_at, _)| expires_at > cutoff)?;
    txn.commit()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_entry(file: &str) -> Entry {
        Entry {
            secret: EncryptedData {
                data: vec![1, 2, 3],
                nonce: "n".to_string(),
            },
            password: None,
            file_list: HashMap::from([(file.to_string(), 100u64)]),
        }
    }

    #[test]
    fn roundtrip_take_and_expiry() {
        let dir = std::env::temp_dir().join(format!("ss_test_{}", std::process::id()));
        let db = open(dir.to_str().unwrap()).unwrap();

        // set + non-consuming get + atomic take
        set_entry(&db, "a", &test_entry("f"), 60).unwrap();
        assert!(get_entry(&db, "a").unwrap().is_some());
        assert!(matches!(
            take_entry_if(&db, "a", |_| true).unwrap(),
            Take::Taken(_)
        ));
        assert!(matches!(
            take_entry_if(&db, "a", |_| true).unwrap(),
            Take::Missing
        ));

        // rejected take keeps the entry
        set_entry(&db, "b", &test_entry("f"), 60).unwrap();
        assert!(matches!(
            take_entry_if(&db, "b", |_| false).unwrap(),
            Take::Rejected
        ));
        assert!(get_entry(&db, "b").unwrap().is_some());

        // files: only declared names accepted, size bounded, one-time read
        assert!(set_file(&db, "b", "f", &[9; 100]).unwrap());
        assert!(!set_file(&db, "b", "other", &[9]).unwrap());
        assert!(!set_file(&db, "missing", "f", &[9]).unwrap());
        assert!(!set_file(&db, "b", "f", &[9; 200]).unwrap()); // over declared size
        assert!(take_file(&db, "b", "f").unwrap().is_some());
        assert!(take_file(&db, "b", "f").unwrap().is_none());

        // ttl 0 == already expired; sweep removes it physically
        set_entry(&db, "c", &test_entry("f"), 0).unwrap();
        assert!(get_entry(&db, "c").unwrap().is_none());
        sweep(&db).unwrap();

        drop(db);
        std::fs::remove_file(dir).unwrap();
    }
}
