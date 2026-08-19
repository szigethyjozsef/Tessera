use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldValue {
    pub value: String,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryType {
    Login,
    Note,
    Card,
    Identity,
    Totp,
    Passkey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub id: Uuid,
    #[serde(rename = "type")]
    pub entry_type: EntryType,
    pub version: u32,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub deleted_at: Option<OffsetDateTime>,
    pub last_modified_by: String,
    pub fields: HashMap<String, FieldValue>,
    pub tags: Vec<String>,
    pub favorite: bool,
}

impl Entry {
    pub fn new(entry_type: EntryType, device_id: &str) -> Self {
        let now = OffsetDateTime::now_utc();
        Self {
            id: Uuid::now_v7(),
            version: 1,
            created_at: now,
            updated_at: now,
            deleted_at: None,
            fields: HashMap::new(),
            tags: Vec::new(),
            last_modified_by: device_id.to_owned(),
            entry_type,
            favorite: false,
        }
    }
    pub fn mark_deleted(&mut self) {
        let now = OffsetDateTime::now_utc();
        self.version += 1;
        self.fields.clear();
        self.updated_at = now;
        self.deleted_at = Some(now);
    }

    pub fn set_field(&mut self, name: &str, value: &str, device_id: &str) {
        let now = OffsetDateTime::now_utc();
        let field = FieldValue {
            updated_at: now,
            value: value.to_owned(),
        };
        self.version += 1;
        self.fields.insert(name.to_owned(), field);
        self.updated_at = now;
        self.last_modified_by = device_id.to_owned();
    }

    pub fn get_field(&self, name: &str) -> Option<&str> {
        self.fields.get(name).map(|field| field.value.as_str())
    }
}

// Testing

#[cfg(test)]
mod tests {
use super::*;

    #[test]
    fn new_entry_starts_at_version_one_and_is_empty() {
        let entry = Entry::new(EntryType::Login, "test_device");
        assert_eq!(entry.version, 1);
        assert!(entry.fields.is_empty());
        assert!(entry.deleted_at.is_none());
    }

    #[test]
    fn create_and_edit_then_read_entry() {
        let mut entry = Entry::new(EntryType::Login, "test_device");
        entry.set_field("password", "hunter2", "test_device");
        assert_eq!(entry.get_field("password"), Some("hunter2"));
    }

    #[test]
    fn setting_the_same_field_twice_keeps_the_last_value() {
        let mut entry = Entry::new(EntryType::Login, "test_device");
        entry.set_field("password", "password1", "test_device");
        entry.set_field("password", "password2", "test_device");
        assert_eq!(entry.get_field("password"), Some("password2"));
        assert_eq!(entry.version, 3);
    }

    #[test]
    fn marking_deleted_clears_fields_and_sets_the_timestamp() {
        let mut entry = Entry::new(EntryType::Login, "test_device");
        entry.set_field("password", "password1", "test_device");
        entry.mark_deleted();
        assert!(entry.deleted_at.is_some());
        assert!(entry.fields.is_empty());
        assert_eq!(entry.version, 3);
    }
}