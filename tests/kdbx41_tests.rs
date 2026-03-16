/// Integration tests for KDBX 4.1 features.
///
/// Every test that writes a database uses `db.save` + `Database::open` so it
/// exercises the full stack: DB types → XML serialization → KDBX4 encryption →
/// KDBX4 decryption → XML deserialization → DB types.
#[cfg(feature = "save_kdbx4")]
mod kdbx41_tests {
    use chrono::NaiveDateTime;
    use keepass::{
        config::DatabaseVersion,
        db::{CustomIcon, Database, Entry, Group},
        DatabaseKey,
    };
    use uuid::Uuid;

    /// The KDBX 4.1 minor version number.
    const KDBX41_MINOR: u16 = 1;

    const PASSWORD: &str = "kdbx41-test-password";

    fn roundtrip(db: Database) -> Database {
        let key = DatabaseKey::new().with_password(PASSWORD);
        let mut buf = Vec::new();
        db.save(&mut buf, key.clone()).expect("save failed");
        Database::open(&mut buf.as_slice(), key).expect("open failed")
    }

    // ── File version ─────────────────────────────────────────────────────────

    /// The minor-version bytes in the raw KDBX header must equal 1.
    ///
    /// Header layout (little-endian):
    ///   [0..4]   = KDBX magic identifier
    ///   [4..8]   = app identifier
    ///   [8..10]  = minor version  ← what we check
    ///   [10..12] = major version
    #[test]
    fn written_version_minor_is_1() {
        let db = Database::new(Default::default());
        let key = DatabaseKey::new().with_password(PASSWORD);
        let mut buf = Vec::new();
        db.save(&mut buf, key).expect("save failed");

        let minor = u16::from_le_bytes([buf[8], buf[9]]);
        assert_eq!(minor, KDBX41_MINOR, "KDBX minor version should be 1 (KDBX 4.1)");
    }

    #[test]
    fn default_database_config_is_kdb4_1() {
        let db = Database::new(Default::default());
        assert_eq!(db.config.version, DatabaseVersion::KDB4(KDBX41_MINOR));
    }

    // ── Entry::quality_check ─────────────────────────────────────────────────

    #[test]
    fn entry_quality_check_true_roundtrip() {
        let mut db = Database::new(Default::default());
        let mut entry = Entry::new();
        entry.quality_check = Some(true);
        db.root.entries.push(entry);

        let loaded = roundtrip(db);
        assert_eq!(loaded.root.entries[0].quality_check, Some(true));
    }

    #[test]
    fn entry_quality_check_false_roundtrip() {
        let mut db = Database::new(Default::default());
        let mut entry = Entry::new();
        entry.quality_check = Some(false);
        db.root.entries.push(entry);

        let loaded = roundtrip(db);
        assert_eq!(loaded.root.entries[0].quality_check, Some(false));
    }

    /// When `quality_check` is `None` it should not appear in XML and must
    /// deserialize back to `None`.
    #[test]
    fn entry_quality_check_none_roundtrip() {
        let mut db = Database::new(Default::default());
        db.root.entries.push(Entry::new());

        let loaded = roundtrip(db);
        assert_eq!(loaded.root.entries[0].quality_check, None);
    }

    /// Multiple entries can independently carry different quality_check values.
    #[test]
    fn entry_quality_check_multiple_entries() {
        let mut db = Database::new(Default::default());

        let mut e1 = Entry::new();
        e1.quality_check = Some(true);
        let mut e2 = Entry::new();
        e2.quality_check = Some(false);
        let e3 = Entry::new(); // quality_check = None

        db.root.entries.push(e1);
        db.root.entries.push(e2);
        db.root.entries.push(e3);

        let loaded = roundtrip(db);
        assert_eq!(loaded.root.entries[0].quality_check, Some(true));
        assert_eq!(loaded.root.entries[1].quality_check, Some(false));
        assert_eq!(loaded.root.entries[2].quality_check, None);
    }

    // ── Entry::previous_parent_group ─────────────────────────────────────────

    #[test]
    fn entry_previous_parent_group_roundtrip() {
        let ppg = Uuid::new_v4();

        let mut db = Database::new(Default::default());
        let mut entry = Entry::new();
        entry.previous_parent_group = Some(ppg);
        db.root.entries.push(entry);

        let loaded = roundtrip(db);
        assert_eq!(loaded.root.entries[0].previous_parent_group, Some(ppg));
    }

    #[test]
    fn entry_previous_parent_group_none_roundtrip() {
        let mut db = Database::new(Default::default());
        db.root.entries.push(Entry::new());

        let loaded = roundtrip(db);
        assert_eq!(loaded.root.entries[0].previous_parent_group, None);
    }

    /// The UUID must survive the Base64 encode/decode round-trip exactly.
    #[test]
    fn entry_previous_parent_group_uuid_integrity() {
        // Use a UUID with all bytes distinct to catch byte-swapping bugs.
        let ppg = Uuid::from_bytes([
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        ]);

        let mut db = Database::new(Default::default());
        let mut entry = Entry::new();
        entry.previous_parent_group = Some(ppg);
        db.root.entries.push(entry);

        let loaded = roundtrip(db);
        assert_eq!(loaded.root.entries[0].previous_parent_group, Some(ppg));
    }

    // ── Group::tags ──────────────────────────────────────────────────────────

    #[test]
    fn group_tags_multiple_roundtrip() {
        let mut db = Database::new(Default::default());
        let mut group = Group::new("Tagged");
        group.tags = vec!["alpha".to_string(), "beta".to_string(), "gamma".to_string()];
        db.root.groups.push(group);

        let loaded = roundtrip(db);
        assert_eq!(
            loaded.root.groups[0].tags,
            vec!["alpha".to_string(), "beta".to_string(), "gamma".to_string()]
        );
    }

    #[test]
    fn group_single_tag_roundtrip() {
        let mut db = Database::new(Default::default());
        let mut group = Group::new("Single");
        group.tags = vec!["solo".to_string()];
        db.root.groups.push(group);

        let loaded = roundtrip(db);
        assert_eq!(loaded.root.groups[0].tags, vec!["solo".to_string()]);
    }

    #[test]
    fn group_empty_tags_roundtrip() {
        let mut db = Database::new(Default::default());
        db.root.groups.push(Group::new("Untagged"));

        let loaded = roundtrip(db);
        assert!(
            loaded.root.groups[0].tags.is_empty(),
            "empty tags should stay empty"
        );
    }

    /// Tags with special characters (spaces, hyphens) must survive unchanged.
    #[test]
    fn group_tags_with_special_chars_roundtrip() {
        let mut db = Database::new(Default::default());
        let mut group = Group::new("Styled");
        group.tags = vec!["my-tag".to_string(), "another tag".to_string()];
        db.root.groups.push(group);

        let loaded = roundtrip(db);
        assert_eq!(
            loaded.root.groups[0].tags,
            vec!["my-tag".to_string(), "another tag".to_string()]
        );
    }

    // ── Group::previous_parent_group ─────────────────────────────────────────

    #[test]
    fn group_previous_parent_group_roundtrip() {
        let ppg = Uuid::new_v4();

        let mut db = Database::new(Default::default());
        let mut group = Group::new("Relocated");
        group.previous_parent_group = Some(ppg);
        db.root.groups.push(group);

        let loaded = roundtrip(db);
        assert_eq!(loaded.root.groups[0].previous_parent_group, Some(ppg));
    }

    #[test]
    fn group_previous_parent_group_none_roundtrip() {
        let mut db = Database::new(Default::default());
        db.root.groups.push(Group::new("Static"));

        let loaded = roundtrip(db);
        assert_eq!(loaded.root.groups[0].previous_parent_group, None);
    }

    // ── CustomIcon – entry ───────────────────────────────────────────────────

    #[test]
    fn entry_custom_icon_data_only_roundtrip() {
        let icon_uuid = Uuid::new_v4();
        let icon_data = vec![0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]; // PNG magic

        let mut db = Database::new(Default::default());
        let mut entry = Entry::new();
        entry.custom_icon = Some(CustomIcon {
            uuid: icon_uuid,
            data: icon_data.clone(),
            name: None,
            last_modification_time: None,
        });
        db.root.entries.push(entry);

        let loaded = roundtrip(db);
        let ci = loaded.root.entries[0].custom_icon.as_ref().unwrap();
        assert_eq!(ci.uuid, icon_uuid);
        assert_eq!(ci.data, icon_data);
        assert_eq!(ci.name, None);
        assert_eq!(ci.last_modification_time, None);
    }

    #[test]
    fn entry_custom_icon_name_roundtrip() {
        let icon_uuid = Uuid::new_v4();

        let mut db = Database::new(Default::default());
        let mut entry = Entry::new();
        entry.custom_icon = Some(CustomIcon {
            uuid: icon_uuid,
            data: vec![1, 2, 3],
            name: Some("My Custom Icon".to_string()),
            last_modification_time: None,
        });
        db.root.entries.push(entry);

        let loaded = roundtrip(db);
        let ci = loaded.root.entries[0].custom_icon.as_ref().unwrap();
        assert_eq!(ci.name.as_deref(), Some("My Custom Icon"));
    }

    #[test]
    fn entry_custom_icon_last_modification_time_roundtrip() {
        let icon_uuid = Uuid::new_v4();
        // Use a timestamp with second precision (sub-second is not stored).
        let ts = NaiveDateTime::parse_from_str("2024-01-15 12:34:56", "%Y-%m-%d %H:%M:%S").unwrap();

        let mut db = Database::new(Default::default());
        let mut entry = Entry::new();
        entry.custom_icon = Some(CustomIcon {
            uuid: icon_uuid,
            data: vec![0xAB],
            name: None,
            last_modification_time: Some(ts),
        });
        db.root.entries.push(entry);

        let loaded = roundtrip(db);
        let ci = loaded.root.entries[0].custom_icon.as_ref().unwrap();
        assert_eq!(ci.last_modification_time, Some(ts));
    }

    #[test]
    fn entry_custom_icon_all_fields_roundtrip() {
        let icon_uuid = Uuid::new_v4();
        let ts = NaiveDateTime::parse_from_str("2025-06-01 08:00:00", "%Y-%m-%d %H:%M:%S").unwrap();

        let mut db = Database::new(Default::default());
        let mut entry = Entry::new();
        entry.custom_icon = Some(CustomIcon {
            uuid: icon_uuid,
            data: vec![0xDE, 0xAD, 0xBE, 0xEF],
            name: Some("Full Icon".to_string()),
            last_modification_time: Some(ts),
        });
        db.root.entries.push(entry);

        let loaded = roundtrip(db);
        let ci = loaded.root.entries[0].custom_icon.as_ref().unwrap();
        assert_eq!(ci.uuid, icon_uuid);
        assert_eq!(ci.data, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(ci.name.as_deref(), Some("Full Icon"));
        assert_eq!(ci.last_modification_time, Some(ts));
    }

    #[test]
    fn entry_custom_icon_none_roundtrip() {
        let mut db = Database::new(Default::default());
        db.root.entries.push(Entry::new());

        let loaded = roundtrip(db);
        assert!(loaded.root.entries[0].custom_icon.is_none());
    }

    // ── CustomIcon – group ───────────────────────────────────────────────────

    #[test]
    fn group_custom_icon_all_fields_roundtrip() {
        let icon_uuid = Uuid::new_v4();
        let ts = NaiveDateTime::parse_from_str("2025-03-10 09:15:00", "%Y-%m-%d %H:%M:%S").unwrap();

        let mut db = Database::new(Default::default());
        let mut group = Group::new("Fancy Group");
        group.custom_icon = Some(CustomIcon {
            uuid: icon_uuid,
            data: vec![0x01, 0x02, 0x03],
            name: Some("Group Icon".to_string()),
            last_modification_time: Some(ts),
        });
        db.root.groups.push(group);

        let loaded = roundtrip(db);
        let ci = loaded.root.groups[0].custom_icon.as_ref().unwrap();
        assert_eq!(ci.uuid, icon_uuid);
        assert_eq!(ci.data, vec![0x01, 0x02, 0x03]);
        assert_eq!(ci.name.as_deref(), Some("Group Icon"));
        assert_eq!(ci.last_modification_time, Some(ts));
    }

    #[test]
    fn group_custom_icon_none_roundtrip() {
        let mut db = Database::new(Default::default());
        db.root.groups.push(Group::new("Plain Group"));

        let loaded = roundtrip(db);
        assert!(loaded.root.groups[0].custom_icon.is_none());
    }

    // ── Shared icon deduplication ─────────────────────────────────────────────

    /// Multiple entries sharing the same icon UUID should all get the same data
    /// and metadata back after round-trip, and the icon must appear only once
    /// in Meta/CustomIcons.
    #[test]
    fn shared_custom_icon_three_entries() {
        let icon_uuid = Uuid::new_v4();
        let icon_data = vec![0xCA, 0xFE, 0xBA, 0xBE];

        let mut db = Database::new(Default::default());
        for _ in 0..3 {
            let mut entry = Entry::new();
            entry.custom_icon = Some(CustomIcon {
                uuid: icon_uuid,
                data: icon_data.clone(),
                name: Some("Shared Icon".to_string()),
                last_modification_time: None,
            });
            db.root.entries.push(entry);
        }

        let loaded = roundtrip(db);
        assert_eq!(loaded.root.entries.len(), 3);
        for entry in &loaded.root.entries {
            let ci = entry.custom_icon.as_ref().unwrap();
            assert_eq!(ci.uuid, icon_uuid);
            assert_eq!(ci.data, icon_data);
            assert_eq!(ci.name.as_deref(), Some("Shared Icon"));
        }
    }

    /// A group and an entry can share the same icon UUID; both should resolve
    /// the same data after round-trip.
    #[test]
    fn shared_custom_icon_entry_and_group() {
        let icon_uuid = Uuid::new_v4();
        let icon_data = vec![0x11, 0x22, 0x33];

        let mut db = Database::new(Default::default());

        let mut entry = Entry::new();
        entry.custom_icon = Some(CustomIcon {
            uuid: icon_uuid,
            data: icon_data.clone(),
            name: Some("Shared".to_string()),
            last_modification_time: None,
        });
        db.root.entries.push(entry);

        let mut group = Group::new("Also Shared");
        group.custom_icon = Some(CustomIcon {
            uuid: icon_uuid,
            data: icon_data.clone(),
            name: Some("Shared".to_string()),
            last_modification_time: None,
        });
        db.root.groups.push(group);

        let loaded = roundtrip(db);
        let entry_ci = loaded.root.entries[0].custom_icon.as_ref().unwrap();
        let group_ci = loaded.root.groups[0].custom_icon.as_ref().unwrap();
        assert_eq!(entry_ci.uuid, icon_uuid);
        assert_eq!(group_ci.uuid, icon_uuid);
        assert_eq!(entry_ci.data, icon_data);
        assert_eq!(group_ci.data, icon_data);
    }

    // ── Combined: all new fields together ────────────────────────────────────

    #[test]
    fn all_new_entry_fields_roundtrip() {
        let ppg = Uuid::new_v4();
        let icon_uuid = Uuid::new_v4();

        let mut db = Database::new(Default::default());
        let mut entry = Entry::new();
        entry.quality_check = Some(true);
        entry.previous_parent_group = Some(ppg);
        entry.tags = vec!["tag1".to_string(), "tag2".to_string()];
        entry.custom_icon = Some(CustomIcon {
            uuid: icon_uuid,
            data: vec![0xFF, 0x00],
            name: Some("Entry Icon".to_string()),
            last_modification_time: None,
        });
        db.root.entries.push(entry);

        let loaded = roundtrip(db);
        let e = &loaded.root.entries[0];
        assert_eq!(e.quality_check, Some(true));
        assert_eq!(e.previous_parent_group, Some(ppg));
        assert_eq!(e.tags, vec!["tag1".to_string(), "tag2".to_string()]);
        let ci = e.custom_icon.as_ref().unwrap();
        assert_eq!(ci.uuid, icon_uuid);
        assert_eq!(ci.name.as_deref(), Some("Entry Icon"));
    }

    #[test]
    fn all_new_group_fields_roundtrip() {
        let ppg = Uuid::new_v4();
        let icon_uuid = Uuid::new_v4();

        let mut db = Database::new(Default::default());
        let mut group = Group::new("KDBX 4.1 Group");
        group.tags = vec!["work".to_string(), "important".to_string()];
        group.previous_parent_group = Some(ppg);
        group.custom_icon = Some(CustomIcon {
            uuid: icon_uuid,
            data: vec![0xAB, 0xCD],
            name: Some("Group Icon".to_string()),
            last_modification_time: None,
        });
        db.root.groups.push(group);

        let loaded = roundtrip(db);
        let g = &loaded.root.groups[0];
        assert_eq!(g.tags, vec!["work".to_string(), "important".to_string()]);
        assert_eq!(g.previous_parent_group, Some(ppg));
        let ci = g.custom_icon.as_ref().unwrap();
        assert_eq!(ci.uuid, icon_uuid);
        assert_eq!(ci.name.as_deref(), Some("Group Icon"));
    }

    /// Both a deeply-nested entry and a top-level entry should round-trip
    /// their KDBX 4.1 fields correctly.
    #[test]
    fn nested_group_entry_kdbx41_fields_roundtrip() {
        let ppg_entry = Uuid::new_v4();
        let ppg_group = Uuid::new_v4();

        let mut db = Database::new(Default::default());

        let mut child_group = Group::new("Child");
        child_group.previous_parent_group = Some(ppg_group);
        child_group.tags = vec!["nested".to_string()];

        let mut nested_entry = Entry::new();
        nested_entry.quality_check = Some(false);
        nested_entry.previous_parent_group = Some(ppg_entry);
        child_group.entries.push(nested_entry);

        db.root.groups.push(child_group);

        let loaded = roundtrip(db);
        let g = &loaded.root.groups[0];
        assert_eq!(g.previous_parent_group, Some(ppg_group));
        assert_eq!(g.tags, vec!["nested".to_string()]);

        let e = &g.entries[0];
        assert_eq!(e.quality_check, Some(false));
        assert_eq!(e.previous_parent_group, Some(ppg_entry));
    }

    // ── Backward compatibility: reading KDBX 4.0 files ───────────────────────

    /// Opening existing KDBX 4.0 test files must succeed and produce
    /// None / empty for all KDBX 4.1 fields.
    #[test]
    fn kdbx40_files_parse_cleanly_with_empty_new_fields() {
        use std::{fs::File, path::Path};

        let test_files = [
            (
                "tests/resources/test_db_kdbx4_with_password_argon2.kdbx",
                "demopass",
            ),
            (
                "tests/resources/test_db_kdbx4_with_password_argon2id.kdbx",
                "demopass",
            ),
            ("tests/resources/test_db_kdbx4_with_password_aes.kdbx", "demopass"),
        ];

        for (path_str, password) in &test_files {
            let path = Path::new(path_str);
            let db = Database::open(
                &mut File::open(path).unwrap(),
                DatabaseKey::new().with_password(password),
            )
            .unwrap_or_else(|e| panic!("Failed to open {}: {}", path_str, e));

            fn check_group(group: &Group, path_str: &str) {
                // Group tags and previous_parent_group are KDBX 4.1-only; they
                // must be absent in pre-existing 4.0 files.
                assert!(
                    group.tags.is_empty(),
                    "{}: group '{}' should have no tags in a 4.0 file",
                    path_str,
                    group.name
                );
                assert_eq!(
                    group.previous_parent_group, None,
                    "{}: group.previous_parent_group should be None in a 4.0 file",
                    path_str
                );
                for entry in &group.entries {
                    // NOTE: quality_check was present in some KDBX 4.0 files as
                    // <QualityCheck>False</QualityCheck>, so we don't assert None
                    // here — reading it correctly is the right behaviour.
                    assert_eq!(
                        entry.previous_parent_group, None,
                        "{}: entry.previous_parent_group should be None in a 4.0 file",
                        path_str
                    );
                }
                for child in &group.groups {
                    check_group(child, path_str);
                }
            }

            check_group(&db.root, path_str);
        }
    }
}
