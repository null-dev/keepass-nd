/// KDBX 4 / 4.1 roundtrip tests for spec areas not covered by other test files.
///
/// Each test follows the same pattern:
///   1. Build a database with a specific field set.
///   2. Save → reload (full encrypt/decrypt cycle).
///   3. Assert the field survived unchanged.
///
/// Areas covered:
///   - Binary attachments (KDBX4 inner-header feature)
///   - Protected string fields (inner random-stream encryption)
///   - Entry history
///   - DeletedObjects section
///   - Entry presentation fields (colors, override_url, icon_id)
///   - Group fields (notes, icon_id, enable_autotype, enable_searching,
///     default_autotype_sequence, last_top_visible_entry)
///   - AutoType (sequences, window associations, obfuscation flag)
///   - Times fields (location_changed, usage_count)
///   - CustomData item last_modification_time (entry, group, meta)
///   - Meta fields (database_name, description, color, memory_protection)
///   - Configuration variations (no compression, Salsa20 inner cipher)
#[cfg(feature = "save_kdbx4")]
mod kdbx4_roundtrip_tests {
    use chrono::NaiveDateTime;
    use keepass::{
        config::{CompressionConfig, DatabaseConfig, InnerCipherConfig},
        db::{
            fields, Attachment, AutoType, AutoTypeAssociation, Color, CustomDataItem,
            CustomDataValue, Database, Entry, Group, MemoryProtection, Value,
        },
        DatabaseKey,
    };
    use uuid::Uuid;

    const PASSWORD: &str = "kdbx4-roundtrip-test";

    fn roundtrip(db: Database) -> Database {
        let key = DatabaseKey::new().with_password(PASSWORD);
        let mut buf = Vec::new();
        db.save(&mut buf, key.clone()).expect("save failed");
        Database::open(&mut buf.as_slice(), key).expect("open failed")
    }

    // ── Binary attachments (KDBX4 inner-header feature) ──────────────────────

    /// An entry with a single binary attachment must survive a full roundtrip.
    ///
    /// In KDBX4 attachments live in the encrypted inner header rather than
    /// being Base64-encoded inline in the XML, making this a key architectural
    /// difference from KDBX3.
    #[test]
    fn entry_attachment_roundtrip() {
        let mut db = Database::new(Default::default());
        let mut entry = Entry::new();
        entry.attachments.insert(
            "hello.txt".to_string(),
            Attachment {
                data: Value::unprotected(b"hello, world!".to_vec()),
            },
        );
        db.root.entries.push(entry);

        let loaded = roundtrip(db);
        let att = loaded.root.entries[0]
            .attachments
            .get("hello.txt")
            .expect("attachment missing after roundtrip");
        assert_eq!(att.data.get(), b"hello, world!");
    }

    /// Multiple differently-named attachments on one entry must all survive.
    #[test]
    fn entry_multiple_attachments_roundtrip() {
        let mut db = Database::new(Default::default());
        let mut entry = Entry::new();
        entry.attachments.insert(
            "file1.bin".to_string(),
            Attachment {
                data: Value::unprotected(vec![0x01, 0x02, 0x03]),
            },
        );
        entry.attachments.insert(
            "file2.bin".to_string(),
            Attachment {
                data: Value::unprotected(vec![0xAA, 0xBB, 0xCC, 0xDD]),
            },
        );
        db.root.entries.push(entry);

        let loaded = roundtrip(db);
        let e = &loaded.root.entries[0];
        assert_eq!(e.attachments.len(), 2);
        assert_eq!(
            e.attachments.get("file1.bin").unwrap().data.get(),
            &[0x01, 0x02, 0x03]
        );
        assert_eq!(
            e.attachments.get("file2.bin").unwrap().data.get(),
            &[0xAA, 0xBB, 0xCC, 0xDD]
        );
    }

    // ── Protected string fields (inner random-stream encryption) ─────────────

    /// A protected password field must have the correct value AND remain
    /// protected (i.e. `Value::Protected`) after save/load.
    #[test]
    fn protected_password_survives_roundtrip() {
        let mut db = Database::new(Default::default());
        let mut entry = Entry::new();
        entry.set_unprotected(fields::TITLE, "Login");
        entry.set_protected(fields::PASSWORD, "s3cr3t-passw0rd");
        db.root.entries.push(entry);

        let loaded = roundtrip(db);
        let e = &loaded.root.entries[0];

        assert_eq!(e.get_password(), Some("s3cr3t-passw0rd"), "password value wrong");

        let pass_val = e.fields.get(fields::PASSWORD).unwrap();
        assert!(
            pass_val.is_protected(),
            "password field must stay Protected after roundtrip"
        );
    }

    /// Unprotected fields must stay unprotected; protected fields must stay
    /// protected even when both kinds coexist in the same entry.
    #[test]
    fn mixed_protected_unprotected_fields_roundtrip() {
        let mut db = Database::new(Default::default());
        let mut entry = Entry::new();
        entry.set_unprotected(fields::TITLE, "Mixed Entry");
        entry.set_unprotected(fields::USERNAME, "alice");
        entry.set_protected(fields::PASSWORD, "hunter2");
        entry.set_unprotected(fields::URL, "https://example.com");
        entry.set_protected("SecretNote", "top-secret notes");
        db.root.entries.push(entry);

        let loaded = roundtrip(db);
        let e = &loaded.root.entries[0];

        assert_eq!(e.get_title(), Some("Mixed Entry"));
        assert_eq!(e.get_username(), Some("alice"));
        assert_eq!(e.get_password(), Some("hunter2"));
        assert_eq!(e.get_url(), Some("https://example.com"));
        assert_eq!(e.get("SecretNote"), Some("top-secret notes"));

        assert!(!e.fields[fields::TITLE].is_protected());
        assert!(!e.fields[fields::USERNAME].is_protected());
        assert!(e.fields[fields::PASSWORD].is_protected());
        assert!(!e.fields[fields::URL].is_protected());
        assert!(e.fields["SecretNote"].is_protected());
    }

    // ── Entry history ─────────────────────────────────────────────────────────

    /// Previous versions of an entry (its history) must survive the roundtrip.
    #[test]
    fn entry_history_roundtrip() {
        let mut db = Database::new(Default::default());
        let mut entry = Entry::new();

        // Save the "v1" state into history, then advance to "v2".
        entry.set_unprotected(fields::TITLE, "v1");
        entry.update_history(); // history now contains [v1]
        entry.set_unprotected(fields::TITLE, "v2");
        db.root.entries.push(entry);

        let loaded = roundtrip(db);
        let e = &loaded.root.entries[0];

        assert_eq!(e.get_title(), Some("v2"), "current title should be v2");

        let history = e.history.as_ref().expect("entry should have history");
        let hist_entries = history.get_entries();
        assert!(!hist_entries.is_empty(), "history should contain at least one entry");
        assert_eq!(
            hist_entries[0].get_title(),
            Some("v1"),
            "most-recent history entry should be v1"
        );
    }

    /// An entry that has had history with two snapshots must have both survive.
    #[test]
    fn entry_history_multiple_snapshots_roundtrip() {
        let mut db = Database::new(Default::default());
        let mut entry = Entry::new();

        entry.set_unprotected(fields::TITLE, "v1");
        entry.update_history(); // history: [v1]
        entry.set_unprotected(fields::TITLE, "v2");
        entry.update_history(); // history: [v2, v1]
        entry.set_unprotected(fields::TITLE, "v3");
        db.root.entries.push(entry);

        let loaded = roundtrip(db);
        let e = &loaded.root.entries[0];
        assert_eq!(e.get_title(), Some("v3"));

        let hist = e.history.as_ref().unwrap().get_entries();
        assert_eq!(hist.len(), 2, "should have 2 history snapshots");
        // Snapshots are stored newest-first
        assert_eq!(hist[0].get_title(), Some("v2"));
        assert_eq!(hist[1].get_title(), Some("v1"));
    }

    // ── DeletedObjects ────────────────────────────────────────────────────────

    /// UUIDs and their deletion timestamps in `db.deleted_objects` must
    /// survive the KDBX4 save/load cycle.
    #[test]
    fn deleted_objects_with_timestamp_roundtrip() {
        let uuid = Uuid::new_v4();
        let ts =
            NaiveDateTime::parse_from_str("2024-05-01 10:00:00", "%Y-%m-%d %H:%M:%S").unwrap();

        let mut db = Database::new(Default::default());
        db.deleted_objects.insert(uuid, Some(ts));

        let loaded = roundtrip(db);
        assert_eq!(
            loaded.deleted_objects.get(&uuid),
            Some(&Some(ts)),
            "deleted object with timestamp must survive roundtrip"
        );
    }

    /// A deleted-object entry with a `None` deletion time must also survive.
    #[test]
    fn deleted_objects_with_none_time_roundtrip() {
        let uuid = Uuid::new_v4();

        let mut db = Database::new(Default::default());
        db.deleted_objects.insert(uuid, None);

        let loaded = roundtrip(db);
        assert_eq!(
            loaded.deleted_objects.get(&uuid),
            Some(&None),
            "deleted object with None time must survive roundtrip"
        );
    }

    /// Multiple deleted objects must all survive.
    #[test]
    fn deleted_objects_multiple_roundtrip() {
        let uuid1 = Uuid::new_v4();
        let uuid2 = Uuid::new_v4();
        let ts =
            NaiveDateTime::parse_from_str("2024-06-15 08:30:00", "%Y-%m-%d %H:%M:%S").unwrap();

        let mut db = Database::new(Default::default());
        db.deleted_objects.insert(uuid1, Some(ts));
        db.deleted_objects.insert(uuid2, None);

        let loaded = roundtrip(db);
        assert_eq!(loaded.deleted_objects.len(), 2);
        assert_eq!(loaded.deleted_objects[&uuid1], Some(ts));
        assert_eq!(loaded.deleted_objects[&uuid2], None);
    }

    // ── Entry presentation fields ─────────────────────────────────────────────

    #[test]
    fn entry_foreground_color_roundtrip() {
        let mut db = Database::new(Default::default());
        let mut entry = Entry::new();
        entry.foreground_color = Some(Color { r: 255, g: 0, b: 0 });
        db.root.entries.push(entry);

        let loaded = roundtrip(db);
        assert_eq!(
            loaded.root.entries[0].foreground_color,
            Some(Color { r: 255, g: 0, b: 0 })
        );
    }

    #[test]
    fn entry_background_color_roundtrip() {
        let mut db = Database::new(Default::default());
        let mut entry = Entry::new();
        entry.background_color = Some(Color { r: 0, g: 128, b: 255 });
        db.root.entries.push(entry);

        let loaded = roundtrip(db);
        assert_eq!(
            loaded.root.entries[0].background_color,
            Some(Color { r: 0, g: 128, b: 255 })
        );
    }

    /// Both foreground and background colors must survive independently.
    #[test]
    fn entry_both_colors_roundtrip() {
        let mut db = Database::new(Default::default());
        let mut entry = Entry::new();
        entry.foreground_color = Some(Color { r: 255, g: 255, b: 0 });
        entry.background_color = Some(Color { r: 0, g: 0, b: 128 });
        db.root.entries.push(entry);

        let loaded = roundtrip(db);
        let e = &loaded.root.entries[0];
        assert_eq!(e.foreground_color, Some(Color { r: 255, g: 255, b: 0 }));
        assert_eq!(e.background_color, Some(Color { r: 0, g: 0, b: 128 }));
    }

    /// `None` colors must not appear in the XML and must stay `None`.
    #[test]
    fn entry_no_colors_roundtrip() {
        let mut db = Database::new(Default::default());
        db.root.entries.push(Entry::new());

        let loaded = roundtrip(db);
        assert!(loaded.root.entries[0].foreground_color.is_none());
        assert!(loaded.root.entries[0].background_color.is_none());
    }

    #[test]
    fn entry_override_url_roundtrip() {
        let mut db = Database::new(Default::default());
        let mut entry = Entry::new();
        entry.override_url = Some("cmd://custom-launcher {URL}".to_string());
        db.root.entries.push(entry);

        let loaded = roundtrip(db);
        assert_eq!(
            loaded.root.entries[0].override_url.as_deref(),
            Some("cmd://custom-launcher {URL}")
        );
    }

    #[test]
    fn entry_override_url_none_roundtrip() {
        let mut db = Database::new(Default::default());
        db.root.entries.push(Entry::new());

        let loaded = roundtrip(db);
        assert!(loaded.root.entries[0].override_url.is_none());
    }

    #[test]
    fn entry_icon_id_roundtrip() {
        let mut db = Database::new(Default::default());
        let mut entry = Entry::new();
        entry.icon_id = Some(42);
        db.root.entries.push(entry);

        let loaded = roundtrip(db);
        assert_eq!(loaded.root.entries[0].icon_id, Some(42));
    }

    #[test]
    fn entry_icon_id_zero_roundtrip() {
        // Icon 0 is the default; make sure it round-trips as Some(0) when set.
        let mut db = Database::new(Default::default());
        let mut entry = Entry::new();
        entry.icon_id = Some(0);
        db.root.entries.push(entry);

        let loaded = roundtrip(db);
        assert_eq!(loaded.root.entries[0].icon_id, Some(0));
    }

    // ── Group fields ──────────────────────────────────────────────────────────

    #[test]
    fn group_notes_roundtrip() {
        let mut db = Database::new(Default::default());
        let mut group = Group::new("Annotated");
        group.notes = Some("These are group notes.".to_string());
        db.root.groups.push(group);

        let loaded = roundtrip(db);
        assert_eq!(
            loaded.root.groups[0].notes.as_deref(),
            Some("These are group notes.")
        );
    }

    #[test]
    fn group_notes_none_roundtrip() {
        let mut db = Database::new(Default::default());
        db.root.groups.push(Group::new("Plain"));

        let loaded = roundtrip(db);
        assert!(loaded.root.groups[0].notes.is_none());
    }

    #[test]
    fn group_icon_id_roundtrip() {
        let mut db = Database::new(Default::default());
        let mut group = Group::new("Iconed");
        group.icon_id = Some(7);
        db.root.groups.push(group);

        let loaded = roundtrip(db);
        assert_eq!(loaded.root.groups[0].icon_id, Some(7));
    }

    #[test]
    fn group_enable_autotype_false_roundtrip() {
        let mut db = Database::new(Default::default());
        let mut group = Group::new("No AutoType");
        group.enable_autotype = Some(false);
        db.root.groups.push(group);

        let loaded = roundtrip(db);
        assert_eq!(loaded.root.groups[0].enable_autotype, Some(false));
    }

    #[test]
    fn group_enable_autotype_true_roundtrip() {
        let mut db = Database::new(Default::default());
        let mut group = Group::new("With AutoType");
        group.enable_autotype = Some(true);
        db.root.groups.push(group);

        let loaded = roundtrip(db);
        assert_eq!(loaded.root.groups[0].enable_autotype, Some(true));
    }

    #[test]
    fn group_enable_searching_roundtrip() {
        let mut db = Database::new(Default::default());
        let mut group = Group::new("Searchable");
        group.enable_searching = Some(true);
        db.root.groups.push(group);

        let loaded = roundtrip(db);
        assert_eq!(loaded.root.groups[0].enable_searching, Some(true));
    }

    #[test]
    fn group_default_autotype_sequence_roundtrip() {
        let mut db = Database::new(Default::default());
        let mut group = Group::new("Custom AutoType");
        group.default_autotype_sequence =
            Some("{USERNAME}{TAB}{PASSWORD}{ENTER}".to_string());
        db.root.groups.push(group);

        let loaded = roundtrip(db);
        assert_eq!(
            loaded.root.groups[0]
                .default_autotype_sequence
                .as_deref(),
            Some("{USERNAME}{TAB}{PASSWORD}{ENTER}")
        );
    }

    #[test]
    fn group_last_top_visible_entry_roundtrip() {
        let uuid = Uuid::new_v4();

        let mut db = Database::new(Default::default());
        let mut group = Group::new("Scrolled");
        group.last_top_visible_entry = Some(uuid);
        db.root.groups.push(group);

        let loaded = roundtrip(db);
        assert_eq!(loaded.root.groups[0].last_top_visible_entry, Some(uuid));
    }

    // ── AutoType ──────────────────────────────────────────────────────────────

    /// A fully populated AutoType struct (enabled, default sequence, window
    /// associations, obfuscation flag) must survive.
    #[test]
    fn entry_autotype_roundtrip() {
        let mut db = Database::new(Default::default());
        let mut entry = Entry::new();
        entry.autotype = Some(AutoType {
            enabled: true,
            default_sequence: Some("{USERNAME}{TAB}{PASSWORD}{ENTER}".to_string()),
            data_transfer_obfuscation: Some(true),
            associations: vec![
                AutoTypeAssociation {
                    window: "Example App*".to_string(),
                    sequence: "{USERNAME}{TAB}{PASSWORD}{ENTER}".to_string(),
                },
                AutoTypeAssociation {
                    window: "Login – Firefox".to_string(),
                    sequence: "{PASSWORD}{ENTER}".to_string(),
                },
            ],
        });
        db.root.entries.push(entry);

        let loaded = roundtrip(db);
        let at = loaded.root.entries[0]
            .autotype
            .as_ref()
            .expect("autotype missing");
        assert!(at.enabled);
        assert_eq!(
            at.default_sequence.as_deref(),
            Some("{USERNAME}{TAB}{PASSWORD}{ENTER}")
        );
        assert_eq!(at.data_transfer_obfuscation, Some(true));
        assert_eq!(at.associations.len(), 2);
        assert_eq!(at.associations[0].window, "Example App*");
        assert_eq!(
            at.associations[0].sequence,
            "{USERNAME}{TAB}{PASSWORD}{ENTER}"
        );
        assert_eq!(at.associations[1].window, "Login – Firefox");
        assert_eq!(at.associations[1].sequence, "{PASSWORD}{ENTER}");
    }

    #[test]
    fn entry_autotype_disabled_roundtrip() {
        let mut db = Database::new(Default::default());
        let mut entry = Entry::new();
        entry.autotype = Some(AutoType {
            enabled: false,
            default_sequence: None,
            data_transfer_obfuscation: None,
            associations: vec![],
        });
        db.root.entries.push(entry);

        let loaded = roundtrip(db);
        let at = loaded.root.entries[0].autotype.as_ref().unwrap();
        assert!(!at.enabled);
        assert!(at.default_sequence.is_none());
        assert!(at.associations.is_empty());
    }

    #[test]
    fn entry_autotype_none_roundtrip() {
        let mut db = Database::new(Default::default());
        db.root.entries.push(Entry::new());

        let loaded = roundtrip(db);
        assert!(loaded.root.entries[0].autotype.is_none());
    }

    // ── Times fields ──────────────────────────────────────────────────────────

    /// `Times::location_changed` records when an entry was last moved between
    /// groups — it must survive the roundtrip.
    #[test]
    fn entry_times_location_changed_roundtrip() {
        let ts =
            NaiveDateTime::parse_from_str("2024-03-15 09:30:00", "%Y-%m-%d %H:%M:%S").unwrap();

        let mut db = Database::new(Default::default());
        let mut entry = Entry::new();
        entry.times.location_changed = Some(ts);
        db.root.entries.push(entry);

        let loaded = roundtrip(db);
        assert_eq!(loaded.root.entries[0].times.location_changed, Some(ts));
    }

    #[test]
    fn group_times_location_changed_roundtrip() {
        let ts =
            NaiveDateTime::parse_from_str("2024-07-04 12:00:00", "%Y-%m-%d %H:%M:%S").unwrap();

        let mut db = Database::new(Default::default());
        let mut group = Group::new("Relocated");
        group.times.location_changed = Some(ts);
        db.root.groups.push(group);

        let loaded = roundtrip(db);
        assert_eq!(loaded.root.groups[0].times.location_changed, Some(ts));
    }

    /// `Times::usage_count` tracks how many times an entry has been accessed.
    #[test]
    fn entry_times_usage_count_roundtrip() {
        let mut db = Database::new(Default::default());
        let mut entry = Entry::new();
        entry.times.usage_count = Some(17);
        db.root.entries.push(entry);

        let loaded = roundtrip(db);
        assert_eq!(loaded.root.entries[0].times.usage_count, Some(17));
    }

    #[test]
    fn entry_times_expiry_roundtrip() {
        let expiry =
            NaiveDateTime::parse_from_str("2030-12-31 23:59:59", "%Y-%m-%d %H:%M:%S").unwrap();

        let mut db = Database::new(Default::default());
        let mut entry = Entry::new();
        entry.times.expires = Some(true);
        entry.times.expiry = Some(expiry);
        db.root.entries.push(entry);

        let loaded = roundtrip(db);
        let t = &loaded.root.entries[0].times;
        assert_eq!(t.expires, Some(true));
        assert_eq!(t.expiry, Some(expiry));
    }

    // ── CustomDataItem::last_modification_time ────────────────────────────────

    /// KDBX 4 supports timestamps on individual custom-data items for entries.
    #[test]
    fn entry_custom_data_with_timestamp_roundtrip() {
        let ts =
            NaiveDateTime::parse_from_str("2024-06-15 14:00:00", "%Y-%m-%d %H:%M:%S").unwrap();

        let mut db = Database::new(Default::default());
        let mut entry = Entry::new();
        entry.custom_data.insert(
            "plugin-key".to_string(),
            CustomDataItem {
                value: Some(CustomDataValue::String("plugin-value".to_string())),
                last_modification_time: Some(ts),
            },
        );
        db.root.entries.push(entry);

        let loaded = roundtrip(db);
        let item = loaded.root.entries[0]
            .custom_data
            .get("plugin-key")
            .expect("custom data item missing");

        match item.value.as_ref().unwrap() {
            CustomDataValue::String(s) => assert_eq!(s, "plugin-value"),
            _ => panic!("expected string value"),
        }
        assert_eq!(
            item.last_modification_time,
            Some(ts),
            "custom data last_modification_time must survive roundtrip"
        );
    }

    /// Entry custom data without a timestamp (None) must also survive.
    #[test]
    fn entry_custom_data_without_timestamp_roundtrip() {
        let mut db = Database::new(Default::default());
        let mut entry = Entry::new();
        entry.custom_data.insert(
            "no-ts-key".to_string(),
            CustomDataItem {
                value: Some(CustomDataValue::String("no-ts-value".to_string())),
                last_modification_time: None,
            },
        );
        db.root.entries.push(entry);

        let loaded = roundtrip(db);
        let item = loaded.root.entries[0].custom_data.get("no-ts-key").unwrap();
        assert!(item.last_modification_time.is_none());
    }

    /// Group custom data with timestamps must survive.
    #[test]
    fn group_custom_data_with_timestamp_roundtrip() {
        let ts =
            NaiveDateTime::parse_from_str("2024-08-20 08:00:00", "%Y-%m-%d %H:%M:%S").unwrap();

        let mut db = Database::new(Default::default());
        let mut group = Group::new("Annotated Group");
        group.custom_data.insert(
            "group-plugin-key".to_string(),
            CustomDataItem {
                value: Some(CustomDataValue::String("group-plugin-value".to_string())),
                last_modification_time: Some(ts),
            },
        );
        db.root.groups.push(group);

        let loaded = roundtrip(db);
        let item = loaded.root.groups[0]
            .custom_data
            .get("group-plugin-key")
            .expect("group custom data item missing");
        assert_eq!(item.last_modification_time, Some(ts));
    }

    /// Meta-level custom data with timestamps must survive.
    #[test]
    fn meta_custom_data_with_timestamp_roundtrip() {
        let ts =
            NaiveDateTime::parse_from_str("2024-09-01 00:00:00", "%Y-%m-%d %H:%M:%S").unwrap();

        let mut db = Database::new(Default::default());
        db.meta.custom_data.insert(
            "meta-plugin-key".to_string(),
            CustomDataItem {
                value: Some(CustomDataValue::String("meta-plugin-value".to_string())),
                last_modification_time: Some(ts),
            },
        );

        let loaded = roundtrip(db);
        let item = loaded
            .meta
            .custom_data
            .get("meta-plugin-key")
            .expect("meta custom data item missing");
        assert_eq!(item.last_modification_time, Some(ts));
        match item.value.as_ref().unwrap() {
            CustomDataValue::String(s) => assert_eq!(s, "meta-plugin-value"),
            _ => panic!("expected string value"),
        }
    }

    // ── Meta fields ───────────────────────────────────────────────────────────

    #[test]
    fn meta_database_name_and_description_roundtrip() {
        let mut db = Database::new(Default::default());
        db.meta.database_name = Some("My Test Database".to_string());
        db.meta.database_description = Some("A description of the test DB.".to_string());

        let loaded = roundtrip(db);
        assert_eq!(
            loaded.meta.database_name.as_deref(),
            Some("My Test Database")
        );
        assert_eq!(
            loaded.meta.database_description.as_deref(),
            Some("A description of the test DB.")
        );
    }

    #[test]
    fn meta_default_username_roundtrip() {
        let mut db = Database::new(Default::default());
        db.meta.default_username = Some("alice".to_string());

        let loaded = roundtrip(db);
        assert_eq!(loaded.meta.default_username.as_deref(), Some("alice"));
    }

    #[test]
    fn meta_color_roundtrip() {
        let mut db = Database::new(Default::default());
        db.meta.color = Some(Color { r: 0, g: 128, b: 255 });

        let loaded = roundtrip(db);
        assert_eq!(loaded.meta.color, Some(Color { r: 0, g: 128, b: 255 }));
    }

    /// `MemoryProtection` flags in Meta control which standard fields are
    /// protected by the inner random stream.
    #[test]
    fn meta_memory_protection_all_on_roundtrip() {
        let mut db = Database::new(Default::default());
        db.meta.memory_protection = Some(MemoryProtection {
            protect_title: true,
            protect_username: true,
            protect_password: true,
            protect_url: true,
            protect_notes: true,
        });

        let loaded = roundtrip(db);
        let mp = loaded.meta.memory_protection.unwrap();
        assert!(mp.protect_title);
        assert!(mp.protect_username);
        assert!(mp.protect_password);
        assert!(mp.protect_url);
        assert!(mp.protect_notes);
    }

    #[test]
    fn meta_memory_protection_selective_roundtrip() {
        let mut db = Database::new(Default::default());
        db.meta.memory_protection = Some(MemoryProtection {
            protect_title: false,
            protect_username: false,
            protect_password: true,
            protect_url: false,
            protect_notes: false,
        });

        let loaded = roundtrip(db);
        let mp = loaded.meta.memory_protection.unwrap();
        assert!(!mp.protect_title);
        assert!(!mp.protect_username);
        assert!(mp.protect_password);
        assert!(!mp.protect_url);
        assert!(!mp.protect_notes);
    }

    #[test]
    fn meta_maintenance_history_days_roundtrip() {
        let mut db = Database::new(Default::default());
        db.meta.maintenance_history_days = Some(90);

        let loaded = roundtrip(db);
        assert_eq!(loaded.meta.maintenance_history_days, Some(90));
    }

    #[test]
    fn meta_history_limits_roundtrip() {
        let mut db = Database::new(Default::default());
        db.meta.history_max_items = Some(20);
        db.meta.history_max_size = Some(2 * 1024 * 1024); // 2 MiB

        let loaded = roundtrip(db);
        assert_eq!(loaded.meta.history_max_items, Some(20));
        assert_eq!(loaded.meta.history_max_size, Some(2 * 1024 * 1024));
    }

    // ── Configuration variations ──────────────────────────────────────────────

    /// Databases saved with no compression must still round-trip correctly.
    #[test]
    fn no_compression_roundtrip() {
        let config = DatabaseConfig {
            compression_config: CompressionConfig::None,
            ..Default::default()
        };
        let mut db = Database::new(config);
        let mut entry = Entry::new();
        entry.set_unprotected(fields::TITLE, "Uncompressed Entry");
        entry.set_protected(fields::PASSWORD, "pass123");
        db.root.entries.push(entry);

        let loaded = roundtrip(db);
        assert_eq!(
            loaded.root.entries[0].get_title(),
            Some("Uncompressed Entry")
        );
        assert_eq!(loaded.root.entries[0].get_password(), Some("pass123"));
    }

    /// Databases using the Salsa20 inner cipher for field protection must
    /// round-trip correctly (the default inner cipher is ChaCha20).
    #[test]
    fn salsa20_inner_cipher_roundtrip() {
        let config = DatabaseConfig {
            inner_cipher_config: InnerCipherConfig::Salsa20,
            ..Default::default()
        };
        let mut db = Database::new(config);
        let mut entry = Entry::new();
        entry.set_unprotected(fields::TITLE, "Salsa20 Entry");
        entry.set_protected(fields::PASSWORD, "salsa-secret");
        db.root.entries.push(entry);

        let loaded = roundtrip(db);
        assert_eq!(
            loaded.root.entries[0].get_title(),
            Some("Salsa20 Entry")
        );
        assert_eq!(
            loaded.root.entries[0].get_password(),
            Some("salsa-secret"),
            "password must be correct with Salsa20 inner cipher"
        );
        assert!(
            loaded.root.entries[0].fields[fields::PASSWORD].is_protected(),
            "password must remain Protected with Salsa20 inner cipher"
        );
    }

    /// Databases saved with no inner-stream encryption (Plain cipher) must
    /// round-trip correctly. Fields are not encrypted in transit.
    #[test]
    fn plain_inner_cipher_roundtrip() {
        let config = DatabaseConfig {
            inner_cipher_config: InnerCipherConfig::Plain,
            ..Default::default()
        };
        let mut db = Database::new(config);
        let mut entry = Entry::new();
        entry.set_unprotected(fields::TITLE, "Plain Cipher Entry");
        entry.set_unprotected(fields::PASSWORD, "not-secret-plain");
        db.root.entries.push(entry);

        let loaded = roundtrip(db);
        assert_eq!(
            loaded.root.entries[0].get_title(),
            Some("Plain Cipher Entry")
        );
        assert_eq!(
            loaded.root.entries[0].get_password(),
            Some("not-secret-plain")
        );
    }

    /// Databases with no compression and Salsa20 inner cipher together.
    #[test]
    fn no_compression_salsa20_combined_roundtrip() {
        let config = DatabaseConfig {
            compression_config: CompressionConfig::None,
            inner_cipher_config: InnerCipherConfig::Salsa20,
            ..Default::default()
        };
        let mut db = Database::new(config);
        let mut entry = Entry::new();
        entry.set_protected(fields::PASSWORD, "combined-config-pass");
        db.root.entries.push(entry);

        let loaded = roundtrip(db);
        assert_eq!(
            loaded.root.entries[0].get_password(),
            Some("combined-config-pass")
        );
    }
}
