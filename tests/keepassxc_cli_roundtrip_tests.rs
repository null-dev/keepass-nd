#[cfg(feature = "save_kdbx4")]
mod keepassxc_cli_roundtrip_tests {
    use std::{
        collections::BTreeMap,
        ffi::OsString,
        fs::{self, File},
        io::Write,
        path::Path,
        process::{Command, Stdio},
    };

    use keepass::{
        db::{CustomDataItem, CustomDataValue},
        Database, DatabaseKey,
    };
    use quick_xml::de::from_str;
    use serde::Deserialize;
    use tempfile::TempDir;

    const KEEPASSXC_CLI_ENV: &str = "KEEPASSXC_CLI_BIN";
    const TEST_PASSWORD: &str = "keepassxc-roundtrip-password";
    const ATTACHMENT_BYTES: &[u8] = b"keepassxc-cli-attachment";

    #[derive(Debug)]
    struct FixtureExpectations {
        show_paths: Vec<String>,
        attachments: Vec<AttachmentExpectation>,
    }

    #[derive(Debug)]
    struct AttachmentExpectation {
        entry_path: String,
        attachment_name: String,
        contents: Vec<u8>,
    }

    #[derive(Debug, PartialEq, Eq)]
    struct DatabaseSnapshot {
        meta: MetaSnapshot,
        root: GroupSnapshot,
    }

    #[derive(Debug, PartialEq, Eq)]
    struct DeletedObjectSnapshot {
        uuid: String,
        deletion_time: Option<String>,
    }

    #[derive(Debug, PartialEq, Eq)]
    struct MetaSnapshot {
        generator: Option<String>,
        database_name: Option<String>,
        database_name_changed: Option<String>,
        database_description: Option<String>,
        database_description_changed: Option<String>,
        default_username: Option<String>,
        default_username_changed: Option<String>,
        maintenance_history_days: Option<String>,
        color: Option<String>,
        master_key_changed: Option<String>,
        master_key_change_rec: Option<String>,
        master_key_change_force: Option<String>,
        memory_protection: Option<MemoryProtectionSnapshot>,
        recycle_bin_enabled: Option<String>,
        recycle_bin_uuid: Option<String>,
        recycle_bin_changed: Option<String>,
        entry_templates_group: Option<String>,
        entry_templates_group_changed: Option<String>,
        last_selected_group: Option<String>,
        last_top_visible_group: Option<String>,
        history_max_items: Option<String>,
        history_max_size: Option<String>,
        custom_data: BTreeMap<String, Option<String>>,
    }

    #[derive(Debug, PartialEq, Eq)]
    struct MemoryProtectionSnapshot {
        protect_title: Option<String>,
        protect_user_name: Option<String>,
        protect_password: Option<String>,
        protect_url: Option<String>,
        protect_notes: Option<String>,
    }

    #[derive(Debug, PartialEq, Eq)]
    struct GroupSnapshot {
        uuid: String,
        name: String,
        notes: Option<String>,
        icon_id: Option<String>,
        times: Option<TimesSnapshot>,
        is_expanded: Option<String>,
        default_auto_type_sequence: Option<String>,
        enable_auto_type: Option<String>,
        enable_searching: Option<String>,
        last_top_visible_entry: Option<String>,
        custom_data: BTreeMap<String, Option<String>>,
        tags: Option<String>,
        previous_parent_group: Option<String>,
        groups: Vec<GroupSnapshot>,
        entries: Vec<EntrySnapshot>,
    }

    #[derive(Debug, PartialEq, Eq)]
    struct EntrySnapshot {
        uuid: String,
        icon_id: Option<String>,
        foreground_color: Option<String>,
        background_color: Option<String>,
        override_url: Option<String>,
        tags: Option<String>,
        quality_check: Option<String>,
        previous_parent_group: Option<String>,
        times: Option<TimesSnapshot>,
        fields: BTreeMap<String, FieldSnapshot>,
        attachments: Vec<String>,
        auto_type: Option<AutoTypeSnapshot>,
        history: Vec<EntrySnapshot>,
        custom_data: BTreeMap<String, Option<String>>,
    }

    #[derive(Debug, PartialEq, Eq)]
    struct TimesSnapshot {
        last_modification_time: Option<String>,
        creation_time: Option<String>,
        last_access_time: Option<String>,
        expiry_time: Option<String>,
        expires: Option<String>,
        usage_count: Option<String>,
        location_changed: Option<String>,
    }

    #[derive(Debug, PartialEq, Eq)]
    struct FieldSnapshot {
        value: Option<String>,
        protect_in_memory: bool,
    }

    #[derive(Debug, PartialEq, Eq)]
    struct AutoTypeSnapshot {
        enabled: Option<String>,
        data_transfer_obfuscation: Option<String>,
        default_sequence: Option<String>,
        associations: Vec<AutoTypeAssociationSnapshot>,
    }

    #[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
    struct AutoTypeAssociationSnapshot {
        window: Option<String>,
        keystroke_sequence: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename = "KeePassFile")]
    struct ExportXml {
        #[serde(rename = "Meta")]
        meta: ExportMetaXml,
        #[serde(rename = "Root")]
        root: ExportRootXml,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct ExportMetaXml {
        #[serde(default)]
        generator: Option<String>,
        #[serde(default)]
        database_name: Option<String>,
        #[serde(default)]
        database_name_changed: Option<String>,
        #[serde(default)]
        database_description: Option<String>,
        #[serde(default)]
        database_description_changed: Option<String>,
        #[serde(default, rename = "DefaultUserName")]
        default_username: Option<String>,
        #[serde(default, rename = "DefaultUserNameChanged")]
        default_username_changed: Option<String>,
        #[serde(default)]
        maintenance_history_days: Option<String>,
        #[serde(default)]
        color: Option<String>,
        #[serde(default)]
        master_key_changed: Option<String>,
        #[serde(default)]
        master_key_change_rec: Option<String>,
        #[serde(default)]
        master_key_change_force: Option<String>,
        #[serde(default)]
        memory_protection: Option<ExportMemoryProtectionXml>,
        #[serde(default)]
        recycle_bin_enabled: Option<String>,
        #[serde(default, rename = "RecycleBinUUID")]
        recycle_bin_uuid: Option<String>,
        #[serde(default, rename = "RecycleBinChanged")]
        recycle_bin_changed: Option<String>,
        #[serde(default)]
        entry_templates_group: Option<String>,
        #[serde(default, rename = "EntryTemplatesGroupChanged")]
        entry_templates_group_changed: Option<String>,
        #[serde(default, rename = "LastSelectedGroup")]
        last_selected_group: Option<String>,
        #[serde(default, rename = "LastTopVisibleGroup")]
        last_top_visible_group: Option<String>,
        #[serde(default)]
        history_max_items: Option<String>,
        #[serde(default)]
        history_max_size: Option<String>,
        #[serde(default)]
        custom_data: Option<ExportCustomDataXml>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct ExportMemoryProtectionXml {
        #[serde(default)]
        protect_title: Option<String>,
        #[serde(default)]
        protect_user_name: Option<String>,
        #[serde(default)]
        protect_password: Option<String>,
        #[serde(default)]
        protect_url: Option<String>,
        #[serde(default)]
        protect_notes: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    struct ExportRootXml {
        #[serde(rename = "Group")]
        group: ExportGroupXml,
        #[serde(default, rename = "DeletedObjects")]
        deleted_objects: Option<ExportDeletedObjectsXml>,
    }

    #[derive(Debug, Deserialize)]
    struct ExportDeletedObjectsXml {
        #[serde(rename = "DeletedObject", default)]
        objects: Vec<ExportDeletedObjectXml>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct ExportDeletedObjectXml {
        #[serde(rename = "UUID")]
        uuid: String,
        #[serde(default)]
        deletion_time: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct ExportGroupXml {
        #[serde(rename = "UUID")]
        uuid: String,
        name: String,
        #[serde(default)]
        notes: Option<String>,
        #[serde(default, rename = "IconID")]
        icon_id: Option<String>,
        #[serde(default)]
        times: Option<ExportTimesXml>,
        #[serde(default)]
        is_expanded: Option<String>,
        #[serde(default)]
        default_auto_type_sequence: Option<String>,
        #[serde(default)]
        enable_auto_type: Option<String>,
        #[serde(default)]
        enable_searching: Option<String>,
        #[serde(default)]
        last_top_visible_entry: Option<String>,
        #[serde(default)]
        custom_data: Option<ExportCustomDataXml>,
        #[serde(default)]
        tags: Option<String>,
        #[serde(default, rename = "PreviousParentGroup")]
        previous_parent_group: Option<String>,
        #[serde(rename = "Group", default)]
        groups: Vec<ExportGroupXml>,
        #[serde(rename = "Entry", default)]
        entries: Vec<ExportEntryXml>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct ExportEntryXml {
        #[serde(rename = "UUID")]
        uuid: String,
        #[serde(default, rename = "IconID")]
        icon_id: Option<String>,
        #[serde(default)]
        foreground_color: Option<String>,
        #[serde(default)]
        background_color: Option<String>,
        #[serde(default, rename = "OverrideURL")]
        override_url: Option<String>,
        #[serde(default)]
        tags: Option<String>,
        #[serde(default)]
        quality_check: Option<String>,
        #[serde(default, rename = "PreviousParentGroup")]
        previous_parent_group: Option<String>,
        #[serde(default)]
        times: Option<ExportTimesXml>,
        #[serde(rename = "String", default)]
        string_fields: Vec<ExportStringFieldXml>,
        #[serde(rename = "Binary", default)]
        binary_fields: Vec<ExportBinaryFieldXml>,
        #[serde(default)]
        auto_type: Option<ExportAutoTypeXml>,
        #[serde(default)]
        history: Option<ExportHistoryXml>,
        #[serde(default)]
        custom_data: Option<ExportCustomDataXml>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct ExportTimesXml {
        #[serde(default)]
        last_modification_time: Option<String>,
        #[serde(default)]
        creation_time: Option<String>,
        #[serde(default)]
        last_access_time: Option<String>,
        #[serde(default)]
        expiry_time: Option<String>,
        #[serde(default)]
        expires: Option<String>,
        #[serde(default)]
        usage_count: Option<String>,
        #[serde(default)]
        location_changed: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct ExportStringFieldXml {
        key: String,
        value: ExportStringValueXml,
    }

    #[derive(Debug, Deserialize)]
    struct ExportStringValueXml {
        #[serde(rename = "@ProtectInMemory", default)]
        protect_in_memory: Option<String>,
        #[serde(rename = "$value", default)]
        value: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct ExportBinaryFieldXml {
        key: String,
        #[serde(rename = "Value")]
        _value: ExportBinaryValueXml,
    }

    #[derive(Debug, Deserialize)]
    struct ExportBinaryValueXml {
        #[serde(rename = "@Ref")]
        _value_ref: usize,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct ExportAutoTypeXml {
        #[serde(default)]
        enabled: Option<String>,
        #[serde(default)]
        data_transfer_obfuscation: Option<String>,
        #[serde(default)]
        default_sequence: Option<String>,
        #[serde(rename = "Association", default)]
        associations: Vec<ExportAutoTypeAssociationXml>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct ExportAutoTypeAssociationXml {
        #[serde(default)]
        window: Option<String>,
        #[serde(default)]
        keystroke_sequence: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    struct ExportHistoryXml {
        #[serde(rename = "Entry", default)]
        entries: Vec<ExportEntryXml>,
    }

    #[derive(Debug, Deserialize)]
    struct ExportCustomDataXml {
        #[serde(rename = "Item", default)]
        items: Vec<ExportCustomDataItemXml>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct ExportCustomDataItemXml {
        key: String,
        #[serde(default)]
        value: Option<String>,
    }

    #[test]
    fn keepassxc_cli_roundtrip_preserves_recycle_bin_password_database() {
        let Some(binary) = require_keepassxc_cli() else {
            return;
        };

        let tempdir = TempDir::new().expect("failed to create tempdir");
        let original = tempdir.path().join("recycle-bin-original.kdbx");
        let rewritten = tempdir.path().join("recycle-bin-rewritten.kdbx");

        let expectations = build_recycle_bin_fixture(&binary, &original);

        assert_roundtrip_matches_keepassxc_export(&binary, &original, &rewritten);
        assert_show_roundtrip_matches(&binary, &original, &rewritten, &expectations.show_paths);
        assert_attachment_exports_match(&binary, &rewritten, &expectations.attachments);
    }

    #[test]
    fn keepassxc_cli_roundtrip_preserves_basic_password_database() {
        let Some(binary) = require_keepassxc_cli() else {
            return;
        };

        let tempdir = TempDir::new().expect("failed to create tempdir");
        let original = tempdir.path().join("basic-original.kdbx");
        let rewritten = tempdir.path().join("basic-rewritten.kdbx");

        let expectations = build_basic_fixture(&binary, &original, tempdir.path());

        assert_roundtrip_matches_keepassxc_export(&binary, &original, &rewritten);
        assert_show_roundtrip_matches(&binary, &original, &rewritten, &expectations.show_paths);
        assert_attachment_exports_match(&binary, &rewritten, &expectations.attachments);
    }

    #[test]
    fn keepassxc_cli_roundtrip_preserves_complex_password_database() {
        let Some(binary) = require_keepassxc_cli() else {
            return;
        };

        let tempdir = TempDir::new().expect("failed to create tempdir");
        let original = tempdir.path().join("complex-original.kdbx");
        let rewritten = tempdir.path().join("complex-rewritten.kdbx");

        let expectations = build_complex_fixture(&binary, &original, tempdir.path());

        assert_roundtrip_matches_keepassxc_export(&binary, &original, &rewritten);
        assert_show_roundtrip_matches(&binary, &original, &rewritten, &expectations.show_paths);
        assert_attachment_exports_match(&binary, &rewritten, &expectations.attachments);
    }

    #[test]
    fn keepassxc_cli_roundtrip_preserves_deleted_objects() {
        let Some(binary) = require_keepassxc_cli() else {
            return;
        };

        let tempdir = TempDir::new().expect("failed to create tempdir");
        let original = tempdir.path().join("deleted-objects-original.kdbx");
        let rewritten = tempdir.path().join("deleted-objects-rewritten.kdbx");

        create_database(&binary, &original);
        add_entry(
            &binary,
            &original,
            "TrashMe",
            "delete-me",
            "https://example.invalid",
            "to-be-removed",
            "trashpass",
        );

        // KeePassXC first moves deleted entries into the recycle bin. Deleting
        // the recycled entry records it in DeletedObjects.
        remove_entry(&binary, &original, "TrashMe");
        remove_entry(&binary, &original, "Recycle Bin/TrashMe");

        let before = deleted_objects_snapshot(&binary, &original);
        assert_eq!(before.len(), 1, "expected one deleted object in source database");

        roundtrip_with_library(&original, &rewritten);

        let after = deleted_objects_snapshot(&binary, &rewritten);
        assert_eq!(after, before, "deleted objects changed after roundtrip");
    }

    // KeePassXC maintains a per-entry `_LAST_MODIFIED` marker in entry CustomData for
    // entries that have TOTP (OTP) configuration.  When KeePassXC writes a database it
    // refreshes this marker to the current wall-clock time, but it does NOT always bump
    // the entry's `Times.LastModificationTime`.  If the same database is written by
    // KeePassXC at two different moments, the two resulting files contain entries with
    // identical `LastModificationTime` values but different `_LAST_MODIFIED` strings.
    //
    // Our merge algorithm relies on `LastModificationTime` to decide which side is
    // newer, and flags identical timestamps with divergent content as an error
    // (`MergeError::EntryModificationTimeNotUpdated`).  This test pins that failure.
    //
    // The test creates the scenario programmatically (via our library) to simulate
    // exactly what KeePassXC does, and uses `keepassxc-cli` to seed the initial
    // database so the test is anchored to a real KeePassXC-created file.
    #[test]
    #[cfg(feature = "_merge")]
    fn keepassxc_entry_custom_data_last_modified_without_modification_time_causes_merge_failure() {
        let Some(binary) = require_keepassxc_cli() else {
            return;
        };

        let tempdir = TempDir::new().expect("failed to create tempdir");
        let db_base = tempdir.path().join("last-modified-base.kdbx");
        let db_a = tempdir.path().join("last-modified-a.kdbx");
        let db_b = tempdir.path().join("last-modified-b.kdbx");

        // Step 1 – use keepassxc-cli to create a real database with one entry.
        // keepassxc-cli creates KDBX3.1 databases; our library only saves KDBX4.
        // Adding and immediately removing a dummy entry triggers KeePassXC's internal
        // KDBX3→KDBX4 format upgrade, after which our library can save the file.
        create_database(&binary, &db_base);
        add_entry(
            &binary,
            &db_base,
            "Service",
            "user",
            "https://example.com",
            "notes",
            "pass",
        );
        add_entry(
            &binary,
            &db_base,
            "Upgrade",
            "x",
            "https://upgrade.example",
            "",
            "upgradepass",
        );
        remove_entry(&binary, &db_base, "Upgrade");

        // Step 2 – read the database with our library and inject _LAST_MODIFIED into
        // the entry's CustomData, exactly as KeePassXC does for TOTP entries.
        // We write two snapshots:
        //   DB_B  –  the "old" state, _LAST_MODIFIED = T1
        //   DB_A  –  the "new write" state, _LAST_MODIFIED = T2, same LastModificationTime
        {
            let key = DatabaseKey::new().with_password(TEST_PASSWORD);
            let mut f = File::open(&db_base).expect("failed to open base database");
            let mut db = Database::open(&mut f, key.clone()).expect("library failed to open base database");

            // Locate the entry and stamp _LAST_MODIFIED = T1 (the "first write" time).
            for entry in &mut db.root.entries {
                if entry.get_title() == Some("Service") {
                    entry.custom_data.insert(
                        "_LAST_MODIFIED".to_string(),
                        CustomDataItem {
                            value: Some(CustomDataValue::String(
                                "Mon Jan  1 00:00:00 2024 GMT".to_string(),
                            )),
                            last_modification_time: None,
                        },
                    );
                    // Deliberately do NOT call entry.update_history() – this mirrors
                    // KeePassXC's behaviour of refreshing _LAST_MODIFIED without touching
                    // Times.LastModificationTime.
                }
            }

            // DB_B represents a copy of the database that was NOT rewritten by KeePassXC
            // after the _LAST_MODIFIED marker was first set.
            let mut out = File::create(&db_b).expect("failed to create db_b");
            db.save(&mut out, key.clone()).expect("library failed to save db_b");

            // Now simulate KeePassXC rewriting the database at a later time: it updates
            // _LAST_MODIFIED to T2 but leaves Times.LastModificationTime unchanged.
            for entry in &mut db.root.entries {
                if entry.get_title() == Some("Service") {
                    entry.custom_data.insert(
                        "_LAST_MODIFIED".to_string(),
                        CustomDataItem {
                            value: Some(CustomDataValue::String(
                                "Tue Jan  2 00:00:00 2024 GMT".to_string(),
                            )),
                            last_modification_time: None,
                        },
                    );
                }
            }

            // DB_A is the database that was last touched by KeePassXC.
            let mut out = File::create(&db_a).expect("failed to create db_a");
            db.save(&mut out, key).expect("library failed to save db_a");
        }

        // Step 3 – verify both databases are valid and readable by keepassxc-cli, which
        // anchors this test to real KeePassXC compatibility.
        let snapshot_a = export_snapshot(&binary, &db_a);
        let snapshot_b = export_snapshot(&binary, &db_b);

        // The two snapshots are equal when _LAST_MODIFIED is excluded (normalize_custom_data
        // already filters that key), confirming the only difference is the marker itself.
        assert_eq!(
            snapshot_a, snapshot_b,
            "snapshots should be identical except for _LAST_MODIFIED"
        );

        // Step 4 – attempt to merge DB_A (KeePassXC-rewritten) into DB_B (the stale copy).
        let key = DatabaseKey::new().with_password(TEST_PASSWORD);
        let mut f_a = File::open(&db_a).expect("failed to open db_a");
        let db_a_loaded =
            Database::open(&mut f_a, key.clone()).expect("library failed to open db_a");

        let mut f_b = File::open(&db_b).expect("failed to open db_b");
        let mut db_b_loaded =
            Database::open(&mut f_b, key.clone()).expect("library failed to open db_b");

        // The merge should succeed: the entries are semantically identical; only the
        // KeePassXC-internal _LAST_MODIFIED marker differs.
        //
        // BUG: this currently fails with EntryModificationTimeNotUpdated because our
        // merge algorithm treats any content divergence at the same LastModificationTime
        // as an error, without special-casing _LAST_MODIFIED.
        let result = db_b_loaded.merge(&db_a_loaded);
        assert!(
            result.is_ok(),
            "merge should succeed but failed: {:?}",
            result.unwrap_err()
        );
    }

    fn build_recycle_bin_fixture(binary: &OsString, db_path: &Path) -> FixtureExpectations {
        create_database(binary, db_path);
        add_entry(
            binary,
            db_path,
            "TrashMe",
            "delete-me",
            "https://example.invalid",
            "to-be-removed",
            "trashpass",
        );
        remove_entry(binary, db_path, "TrashMe");

        FixtureExpectations {
            show_paths: Vec::new(),
            attachments: Vec::new(),
        }
    }

    fn build_basic_fixture(binary: &OsString, db_path: &Path, tempdir: &Path) -> FixtureExpectations {
        create_database(binary, db_path);
        mkdir(binary, db_path, "Services");
        add_entry(
            binary,
            db_path,
            "Services/Primary",
            "demo-user",
            "https://example.com/login",
            "basic-fixture",
            "demo-entry-pass",
        );

        let attachment_path = tempdir.join("basic-payload.txt");
        fs::write(&attachment_path, ATTACHMENT_BYTES).expect("failed to write attachment fixture");
        attachment_import(binary, db_path, "Services/Primary", "payload", &attachment_path);
        add_entry(
            binary,
            db_path,
            "TrashMe",
            "delete-me",
            "https://example.invalid",
            "to-be-removed",
            "trashpass",
        );
        remove_entry(binary, db_path, "TrashMe");

        FixtureExpectations {
            show_paths: vec!["Services/Primary".to_string()],
            attachments: vec![AttachmentExpectation {
                entry_path: "Services/Primary".to_string(),
                attachment_name: "payload".to_string(),
                contents: ATTACHMENT_BYTES.to_vec(),
            }],
        }
    }

    fn build_complex_fixture(binary: &OsString, db_path: &Path, tempdir: &Path) -> FixtureExpectations {
        create_database(binary, db_path);
        mkdir(binary, db_path, "GroupA");
        mkdir(binary, db_path, "GroupA/Subgroup");
        add_entry(
            binary,
            db_path,
            "GroupA/Subgroup/EntryOne",
            "alice",
            "https://example.com",
            "note-1",
            "firstpass",
        );

        let attachment_path = tempdir.join("payload.txt");
        fs::write(&attachment_path, ATTACHMENT_BYTES).expect("failed to write attachment fixture");
        attachment_import(
            binary,
            db_path,
            "GroupA/Subgroup/EntryOne",
            "payload",
            &attachment_path,
        );

        edit_entry(
            binary,
            db_path,
            "GroupA/Subgroup/EntryOne",
            "bob",
            "https://example.org",
            "note-2",
            "secondpass",
        );

        add_entry(
            binary,
            db_path,
            "EntryTwo",
            "carol",
            "https://example.net",
            "line1\nline2",
            "entry2pass",
        );

        add_entry(
            binary,
            db_path,
            "TrashMe",
            "delete-me",
            "https://example.invalid",
            "to-be-removed",
            "trashpass",
        );
        remove_entry(binary, db_path, "TrashMe");

        FixtureExpectations {
            show_paths: vec!["GroupA/Subgroup/EntryOne".to_string(), "EntryTwo".to_string()],
            attachments: vec![AttachmentExpectation {
                entry_path: "GroupA/Subgroup/EntryOne".to_string(),
                attachment_name: "payload".to_string(),
                contents: ATTACHMENT_BYTES.to_vec(),
            }],
        }
    }

    fn assert_roundtrip_matches_keepassxc_export(binary: &OsString, original: &Path, rewritten: &Path) {
        let before = export_snapshot(binary, original);
        roundtrip_with_library(original, rewritten);
        let after = export_snapshot(binary, rewritten);

        assert_eq!(before, after, "KeePassXC export changed after roundtrip");
    }

    fn assert_show_roundtrip_matches(
        binary: &OsString,
        original: &Path,
        rewritten: &Path,
        show_paths: &[String],
    ) {
        for path in show_paths {
            let before = show_entry(binary, original, path);
            let after = show_entry(binary, rewritten, path);
            assert_eq!(
                before.trim_end(),
                after.trim_end(),
                "KeePassXC show output changed for {path}"
            );
        }
    }

    fn assert_attachment_exports_match(
        binary: &OsString,
        rewritten: &Path,
        attachments: &[AttachmentExpectation],
    ) {
        for attachment in attachments {
            let exported = export_attachment(
                binary,
                rewritten,
                &attachment.entry_path,
                &attachment.attachment_name,
            );
            assert_eq!(
                exported, attachment.contents,
                "attachment bytes changed for {}:{}",
                attachment.entry_path, attachment.attachment_name
            );
        }
    }

    fn require_keepassxc_cli() -> Option<OsString> {
        let binary = std::env::var_os(KEEPASSXC_CLI_ENV)
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| OsString::from("keepassxc-cli"));

        let available = Command::new(&binary)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false);

        if available {
            Some(binary)
        } else {
            eprintln!(
                "skipping keepassxc-cli roundtrip test because {} is unavailable",
                binary.to_string_lossy()
            );
            None
        }
    }

    fn create_database(binary: &OsString, db_path: &Path) {
        let args = vec![
            "db-create".to_string(),
            "-q".to_string(),
            "-p".to_string(),
            path_to_string(db_path),
        ];
        run_keepassxc(binary, &args, &database_create_stdin());
    }

    fn mkdir(binary: &OsString, db_path: &Path, group_path: &str) {
        let args = vec![
            "mkdir".to_string(),
            "-q".to_string(),
            path_to_string(db_path),
            group_path.to_string(),
        ];
        run_keepassxc(binary, &args, &database_unlock_stdin());
    }

    fn add_entry(
        binary: &OsString,
        db_path: &Path,
        entry_path: &str,
        username: &str,
        url: &str,
        notes: &str,
        entry_password: &str,
    ) {
        let args = vec![
            "add".to_string(),
            "-q".to_string(),
            "-u".to_string(),
            username.to_string(),
            "--url".to_string(),
            url.to_string(),
            "--notes".to_string(),
            notes.to_string(),
            "-p".to_string(),
            path_to_string(db_path),
            entry_path.to_string(),
        ];
        run_keepassxc(binary, &args, &entry_password_stdin(entry_password));
    }

    fn edit_entry(
        binary: &OsString,
        db_path: &Path,
        entry_path: &str,
        username: &str,
        url: &str,
        notes: &str,
        entry_password: &str,
    ) {
        let args = vec![
            "edit".to_string(),
            "-q".to_string(),
            "-u".to_string(),
            username.to_string(),
            "--url".to_string(),
            url.to_string(),
            "--notes".to_string(),
            notes.to_string(),
            "-p".to_string(),
            path_to_string(db_path),
            entry_path.to_string(),
        ];
        run_keepassxc(binary, &args, &entry_password_stdin(entry_password));
    }

    fn attachment_import(
        binary: &OsString,
        db_path: &Path,
        entry_path: &str,
        attachment_name: &str,
        attachment_path: &Path,
    ) {
        let args = vec![
            "attachment-import".to_string(),
            "-q".to_string(),
            path_to_string(db_path),
            entry_path.to_string(),
            attachment_name.to_string(),
            path_to_string(attachment_path),
        ];
        run_keepassxc(binary, &args, &database_unlock_stdin());
    }

    fn remove_entry(binary: &OsString, db_path: &Path, entry_path: &str) {
        let args = vec![
            "rm".to_string(),
            "-q".to_string(),
            path_to_string(db_path),
            entry_path.to_string(),
        ];

        let mut stdin = database_unlock_stdin();
        stdin.extend_from_slice(b"y\n");
        run_keepassxc(binary, &args, &stdin);
    }

    fn show_entry(binary: &OsString, db_path: &Path, entry_path: &str) -> String {
        let args = vec![
            "show".to_string(),
            "-q".to_string(),
            "-s".to_string(),
            "--all".to_string(),
            "--show-attachments".to_string(),
            path_to_string(db_path),
            entry_path.to_string(),
        ];
        String::from_utf8(run_keepassxc(binary, &args, &database_unlock_stdin()))
            .expect("show output was not valid UTF-8")
    }

    fn export_attachment(
        binary: &OsString,
        db_path: &Path,
        entry_path: &str,
        attachment_name: &str,
    ) -> Vec<u8> {
        let args = vec![
            "attachment-export".to_string(),
            "-q".to_string(),
            "--stdout".to_string(),
            path_to_string(db_path),
            entry_path.to_string(),
            attachment_name.to_string(),
            "unused-output-path".to_string(),
        ];
        run_keepassxc(binary, &args, &database_unlock_stdin())
    }

    fn export_snapshot(binary: &OsString, db_path: &Path) -> DatabaseSnapshot {
        let xml = export_xml(binary, db_path);
        parse_snapshot(&xml)
    }

    fn deleted_objects_snapshot(binary: &OsString, db_path: &Path) -> Vec<DeletedObjectSnapshot> {
        parse_deleted_objects(&export_xml(binary, db_path))
    }

    fn export_xml(binary: &OsString, db_path: &Path) -> String {
        let args = vec![
            "export".to_string(),
            "-q".to_string(),
            "-f".to_string(),
            "xml".to_string(),
            path_to_string(db_path),
        ];
        String::from_utf8(run_keepassxc(binary, &args, &database_unlock_stdin()))
            .expect("export output was not valid UTF-8")
    }

    fn roundtrip_with_library(original: &Path, rewritten: &Path) {
        let key = DatabaseKey::new().with_password(TEST_PASSWORD);
        let mut input = File::open(original).expect("failed to open original KeePassXC database");
        let db = Database::open(&mut input, key.clone()).expect("library failed to open KeePassXC database");

        let mut output = File::create(rewritten).expect("failed to create rewritten database");
        db.save(&mut output, key)
            .expect("library failed to save KeePassXC database");
    }

    fn parse_snapshot(xml: &str) -> DatabaseSnapshot {
        let ExportXml { meta, root } = from_str(xml).expect("failed to parse KeePassXC export");

        DatabaseSnapshot {
            meta: normalize_meta(meta),
            root: normalize_group(root.group),
        }
    }

    fn parse_deleted_objects(xml: &str) -> Vec<DeletedObjectSnapshot> {
        let ExportXml { root, .. } = from_str(xml).expect("failed to parse KeePassXC export");

        root.deleted_objects
            .map(|deleted_objects| {
                deleted_objects
                    .objects
                    .into_iter()
                    .map(|deleted_object| DeletedObjectSnapshot {
                        uuid: deleted_object.uuid,
                        deletion_time: empty_to_none(deleted_object.deletion_time),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn normalize_meta(meta: ExportMetaXml) -> MetaSnapshot {
        MetaSnapshot {
            generator: empty_to_none(meta.generator),
            database_name: empty_to_none(meta.database_name),
            database_name_changed: empty_to_none(meta.database_name_changed),
            database_description: empty_to_none(meta.database_description),
            database_description_changed: empty_to_none(meta.database_description_changed),
            default_username: empty_to_none(meta.default_username),
            default_username_changed: empty_to_none(meta.default_username_changed),
            maintenance_history_days: empty_to_none(meta.maintenance_history_days),
            color: empty_to_none(meta.color),
            master_key_changed: empty_to_none(meta.master_key_changed),
            master_key_change_rec: empty_to_none(meta.master_key_change_rec),
            master_key_change_force: empty_to_none(meta.master_key_change_force),
            memory_protection: meta.memory_protection.map(normalize_memory_protection),
            recycle_bin_enabled: empty_to_none(meta.recycle_bin_enabled),
            recycle_bin_uuid: empty_to_none(meta.recycle_bin_uuid),
            recycle_bin_changed: empty_to_none(meta.recycle_bin_changed),
            entry_templates_group: empty_to_none(meta.entry_templates_group),
            entry_templates_group_changed: empty_to_none(meta.entry_templates_group_changed),
            last_selected_group: empty_to_none(meta.last_selected_group),
            last_top_visible_group: empty_to_none(meta.last_top_visible_group),
            history_max_items: empty_to_none(meta.history_max_items),
            history_max_size: empty_to_none(meta.history_max_size),
            custom_data: normalize_custom_data(meta.custom_data),
        }
    }

    fn normalize_memory_protection(memory_protection: ExportMemoryProtectionXml) -> MemoryProtectionSnapshot {
        MemoryProtectionSnapshot {
            protect_title: empty_to_none(memory_protection.protect_title),
            protect_user_name: empty_to_none(memory_protection.protect_user_name),
            protect_password: empty_to_none(memory_protection.protect_password),
            protect_url: empty_to_none(memory_protection.protect_url),
            protect_notes: empty_to_none(memory_protection.protect_notes),
        }
    }

    fn normalize_group(group: ExportGroupXml) -> GroupSnapshot {
        let mut groups = group.groups.into_iter().map(normalize_group).collect::<Vec<_>>();
        groups.sort_by(|left, right| left.name.cmp(&right.name).then(left.uuid.cmp(&right.uuid)));

        let mut entries = group.entries.into_iter().map(normalize_entry).collect::<Vec<_>>();
        entries.sort_by(|left, right| {
            left.title_key()
                .cmp(&right.title_key())
                .then(left.uuid.cmp(&right.uuid))
        });

        GroupSnapshot {
            uuid: group.uuid,
            name: group.name,
            notes: empty_to_none(group.notes),
            icon_id: empty_to_none(group.icon_id),
            times: group.times.map(normalize_times),
            is_expanded: empty_to_none(group.is_expanded),
            default_auto_type_sequence: empty_to_none(group.default_auto_type_sequence),
            enable_auto_type: empty_to_none(group.enable_auto_type),
            enable_searching: empty_to_none(group.enable_searching),
            last_top_visible_entry: empty_to_none(group.last_top_visible_entry),
            custom_data: normalize_custom_data(group.custom_data),
            tags: empty_to_none(group.tags),
            previous_parent_group: empty_to_none(group.previous_parent_group),
            groups,
            entries,
        }
    }

    fn normalize_entry(entry: ExportEntryXml) -> EntrySnapshot {
        let fields = entry
            .string_fields
            .into_iter()
            .map(|field| {
                (
                    field.key,
                    FieldSnapshot {
                        value: empty_to_none(field.value.value),
                        protect_in_memory: matches!(
                            empty_to_none(field.value.protect_in_memory),
                            Some(ref value) if value == "True"
                        ),
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();

        let mut attachments = entry
            .binary_fields
            .into_iter()
            .map(|field| field.key)
            .collect::<Vec<_>>();
        attachments.sort();

        let history = entry
            .history
            .map(|history| history.entries.into_iter().map(normalize_entry).collect())
            .unwrap_or_default();

        EntrySnapshot {
            uuid: entry.uuid,
            icon_id: empty_to_none(entry.icon_id),
            foreground_color: empty_to_none(entry.foreground_color),
            background_color: empty_to_none(entry.background_color),
            override_url: empty_to_none(entry.override_url),
            tags: empty_to_none(entry.tags),
            quality_check: empty_to_none(entry.quality_check),
            previous_parent_group: empty_to_none(entry.previous_parent_group),
            times: entry.times.map(normalize_times),
            fields,
            attachments,
            auto_type: entry.auto_type.map(normalize_auto_type),
            history,
            custom_data: normalize_custom_data(entry.custom_data),
        }
    }

    fn normalize_times(times: ExportTimesXml) -> TimesSnapshot {
        TimesSnapshot {
            last_modification_time: empty_to_none(times.last_modification_time),
            creation_time: empty_to_none(times.creation_time),
            last_access_time: empty_to_none(times.last_access_time),
            expiry_time: empty_to_none(times.expiry_time),
            expires: empty_to_none(times.expires),
            usage_count: empty_to_none(times.usage_count),
            location_changed: empty_to_none(times.location_changed),
        }
    }

    fn normalize_auto_type(auto_type: ExportAutoTypeXml) -> AutoTypeSnapshot {
        let mut associations = auto_type
            .associations
            .into_iter()
            .map(|association| AutoTypeAssociationSnapshot {
                window: empty_to_none(association.window),
                keystroke_sequence: empty_to_none(association.keystroke_sequence),
            })
            .collect::<Vec<_>>();
        associations.sort();

        AutoTypeSnapshot {
            enabled: empty_to_none(auto_type.enabled),
            data_transfer_obfuscation: empty_to_none(auto_type.data_transfer_obfuscation),
            default_sequence: empty_to_none(auto_type.default_sequence),
            associations,
        }
    }

    fn normalize_custom_data(custom_data: Option<ExportCustomDataXml>) -> BTreeMap<String, Option<String>> {
        custom_data
            .map(|custom_data| {
                custom_data
                    .items
                    .into_iter()
                    // KeePassXC refreshes this marker when it writes a database, so it is
                    // expected to differ across an otherwise lossless roundtrip.
                    .filter(|item| item.key != "_LAST_MODIFIED")
                    .map(|item| (item.key, empty_to_none(item.value)))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn empty_to_none(value: Option<String>) -> Option<String> {
        value.and_then(|value| if value.is_empty() { None } else { Some(value) })
    }

    fn database_create_stdin() -> Vec<u8> {
        format!("{TEST_PASSWORD}\n{TEST_PASSWORD}\n").into_bytes()
    }

    fn database_unlock_stdin() -> Vec<u8> {
        format!("{TEST_PASSWORD}\n").into_bytes()
    }

    fn entry_password_stdin(entry_password: &str) -> Vec<u8> {
        let mut stdin = database_unlock_stdin();
        stdin.extend_from_slice(entry_password.as_bytes());
        stdin.push(b'\n');
        stdin
    }

    fn run_keepassxc(binary: &OsString, args: &[String], stdin: &[u8]) -> Vec<u8> {
        let mut child = Command::new(binary)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|error| panic!("failed to spawn keepassxc-cli {:?}: {error}", args));

        if !stdin.is_empty() {
            child
                .stdin
                .as_mut()
                .expect("missing stdin pipe")
                .write_all(stdin)
                .expect("failed to write keepassxc-cli stdin");
        }

        let output = child
            .wait_with_output()
            .expect("failed waiting for keepassxc-cli");

        assert!(
            output.status.success(),
            "keepassxc-cli {:?} failed\nstatus: {:?}\nstdout:\n{}\nstderr:\n{}",
            args,
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );

        output.stdout
    }

    fn path_to_string(path: &Path) -> String {
        path.to_string_lossy().into_owned()
    }

    impl EntrySnapshot {
        fn title_key(&self) -> (&str, &str) {
            let title = self
                .fields
                .get("Title")
                .and_then(|field| field.value.as_deref())
                .unwrap_or("");
            (title, &self.uuid)
        }
    }
}
