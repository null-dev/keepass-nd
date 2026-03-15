use chrono::NaiveDateTime;
use uuid::Uuid;

/// A custom icon stored in the database's `Meta/CustomIcons` section.
///
/// KDBX 4.1 extended the icon format to include an optional `Name` and
/// `LastModificationTime`. Older fields (`uuid`, `data`) remain valid for
/// KDBX 4.0 databases.
#[derive(Debug, Default, Eq, PartialEq, Clone)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct CustomIcon {
    /// UUID that uniquely identifies this icon within the database
    pub uuid: Uuid,

    /// Raw image data (typically PNG)
    pub data: Vec<u8>,

    /// Optional human-readable name for the icon (KDBX 4.1+)
    pub name: Option<String>,

    /// Time the icon was last modified (KDBX 4.1+)
    pub last_modification_time: Option<NaiveDateTime>,
}
