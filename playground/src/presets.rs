//! Editor presets for the playground; never an execution or protocol contract.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PresetGroup {
    Select,
    Filter,
    Insert,
    Update,
}
impl PresetGroup {
    pub fn label(self) -> &'static str {
        match self {
            Self::Select => "Read rows",
            Self::Filter => "Filter rows",
            Self::Insert => "Insert",
            Self::Update => "Update",
        }
    }
}
pub struct Preset {
    pub name: &'static str,
    pub group: PresetGroup,
    pub sql: &'static str,
}

pub const PRESETS: &[Preset] = &[
    Preset {
        name: "All rows",
        group: PresetGroup::Select,
        sql: "SELECT * FROM records;",
    },
    Preset {
        name: "Adults",
        group: PresetGroup::Filter,
        sql: "SELECT * FROM records WHERE age >= 18;",
    },
    Preset {
        name: "Insert one row",
        group: PresetGroup::Insert,
        sql: "INSERT INTO records (age, amount) VALUES (18, 10);",
    },
    Preset {
        name: "Increase adult amounts by 5",
        group: PresetGroup::Update,
        sql: "UPDATE records SET amount = amount + 5 WHERE age >= 18;",
    },
];
