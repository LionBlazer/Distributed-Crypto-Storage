//! Editor presets for the playground; never an execution or protocol contract.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PresetGroup {
    Select,
    Filter,
    Aggregate,
    Insert,
    Update,
}
impl PresetGroup {
    pub fn label(self) -> &'static str {
        match self {
            Self::Select => "Read rows",
            Self::Filter => "Filter rows",
            Self::Aggregate => "Summarize",
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
        name: "First 10 rows",
        group: PresetGroup::Select,
        sql: "SELECT * FROM records LIMIT 10;",
    },
    Preset {
        name: "Adults",
        group: PresetGroup::Filter,
        sql: "SELECT * FROM records WHERE age >= 18;",
    },
    Preset {
        name: "Age 18",
        group: PresetGroup::Filter,
        sql: "SELECT * FROM records WHERE age = 18;",
    },
    Preset {
        name: "Under 18",
        group: PresetGroup::Filter,
        sql: "SELECT * FROM records WHERE age < 18;",
    },
    Preset {
        name: "At most 18",
        group: PresetGroup::Filter,
        sql: "SELECT * FROM records WHERE age <= 18;",
    },
    Preset {
        name: "Over 18",
        group: PresetGroup::Filter,
        sql: "SELECT * FROM records WHERE age > 18;",
    },
    Preset {
        name: "Ages 18..42",
        group: PresetGroup::Filter,
        sql: "SELECT * FROM records WHERE age BETWEEN 18 AND 42;",
    },
    Preset {
        name: "Age 255",
        group: PresetGroup::Filter,
        sql: "SELECT * FROM records WHERE age = 255;",
    },
    Preset {
        name: "Adult amounts",
        group: PresetGroup::Filter,
        sql: "SELECT amount FROM records WHERE age >= 18 LIMIT 10;",
    },
    Preset {
        name: "Count rows",
        group: PresetGroup::Aggregate,
        sql: "SELECT COUNT(*) FROM records;",
    },
    Preset {
        name: "Sum amounts",
        group: PresetGroup::Aggregate,
        sql: "SELECT SUM(amount) FROM records;",
    },
    Preset {
        name: "Count and sum",
        group: PresetGroup::Aggregate,
        sql: "SELECT COUNT(*), SUM(amount) FROM records;",
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
    Preset {
        name: "Overflow test",
        group: PresetGroup::Update,
        sql: "UPDATE records SET amount = amount + 65535 WHERE age >= 18;",
    },
];
