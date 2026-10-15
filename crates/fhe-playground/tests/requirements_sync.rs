//! Repository contract guard; no cryptographic setup, network or native UI.

#[test]
fn agent_instructions_mirror_the_canonical_requirements() {
    let canonical = include_str!("../../../REQUIREMENTS.md").replace("\r\n", "\n");
    let instructions = include_str!("../../../AGENTS.md").replace("\r\n", "\n");
    let begin = "<!-- requirements:begin -->";
    let end = "<!-- requirements:end -->";
    assert_eq!(instructions.matches(begin).count(), 1, "one mirror start");
    assert_eq!(instructions.matches(end).count(), 1, "one mirror end");
    let mirrored = instructions
        .split_once(begin)
        .expect("AGENTS.md needs a requirements mirror")
        .1
        .split_once(end)
        .expect("the requirements mirror must be closed")
        .0
        .trim();
    let requirements = canonical
        .split_once("\n## Источники для проектирования")
        .expect("preserve the separate research-source appendix")
        .0
        .trim();

    assert_eq!(
        mirrored, requirements,
        "Synchronize REQUIREMENTS.md and the marked AGENTS.md block before implementing or publishing."
    );
}
