//! Observable bulk framing, full-image authentication and actual owning BFV tests.
use super::*;
use bulk_wire::{HEADER_BYTES, Header, WireError};
use roles::{Counters, DiskPeer, Mode, OwnerTable, TrustedTable};
fn header() -> Header {
    Header {
        table_id: 7,
        request_id: [1; 16],
        data_head: [2; 112],
        index_head: [3; 112],
        data_len: 112,
        index_len: 112,
    }
}
#[test]
fn full_image_wire_has_no_selection_field_and_rejects_replay_truncation_trailing_and_oversize() {
    let pending = header();
    let request = pending.request().unwrap();
    assert_eq!(request.len(), 270);
    assert_eq!(Header::parse_request(&request).unwrap(), pending);
    let mut extra = request.clone();
    extra.push(0);
    assert_eq!(Header::parse_request(&extra), Err(WireError::Shape));
    let mut version = request.clone();
    version[8] ^= 1;
    assert_eq!(Header::parse_request(&version), Err(WireError::Version));
    let mut over = request;
    over[254..262].copy_from_slice(&u64::MAX.to_le_bytes());
    assert_eq!(Header::parse_request(&over), Err(WireError::Limit));
    let mut response = pending.response_header().unwrap();
    response.extend_from_slice(&[17; 224]);
    let (data, index) = pending.split_response(&response).unwrap();
    assert_eq!((data.len(), index.len()), (112, 112));
    assert_eq!(
        pending.split_response(&response[..response.len() - 1]),
        Err(WireError::Shape)
    );
    let mut trailing = response.clone();
    trailing.push(0);
    assert_eq!(pending.split_response(&trailing), Err(WireError::Shape));
    for offset in [14, 30, 142] {
        let mut wrong = response.clone();
        wrong[offset] ^= 1;
        assert_eq!(pending.split_response(&wrong), Err(WireError::Binding));
    }
    let mut current = pending.clone();
    current.table_id += 1;
    assert_eq!(current.split_response(&response), Err(WireError::Binding));
    assert_eq!(response.len(), HEADER_BYTES + 224);
}
#[test]
fn sparse_public_fixture_has_exact0_1_256_groups_and256_distinct_data_pages() {
    let counts = fixture::CASES.map(|case| {
        let (ids, sum) = fixture::oracle(case);
        (ids.len(), sum)
    });
    assert_eq!(counts, [(0, 0), (1, 4095), (256, 16_776_960)]);
    let (ids, _) = fixture::oracle(fixture::CASES[2]);
    assert_eq!(ids.first(), Some(&0));
    assert_eq!(ids.last(), Some(&999_999));
    assert_eq!(
        ids.iter()
            .map(|id| *id / u64::from(fixture::PAGE_ROWS))
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        256
    );
}
struct Setup {
    owner: OwnerTable,
    peer: DiskPeer,
    data: Vec<u8>,
    index: Vec<u8>,
    directory: PathBuf,
}
fn setup() -> Setup {
    let mut nonce = [0u8; 8];
    getrandom::getrandom(&mut nonce).unwrap();
    let directory = std::env::temp_dir().join(format!(
        "public-bulk-{}-{}",
        std::process::id(),
        u64::from_le_bytes(nonce)
    ));
    std::fs::create_dir(&directory).unwrap();
    let (authority, evaluator) = bfv::Owner::generate(*b"public-bulk-tst1").unwrap();
    let table = authority
        .seal(
            &fixture::public_rows(),
            fixture::PAGE_ROWS,
            roles::data_limits(),
        )
        .unwrap();
    let trusted = TrustedTable::capture(0, &table).unwrap();
    let data = table.snapshot().encode();
    let index = table.encrypted_index().encode();
    roles::write_new(&directory.join("data.bin"), &data).unwrap();
    roles::write_new(&directory.join("index.bin"), &index).unwrap();
    Setup {
        owner: OwnerTable::new(authority, trusted.clone()),
        peer: DiskPeer::new(
            evaluator,
            trusted,
            directory.join("data.bin"),
            directory.join("index.bin"),
        ),
        data,
        index,
        directory,
    }
}
#[test]
fn real_complete_bulk_snapshots_feed_exact_fhe_for_absent_point_and_scattered_max256_in_both_modes()
{
    let mut fixture = setup();
    let counters = Counters::default();
    let mut body = None;
    let mut sizes = None;
    for mode in [Mode::Disk, Mode::Resident] {
        if matches!(mode, Mode::Resident) {
            fixture.peer.preload_resident().unwrap();
        }
        for case in fixture::CASES {
            let result = fixture
                .owner
                .execute(&fixture.peer, mode, case, &counters)
                .unwrap();
            let (ids, sum) = fixture::oracle(case);
            assert_eq!(
                (result.actual.count, result.actual.sum),
                (ids.len() as u32, sum)
            );
            assert_eq!(result.actual.proof, bfv::ProofStatus::Unavailable);
            assert_eq!(result.stages.peer.rotations, 8);
            let shape = (
                result.stages.bulk_request_bytes,
                result.stages.bulk_response_bytes,
                result.stages.bfv_request_bytes,
                result.stages.bfv_response_bytes,
            );
            if let Some(old) = sizes.replace(shape) {
                assert_eq!(old, shape)
            }
            if let Some(old) = body.replace(result.payload_sha256) {
                assert_eq!(old, result.payload_sha256)
            }
        }
    }
    assert_eq!(
        (
            counters.prepare_successes.get(),
            counters.peer_evaluations.get(),
            counters.owner_completions.get()
        ),
        (6, 6, 6)
    );
}
#[test]
fn corrupted_data_or_index_ciphertext_and_extra_file_bytes_reject_before_owner_prepare() {
    let fixture = setup();
    for (name, original) in [("data.bin", &fixture.data), ("index.bin", &fixture.index)] {
        let mut corrupted = original.clone();
        let last = corrupted.len() - 1;
        corrupted[last] ^= 1;
        std::fs::write(fixture.directory.join(name), &corrupted).unwrap();
        let counters = Counters::default();
        assert!(
            fixture
                .owner
                .execute(&fixture.peer, Mode::Disk, fixture::CASES[1], &counters)
                .is_err()
        );
        assert_eq!(
            (
                counters.prepare_calls.get(),
                counters.prepare_successes.get(),
                counters.peer_evaluations.get()
            ),
            (0, 0, 0)
        );
        let mut extra = original.clone();
        extra.push(0);
        std::fs::write(fixture.directory.join(name), extra).unwrap();
        assert!(
            fixture
                .owner
                .execute(&fixture.peer, Mode::Disk, fixture::CASES[1], &counters)
                .is_err()
        );
        assert_eq!(counters.prepare_calls.get(), 0);
        std::fs::write(fixture.directory.join(name), original).unwrap();
    }
}
#[test]
fn complete_overbudget_group_rejects_inside_owning_preflight_without_a_successful_fhe_prepare() {
    let fixture = setup();
    let counters = Counters::default();
    let error = fixture
        .owner
        .execute(
            &fixture.peer,
            Mode::Disk,
            fixture::Case {
                name: "overbudget",
                age: 0,
            },
            &counters,
        )
        .err()
        .expect("complete group exceeds256");
    assert!(
        matches!(error.downcast_ref::<compact_query::Error>(),Some(compact_query::Error::SelectionBudget{selected,budget:256}) if *selected>256)
    );
    assert_eq!(
        (
            counters.prepare_calls.get(),
            counters.prepare_successes.get(),
            counters.peer_evaluations.get()
        ),
        (1, 0, 0)
    );
}
#[test]
fn a_foreign_owner_cannot_accept_full_valid_snapshots_even_for_an_absent_selection() {
    let fixture = setup();
    let (foreign, _) = bfv::Owner::generate(*b"public-bulk-tst2").unwrap();
    let foreign = OwnerTable::new(foreign, fixture.owner.trusted.clone());
    let counters = Counters::default();
    assert!(
        foreign
            .execute(&fixture.peer, Mode::Disk, fixture::CASES[0], &counters)
            .is_err()
    );
    assert_eq!(counters.prepare_calls.get(), 0);
}
