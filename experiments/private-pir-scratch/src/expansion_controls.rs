//! Public-fixture controls; owner recovery/authentication stays in this controller,
//! outside the public-only scheduling module. No production/client protocol shortcut.
use super::*;
use spiral_rs::server::expand_query;
const BOUNDARIES: [usize; 11] = [0, 1, 2, 63, 64, 127, 128, 255, 256, 488, 511];

fn exact_expansion(pir: &Pir<'_>, query: &Query<'_>) -> ProbeResult<()> {
    let frozen = expansion_schedule::expand_query_pairs(pir.params, pir.public, query);
    let native_check = expand_query(pir.params, pir.public, query);
    if frozen.0.as_slice() != native_check.0.as_slice() || frozen.1.len() != native_check.1.len() {
        return Err("Frozen paired selector mismatch".into());
    }
    for (left, right) in frozen.1.iter().zip(&native_check.1) {
        if left.rows != right.rows
            || left.cols != right.cols
            || left.data.as_slice() != right.data.as_slice()
        {
            return Err("Frozen paired folding mismatch".into());
        }
    }
    drop(frozen);
    drop(native_check);
    let original = expand_query(pir.params, pir.public, query);
    let paired = scratch_schedule::expand_query_selected(pir.params, pir.public, query);
    if original.0.as_slice() != paired.0.as_slice() || original.1.len() != paired.1.len() {
        return Err("Expanded selector mismatch".into());
    }
    for (left, right) in original.1.iter().zip(&paired.1) {
        if left.rows != right.rows
            || left.cols != right.cols
            || left.data.as_slice() != right.data.as_slice()
        {
            return Err("Expanded folding matrix mismatch".into());
        }
    }
    Ok(())
}
fn validate(
    owner: &Owner,
    pir: &Pir<'_>,
    snapshot: &EncryptedSnapshot,
    page: usize,
    answer: &[u8],
    limits: Limits,
) -> ProbeResult<()> {
    if answer.len() != 20480 {
        return Err("Wrong answer length".into());
    }
    let mut record = pir.client.decode_response(answer);
    if record.len() < RECORD_BYTES {
        return Err("Truncated record".into());
    }
    record.truncate(RECORD_BYTES);
    let verified = decode_page(&record, snapshot.commitment(), page, limits)?;
    drop(owner.decrypt(&verified)?);
    if record != visible_record(snapshot, page, limits)? {
        return Err("Full record oracle mismatch".into());
    }
    Ok(())
}
fn framed_query(
    pir: &Pir<'_>,
    snapshot: &EncryptedSnapshot,
    page: usize,
    store: u8,
) -> ProbeResult<Vec<u8>> {
    let payload = pir.client.generate_query(page).serialize();
    if payload.len() != pir.params.query_bytes() {
        return Err("Wrong request length".into());
    }
    let mut wire = Vec::with_capacity(33 + payload.len());
    wire.push(store);
    wire.extend_from_slice(&snapshot.commitment().root());
    wire.extend_from_slice(&payload);
    Ok(wire)
}

pub(super) fn run(
    owner: &Owner,
    pir: &Pir<'_>,
    data: &EncryptedSnapshot,
    data_db: &AlignedMemory64,
    index: &EncryptedSnapshot,
    index_db: &AlignedMemory64,
) -> ProbeResult<bool> {
    // Distinct fully authenticated512-page fixture: slot511 is NOT presented as
    // a page from the one-million-row data/index snapshots.
    let bytes = (0..512 * 64)
        .map(|i| ((i * 73 + i / 64 * 11) % 256) as u8)
        .collect::<Vec<_>>();
    let fixture = owner.seal(
        Layout {
            schema: *b"PUBLICBOUNDARY01",
            row_width: 64,
            rows_per_page: 1,
            row_count: 512,
        },
        &bytes,
        Limits::default(),
    )?;
    let (db, _, record_ms, ntt_ms) = prepare(&fixture, pir.params, Limits::default());
    println!(
        "{}",
        json!({"experiment":"private-pir-scratch-boundary-fixture","public_fixture":true,
        "logical_bytes":bytes.len(),"canonical_bytes":fixture.encoded_len(),"merkle_bytes":fixture.index_hash_bytes(),
        "ntt_bytes":db.len()*8,"record_build_ms":record_ms,"ntt_ms":ntt_ms,"pages":512,
        "separate_from_1m_table":true,"resources":resources::sample()})
    );
    let mut trial_sum = 0.0;
    let mut combined_sum = 0.0;
    for page in BOUNDARIES {
        for fresh in 0..2 {
            let request = framed_query(pir, &fixture, page, 2)?;
            if request[0] != 2 || request[1..33] != fixture.commitment().root() {
                return Err("Boundary frame mismatch".into());
            }
            let query = Query::deserialize(pir.params, &request[33..]);
            exact_expansion(pir, &query)?;
            let mut outputs = Vec::new();
            let mut times = Vec::new();
            for schedule in Schedule::all_order(fresh) {
                let start = Instant::now();
                let response = scratch_schedule::evaluate(
                    pir.params,
                    pir.public,
                    &query,
                    db.as_slice(),
                    schedule,
                );
                let server_ms = ms(start);
                validate(owner, pir, &fixture, page, &response, Limits::default())?;
                if schedule == Schedule::PairedCombined {
                    trial_sum += server_ms;
                }
                if schedule == Schedule::SelectedCombined {
                    combined_sum += server_ms;
                }
                times.push(json!({"schedule":schedule,"server_ms":server_ms}));
                outputs.push(response);
            }
            for response in &outputs[1..] {
                if response != &outputs[0] {
                    return Err("Same ciphertext response mismatch".into());
                }
            }
            println!(
                "{}",
                json!({"experiment":"private-pir-scratch-boundary-control","page":page,"fresh":fresh,
            "exact_expansion":true,"exact_all_four_responses":true,"authenticated":true,
            "request_bytes":request.len(),"response_bytes":outputs[0].len(),"timings":times,"resources":resources::sample()})
            );
        }
    }
    drop(db);
    drop(fixture);
    drop(bytes);
    for (snapshot, db, page, store, limits) in [
        (index, index_db, 0, 1, padded_index_codec::index_limits()),
        (index, index_db, 488, 1, padded_index_codec::index_limits()),
        (data, data_db, 0, 0, Limits::default()),
        (data, data_db, 488, 0, Limits::default()),
    ] {
        let request = framed_query(pir, snapshot, page, store)?;
        let query = Query::deserialize(pir.params, &request[33..]);
        exact_expansion(pir, &query)?;
        let mut first = None;
        for schedule in Schedule::all_order(0) {
            let response =
                scratch_schedule::evaluate(pir.params, pir.public, &query, db.as_slice(), schedule);
            validate(owner, pir, snapshot, page, &response, limits)?;
            if let Some(old) = &first {
                if old != &response {
                    return Err("Real page response mismatch".into());
                }
            } else {
                first = Some(response);
            }
        }
        println!(
            "{}",
            json!({"experiment":"private-pir-scratch-real-page-control","store":store,"page":page,
            "exact_expansion":true,"exact_all_four_responses":true,"authenticated":true,"resources":resources::sample()})
        );
    }
    // Predeclared gate: run the entire32-operation full matrix only for a >=5%
    // average server gain across ALL22 boundary controls, with exactness intact.
    let gain = combined_sum <= trial_sum * 0.95;
    println!(
        "{}",
        json!({"experiment":"private-pir-scratch-gain-gate","controls":22,
        "paired_combined_total_server_ms":trial_sum,"selected_combined_total_server_ms":combined_sum,
        "ratio":combined_sum/trial_sum,"required_max_ratio":0.95,"run_full_matrix":gain,"resources":resources::sample()})
    );
    Ok(gain)
}
