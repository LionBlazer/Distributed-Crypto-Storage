//! Public non-secret adversarial fixtures and explicit mode controls for the UPDATE experiment.
use crate::update::{Environment, OutputMode};
use crate::*;
use bincode::Options;
use serde::{Deserialize, Serialize};
use std::io::Read;

#[derive(Deserialize)]
struct ObservedRequest {
    magic: [u8; 8],
    version: u16,
    operation: u32,
    keyset_id: [u8; 32],
    context: QueryContext,
    geometry: Geometry,
    amounts: Vec<u8>,
    deltas: Vec<u8>,
}
#[derive(Serialize)]
struct ForgedResponse {
    magic: [u8; 8],
    version: u16,
    operation: u32,
    keyset_id: [u8; 32],
    context: QueryContext,
    geometry: Geometry,
    updated_limbs: Vec<u8>,
}
/// Public-only echo attack against the observed bounded protocol, never a production codec.
/// The actual honest ciphertext addition is executed first by the caller and then tampered with.
pub(crate) fn public_echo(request: &[u8]) -> ProbeResult<Vec<u8>> {
    let bound = compact_bfv_byte_limb_core::MAX_WIRE_BYTES;
    if request.len() as u64 > bound {
        return Err("Adversary fixture wire limit".into());
    }
    let observed: ObservedRequest = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(bound)
        .reject_trailing_bytes()
        .deserialize(request)?;
    if observed.magic != *b"BFVADDQ1"
        || observed.version != 1
        || observed.operation != 1
        || observed.deltas.is_empty()
    {
        return Err("Unexpected observed UPDATE protocol".into());
    }
    Ok(bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(bound)
        .serialize(&ForgedResponse {
            magic: *b"BFVADDR1",
            version: observed.version,
            operation: observed.operation,
            keyset_id: observed.keyset_id,
            context: observed.context,
            geometry: observed.geometry,
            updated_limbs: observed.amounts,
        })?)
}
fn file_digest(path: &std::path::Path) -> ProbeResult<[u8; 32]> {
    let mut file = std::fs::File::open(path)?;
    let mut digest = sha2::Sha256::new();
    let mut block = [0; 8192];
    loop {
        let count = file.read(&mut block)?;
        if count == 0 {
            break;
        }
        digest.update(&block[..count]);
    }
    Ok(digest.finalize().into())
}
#[derive(PartialEq, Eq)]
struct DiskState {
    data_digest: [u8; 32],
    index_digest: [u8; 32],
    catalog_digest: [u8; 32],
    data_head: Commitment,
    index_head: Commitment,
}
fn disk_state(
    catalog: &[disk::CatalogEntry],
    id: usize,
    directory: &std::path::Path,
) -> ProbeResult<DiskState> {
    Ok(DiskState {
        data_digest: file_digest(&catalog[id].data_path)?,
        index_digest: file_digest(&catalog[id].index_path)?,
        catalog_digest: file_digest(&directory.join("catalog.jsonl"))?,
        data_head: catalog[id].data_head.clone(),
        index_head: catalog[id].index_head.clone(),
    })
}
pub(crate) fn before_commits(
    catalog: &mut [disk::CatalogEntry],
    loader: &mut disk::Loader,
    id: usize,
    env: &Environment<'_>,
) -> ProbeResult<()> {
    let original = disk_state(catalog, id, env.directory)?;
    let before = env.preparations.get();
    let plan = Plan {
        kernel: KernelMode::ExactIndex,
        access: Access::Private,
        profile: Profile::Fixed256,
        header: HeaderMode::Uncached,
        query: QuerySpec::Equal(250),
        query_id: nonce()?,
    };
    let rejected = update::execute(catalog, loader, id, plan, 1, env, OutputMode::PublicEcho);
    let error = rejected
        .err()
        .ok_or("Public in-bounds echo was not rejected by local UPDATE oracle")?;
    if !error
        .to_string()
        .contains("Local experiment oracle rejected")
        || env.preparations.get() != before + 1
        || disk_state(catalog, id, env.directory)? != original
    {
        return Err("Wrong-arithmetic control mutated state or skipped real FHE".into());
    }
    println!(
        "{}",
        json!({"experiment":"update-disk-rejection","case":"public_in_bounds_echo_after_real_addition","canonical_catalog_heads_unchanged":true,"actual_bfv_addition_before_oracle":true,"computation_proof":false})
    );
    // Mixed safe/overflow rows must reject globally, not update the earlier safe rows.
    let plan = Plan {
        query: QuerySpec::Equal(240),
        query_id: nonce()?,
        ..plan
    };
    let rejected = update::execute(catalog, loader, id, plan, 1, env, OutputMode::Honest)?;
    if rejected.outcome != "GlobalOverflowNoCommit"
        || rejected.selected != 64
        || disk_state(catalog, id, env.directory)? != original
    {
        return Err("Mixed global overflow changed compact state".into());
    }
    println!(
        "{}",
        json!({"experiment":"update-disk-rejection","case":"mixed64_global_overflow","stages":rejected.stages,"canonical_catalog_heads_unchanged":true})
    );
    Ok(())
}
pub(crate) fn after_commits(
    catalog: &mut [disk::CatalogEntry],
    loader: &mut disk::Loader,
    id: usize,
    env: &Environment<'_>,
) -> ProbeResult<()> {
    for access in [Access::Visible, Access::Private] {
        for profile in [Profile::AddressOnly, Profile::Fixed256] {
            for header in [HeaderMode::Cached, HeaderMode::Uncached] {
                for (label, query, delta, selected, commit, overflow) in [
                    ("four_rows", QuerySpec::Equal(251), 1, 4, true, false),
                    ("sixteen_rows", QuerySpec::Equal(252), 1, 16, true, false),
                    (
                        "range21",
                        QuerySpec::ClosedRange {
                            lower: 250,
                            upper: 252,
                        },
                        1,
                        21,
                        true,
                        false,
                    ),
                    ("absence", QuerySpec::Equal(253), 1, 0, false, false),
                    (
                        "max256_overflow",
                        QuerySpec::Equal(255),
                        1,
                        256,
                        false,
                        true,
                    ),
                    (
                        "max256_zero_delta_noop",
                        QuerySpec::Equal(255),
                        0,
                        256,
                        false,
                        false,
                    ),
                ] {
                    let before = disk_state(catalog, id, env.directory)?;
                    let plan = Plan {
                        kernel: KernelMode::ExactIndex,
                        access,
                        profile,
                        header,
                        query,
                        query_id: nonce()?,
                    };
                    let result =
                        update::execute(catalog, loader, id, plan, delta, env, OutputMode::Honest)?;
                    if result.selected != selected
                        || result.committed != commit
                        || (result.outcome == "GlobalOverflowNoCommit") != overflow
                    {
                        return Err("UPDATE mode/control outcome mismatch".into());
                    }
                    if !commit && disk_state(catalog, id, env.directory)? != before {
                        return Err(
                            "Rejected/no-op UPDATE changed canonical/catalog/head state".into()
                        );
                    }
                    println!(
                        "{}",
                        json!({"experiment":"update-disk-control","case":label,"outcome":result.outcome,"selected":result.selected,"access":format!("{access:?}"),"profile":format!("{profile:?}"),"header":format!("{header:?}"),"stages":result.stages,"public_fixture_input_amounts":result.input_amounts,"public_fixture_updated_rows":result.output_rows,"proof":"Unavailable","local_oracle":true})
                    );
                }
            }
        }
    }
    // Use an untouched already-created table so endpoint controls cannot poison later positive modes.
    let boundary = if id == 0 { 1 } else { 0 };
    for (label, query, delta, minimum, maximum, count) in [
        (
            "actual_four_row_byte_carry",
            QuerySpec::Equal(251),
            55 - boundary as u16,
            256,
            259,
            4,
        ),
        (
            "actual_sixteen_row_65535_endpoint",
            QuerySpec::Equal(252),
            65215 - boundary as u16,
            65520,
            65535,
            16,
        ),
    ] {
        let plan = Plan {
            kernel: KernelMode::ExactIndex,
            access: Access::Private,
            profile: Profile::Fixed256,
            header: HeaderMode::Uncached,
            query,
            query_id: nonce()?,
        };
        let result = update::execute(
            catalog,
            loader,
            boundary,
            plan,
            delta,
            env,
            OutputMode::Honest,
        )?;
        let actual = result
            .output_rows
            .as_ref()
            .ok_or("Boundary UPDATE lacked values")?;
        if !result.committed
            || actual.len() != count
            || actual.first().map(|r| r.amount) != Some(minimum)
            || actual.last().map(|r| r.amount) != Some(maximum)
        {
            return Err("Actual compact-writeback byte-carry/endpoint control failed".into());
        }
        println!(
            "{}",
            json!({"experiment":"update-disk-boundary","case":label,"table_id":boundary,"delta":delta,"expected_min":minimum,"expected_max":maximum,"public_fixture_input_amounts":result.input_amounts,"public_fixture_updated_rows":result.output_rows,"stages":result.stages,"canonical_no_growth":true,"proof":"Unavailable"})
        );
    }
    Ok(())
}
