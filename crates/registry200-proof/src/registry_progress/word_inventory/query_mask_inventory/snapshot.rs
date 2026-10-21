//! Full native AIR and complete public routing capture before any private writer.
use super::{air::QueryMaskAir, layout::*, *};
use bfv_hiding_stark::{Challenge, Challenger, Pcs};
use p3_air::symbolic::AirLayout;
use p3_batch_stark::symbolic::get_symbolic_constraints;
use p3_commit::UnivariateStarkPcs;
use p3_field::PrimeField64;
use p3_lookup::{LogUpGadget, Lookups};

fn hex(bytes: impl AsRef<[u8]>) -> String {
    use core::fmt::Write;
    let mut out = String::new();
    for byte in bytes.as_ref() {
        write!(&mut out, "{byte:02x}").unwrap();
    }
    out
}

pub(super) fn require_closed(air: &QueryMaskAir) {
    let lookups = Lookups::<Val>::from_air::<Challenge, _>(air);
    assert!(lookups.is_empty());
    const { assert!(<Pcs as UnivariateStarkPcs<Challenge, Challenger>>::ZK) };
    let (base, extension) = get_symbolic_constraints::<Val, Challenge, _, _>(
        air,
        AirLayout::from_air(air),
        &lookups,
        &LogUpGadget::new(),
    );
    assert!(extension.is_empty());
    let bytes = postcard::to_allocvec(&(base, extension, lookups)).unwrap();
    assert!(bytes.len() <= 4 * 1024 * 1024);
    let mut ordered = Sha256::new();
    ordered.update(PROFILE_DOMAIN);
    ordered.update(b"/ordered-native-postcard-p3-0.8/v1");
    ordered.update(&bytes);
    let mut pp = Sha256::new();
    pp.update(PROFILE_DOMAIN);
    pp.update(b"/complete-PP-LE64/v1");
    pp.update((HEIGHT as u64).to_le_bytes());
    pp.update((PP_WIDTH as u64).to_le_bytes());
    for row in 0..HEIGHT {
        for value in air.plan.pp_row(row) {
            pp.update(value.as_canonical_u64().to_le_bytes());
        }
    }
    // Root native r32 captured these before any private writer or proof existed.
    let pins = [hex(profile()), hex(ordered.finalize()), hex(pp.finalize())];
    assert_eq!(bytes.len(), 536034);
    assert_eq!(
        pins,
        [
            "9c7eed4ea91c661a27e786718132d9af85cbe6e7a23f44339dbde7490a0aeaae",
            "4976a8a87c3a88248fba246a0e7992c5b95da7baa446eb44b9d4fb18f57a0627",
            "2074e398f262919412ded11aeaebd2c8543b02d80ed1fcc5961053f4abe86c0c",
        ]
    );
    eprintln!(
        "query_mask_inventory_snapshot profile={} ordered={} symbolic_bytes={} full_pp={} pp_fields={} MAIN=false full_PP_matrix=false PP_commitment=false proof=false accepted=false",
        pins[0],
        pins[1],
        bytes.len(),
        pins[2],
        HEIGHT * PP_WIDTH
    );
}

#[test]
fn full_ordered_native_air_and_every_public_routing_field_snapshot() {
    require_closed(&QueryMaskAir::closed().unwrap());
}
