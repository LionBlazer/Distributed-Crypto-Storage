//! Complete native symbolic snapshot before adding any witness or proof backend.
use super::*;
use bfv_hiding_stark::{Challenge, Challenger, Pcs};
use p3_air::symbolic::AirLayout;
use p3_batch_stark::symbolic::{get_log_num_quotient_chunks_for_domain, get_symbolic_constraints};
use p3_commit::{PolynomialSpace, UnivariateStarkPcs};
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_lookup::{LogUpGadget, Lookups};

#[test]
fn complete_ordered_native_constraints_and_lookups_snapshot() {
    let air = air::MetadataAir::new(&expected().unwrap()).unwrap();
    let layout = AirLayout::from_air(&air);
    let domain = TwoAdicMultiplicativeCoset::<Val>::new(Val::ONE, LOG_H).unwrap();
    let gadget = LogUpGadget::new();
    let zk = usize::from(<Pcs as UnivariateStarkPcs<Challenge, Challenger>>::ZK);
    assert_eq!(zk, 1);
    let original = Lookups::<Val>::from_air::<Challenge, _>(&air);
    let log = get_log_num_quotient_chunks_for_domain::<Val, Challenge, _, _>(
        &air, layout, domain, &original, zk, &gadget,
    );
    let packed = original
        .clone()
        .pack_same_bus_with_degree((1 << log) + 1 - zk, |lookup| {
            gadget.constraint_degree_with_transition(lookup, domain.transition_degree_multiple())
        });
    assert_eq!(
        get_log_num_quotient_chunks_for_domain::<Val, Challenge, _, _>(
            &air, layout, domain, &packed, zk, &gadget,
        ),
        log,
    );
    let (base, extension) =
        get_symbolic_constraints::<Val, Challenge, _, _>(&air, layout, &packed, &gadget);
    assert_eq!(
        [base.len(), extension.len(), original.len(), packed.len()],
        [1248, 84, 243, 81]
    );
    assert_eq!(1 << (log + zk), 8);
    let bytes = postcard::to_allocvec(&(base, extension, original, packed)).unwrap();
    assert!(bytes.len() <= 4 * 1024 * 1024);
    let mut hash = Sha256::new();
    hash.update(DOMAIN);
    hash.update(b"/ordered-native-postcard-p3-0.8/v1");
    hash.update(&bytes);
    let digest = hex(hash.finalize());
    // Root native r28 captured this complete tuple before a MAIN/proof existed.
    assert_eq!(bytes.len(), 571450);
    assert_eq!(
        digest,
        "6fe109f433d7f0c66dc51ec403cd103bdbf0056a72634af2cc0888a8ba8b3814"
    );
    eprintln!(
        "dense_data_inventory_ordered ordered={} symbolic_bytes={} MAIN=false full_PP=false proof=false accepted=false",
        digest,
        bytes.len()
    );
}
