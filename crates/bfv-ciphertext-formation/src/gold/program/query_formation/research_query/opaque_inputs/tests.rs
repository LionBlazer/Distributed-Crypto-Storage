//! Actual native MMCS checks; tiny8 and full Query32768 are separate cases.
//! Public literal rows here are not an AIR trace, SQL answer or private fixture.
use super::super::research_config;
use super::*;
use p3_commit::Mmcs as _;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use rand_public_pp::{RngExt, SeedableRng, TryCryptoRng, TryRng, rngs::StdRng};

/// Count every delegated call without cloning a private RNG state. Seeds below
/// are explicitly public regression fixtures, never production entropy.
struct CountingRng {
    inner: StdRng,
    calls: usize,
}
impl CountingRng {
    fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            inner: StdRng::from_seed(seed),
            calls: 0,
        }
    }
}
impl TryRng for CountingRng {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> core::result::Result<u32, Self::Error> {
        self.calls += 1;
        self.inner.try_next_u32()
    }
    fn try_next_u64(&mut self) -> core::result::Result<u64, Self::Error> {
        self.calls += 1;
        self.inner.try_next_u64()
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> core::result::Result<(), Self::Error> {
        self.calls += 1;
        self.inner.try_fill_bytes(dst)
    }
}
impl TryCryptoRng for CountingRng {}

fn rows(widths: &[usize], indices: &[usize]) -> Vec<Rows> {
    indices
        .iter()
        .map(|&index| {
            widths
                .iter()
                .enumerate()
                .map(|(matrix, &width)| {
                    (0..width)
                        .map(|column| {
                            F::from_usize((matrix + 1) * 1_000_000 + index * 512 + column)
                        })
                        .collect()
                })
                .collect()
        })
        .collect()
}
fn copy(opening: &BatchMultiOpening<F, ResearchMmcs>) -> BatchMultiOpening<F, ResearchMmcs> {
    BatchMultiOpening {
        opened_values: opening.opened_values.clone(),
        opening_proof: opening.opening_proof.clone(),
    }
}
fn native(
    mmcs: &ResearchMmcs,
    cap: &MerkleCap<F, Digest>,
    dimensions: &[Dimensions],
    indices: &[usize],
    opening: &BatchMultiOpening<F, ResearchMmcs>,
) -> bool {
    mmcs.verify_multi_batch(
        cap,
        dimensions,
        indices,
        &opening.opened_values,
        &opening.opening_proof,
    )
    .is_ok()
}
fn require_hostile_rejections(
    mmcs: &ResearchMmcs,
    cap: &MerkleCap<F, Digest>,
    dimensions: &[Dimensions],
    indices: &[usize],
    honest: &BatchMultiOpening<F, ResearchMmcs>,
) {
    assert!(honest.opening_proof.1.sibling_hashes.len() >= 2);
    let mut changed = copy(honest);
    changed.opening_proof.1.sibling_hashes.swap(0, 1);
    assert!(
        !native(mmcs, cap, dimensions, indices, &changed),
        "frontier reordering"
    );
    let mut changed = copy(honest);
    changed.opening_proof.1.sibling_hashes.pop();
    assert!(
        !native(mmcs, cap, dimensions, indices, &changed),
        "missing frontier digest"
    );
    let mut changed = copy(honest);
    changed.opening_proof.1.sibling_hashes.push([0xbd; 32]);
    assert!(
        !native(mmcs, cap, dimensions, indices, &changed),
        "trailing frontier digest"
    );
    // Slot1 is a UNIQUE physical index in both supplied test grammars, so
    // these negatives test actual root binding, not only duplicate consistency.
    assert_eq!(
        indices.iter().filter(|&&index| index == indices[1]).count(),
        1
    );
    let mut changed = copy(honest);
    changed.opening_proof.0[1][0][0] += F::ONE;
    assert!(
        !native(mmcs, cap, dimensions, indices, &changed),
        "changed salt"
    );
    let mut changed = copy(honest);
    changed.opened_values[1][0][0] += F::ONE;
    assert!(
        !native(mmcs, cap, dimensions, indices, &changed),
        "changed row"
    );
    let mut changed = copy(honest);
    changed.opened_values[1][0].pop();
    assert!(
        !native(mmcs, cap, dimensions, indices, &changed),
        "changed matrix width"
    );
}
#[test]
fn literal_eight_leaf_opaque_tree_authenticates_real_native_multiproof_and_reuses_rows() {
    let programmer = Programmer::regression([0x61; 32]);
    let mut rng = CountingRng::from_seed([0x62; 32]);
    let widths = vec![2, 1];
    let mut tree = Tree::sample(8, widths.clone(), programmer.clone(), &mut rng).unwrap();
    let indices = [1, 2, 5, 1];
    let data = rows(&widths, &indices);
    let opening = tree.opening(&indices, &data, &mut rng).unwrap();
    let mmcs = research_config::mmcs(programmer.oracle(), StdRng::from_seed([0x63; 32]));
    assert!(native(
        &mmcs,
        &tree.commitment(),
        &tree.dimensions(),
        &indices,
        &opening
    ));
    // Manual canonical frontier from the SDK's literal diagram:
    // queried1,2,5 -> leaf0,leaf3,leaf4,then node(leaf6,leaf7).
    assert_eq!(
        opening.opening_proof.1.sibling_hashes,
        vec![
            tree.levels[0][0],
            tree.levels[0][3],
            tree.levels[0][4],
            tree.levels[1][3]
        ]
    );
    assert_eq!(opening.opened_values[0], opening.opened_values[3]);
    assert_eq!(opening.opening_proof.0[0], opening.opening_proof.0[3]);
    assert_eq!(
        opening.opening_proof.0[0]
            .iter()
            .map(Vec::len)
            .collect::<Vec<_>>(),
        [4, 4]
    );
    let before = rng.calls;
    let replay = tree.opening(&indices, &data, &mut rng).unwrap();
    assert_eq!(before, rng.calls);
    assert_eq!(
        postcard::to_allocvec(&opening).unwrap(),
        postcard::to_allocvec(&replay).unwrap()
    );
    let mut conflict = data.clone();
    conflict[3][0][0] += F::ONE;
    let before = rng.calls;
    assert!(matches!(
        tree.opening(&indices, &conflict, &mut rng),
        Err(Error::ConflictingRow)
    ));
    assert_eq!(before, rng.calls);
    require_hostile_rejections(
        &mmcs,
        &tree.commitment(),
        &tree.dimensions(),
        &indices,
        &opening,
    );
}

#[test]
fn frontier_matches_independent_genuine_native_open_multi_batch_on_public_literal_matrices() {
    let programmer = Programmer::regression([0x64; 32]);
    let oracle = programmer.oracle();
    let mmcs = research_config::mmcs(oracle.clone(), StdRng::from_seed([0x65; 32]));
    let widths = vec![2, 1];
    let all_indices: Vec<usize> = (0..8).collect();
    let all_rows = rows(&widths, &all_indices);
    let matrices = widths
        .iter()
        .enumerate()
        .map(|(matrix, &width)| {
            RowMajorMatrix::new(
                all_rows
                    .iter()
                    .flat_map(|row| row[matrix].iter().copied())
                    .collect(),
                width,
            )
        })
        .collect();
    let (cap, prover_data) = mmcs.commit(matrices);
    let (values, proof) = mmcs.open_multi_batch(&all_indices, &prover_data);
    assert_eq!(values, all_rows);
    let labels = values
        .iter()
        .zip(&proof.0)
        .map(|(query, salts)| {
            oracle.h256(leaf_input(
                query
                    .iter()
                    .zip(salts)
                    .flat_map(|(row, salt)| row.iter().chain(salt).copied()),
            ))
        })
        .collect();
    // from_labels is PRIVATE and used only for this genuine-public-fixture
    // comparison. The public Query constructor ALWAYS samples fresh labels.
    let tree = Tree::from_labels(8, widths, programmer, labels).unwrap();
    assert_eq!(tree.commitment().roots(), cap.roots());
    let indices = [5, 1, 2, 1];
    let (_, native_proof) = mmcs.open_multi_batch(&indices, &prover_data);
    assert_eq!(tree.frontier(&indices), native_proof.1.sibling_hashes);
}

#[test]
fn actual_query_four_input_geometries_use_32768_rows_192_indices_and_native_verification() {
    let programmer = Programmer::regression([0x66; 32]);
    let mut rng = CountingRng::from_seed([0x67; 32]);
    let mut forest = OpaqueInputs::new(programmer.clone(), &mut rng).unwrap();
    let mmcs = research_config::mmcs(programmer.oracle(), StdRng::from_seed([0x68; 32]));
    let mut indices: Vec<usize> = (0..192).map(|i| (257 * i + 17) & 32767).collect();
    indices[191] = indices[0];
    // Independent literal owning grammar, including quotient8 separate matrices.
    for (role, widths) in [
        (PrivateInput::Random, vec![10]),
        (PrivateInput::Main, vec![421]),
        (PrivateInput::Quotient, vec![10; 8]),
        (PrivateInput::Aux, vec![425]),
    ] {
        let dimensions: Vec<_> = widths
            .iter()
            .map(|&width| Dimensions {
                width,
                height: 32768,
            })
            .collect();
        let actual = forest.dimensions(role);
        assert_eq!(actual.len(), dimensions.len());
        assert!(
            actual
                .iter()
                .zip(&dimensions)
                .all(|(a, b)| a.width == b.width && a.height == b.height)
        );
        let data = rows(&widths, &indices);
        let opening = forest.opening(role, &indices, &data, &mut rng).unwrap();
        assert!(native(
            &mmcs,
            &forest.commitment(role),
            &dimensions,
            &indices,
            &opening
        ));
        assert!(opening.opening_proof.1.sibling_hashes.len() <= 192 * 15);
        assert_eq!(opening.opened_values[0], opening.opened_values[191]);
        assert_eq!(opening.opening_proof.0[0], opening.opening_proof.0[191]);
        let before = rng.calls;
        let replay = forest.opening(role, &indices, &data, &mut rng).unwrap();
        assert_eq!(before, rng.calls);
        assert_eq!(
            postcard::to_allocvec(&opening).unwrap(),
            postcard::to_allocvec(&replay).unwrap()
        );
        require_hostile_rejections(
            &mmcs,
            &forest.commitment(role),
            &dimensions,
            &indices,
            &opening,
        );
    }
    // The constructor cannot be persuaded to build a smaller/faster Query tree.
    let data = rows(&[10], &indices);
    assert!(matches!(
        forest.opening(
            PrivateInput::Random,
            &indices[..191],
            &data[..191],
            &mut rng
        ),
        Err(Error::Shape)
    ));
    let mut out_of_range = indices.clone();
    out_of_range[0] = 32768;
    assert!(matches!(
        forest.opening(PrivateInput::Random, &out_of_range, &data, &mut rng),
        Err(Error::Shape)
    ));

    // Disclosure accounting is across calls, not only one request's length.
    // Fill the quotient's one unused slot, then reject a193rd distinct leaf
    // before consuming any salts or modifying that tree's programmed table.
    let mut maximal = indices.clone();
    maximal[191] = 0;
    let maximal_rows = rows(&[10; 8], &maximal);
    let full = forest
        .opening(PrivateInput::Quotient, &maximal, &maximal_rows, &mut rng)
        .unwrap();
    assert!(native(
        &mmcs,
        &forest.commitment(PrivateInput::Quotient),
        &forest.dimensions(PrivateInput::Quotient),
        &maximal,
        &full
    ));
    let mut excessive = maximal.clone();
    excessive[190] = 1;
    assert!(!maximal.contains(&1));
    let before = rng.calls;
    assert!(matches!(
        forest.opening(
            PrivateInput::Quotient,
            &excessive,
            &rows(&[10; 8], &excessive),
            &mut rng
        ),
        Err(Error::DisclosureLimit)
    ));
    assert_eq!(before, rng.calls);

    // One extra unique row fits the192-distinct disclosure cap because the
    // original batch repeated its first index. Force a pre-existing incompatible
    // LEAF answer, proving the builder never overwrites it or retries the proof.
    assert!(!indices.contains(&0));
    let mut fresh_indices = indices.clone();
    fresh_indices[191] = 0;
    let fresh_rows = rows(&[10], &fresh_indices);
    // Explicit public TEST seed gives an independent preview without cloning
    // hidden production state. Only this forced-conflict regression reseeds.
    rng = CountingRng::from_seed([0x69; 32]);
    let mut preview = StdRng::from_seed([0x69; 32]);
    let salt: Vec<F> = (0..4).map(|_| preview.random()).collect();
    let raw = leaf_input(fresh_rows[191][0].iter().chain(&salt).copied());
    let mut incompatible = forest.trees[PrivateInput::Random.index()].levels[0][0];
    incompatible[0] ^= 1;
    programmer.plant256(raw.clone(), incompatible).unwrap();
    assert!(matches!(
        forest.opening(PrivateInput::Random, &fresh_indices, &fresh_rows, &mut rng),
        Err(Error::ProgrammingConflict)
    ));
    assert_eq!(programmer.oracle().h256(raw), incompatible);
    assert!(matches!(
        forest.opening(
            PrivateInput::Main,
            &indices,
            &rows(&[421], &indices),
            &mut rng
        ),
        Err(Error::FailedAttempt)
    ));
    eprintln!(
        "research_query opaque_inputs_native_MMCS=true private_commits=4 height=32768 indices=192 native_positive=5 native_negative=24 repeated_row_salt_reuse=true programming_conflict_fail_closed=true PP_in_forest=false full_simulator=false admission=false"
    );
}
