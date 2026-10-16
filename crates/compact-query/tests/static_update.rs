//! Public synthetic source fixtures and genuine full-residue BFV proofs.
#![cfg(feature = "bfv-experiment")]
use bfv_query_core::{PublicSetup, PublicUpdateEvaluator};
use bfv_query_proof::{GeneratedOperation, Operation, prove};
use compact_query::{
    AgeRange, Error, PageSource, PlainRow, ReadHeads, Table, TableId, UpdateView,
    bfv::{Owner, PreparedUpdate},
};
use compact_store::{Commitment, Limits, LookupResponse, VerifiedPage};
use std::{cell::RefCell, collections::BTreeMap};

fn index_limits() -> Limits {
    Limits {
        max_rows: Limits::default().max_image_bytes as u64,
        ..Limits::default()
    }
}
struct Prefix {
    head: Commitment,
    pages: BTreeMap<u64, LookupResponse>,
    calls: RefCell<Vec<u64>>,
    missing: RefCell<Option<u64>>,
}
impl Prefix {
    fn new(table: &Table) -> Self {
        let count = table
            .read_heads()
            .read_requirements()
            .unwrap()
            .index_prefix_pages;
        Self {
            head: table.index_commitment().clone(),
            pages: (0..u64::from(count))
                .map(|page| (page, table.lookup_index_page(page).unwrap()))
                .collect(),
            calls: Default::default(),
            missing: Default::default(),
        }
    }
    fn view<'a>(&'a self, table: &'a Table, heads: ReadHeads) -> UpdateView<'a> {
        let path = self.pages[&0]
            .verify_for_reissue(&self.head, 0, index_limits())
            .unwrap();
        UpdateView::new(heads, table.snapshot(), self, path).unwrap()
    }
}
impl PageSource for Prefix {
    fn commitment(&self) -> &Commitment {
        &self.head
    }
    fn lookup(&self, page: u64, limits: Limits) -> compact_query::Result<VerifiedPage> {
        self.calls.borrow_mut().push(page);
        if *self.missing.borrow() == Some(page) {
            return Err(Error::InvalidIndex);
        }
        let response = self.pages.get(&page).ok_or(Error::InvalidIndex)?;
        Ok(response.verify(&self.head, page, limits)?)
    }
}
fn public(peer: &compact_query::bfv::Evaluator) -> PublicUpdateEvaluator {
    let setup =
        PublicSetup::from_bytes(&peer.encode_public_setup_for_experiment().unwrap()).unwrap();
    PublicUpdateEvaluator::from_parameters(&setup.update_parameters().unwrap()).unwrap()
}
fn prove_update(public: &PublicUpdateEvaluator, prepared: &PreparedUpdate) -> GeneratedOperation {
    prove(&public.circuit_request(prepared.request()).unwrap()).unwrap()
}
fn images(table: &Table) -> (Vec<u8>, Vec<u8>) {
    (table.snapshot().encode(), table.encrypted_index().encode())
}

#[test]
fn million_row_update_uses_only_prefix_pages_and_preserves_the_entire_encrypted_identity_tail() {
    let limits = Limits::default();
    let (owner, peer) = Owner::generate([101; 16]).unwrap();
    let public = public(&peer);
    let selected = [3, 8888, 999999];
    let mut rows = vec![
        PlainRow {
            age: 18,
            amount: 255
        };
        1_000_000
    ];
    for ordinal in selected {
        rows[ordinal as usize].age = 42;
    }
    let table = owner.seal(&rows, 256, limits).unwrap();
    let before = images(&table);
    let original_ids = owner.row_references(&table, &selected).unwrap();
    let prefix = Prefix::new(&table);
    let view = prefix.view(&table, table.read_heads());
    let prepared = owner
        .prepare_provable_update_from_source(
            view.read_view(),
            Some(AgeRange::equal(42)),
            1,
            256,
            limits,
        )
        .unwrap();
    assert_eq!(prepared.selected_rows(), 3);
    let generated = prove_update(&public, &prepared);
    let checked = owner
        .check_update_proof_from_source(
            &table.read_heads(),
            &prepared,
            generated.output(),
            generated.proof(),
        )
        .unwrap();

    let result = owner
        .stage_checked_update_from_source(view, prepared, generated.output(), checked, limits)
        .unwrap();

    assert_eq!(result.evidence().operation(), Operation::Addition);
    assert_eq!(
        (
            result.matched_rows(),
            result.changed_rows(),
            result.overflowed()
        ),
        (3, 3, false)
    );
    let patch = result.into_patch().unwrap();
    assert_eq!(patch.replaced_data_pages(), &[0, 34, 3906]);
    assert_eq!(patch.heads().data(), patch.data().commitment());
    assert_eq!(patch.heads().table_id(), table.table_id());
    let (page, proof) = patch.index_replacement();
    assert_eq!(page, 0);
    let header = proof
        .verify(patch.heads().index(), page, index_limits())
        .unwrap();
    // Independent FULL fixture reconstruction with the exact returned packet.
    let index = table
        .encrypted_index()
        .clone()
        .apply_verified_replacements(
            table.index_commitment(),
            patch.heads().index(),
            vec![header],
            index_limits(),
        )
        .unwrap();
    let restored = owner
        .restore_table_for_experiment(
            &patch.data().encode(),
            &index.encode(),
            table.table_id(),
            patch.heads().data(),
            patch.heads().index(),
            limits,
        )
        .unwrap();
    let ids = owner.row_references(&restored, &selected).unwrap();
    assert_eq!(ids.rows(), original_ids.rows());
    assert_eq!(ids.table_id(), original_ids.table_id());
    for ordinal in selected {
        assert_eq!(
            owner
                .decrypt_row_for_experiment(&restored, ordinal, limits)
                .unwrap(),
            PlainRow {
                age: 42,
                amount: 256
            }
        );
    }
    let unchanged_suffix = compact_store::MANIFEST_BYTES + 4096 + compact_store::PAGE_OVERHEAD;
    assert_eq!(
        &before.1[unchanged_suffix..],
        &index.encode()[unchanged_suffix..]
    );
    assert_eq!(images(&table), before);
    assert!(prefix.head.layout().page_count().unwrap() > prefix.pages.len());
    assert!(
        prefix
            .calls
            .borrow()
            .iter()
            .all(|page| prefix.pages.contains_key(page))
    );
}

#[test]
fn genuine_empty_zero_delta_and_overflow_results_never_reissue_source_images() {
    let limits = Limits::default();
    let (owner, peer) = Owner::generate([102; 16]).unwrap();
    let public = public(&peer);
    let table = owner
        .seal(
            &[
                PlainRow {
                    age: 42,
                    amount: 255,
                },
                PlainRow {
                    age: 7,
                    amount: 65535,
                },
                PlainRow {
                    age: 42,
                    amount: 256,
                },
            ],
            2,
            limits,
        )
        .unwrap();
    let before = images(&table);
    for (predicate, delta, matched, overflowed) in [
        (None, 1, 0, false),
        (Some(AgeRange::equal(42)), 0, 2, false),
        (
            Some(AgeRange {
                lower: 0,
                upper: 255,
            }),
            1,
            3,
            true,
        ),
    ] {
        let prefix = Prefix::new(&table);
        let view = prefix.view(&table, table.read_heads());
        let prepared = owner
            .prepare_provable_update_from_source(view.read_view(), predicate, delta, 256, limits)
            .unwrap();
        let generated = prove_update(&public, &prepared);
        let checked = owner
            .check_update_proof_from_source(
                &table.read_heads(),
                &prepared,
                generated.output(),
                generated.proof(),
            )
            .unwrap();
        let calls = prefix.calls.borrow().clone();

        let result = owner
            .stage_checked_update_from_source(view, prepared, generated.output(), checked, limits)
            .unwrap();

        assert_eq!(result.matched_rows(), matched);
        assert_eq!(result.changed_rows(), 0);
        assert_eq!(result.overflowed(), overflowed);
        assert!(result.patch().is_none());
        assert_eq!(*prefix.calls.borrow(), calls);
        assert_eq!(images(&table), before);
    }
}

#[test]
fn whole_logical_heads_exact_evidence_and_current_source_limits_bind_static_staging() {
    let limits = Limits::default();
    let (owner, peer) = Owner::generate([103; 16]).unwrap();
    let public = public(&peer);
    let table = owner
        .seal(
            &[PlainRow {
                age: 42,
                amount: 255,
            }; 3],
            2,
            limits,
        )
        .unwrap();
    let before = images(&table);
    let prefix = Prefix::new(&table);
    let prepare = || {
        owner
            .prepare_provable_update_from_source(
                &table.read_view(),
                Some(AgeRange::equal(42)),
                1,
                256,
                limits,
            )
            .unwrap()
    };
    let prepared = prepare();
    let generated = prove_update(&public, &prepared);
    let alias = ReadHeads::new(
        TableId::from_bytes([99; 32]).unwrap(),
        table.commitment(),
        table.index_commitment(),
        limits,
    )
    .unwrap();
    assert!(matches!(
        owner.check_update_proof_from_source(
            &alias,
            &prepared,
            generated.output(),
            generated.proof()
        ),
        Err(Error::WrongVersion)
    ));
    let checked = owner
        .check_update_proof_from_source(
            &table.read_heads(),
            &prepared,
            generated.output(),
            generated.proof(),
        )
        .unwrap();
    assert!(matches!(
        owner.stage_checked_update_from_source(
            prefix.view(&table, alias),
            prepared,
            generated.output(),
            checked,
            limits
        ),
        Err(Error::WrongVersion)
    ));

    let prepared = prepare();
    let other = prepare();
    let generated = prove_update(&public, &prepared);
    let checked = owner
        .check_update_proof_from_source(
            &table.read_heads(),
            &prepared,
            generated.output(),
            generated.proof(),
        )
        .unwrap();
    assert!(matches!(
        owner.stage_checked_update_from_source(
            prefix.view(&table, table.read_heads()),
            other,
            generated.output(),
            checked,
            limits
        ),
        Err(Error::ComputationProof(_))
    ));
    let changed_source = owner
        .seal(
            &[PlainRow {
                age: 42,
                amount: 256,
            }; 3],
            2,
            limits,
        )
        .unwrap();
    let changed_prefix = Prefix::new(&changed_source);
    let checked = owner
        .check_update_proof_from_source(
            &table.read_heads(),
            &prepared,
            generated.output(),
            generated.proof(),
        )
        .unwrap();
    assert!(matches!(
        owner.stage_checked_update_from_source(
            changed_prefix.view(&changed_source, changed_source.read_heads()),
            prepared,
            generated.output(),
            checked,
            limits
        ),
        Err(Error::WrongVersion)
    ));
    let prepared = prepare();
    let generated = prove_update(&public, &prepared);
    let checked = owner
        .check_update_proof_from_source(
            &table.read_heads(),
            &prepared,
            generated.output(),
            generated.proof(),
        )
        .unwrap();
    let low = Limits {
        max_image_bytes: table.canonical_data_bytes() - 1,
        ..limits
    };
    assert!(
        owner
            .stage_checked_update_from_source(
                prefix.view(&table, table.read_heads()),
                prepared,
                generated.output(),
                checked,
                low
            )
            .is_err()
    );
    assert_eq!(images(&table), before);
}

#[test]
fn incomplete_later_prefix_or_missing_header_rejects_and_preserves_the_whole_source() {
    let limits = Limits::default();
    let (owner, peer) = Owner::generate([104; 16]).unwrap();
    let public = public(&peer);
    let mut rows = vec![PlainRow { age: 0, amount: 7 }; 10_000];
    for index in [1, 5000, 9999] {
        rows[index].age = 42;
    }
    let table = owner.seal(&rows, 256, limits).unwrap();
    let before = images(&table);
    let prefix = Prefix::new(&table);
    let prepared = owner
        .prepare_provable_update_from_source(
            prefix.view(&table, table.read_heads()).read_view(),
            Some(AgeRange::equal(42)),
            1,
            256,
            limits,
        )
        .unwrap();
    let later = *prefix.calls.borrow().iter().max().unwrap();
    assert!(later > 0);
    *prefix.missing.borrow_mut() = Some(later);
    assert!(
        owner
            .prepare_provable_update_from_source(
                prefix.view(&table, table.read_heads()).read_view(),
                Some(AgeRange::equal(42)),
                1,
                256,
                limits
            )
            .is_err()
    );
    *prefix.missing.borrow_mut() = None;
    let generated = prove_update(&public, &prepared);
    let checked = owner
        .check_update_proof_from_source(
            &table.read_heads(),
            &prepared,
            generated.output(),
            generated.proof(),
        )
        .unwrap();
    *prefix.missing.borrow_mut() = Some(0);

    assert!(
        owner
            .stage_checked_update_from_source(
                prefix.view(&table, table.read_heads()),
                prepared,
                generated.output(),
                checked,
                limits
            )
            .is_err()
    );

    assert_eq!(images(&table), before);
}

#[test]
fn update_view_rejects_foreign_or_nonzero_header_paths_and_preparation_keeps_256_budget() {
    let limits = Limits::default();
    let (owner, _) = Owner::generate([105; 16]).unwrap();
    let table = owner
        .seal(&[PlainRow { age: 42, amount: 7 }; 300], 256, limits)
        .unwrap();
    let foreign = owner
        .seal(&[PlainRow { age: 42, amount: 7 }; 300], 256, limits)
        .unwrap();
    for (image, page) in [(table.encrypted_index(), 1), (foreign.encrypted_index(), 0)] {
        let path = image
            .lookup(page, index_limits())
            .unwrap()
            .verify_for_reissue(image.commitment(), page, index_limits())
            .unwrap();
        assert!(matches!(
            UpdateView::new(
                table.read_heads(),
                table.snapshot(),
                table.encrypted_index(),
                path
            ),
            Err(Error::WrongVersion)
        ));
    }
    assert!(matches!(
        owner.prepare_provable_update_from_source(
            &table.read_view(),
            Some(AgeRange::equal(42)),
            1,
            usize::MAX,
            limits
        ),
        Err(Error::SelectionBudget {
            selected: 300,
            budget: 256
        })
    ));
}

#[test]
fn reissued_small_index_header_preserves_every_row_identity_inside_page_zero() {
    let limits = Limits::default();
    let (owner, peer) = Owner::generate([106; 16]).unwrap();
    let public = public(&peer);
    let table = owner
        .seal(
            &[PlainRow {
                age: 42,
                amount: 255,
            }; 3],
            2,
            limits,
        )
        .unwrap();
    assert_eq!(table.index_commitment().layout().page_count().unwrap(), 1);
    let original = owner.row_references(&table, &[0, 1, 2]).unwrap();
    let before = images(&table);
    let prefix = Prefix::new(&table);
    let view = prefix.view(&table, table.read_heads());
    let prepared = owner
        .prepare_provable_update_from_source(
            view.read_view(),
            Some(AgeRange::equal(42)),
            1,
            256,
            limits,
        )
        .unwrap();
    let generated = prove_update(&public, &prepared);
    let checked = owner
        .check_update_proof_from_source(
            &table.read_heads(),
            &prepared,
            generated.output(),
            generated.proof(),
        )
        .unwrap();

    let result = owner
        .stage_checked_update_from_source(view, prepared, generated.output(), checked, limits)
        .unwrap();

    let patch = result.into_patch().unwrap();
    let (page, proof) = patch.index_replacement();
    let checked = proof
        .verify(patch.heads().index(), page, index_limits())
        .unwrap();
    let index = table
        .encrypted_index()
        .clone()
        .apply_verified_replacements(
            table.index_commitment(),
            patch.heads().index(),
            vec![checked],
            index_limits(),
        )
        .unwrap();
    let restored = owner
        .restore_table_for_experiment(
            &patch.data().encode(),
            &index.encode(),
            table.table_id(),
            patch.heads().data(),
            patch.heads().index(),
            limits,
        )
        .unwrap();
    assert_eq!(
        owner.row_references(&restored, &[0, 1, 2]).unwrap().rows(),
        original.rows()
    );
    assert_eq!(images(&table), before);
}
