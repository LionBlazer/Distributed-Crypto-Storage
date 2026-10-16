//! Public synthetic sources cross the genuine serialized BFV proof boundary.
#![cfg(feature = "bfv-experiment")]
use bfv_query_core::{PublicSetup, PublicUpdateEvaluator};
use compact_query::{
    AgeRange, Error, PageSource, PlainRow, ReadHeads, ReadView, TableId,
    bfv::{Owner, POLYNOMIAL_AGGREGATE_CAPACITY},
};
use compact_store::{Commitment, Limits, LookupResponse, VerifiedPage};
use std::cell::RefCell;

/// Owns only the public posting prefix; omitted RowId pages cannot be requested.
struct PostingPrefix {
    head: Commitment,
    pages: Vec<LookupResponse>,
    requested: RefCell<Vec<u64>>,
}
impl PostingPrefix {
    fn from_table(table: &compact_query::Table) -> Self {
        let count = table
            .read_heads()
            .read_requirements()
            .unwrap()
            .index_prefix_pages;
        assert!((count as usize) < table.index_commitment().layout().page_count().unwrap());
        Self {
            head: table.index_commitment().clone(),
            pages: (0..u64::from(count))
                .map(|page| table.lookup_index_page(page).unwrap())
                .collect(),
            requested: RefCell::new(Vec::new()),
        }
    }
}
impl PageSource for PostingPrefix {
    fn commitment(&self) -> &Commitment {
        &self.head
    }
    fn lookup(&self, page: u64, limits: Limits) -> compact_query::Result<VerifiedPage> {
        self.requested.borrow_mut().push(page);
        Ok(self
            .pages
            .get(page as usize)
            .ok_or(Error::InvalidIndex)?
            .verify(&self.head, page, limits)?)
    }
}
fn evaluator(peer: &compact_query::bfv::Evaluator) -> PublicUpdateEvaluator {
    let setup =
        PublicSetup::from_bytes(&peer.encode_public_setup_for_experiment().unwrap()).unwrap();
    PublicUpdateEvaluator::from_parameters(&setup.update_parameters().unwrap()).unwrap()
}

#[test]
fn million_row_posting_prefix_completes_the_same_checked_aggregate_without_the_identity_tail() {
    let limits = Limits::default();
    let (owner, peer) = Owner::generate([96; 16]).unwrap();
    let public = evaluator(&peer);
    let source: Vec<_> = (0..1_000_000usize)
        .map(|ordinal| PlainRow {
            age: if ordinal >= 1_000_000 - POLYNOMIAL_AGGREGATE_CAPACITY {
                42
            } else {
                7
            },
            amount: (ordinal % 65_536) as u16,
        })
        .collect();
    let expected_sum = source
        .iter()
        .filter(|row| row.age == 42)
        .map(|row| u32::from(row.amount))
        .sum::<u32>();
    let table = owner.seal(&source, 256, limits).unwrap();
    let heads = table.read_heads();
    // The prepared capability survives after all temporary source proofs drop.
    let prepared = {
        let prefix = PostingPrefix::from_table(&table);
        let view = ReadView::new(heads.clone(), table.snapshot(), &prefix).unwrap();
        let prepared = owner
            .prepare_provable_aggregate_from_source(
                &view,
                Some(AgeRange::equal(42)),
                POLYNOMIAL_AGGREGATE_CAPACITY,
                limits,
            )
            .unwrap();
        let requested = prefix.requested.borrow();
        assert!(!requested.is_empty());
        assert!(
            requested
                .iter()
                .all(|&page| page < prefix.pages.len() as u64)
        );
        prepared
    };
    let input = public
        .aggregate_circuit_request(prepared.request())
        .unwrap();
    let generated = bfv_query_proof::prove(&input).unwrap();
    let checked = owner
        .check_aggregate_proof_for_heads(&heads, &prepared, generated.output(), generated.proof())
        .unwrap();

    // The full-table entry point accepts the exact SAME pending encrypted packet.
    let answer = owner
        .complete_checked_aggregate(&table, prepared, generated.output(), checked)
        .unwrap();

    assert_eq!(answer.count(), POLYNOMIAL_AGGREGATE_CAPACITY as u32);
    assert_eq!(answer.sum(), Some(expected_sum));
    assert!(
        answer
            .evidence()
            .matches_statement(&input, generated.output())
    );
}

#[test]
fn aggregate_completion_rechecks_table_identity_each_head_and_exact_checked_statement() {
    let limits = Limits::default();
    let (owner, peer) = Owner::generate([97; 16]).unwrap();
    let public = evaluator(&peer);
    let table = owner
        .seal(
            &vec![
                PlainRow {
                    age: 18,
                    amount: 65_535
                };
                300
            ],
            17,
            limits,
        )
        .unwrap();
    let heads = table.read_heads();
    let prefix = PostingPrefix::from_table(&table);
    let view = ReadView::new(heads.clone(), table.snapshot(), &prefix).unwrap();
    let changed_root = |head: &Commitment, index| {
        let mut bytes = head.encode();
        bytes[80] ^= 1;
        if index {
            compact_query::decode_index_head(&bytes, 300).unwrap()
        } else {
            Commitment::decode(&bytes, limits).unwrap()
        }
    };
    let alternatives = [
        ReadHeads::new(
            TableId::from_bytes([98; 32]).unwrap(),
            heads.data(),
            heads.index(),
            limits,
        )
        .unwrap(),
        ReadHeads::new(
            *heads.table_id(),
            &changed_root(heads.data(), false),
            heads.index(),
            limits,
        )
        .unwrap(),
        ReadHeads::new(
            *heads.table_id(),
            heads.data(),
            &changed_root(heads.index(), true),
            limits,
        )
        .unwrap(),
    ];
    for alternative in alternatives {
        let prepared = owner
            .prepare_provable_aggregate_from_source(&view, Some(AgeRange::equal(18)), 300, limits)
            .unwrap();
        let generated = bfv_query_proof::prove(
            &public
                .aggregate_circuit_request(prepared.request())
                .unwrap(),
        )
        .unwrap();
        let checked = owner
            .check_aggregate_proof_for_heads(
                &heads,
                &prepared,
                generated.output(),
                generated.proof(),
            )
            .unwrap();
        assert!(matches!(
            owner.check_aggregate_proof_for_heads(
                &alternative,
                &prepared,
                generated.output(),
                generated.proof()
            ),
            Err(Error::WrongVersion)
        ));
        assert!(matches!(
            owner.complete_checked_aggregate_for_heads(
                &alternative,
                prepared,
                generated.output(),
                checked
            ),
            Err(Error::WrongVersion)
        ));
    }
    let prepared = owner
        .prepare_provable_aggregate_from_source(&view, Some(AgeRange::equal(18)), 300, limits)
        .unwrap();
    let generated = bfv_query_proof::prove(
        &public
            .aggregate_circuit_request(prepared.request())
            .unwrap(),
    )
    .unwrap();
    let checked = owner
        .check_aggregate_proof_for_heads(&heads, &prepared, generated.output(), generated.proof())
        .unwrap();
    let second = owner
        .prepare_provable_aggregate_from_source(&view, Some(AgeRange::equal(18)), 300, limits)
        .unwrap();
    assert!(matches!(
        owner.complete_checked_aggregate_for_heads(&heads, second, generated.output(), checked),
        Err(Error::ComputationProof(_))
    ));
    let checked = owner
        .check_aggregate_proof(&table, &prepared, generated.output(), generated.proof())
        .unwrap();
    let mut altered = generated.output().to_vec();
    *altered.last_mut().unwrap() ^= 1;
    assert!(matches!(
        owner.complete_checked_aggregate_for_heads(&heads, prepared, &altered, checked),
        Err(Error::ComputationProof(_))
    ));
}

#[test]
fn static_aggregate_rejects_incomplete_postings_and_budget_before_encrypting_an_answer() {
    let limits = Limits::default();
    let (owner, _) = Owner::generate([98; 16]).unwrap();
    let table = owner
        .seal(
            &vec![
                PlainRow {
                    age: 255,
                    amount: 1
                };
                2_561
            ],
            256,
            limits,
        )
        .unwrap();
    let heads = table.read_heads();
    let prefix = PostingPrefix::from_table(&table);
    let view = ReadView::new(heads.clone(), table.snapshot(), &prefix).unwrap();
    assert!(matches!(
        owner.prepare_provable_aggregate_from_source(
            &view,
            Some(AgeRange::equal(255)),
            usize::MAX,
            limits
        ),
        Err(Error::SelectionBudget {
            selected: 2561,
            budget: 2560
        })
    ));
    let alias = ReadHeads::new(
        TableId::from_bytes([99; 32]).unwrap(),
        heads.data(),
        heads.index(),
        limits,
    )
    .unwrap();
    let alias_view = ReadView::new(alias, table.snapshot(), &prefix).unwrap();
    assert!(matches!(
        owner.prepare_provable_aggregate_from_source(&alias_view, None, 2560, limits),
        Err(Error::WrongVersion)
    ));
    let smaller = owner
        .seal(
            &vec![
                PlainRow {
                    age: 255,
                    amount: 1
                };
                2_560
            ],
            256,
            limits,
        )
        .unwrap();
    let mut prefix = PostingPrefix::from_table(&smaller);
    prefix.pages.pop();
    let view = ReadView::new(smaller.read_heads(), smaller.snapshot(), &prefix).unwrap();
    assert!(
        owner
            .prepare_provable_aggregate_from_source(&view, Some(AgeRange::equal(255)), 2560, limits)
            .is_err()
    );
    assert_eq!(
        prefix.requested.borrow().last().copied(),
        Some(prefix.pages.len() as u64)
    );
}
