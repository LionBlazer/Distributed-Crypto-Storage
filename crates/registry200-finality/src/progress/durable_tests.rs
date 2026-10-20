//! Real filesystem/floor/WAL faults on the same shared engine.
use super::*;
use crate::joint::history::tests::keys;
use crate::progress::{
    self,
    tests::{block, checkpoint, install},
};
use version_journal::Body;

#[test]
fn progress_floor_ack_loss_recovers_but_partial_floor_never_repairs() {
    for fault in [
        crate::store::Fault::AfterSync,
        crate::store::Fault::Partial(9),
    ] {
        let (directory, quota, binding, mut owner, history, ingress) = install();
        let body = block(&history, &Body::Empty);
        let d = owner
            .import_candidate(body.header().clone(), body.body())
            .unwrap();
        let q = checkpoint(owner.context().unwrap(), &d, 0);
        let paths = Paths::participant(
            &quota,
            Pins::Progress(&binding),
            keys().remove(0).verifying_key().to_bytes(),
        );
        owner.engine.floor.inject(fault);
        assert!(owner.receive_checkpoint(&q).is_err());
        assert!(owner.outbound().is_err());
        assert!(owner.finalized_parent().is_err());
        assert!(quota.depot_budget().reserve(1).is_err());
        drop(history);
        drop(ingress);
        drop(owner);
        drop(quota);
        let exact = std::fs::read(&paths.floor).unwrap();
        let quota =
            ParticipantQuota::open_existing(directory.root(), [0xb6; 32], 10_000_000_000).unwrap();
        let reopened =
            progress::DurableFinality::open_participant(&quota, binding, keys().remove(0));
        match fault {
            crate::store::Fault::AfterSync => {
                let reopened = reopened.unwrap();
                assert_eq!(reopened.context().unwrap().slot(), 2);
                assert_eq!(
                    reopened.finalized_parent().unwrap().unwrap().head().block,
                    d.header().id()
                );
                assert!(reopened.outbound().unwrap().is_empty());
                drop(reopened);
            }
            crate::store::Fault::Partial(_) => {
                assert!(matches!(
                    reopened,
                    Err(Error::Durable(crate::Error::CorruptFloor))
                ));
            }
        }
        assert_eq!(std::fs::read(&paths.floor).unwrap(), exact);
        drop(quota);
    }
}
