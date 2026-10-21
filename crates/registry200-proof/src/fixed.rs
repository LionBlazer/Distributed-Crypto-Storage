use crate::{
    coefficient_encoding, control_kind, lifecycle, predicate_acquire, source, two_lane_encoding,
};
use bfv_hiding_stark::{self as engine, Config, Error, SecurityReport, Val};
use engine::codec::Topology;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{Proof, StarkSecurityParams};
use std::borrow::Cow;
enum FixedAir {
    TwoLaneEncoding(Box<two_lane_encoding::air::EncodingAir>),
    Source(Box<source::air::OpeningAir>),
    Bootstrap(Box<lifecycle::bootstrap::BootstrapAir>),
    Lifecycle(Box<lifecycle::air::LifecycleAir>),
    Encoding(Box<coefficient_encoding::air::EncodingAir>),
    PredicateAcquire(Box<predicate_acquire::air::PredicateAcquireAir>),
    ControlKind(Box<control_kind::air::ControlKindAir>),
}
macro_rules! dispatch { ($s:expr,$m:ident $(,$a:expr)*)=>{match $s {FixedAir::TwoLaneEncoding(a)=>a.$m($($a),*),FixedAir::Source(a)=>a.$m($($a),*),FixedAir::Bootstrap(a)=>a.$m($($a),*),FixedAir::Lifecycle(a)=>a.$m($($a),*),FixedAir::Encoding(a)=>a.$m($($a),*),FixedAir::PredicateAcquire(a)=>a.$m($($a),*),FixedAir::ControlKind(a)=>a.$m($($a),*)}}; }
impl BaseAir<Val> for FixedAir {
    fn width(&self) -> usize {
        dispatch!(self, width)
    }
    fn num_public_values(&self) -> usize {
        dispatch!(self, num_public_values)
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        dispatch!(self, main_next_row_columns)
    }
    fn num_periodic_columns(&self) -> usize {
        dispatch!(self, num_periodic_columns)
    }
    fn periodic_columns(&self) -> Cow<'_, [Vec<Val>]> {
        dispatch!(self, periodic_columns)
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        dispatch!(self, max_constraint_degree)
    }
}
impl<AB: AirBuilder<F = Val>> Air<AB> for FixedAir {
    fn eval(&self, b: &mut AB) {
        dispatch!(self, eval, b)
    }
}
pub(crate) struct Backend {
    air: FixedAir,
    values: Vec<Val>,
    config: Config,
    parameters: StarkSecurityParams,
    report: SecurityReport,
    pub shape: Topology,
}
impl Backend {
    fn new(air: FixedAir, values: Vec<Val>, wanted: (usize, usize)) -> Result<Self, Error> {
        let (parameters, report) = engine::analyze(&air)?;
        let report = report.require_target()?;
        if (air.width(), air.num_public_values()) != wanted
            || values.len() != wanted.1
            || air.preprocessed_width() != 0
            || air.main_next_row_columns().is_empty()
            || report.degree > 5
            || !(2..=16).contains(&report.quotient_chunks)
        {
            return Err(Error::Shape);
        }
        let shape =
            Topology::checked(wanted.0, report.quotient_chunks).map_err(|_| Error::Shape)?;
        Ok(Self {
            air,
            values,
            parameters,
            report,
            shape,
            config: engine::config()?,
        })
    }
    pub fn source(s: &source::Statement) -> Result<Self, Error> {
        if s.relation != source::Relation::CanonicalIndex {
            return Err(Error::Shape);
        }
        Self::new(
            FixedAir::Source(Box::new(source::air::OpeningAir::new(s))),
            s.values(),
            (11521, 691),
        )
    }
    pub fn child(s: &lifecycle::statement::Statement) -> Result<Self, Error> {
        if s.expected.is_bootstrap() {
            Self::new(
                FixedAir::Bootstrap(Box::new(lifecycle::bootstrap::BootstrapAir::new(s))),
                s.values(),
                (1082, 104),
            )
        } else {
            Self::new(
                FixedAir::Lifecycle(Box::new(lifecycle::air::LifecycleAir::new(s))),
                s.values(),
                (6741, 116),
            )
        }
    }
    pub fn verify(&self, p: &Proof<Config>) -> Result<(), Error> {
        engine::verify_with_assessment(
            &self.config,
            &self.air,
            &self.parameters,
            self.report,
            p,
            &self.values,
        )
    }
    pub(crate) fn prove(&self, trace: RowMajorMatrix<Val>) -> Result<Proof<Config>, Error> {
        engine::prove_with_config(&self.config, &self.air, trace, &self.values)
    }
    pub fn encoding(s: &coefficient_encoding::statement::Statement) -> Result<Self, Error> {
        let role = s.expected.role();
        Self::new(
            FixedAir::Encoding(Box::new(coefficient_encoding::air::EncodingAir::new(s))),
            s.values(),
            (role.width(), role.public_values()),
        )
    }
    pub fn two_lane_encoding(s: &two_lane_encoding::statement::Statement) -> Result<Self, Error> {
        let role = s.expected.role();
        Self::new(
            FixedAir::TwoLaneEncoding(Box::new(two_lane_encoding::air::EncodingAir::new(s))),
            s.values(),
            (role.width(), role.public_values()),
        )
    }
    pub fn predicate_acquire(e: &predicate_acquire::Expected) -> Result<Self, Error> {
        Self::new(
            FixedAir::PredicateAcquire(Box::new(predicate_acquire::air::PredicateAcquireAir::new(
                e,
            ))),
            e.values(),
            (
                predicate_acquire::layout::WIDTH,
                predicate_acquire::PUBLIC_VALUES,
            ),
        )
    }
    pub fn control_kind(e: &control_kind::Expected) -> Result<Self, Error> {
        Self::new(
            FixedAir::ControlKind(Box::new(control_kind::air::ControlKindAir::new(e))),
            e.values(),
            (control_kind::layout::WIDTH, control_kind::PUBLIC_VALUES),
        )
    }
}
