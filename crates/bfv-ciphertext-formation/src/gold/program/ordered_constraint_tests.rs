// Lexically included only by the two owning DATA/Query #[cfg(test)] modules.
// Actual native evaluator + SDK folder, with arbitrary FIELD-valued test rows.
// No proof, complete PP, secret, RNG, public arbitrary-AIR API or admission.
use super::{Val, air, layout::*, native};
use bfv_hiding_stark::{Challenge, hash::Config};
use p3_air::symbolic::{
    AirLayout, ConstraintLayout, ExtEntry, ExtLeaf, SymbolicExpression, SymbolicExpressionExt,
};
use p3_air::{
    Air, AirBuilder, BaseAir, ExtensionBuilder, PermutationAirBuilder, RowWindow, WindowAccess,
};
use p3_batch_stark::folder::VerifierConstraintFolderWithLookups;
use p3_batch_stark::symbolic::{
    get_constraint_layout, get_log_num_quotient_chunks_for_domain, get_symbolic_constraints,
};
use p3_commit::PolynomialSpace;
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_lookup::{
    Challenges, Count, InteractionBuilder, Kind, LogUpGadget, LookupProtocol, Lookups,
};
use p3_matrix::{
    dense::RowMajorMatrixView,
    stack::{VerticalPair, ViewPair},
};
use p3_uni_stark::VerifierConstraintFolder;
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KindOfConstraint {
    Base,
    Ext,
}
#[derive(Clone, Copy, Debug)]
struct Emission {
    kind: KindOfConstraint,
    value: Challenge,
}
#[derive(Debug)]
struct Message {
    fields: Vec<Challenge>,
    count: Challenge,
}

struct Tap<'a> {
    native: VerifierConstraintFolderWithLookups<'a, Config>,
    emitted: Vec<Emission>,
    messages: Vec<Message>,
    app_end: Option<usize>,
}
impl<'a> AirBuilder for Tap<'a> {
    type F = Val;
    type Expr = Challenge;
    type Var = Challenge;
    type PublicVar = Val;
    type PeriodicVar = Challenge;
    type MainWindow = RowWindow<'a, Challenge>;
    type PreprocessedWindow = RowWindow<'a, Challenge>;
    fn main(&self) -> Self::MainWindow {
        self.native.main()
    }
    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        self.native.preprocessed()
    }
    fn public_values(&self) -> &[Val] {
        self.native.public_values()
    }
    fn periodic_values(&self) -> &[Challenge] {
        self.native.periodic_values()
    }
    fn is_first_row(&self) -> Challenge {
        self.native.is_first_row()
    }
    fn is_last_row(&self) -> Challenge {
        self.native.is_last_row()
    }
    fn is_transition(&self) -> Challenge {
        self.native.is_transition()
    }
    fn assert_zero<I: Into<Challenge>>(&mut self, value: I) {
        let value = value.into();
        let before = self.native.inner.accumulator;
        self.emitted.push(Emission {
            kind: KindOfConstraint::Base,
            value,
        });
        self.native.assert_zero(value);
        assert_eq!(
            self.native.inner.accumulator,
            before * self.native.inner.alpha + value
        );
    }
}
impl ExtensionBuilder for Tap<'_> {
    type EF = Challenge;
    type ExprEF = Challenge;
    type VarEF = Challenge;
    fn assert_zero_ext<I: Into<Challenge>>(&mut self, value: I) {
        let value = value.into();
        let before = self.native.inner.accumulator;
        self.emitted.push(Emission {
            kind: KindOfConstraint::Ext,
            value,
        });
        self.native.assert_zero_ext(value);
        assert_eq!(
            self.native.inner.accumulator,
            before * self.native.inner.alpha + value
        );
    }
}
impl<'a> PermutationAirBuilder for Tap<'a> {
    type RandomVar = Challenge;
    type PermutationVar = Challenge;
    type MP = RowWindow<'a, Challenge>;
    fn permutation(&self) -> Self::MP {
        self.native.permutation()
    }
    fn permutation_randomness(&self) -> &[Challenge] {
        self.native.permutation_randomness()
    }
    fn permutation_values(&self) -> &[Challenge] {
        self.native.permutation_values()
    }
}
impl InteractionBuilder for Tap<'_> {
    fn push_interaction<E: Into<Challenge>>(
        &mut self,
        bus: &str,
        fields: impl IntoIterator<Item = E>,
        count: impl Into<Count<Challenge>>,
    ) {
        assert_eq!(bus, BUS, "only the sealed single bus belongs to this test");
        let fields: Vec<_> = fields.into_iter().map(Into::into).collect();
        let (count, weight) = count.into().into_parts();
        self.messages.push(Message {
            fields: fields.clone(),
            count,
        });
        self.native
            .push_interaction(bus, fields, Count::bounded(count, weight));
    }
    fn push_local_interaction(
        &mut self,
        tuples: impl IntoIterator<Item = (Vec<Challenge>, Count<Challenge>)>,
    ) {
        self.native.push_local_interaction(tuples);
        panic!("sealed DATA/Query has no local lookup");
    }
    fn push_exclusive_interaction(
        &mut self,
        _bus: &str,
        branches: impl IntoIterator<Item = (Challenge, Count<Challenge>, Vec<Challenge>)>,
    ) {
        branches.into_iter().for_each(drop);
        panic!("generalized field PP cannot assume exclusive Boolean selectors");
    }
}

// Marks the actual App_mu boundary inside SDK eval_air_and_lookups. Equations
// are emitted once by the SAME FullAir/MetadataAir code; none are copied here.
struct Application<'a>(&'a native::FullAir);
impl BaseAir<Val> for Application<'_> {
    fn width(&self) -> usize {
        self.0.width()
    }
    fn preprocessed_width(&self) -> usize {
        self.0.preprocessed_width()
    }
    fn num_public_values(&self) -> usize {
        self.0.num_public_values()
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        self.0.main_next_row_columns()
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        self.0.preprocessed_next_row_columns()
    }
}
impl Air<Tap<'_>> for Application<'_> {
    fn eval(&self, tap: &mut Tap<'_>) {
        assert!(tap.app_end.is_none(), "application evaluated twice");
        self.0.eval(tap);
        tap.app_end = Some(tap.emitted.len());
    }
}

struct Input {
    main: [Vec<Challenge>; 2],
    pp: [Vec<Challenge>; 2],
    aux: [Vec<Challenge>; 2],
    public: Vec<Val>,
    randomness: Vec<Challenge>,
    terminal: [Challenge; 1],
    selectors: [Challenge; 3],
}
fn pair(rows: &[Vec<Challenge>; 2]) -> ViewPair<'_, Challenge> {
    VerticalPair::new(
        RowMajorMatrixView::new_row(&rows[0]),
        RowMajorMatrixView::new_row(&rows[1]),
    )
}
impl Input {
    fn new(public: &[Val], lookups: &Lookups<Val>) -> Self {
        assert!(lookups.iter().all(
            |lookup| matches!(&lookup.kind, Kind::Global(name) if name == BUS)
                && lookup.flags.is_none()
                && lookup.elements.iter().all(|tuple| tuple.len() == 2)
        ));
        // Exactly the native one-bus layout from this fixed test pair.
        // A has a non-base component, avoiding poles for these base-only rows.
        let a = Challenge::from_basis_coefficients_fn(|i| Val::from_usize(i + 17));
        let b = Challenge::from_u32(3);
        let table = Challenges::new(a, b, 2, 1);
        Self {
            main: core::array::from_fn(|_| vec![Challenge::ZERO; W]),
            pp: core::array::from_fn(|_| vec![Challenge::ZERO; PP]),
            aux: core::array::from_fn(|_| vec![Challenge::ZERO; lookups.len() + 1]),
            public: public.to_vec(),
            randomness: (0..lookups.len())
                .flat_map(|_| [table.bus_prefix[0], b])
                .collect(),
            terminal: [Challenge::ZERO],
            selectors: [Challenge::ZERO, Challenge::ZERO, Challenge::ONE],
        }
    }
    fn tap(&self, alpha: Challenge) -> Tap<'_> {
        let pp = pair(&self.pp);
        Tap {
            native: VerifierConstraintFolderWithLookups {
                inner: VerifierConstraintFolder {
                    main: pair(&self.main),
                    preprocessed: pp,
                    preprocessed_window: RowWindow::from_two_rows(&self.pp[0], &self.pp[1]),
                    periodic_values: &[],
                    public_values: &self.public,
                    is_first_row: self.selectors[0],
                    is_last_row: self.selectors[1],
                    is_transition: self.selectors[2],
                    alpha,
                    accumulator: Challenge::ZERO,
                },
                permutation: pair(&self.aux),
                permutation_challenges: &self.randomness,
                permutation_values: &self.terminal,
            },
            emitted: Vec::new(),
            messages: Vec::new(),
            app_end: None,
        }
    }
}

fn packed(air: &native::FullAir) -> (Lookups<Val>, usize) {
    let gadget = LogUpGadget::new();
    let original = Lookups::<Val>::from_air::<Challenge, _>(air);
    let domain = TwoAdicMultiplicativeCoset::<Val>::new(Val::ONE, LOG_H).unwrap();
    let log = get_log_num_quotient_chunks_for_domain::<Val, Challenge, _, _>(
        air,
        AirLayout::from_air(air),
        domain,
        &original,
        1,
        &gadget,
    );
    let ceiling = 1usize << log;
    let packed = original.pack_same_bus_with_degree(ceiling, |lookup| {
        gadget.constraint_degree_with_transition(lookup, domain.transition_degree_multiple())
    });
    assert_eq!(packed.len(), PACKED);
    (packed, ceiling)
}

fn run<'a>(
    air: &native::FullAir,
    lookups: &Lookups<Val>,
    input: &'a Input,
    alpha: Challenge,
) -> Tap<'a> {
    let mut tap = input.tap(alpha);
    LogUpGadget::new().eval_air_and_lookups(&Application(air), &mut tap, lookups);
    let end = tap.app_end.unwrap();
    assert!(
        tap.emitted[..end]
            .iter()
            .all(|event| event.kind == KindOfConstraint::Base)
    );
    assert_eq!(tap.emitted.len() - end, lookups.len() + 3);
    assert!(
        tap.emitted[end..]
            .iter()
            .all(|event| event.kind == KindOfConstraint::Ext)
    );
    // Independent powers formula, not another Horner loop.
    let count = tap.emitted.len();
    let direct: Challenge = tap
        .emitted
        .iter()
        .enumerate()
        .map(|(i, event)| event.value * alpha.exp_u64(u64::try_from(count - 1 - i).unwrap()))
        .sum();
    assert_eq!(direct, tap.native.inner.accumulator);
    // Preserve EVERY fraction (including last row), then first/transition/last.
    // Independent additive polynomial form; never divide or omit pole cases.
    for (i, lookup) in lookups.iter().enumerate() {
        let a = input.randomness[2 * lookup.column];
        let b = input.randomness[2 * lookup.column + 1];
        let denominators: Vec<Challenge> = lookup
            .elements
            .iter()
            .map(|tuple| {
                a - tuple.iter().fold(Challenge::ZERO, |value, field| {
                    value * b + field.resolve(&tap)
                })
            })
            .collect();
        let denominator: Challenge = denominators.iter().copied().product();
        let numerator: Challenge = lookup
            .multiplicities
            .iter()
            .enumerate()
            .map(|(i, count)| {
                count.resolve(&tap)
                    * denominators
                        .iter()
                        .enumerate()
                        .filter_map(|(j, value)| (i != j).then_some(*value))
                        .product::<Challenge>()
            })
            .sum();
        let expected = denominator * input.aux[0][lookup.column + 1] - numerator;
        assert_eq!(
            tap.emitted[end + i].value,
            expected,
            "every original fraction is pinned even on the last row"
        );
    }
    let fractions: Challenge = input.aux[0][1..].iter().copied().sum();
    let last = &tap.emitted[count - 3..];
    let expected = [
        input.selectors[0] * input.aux[0][0],
        input.selectors[2] * (input.aux[1][0] - input.aux[0][0] - fractions),
        input.selectors[1] * (input.terminal[0] - input.aux[0][0] - fractions),
    ];
    assert_eq!(
        last.iter().map(|event| event.value).collect::<Vec<_>>(),
        expected
    );
    assert_eq!(input.terminal, [Challenge::ZERO]);
    LogUpGadget::new()
        .verify_terminal_sum(&[Some(p3_lookup::LookupTerminal(input.terminal[0]))])
        .unwrap();
    tap
}

fn check_layout(tap: &Tap<'_>, layout: &ConstraintLayout) {
    assert_eq!(tap.emitted.len(), layout.total_constraints());
    for &index in &layout.base_indices {
        assert_eq!(tap.emitted[index].kind, KindOfConstraint::Base);
    }
    for &index in &layout.ext_indices {
        assert_eq!(tap.emitted[index].kind, KindOfConstraint::Ext);
    }
    // Check the SAME SDK prover-side split powers against the independent
    // descending-power convention used by the native verifier's Horner loop.
    let alpha = tap.native.inner.alpha;
    let (base_powers, ext_powers) = layout.decompose_alpha::<Val, Challenge>(alpha);
    for (i, &index) in layout.base_indices.iter().enumerate() {
        let power = Challenge::from_basis_coefficients_fn(|d| base_powers[d][i]);
        assert_eq!(
            power,
            alpha.exp_u64(u64::try_from(tap.emitted.len() - 1 - index).unwrap())
        );
    }
    for (&index, power) in layout.ext_indices.iter().zip(&ext_powers) {
        assert_eq!(
            *power,
            alpha.exp_u64(u64::try_from(tap.emitted.len() - 1 - index).unwrap())
        );
    }
}

// Evaluate the ORIGINAL SDK ASTs, not recreated AIR/fraction equations. The
// Poseidon partial rounds share linear-layer Arc nodes: SDK base `resolve`
// expands that DAG exponentially. Cache by node identity and delegate only
// base LEAVES to the SDK's exact leaf resolution.
//
// One instance belongs to one unchanged Tap/input/selector case. All original
// roots and Arc children stay alive until it is dropped; no pointer is ever
// dereferenced and separate maps distinguish the two AST node types.
#[derive(Default)]
struct Resolved {
    base: BTreeMap<*const SymbolicExpression<Val>, Challenge>,
    extension: BTreeMap<*const SymbolicExpressionExt<Val, Challenge>, Challenge>,
}
impl Resolved {
    fn base(&mut self, expression: &SymbolicExpression<Val>, tap: &Tap<'_>) -> Challenge {
        let key = core::ptr::from_ref(expression);
        if let Some(&value) = self.base.get(&key) {
            return value;
        }
        let value = match expression {
            SymbolicExpression::Leaf(_) => expression.resolve(tap),
            SymbolicExpression::Add { x, y, .. } => self.base(x, tap) + self.base(y, tap),
            SymbolicExpression::Sub { x, y, .. } => self.base(x, tap) - self.base(y, tap),
            SymbolicExpression::Mul { x, y, .. } => self.base(x, tap) * self.base(y, tap),
            SymbolicExpression::Neg { x, .. } => -self.base(x, tap),
        };
        self.base.insert(key, value);
        value
    }

    fn extension(
        &mut self,
        expression: &SymbolicExpressionExt<Val, Challenge>,
        tap: &Tap<'_>,
    ) -> Challenge {
        let key = core::ptr::from_ref(expression);
        if let Some(&value) = self.extension.get(&key) {
            return value;
        }
        let value = match expression {
            SymbolicExpressionExt::Leaf(ExtLeaf::Base(base)) => self.base(base, tap),
            SymbolicExpressionExt::Leaf(ExtLeaf::ExtConstant(value)) => *value,
            SymbolicExpressionExt::Leaf(ExtLeaf::ExtVariable(variable)) => match variable.entry {
                ExtEntry::Permutation { offset: 0 } => {
                    tap.permutation().current(variable.index).unwrap()
                }
                ExtEntry::Permutation { offset: 1 } => {
                    tap.permutation().next(variable.index).unwrap()
                }
                ExtEntry::Permutation { .. } => {
                    panic!("original constraints span more than two rows")
                }
                ExtEntry::Challenge => tap.permutation_randomness()[variable.index],
                ExtEntry::PermutationValue => tap.permutation_values()[variable.index],
            },
            SymbolicExpressionExt::Add { x, y, .. } => {
                self.extension(x, tap) + self.extension(y, tap)
            }
            SymbolicExpressionExt::Sub { x, y, .. } => {
                self.extension(x, tap) - self.extension(y, tap)
            }
            SymbolicExpressionExt::Mul { x, y, .. } => {
                self.extension(x, tap) * self.extension(y, tap)
            }
            SymbolicExpressionExt::Neg { x, .. } => -self.extension(x, tap),
        };
        self.extension.insert(key, value);
        value
    }
}

#[test]
fn actual_ordered_app_and_logup_emissions_match_native_horner_for_field_valued_pp() {
    let expected = metadata();
    let air = native::FullAir(air::MetadataAir::new(&expected).unwrap());
    let (lookups, ceiling) = packed(&air);
    let layout = get_constraint_layout::<Val, Challenge, _, _>(
        &air,
        AirLayout::from_air(&air),
        &lookups,
        &LogUpGadget::new(),
    );
    let (base, extension) = get_symbolic_constraints::<Val, Challenge, _, _>(
        &air,
        AirLayout::from_air(&air),
        &lookups,
        &LogUpGadget::new(),
    );
    let degree = base
        .iter()
        .map(|expression| expression.degree_multiple())
        .chain(
            extension
                .iter()
                .map(|expression| expression.degree_multiple()),
        )
        .max()
        .unwrap();
    assert!(degree <= ceiling);
    let mut input = Input::new(expected.values(), &lookups);
    for row in 0..2 {
        for (i, value) in input.main[row].iter_mut().enumerate() {
            *value = Challenge::from_usize(i + row + 2);
        }
        for (i, value) in input.pp[row].iter_mut().enumerate() {
            *value = Challenge::from_usize(2 + (i + row) % 7);
        }
        for (i, value) in input.aux[row].iter_mut().enumerate() {
            *value = Challenge::from_usize(i + row + 11);
        }
    }
    // First actual graph message is -1=p-1 despite its static Count weight4.
    // Non-Boolean flags/counts elsewhere remain untouched as arbitrary fields.
    input.pp[0][ACTIVE] = Challenge::ONE;
    input.pp[0][POINTWISE] = Challenge::ZERO;
    input.pp[0][FANOUT] = Challenge::ZERO;
    input.pp[0][FLAGS + super::old_pp::PAYLOAD] = Challenge::ZERO;
    clear_first_statement_count(&mut input.pp[0]);
    let alpha = Challenge::from_basis_coefficients_fn(|i| Val::from_usize(i + 31));
    for selectors in [[1, 0, 1], [0, 0, 1], [0, 1, 0]] {
        input.selectors = selectors.map(Challenge::from_u32);
        let tap = run(&air, &lookups, &input, alpha);
        check_layout(&tap, &layout);
        assert_eq!(tap.app_end.unwrap(), base.len());
        assert_eq!(tap.messages[0].count, -Challenge::ONE);
        assert!(tap.messages.iter().all(|message| message.fields.len() == 2));
        // Resolve every ORIGINAL symbolic emitted equation at these arbitrary
        // rows and compare to actual native evaluation in exact global order.
        let mut resolved = Resolved::default();
        for (&index, expression) in layout.base_indices.iter().zip(&base) {
            assert_eq!(tap.emitted[index].value, resolved.base(expression, &tap));
        }
        for (&index, expression) in layout.ext_indices.iter().zip(&extension) {
            assert_eq!(
                tap.emitted[index].value,
                resolved.extension(expression, &tap)
            );
        }
    }
    eprintln!(
        "ordered_native_app DATA_or_Query_width={W} PP={PP} application={} fractions={} accumulator_terminal=3 C={} degree={degree} original_template=true PP_boolean=false count_integer_bound_assumed=false proof=false admission=false",
        base.len(),
        lookups.len(),
        layout.total_constraints()
    );
}

#[test]
fn balanced_lookup_with_invalid_local_main_is_filtered_before_lookup_coins_and_alpha() {
    let expected = metadata();
    let air = native::FullAir(air::MetadataAir::new(&expected).unwrap());
    let (lookups, _) = packed(&air);
    let mut input = Input::new(expected.values(), &lookups);
    // Constant public PP has degree0, all count expressions zero. The MAIN is
    // fixed before testing either alpha; its two inactive-bit equations are
    // nonzero but cancel at alpha=2. They do not become a lookup imbalance.
    for row in &mut input.pp {
        row[COEFFICIENTS] = Challenge::from_u32(2);
    }
    input.main[0][BITS] = Challenge::ONE;
    input.main[0][BITS + 1] = -Challenge::from_u32(4);
    for point in [2, 3] {
        let tap = run(&air, &lookups, &input, Challenge::from_u32(point));
        let end = tap.app_end.unwrap();
        assert!(
            tap.messages
                .iter()
                .all(|message| message.count == Challenge::ZERO)
        );
        assert!(
            lookups
                .iter()
                .flat_map(|lookup| &lookup.multiplicities)
                .all(|count| count.resolve(&tap) == Challenge::ZERO)
        );
        assert!(
            tap.emitted[end..]
                .iter()
                .all(|event| event.value == Challenge::ZERO)
        );
        let eligible_app = tap.emitted[..end]
            .iter()
            .all(|event| event.value == Challenge::ZERO);
        assert!(!eligible_app, "balanced lookup cannot bypass App_mu filter");
        assert_eq!(
            tap.emitted[..end]
                .iter()
                .filter(|event| event.value != Challenge::ZERO)
                .count(),
            2
        );
        assert_eq!(
            tap.native.inner.accumulator == Challenge::ZERO,
            point == 2,
            "only the fixed alpha cancellation point is folded-valid"
        );
    }
}
