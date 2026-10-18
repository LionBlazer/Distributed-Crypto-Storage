//! Bounded scalar lookup leaf access over the original commitment-bound tables.
use super::*;
use crate::lookup::FractionSource;
use core::{alloc::Layout, cell::RefCell};

struct Block<'a, F, EF> {
    start: usize,
    end: usize,
    height: usize,
    air: usize,
    fields: &'a [SymbolicExpression<F>],
    multiplicity: &'a SymbolicExpression<F>,
    prefix: EF,
}

struct CachedRow<F> {
    location: Option<(usize, usize)>,
    values: Scratch<F>,
}

/// Not serialized, exported, or accepted by a verifier. Immutable committed table
/// views and a bounded row scratch are the only witness storage this source owns.
pub(crate) struct LookupFractionSource<'a, F: Field, EF: ExtensionField<F>> {
    variables: usize,
    len: usize,
    blocks: Vec<Block<'a, F, EF>>,
    main: &'a [&'a Table<F>],
    preprocessed: &'a [Option<&'a Table<F>>],
    public_values: &'a [&'a [F]],
    powers: Vec<EF>,
    cache: RefCell<CachedRow<F>>,
}

impl<'a, F: Field, EF: ExtensionField<F>> LookupFractionSource<'a, F, EF> {
    pub(crate) fn new(
        plan: &'a LookupPlan<F>,
        main: &'a [&'a Table<F>],
        preprocessed: &'a [Option<&'a Table<F>>],
        public_values: &'a [&'a [F]],
        alpha: EF,
        beta: EF,
    ) -> Self {
        assert_eq!(main.len(), preprocessed.len());
        assert_eq!(main.len(), public_values.len());
        let shift = u32::try_from(plan.num_variables).expect("lookup variable count exceeds u32");
        let len = 1usize
            .checked_shl(shift)
            .expect("lookup fraction size overflow");
        assert!(
            plan.num_variables > 0,
            "lookup fractions require a nonconstant cube"
        );
        // Preserve the dense protocol's representable logical shape without allocating it.
        Layout::array::<EF>(len).expect("lookup fraction layout overflow");
        let challenges = Challenges::new(alpha, beta, plan.max_width, plan.num_buses);
        let mut blocks = Vec::new();
        let mut max_main = 0;
        let mut max_preprocessed = 0;
        let mut previous_end = 0;
        for planned in &plan.instances {
            let table = main[planned.air_index];
            assert_eq!(table.num_variables(), planned.num_variables);
            max_main = max_main.max(table.num_polys());
            if let Some(table) = preprocessed[planned.air_index] {
                assert_eq!(table.num_variables(), planned.num_variables);
                max_preprocessed = max_preprocessed.max(table.num_polys());
            }
            let height = 1usize
                .checked_shl(
                    u32::try_from(planned.num_variables)
                        .expect("lookup trace variable count exceeds u32"),
                )
                .expect("lookup trace height overflow");
            let mut start = planned.base_offset;
            assert_eq!(
                start, previous_end,
                "lookup blocks must be contiguous in plan order"
            );
            for (lookup, &bus) in planned.lookups.iter().zip(&planned.bus_ids) {
                for (fields, multiplicity) in lookup.elements.iter().zip(&lookup.multiplicities) {
                    let end = start
                        .checked_add(height)
                        .expect("lookup contribution range overflow");
                    assert!(end <= len, "lookup contribution exceeds its padded cube");
                    blocks.push(Block {
                        start,
                        end,
                        height,
                        air: planned.air_index,
                        fields,
                        multiplicity,
                        prefix: challenges.bus_prefix[bus],
                    });
                    start = end;
                }
            }
            previous_end = start;
        }
        Layout::array::<F>(max_main).expect("lookup main row layout overflow");
        Layout::array::<F>(max_preprocessed).expect("lookup public row layout overflow");
        Self {
            variables: plan.num_variables,
            len,
            blocks,
            main,
            preprocessed,
            public_values,
            powers: beta.powers().take(plan.max_width).collect(),
            cache: RefCell::new(CachedRow {
                location: None,
                values: Scratch::new(max_main, max_preprocessed),
            }),
        }
    }
}

impl<F: Field, EF: ExtensionField<F>> FractionSource<EF> for LookupFractionSource<'_, F, EF> {
    fn num_variables(&self) -> usize {
        self.variables
    }
    fn leaf(&self, index: usize) -> (EF, EF) {
        assert!(index < self.len, "lookup leaf is outside its planned cube");
        let end = self.blocks.partition_point(|block| block.start <= index);
        let Some(block) = end.checked_sub(1).map(|i| &self.blocks[i]) else {
            return (EF::ZERO, EF::ONE);
        };
        if index >= block.end {
            return (EF::ZERO, EF::ONE);
        }
        let row = index - block.start;
        let table = self.main[block.air];
        let public = self.preprocessed[block.air];
        let mut cache = self.cache.borrow_mut();
        if cache.location != Some((block.air, row)) {
            let fill = |local: &mut [F], next: &mut [F], table: &Table<F>| {
                for ((local, next), column) in local.iter_mut().zip(next).zip(table.columns()) {
                    *local = column.value(row);
                    *next = column.value((row + 1).min(block.height - 1));
                }
            };
            let Scratch {
                local,
                next,
                preprocessed_local,
                preprocessed_next,
            } = &mut cache.values;
            fill(local, next, table);
            if let Some(public) = public {
                fill(preprocessed_local, preprocessed_next, public);
            }
            cache.location = Some((block.air, row));
        }
        let pp_width = public.map_or(0, Table::num_polys);
        let evaluator = LookupRowEvaluator {
            main_window: RowWindow::from_two_rows(
                &cache.values.local[..table.num_polys()],
                &cache.values.next[..table.num_polys()],
            ),
            preprocessed_window: RowWindow::from_two_rows(
                &cache.values.preprocessed_local[..pp_width],
                &cache.values.preprocessed_next[..pp_width],
            ),
            boundary: BoundaryEvals::from_row(row, block.height),
            public_values: self.public_values[block.air],
        };
        let numerator = EF::from(block.multiplicity.resolve(&evaluator));
        let fingerprint = dot_product::<EF, _, _>(
            self.powers.iter().copied(),
            block.fields.iter().map(|field| field.resolve(&evaluator)),
        );
        (numerator, block.prefix - fingerprint)
    }
}
