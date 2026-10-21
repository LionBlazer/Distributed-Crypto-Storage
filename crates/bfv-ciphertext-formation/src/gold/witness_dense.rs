//! Dense child of witness: direct access to SAME guarded equation banks.
//! No raw opening/key getter, alternative derivation or admission grant.
use super::*;
use crate::gold::{data, program::dense_data_inventory::WRITER_LAYOUT};
impl Preparation {
    pub(in crate::gold) fn dense_trace(self, expected: &data::Expected) -> Result<PrivateTrace> {
        self.dense_trace_layout(expected, WRITER_LAYOUT, None, false)
    }
    pub(in crate::gold) fn fused_query_trace(
        self,
        expected: &data::Expected,
        statement: &[Val; 96],
        root: [Val; 4],
    ) -> Result<PrivateTrace> {
        self.dense_trace_layout(
            expected,
            crate::gold::program::query_formation::WRITER_LAYOUT,
            Some((statement, root)),
            false,
        )
    }
    #[cfg(test)]
    pub(in crate::gold) fn fused_query_negative_trace(
        self,
        expected: &data::Expected,
        statement: &[Val; 96],
        root: [Val; 4],
    ) -> Result<PrivateTrace> {
        self.dense_trace_layout(
            expected,
            crate::gold::program::query_formation::WRITER_LAYOUT,
            Some((statement, root)),
            true,
        )
    }
    fn dense_trace_layout(
        self,
        expected: &data::Expected,
        writer_layout: [usize; 10],
        statement: Option<(&[Val; 96], [Val; 4])>,
        negative: bool,
    ) -> Result<PrivateTrace> {
        let scope = ExpectedRef::Data(expected);
        self.require_expected(scope)?;
        if let Some((statement, _)) = statement.filter(|_| !(cfg!(test) && negative)) {
            for (coefficient, &word) in self.openings[0].words.iter().enumerate() {
                let want = if coefficient < 256 {
                    let bit = 255 - coefficient;
                    ((statement[78 + bit / 32].as_canonical_u64() >> (bit % 32)) & 1)
                        * super::super::geometry::SCALE
                } else {
                    0
                };
                if word != want {
                    return Err(Error::Arithmetic);
                }
            }
        }
        let EquationWitness {
            plan,
            graph,
            products,
            errors,
            quotients,
        } = self.derive_equations(scope)?;
        let [
            height,
            width,
            _graph_rows,
            cw_first,
            cs_first,
            range_values,
            bits,
            checkpoint,
            acc_cell,
            slots,
        ] = writer_layout;
        if (statement.is_none() && writer_layout != WRITER_LAYOUT)
            || (statement.is_some()
                && writer_layout != crate::gold::program::query_formation::WRITER_LAYOUT)
            || (negative && !cfg!(test))
            || graph.values.len() != 81920
            || products.len() != 2
            || errors.len() != 1
            || quotients.len() != 2
        {
            return Err(Error::Shape);
        }
        let layout = scope.kind().range();
        if (layout.stride, layout.bits) != (9, 98) {
            return Err(Error::Shape);
        }
        let coefficient_bits = if statement.is_some() { 64 } else { layout.bits };
        let mut main = PrivateTrace(RowMajorMatrix::new(Val::zero_vec(height * width), width));
        for (gate, values) in graph.values.iter().enumerate() {
            let at = (gate / slots) * width + 4 * (gate % slots);
            for (cell, &value) in main.0.values[at..at + 4].iter_mut().zip(values) {
                *cell = Val::from_u64(value)
            }
        }
        drop(graph);
        drop(plan);
        let mut cs_words = Zeroizing::new(Vec::with_capacity(512));
        let mut accumulator = 0u64;
        let mut mask_accumulator = 0u64;
        for row_index in 0..height {
            let row = &mut main.0.values[row_index * width..(row_index + 1) * width];
            row[acc_cell] = Val::from_u64(accumulator);
            if statement.is_some() && row_index < 128 {
                row[acc_cell + 1] = Val::from_u64(mask_accumulator);
                let bit0 = self.openings[0].words[2 * row_index] / super::super::geometry::SCALE;
                let bit1 =
                    self.openings[0].words[2 * row_index + 1] / super::super::geometry::SCALE;
                let word = mask_accumulator + ((2 * bit0 + bit1) << (30 - 2 * (row_index % 16)));
                if row_index % 16 == 15 {
                    row[acc_cell + 2] = Val::from_u64(word);
                    mask_accumulator = 0;
                } else {
                    mask_accumulator = word;
                }
            }
            for k in 0..2 {
                let at = 2 * row_index + k;
                let base = range_values + layout.stride * k;
                let mut bit = bits + coefficient_bits * k;
                for bank in 0..2 {
                    let value = if bank == 0 {
                        self.key.secret[at]
                    } else {
                        errors[0][at]
                    };
                    row[base + bank] = signed(value);
                    let biased = (value + 20) as u64;
                    write_bits(&mut row[bit..bit + 6], biased);
                    write_bits(&mut row[bit + 6..bit + 12], 40 - biased);
                    bit += 12;
                }
                for job in 0..2 {
                    let value = quotients[job][at];
                    row[base + layout.k + job] = signed(value);
                    let biased = (value + 524288) as u64;
                    write_bits(&mut row[bit..bit + 20], biased);
                    bit += 20;
                    row[base + layout.inverse + job] = Val::from_u64(biased)
                        .try_inverse()
                        .ok_or(Error::Arithmetic)?;
                }
                let word = self.openings[0].words[at];
                row[base + layout.w] = Val::from_u64(word);
                if statement.is_none() {
                    write_bits(&mut row[bit..bit + 17], word);
                    write_bits(&mut row[bit + 17..bit + 34], T - 1 - word);
                    bit += 34;
                }
                for job in 0..2 {
                    row[base + layout.product + job] = signed(products[job][at])
                }
                if bit != bits + coefficient_bits * (k + 1) {
                    return Err(Error::Shape);
                }
            }
            let pair = (self.key.secret[2 * row_index] + 20) as u64
                + 64 * ((self.key.secret[2 * row_index + 1] + 20) as u64);
            let word = accumulator + (pair << (12 * (row_index % 4)));
            if row_index % 4 == 3 {
                row[range_values + 18] = Val::from_u64(word);
                cs_words.push(word);
                accumulator = 0
            } else {
                accumulator = word
            }
        }
        drop(products);
        drop(errors);
        drop(quotients);
        // Stage all512 secret words first: their global lookup producers may occur
        // after the Cs hash rows physically, without any circular commitment/witness.
        dense_hash(
            &mut main.0,
            checkpoint,
            cw_first,
            self.openings[0].context,
            &self.openings[0].salt,
            &self.openings[0].words,
            self.openings[0].root,
        )?;
        dense_hash(
            &mut main.0,
            checkpoint,
            cs_first,
            self.key.context,
            &self.key.salt,
            &cs_words,
            self.key.root,
        )?;
        if let Some((statement, root)) = statement {
            let mut state = PrivateFields([Val::ZERO; 12]);
            for (block, words) in statement.as_chunks::<8>().0.iter().enumerate() {
                let row = &mut main.0.values
                    [(cs_first + 66 + block) * width..(cs_first + 67 + block) * width];
                row[checkpoint..checkpoint + 12].copy_from_slice(&state.0);
                state.0[..8].copy_from_slice(words);
                state.0 = poseidon::write(&mut row[..poseidon::WIDTH], state.0);
            }
            if state.0[..4] != root {
                return Err(Error::Binding);
            }
        }
        Ok(main)
    }
}
fn dense_hash(
    main: &mut RowMajorMatrix<Val>,
    checkpoint: usize,
    start: usize,
    context: [Val; 8],
    salt: &[u64; 4],
    words: &[u64],
    root: [Val; 4],
) -> Result<()> {
    let width = main.width;
    let mut state = PrivateFields([Val::ZERO; 12]);
    for block in 0..2 + words.len() / 8 {
        let row = &mut main.values[(start + block) * width..(start + block + 1) * width];
        row[checkpoint..checkpoint + 12].copy_from_slice(&state.0);
        let mut input = PrivateFields([Val::ZERO; 12]);
        input.0[8..].copy_from_slice(&state.0[8..]);
        if block == 0 {
            input.0[..8].copy_from_slice(&context)
        } else if block == 1 {
            for (i, &value) in salt.iter().enumerate() {
                input.0[i] = Val::from_u64(value)
            }
        } else {
            for (i, value) in input.0.iter_mut().enumerate().take(8) {
                *value = Val::from_u64(words[8 * (block - 2) + i])
            }
        }
        state.0 = poseidon::write(&mut row[..poseidon::WIDTH], input.0);
    }
    if state.0[..4] != root {
        return Err(Error::Binding);
    }
    Ok(())
}
