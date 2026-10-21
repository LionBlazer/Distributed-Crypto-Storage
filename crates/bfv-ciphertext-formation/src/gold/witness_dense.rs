//! Dense child of witness: direct access to SAME guarded equation banks.
//! No raw opening/key getter, alternative derivation or admission grant.
use super::*;
use crate::gold::{data, program::dense_data_inventory::WRITER_LAYOUT};
impl Preparation {
    pub(in crate::gold) fn dense_trace(self, expected: &data::Expected) -> Result<PrivateTrace> {
        let scope = ExpectedRef::Data(expected);
        self.require_expected(scope)?;
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
            graph_rows,
            cw_first,
            cs_first,
            range_values,
            bits,
            checkpoint,
            acc_cell,
            slots,
        ] = WRITER_LAYOUT;
        if (
            height,
            width,
            graph_rows,
            cw_first,
            cs_first,
            range_values,
            bits,
            checkpoint,
            acc_cell,
            slots,
        ) != (2048, 512, 1463, 1463, 1977, 248, 267, 496, 508, 56)
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
        for row_index in 0..height {
            let row = &mut main.0.values[row_index * width..(row_index + 1) * width];
            row[acc_cell] = Val::from_u64(accumulator);
            for k in 0..2 {
                let at = 2 * row_index + k;
                let base = range_values + layout.stride * k;
                let mut bit = bits + layout.bits * k;
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
                write_bits(&mut row[bit..bit + 17], word);
                write_bits(&mut row[bit + 17..bit + 34], T - 1 - word);
                bit += 34;
                for job in 0..2 {
                    row[base + layout.product + job] = signed(products[job][at])
                }
                if bit != bits + layout.bits * (k + 1) {
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
            cw_first,
            self.openings[0].context,
            &self.openings[0].salt,
            &self.openings[0].words,
            self.openings[0].root,
        )?;
        dense_hash(
            &mut main.0,
            cs_first,
            self.key.context,
            &self.key.salt,
            &cs_words,
            self.key.root,
        )?;
        Ok(main)
    }
}
fn dense_hash(
    main: &mut RowMajorMatrix<Val>,
    start: usize,
    context: [Val; 8],
    salt: &[u64; 4],
    words: &[u64],
    root: [Val; 4],
) -> Result<()> {
    let [_, width, _, _, _, _, _, checkpoint, _, _] = WRITER_LAYOUT;
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
