//! Complete ordered independent NTTs, private data namespaces and four shared range tables.
use super::*;
use crate::Error;
use p3_field::PrimeField64;

pub const BATCH_DESCRIPTOR: &[u8] = b"DCS/BFV-NTT-BATCH/v1/count2,4,8/ordered-mixed-directions-and-Q5P5/instance-data-buses/shared-four-ranges/unique-bindings/no-causal-chain-claim";
#[derive(Clone, Copy, Debug)]
pub struct BatchSpec {
    pub direction: Direction,
    pub basis: Basis,
}
#[derive(Clone)]
pub struct BatchTable {
    instance: Option<usize>,
    table: TableShape,
}
impl BatchTable {
    pub fn instance(&self) -> Option<usize> {
        self.instance
    }
    pub fn table(&self) -> &TableShape {
        &self.table
    }
}
#[derive(Clone)]
pub struct BatchShape {
    specs: Vec<BatchSpec>,
    tables: Vec<BatchTable>,
    airs: Vec<ProgramAir>,
}
impl BatchShape {
    pub fn specs(&self) -> &[BatchSpec] {
        &self.specs
    }
    pub fn tables(&self) -> &[BatchTable] {
        &self.tables
    }
    pub fn airs(&self) -> &[ProgramAir] {
        &self.airs
    }
    pub fn total_main_cells(&self) -> usize {
        self.tables
            .iter()
            .map(|t| t.table.height * t.table.main)
            .sum()
    }
    pub fn total_preprocessed_cells(&self) -> usize {
        self.tables
            .iter()
            .map(|t| t.table.height * t.table.public)
            .sum()
    }
    pub fn total_lookup_contributions(&self) -> usize {
        self.tables
            .iter()
            .map(|t| t.table.height * t.table.interactions)
            .sum()
    }
    pub fn total_lookup_count_weight(&self) -> usize {
        self.tables
            .iter()
            .map(|t| t.table.height * t.table.count_weight)
            .sum()
    }
}
fn count(n: usize) -> Result<()> {
    if matches!(n, 2 | 4 | 8) {
        Ok(())
    } else {
        Err(Error::Shape)
    }
}
pub fn batch_shape(specs: &[BatchSpec]) -> Result<BatchShape> {
    count(specs.len())?;
    let mut airs = Vec::new();
    let mut tables = Vec::new();
    for (instance, spec) in specs.iter().enumerate() {
        let single = shape(spec.direction, spec.basis);
        for air in single.airs.into_iter().take(spec.direction.stages() + 1) {
            tables.push(BatchTable {
                instance: Some(instance),
                table: air.table_shape(),
            });
            airs.push(air.in_batch(instance));
        }
    }
    for range in RANGES {
        let air = ProgramAir::range(range);
        tables.push(BatchTable {
            instance: None,
            table: air.table_shape(),
        });
        airs.push(air);
    }
    Ok(BatchShape {
        specs: specs.to_vec(),
        tables,
        airs,
    })
}
/// Bounds/complete canonical bindings only: no NTT, Aux evaluation or public matrices.
pub fn validate_batch(requests: &[Request], outputs: &[Output]) -> Result<BatchShape> {
    count(requests.len())?;
    if outputs.len() != requests.len() {
        return Err(Error::Shape);
    }
    for (index, (request, output)) in requests.iter().zip(outputs).enumerate() {
        codec::check_output_binding(request, output)?;
        if requests[..index]
            .iter()
            .any(|old| old.binding() == request.binding())
        {
            return Err(Error::Binding);
        }
    }
    batch_shape(
        &requests
            .iter()
            .map(|r| BatchSpec {
                direction: r.direction(),
                basis: r.basis(),
            })
            .collect::<Vec<_>>(),
    )
}
/// One sealed batch only. Verification prepares exact ordered IO without auxiliary data.
pub struct PreparedBatch {
    requests: Vec<Request>,
    outputs: Vec<Output>,
    shape: BatchShape,
    airs: Vec<ProgramAir>,
}
impl PreparedBatch {
    pub fn shape(&self) -> &BatchShape {
        &self.shape
    }
    pub fn airs(&self) -> &[ProgramAir] {
        &self.airs
    }
    pub fn witness(&self, aux: &[Aux]) -> Result<Vec<RowMajorMatrix<Val>>> {
        if aux.len() != self.requests.len() {
            return Err(Error::Shape);
        }
        let mut traces = Vec::with_capacity(self.airs.len());
        let mut counts: [Vec<u64>; 4] = RANGES.map(|r| vec![0; r.domain_size()]);
        for ((request, output), aux) in self.requests.iter().zip(&self.outputs).zip(aux) {
            let single_shape = shape(request.direction(), request.basis());
            let single = PreparedMachine {
                request: request.clone(),
                output: output.clone(),
                airs: single_shape.airs.clone(),
                shape: single_shape,
            };
            let mut component = witness::build(&single, aux)?;
            let providers = component.split_off(request.direction().stages() + 1);
            for (range, table) in RANGES.into_iter().zip(providers) {
                for (index, row) in table
                    .values
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .take(range.domain_size())
                    .enumerate()
                {
                    let frequency = &mut counts[range.index()][index];
                    *frequency = frequency
                        .checked_add(row[1].as_canonical_u64())
                        .ok_or(Error::Arithmetic)?;
                    if *frequency >= Val::ORDER_U64 {
                        return Err(Error::Arithmetic);
                    }
                }
            }
            traces.extend(component);
        }
        for range in RANGES {
            let mut values = Vec::with_capacity(range.height() * 2);
            let frequencies = counts[range.index()]
                .iter()
                .copied()
                .chain(core::iter::repeat_n(
                    0,
                    range.height() - range.domain_size(),
                ));
            for (index, frequency) in frequencies.enumerate() {
                values.extend([
                    Val::from_usize(index % range.domain_size()),
                    Val::from_u64(frequency),
                ]);
            }
            traces.push(RowMajorMatrix::new(values, 2));
        }
        Ok(traces)
    }
}
pub fn prepare_batch(requests: &[Request], outputs: &[Output]) -> Result<PreparedBatch> {
    let shape = validate_batch(requests, outputs)?;
    let mut airs = Vec::with_capacity(shape.airs.len());
    let mut shared = Vec::new();
    for (index, (request, output)) in requests.iter().zip(outputs).enumerate() {
        let single = prepare_public(request, output)?;
        let mut component = single.airs;
        let providers = component.split_off(request.direction().stages() + 1);
        airs.extend(component.into_iter().map(|a| a.in_batch(index)));
        if index == 0 {
            shared = providers;
        }
    }
    airs.extend(shared);
    Ok(PreparedBatch {
        requests: requests.to_vec(),
        outputs: outputs.to_vec(),
        shape,
        airs,
    })
}
#[cfg(test)]
mod tests;
