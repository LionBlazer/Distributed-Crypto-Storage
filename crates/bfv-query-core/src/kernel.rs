use super::{PredicateKind, Result, backend};
use fhe::bfv::{BfvParameters, Ciphertext, Encoding, EvaluationKey, Plaintext, RelinearizationKey};
use fhe_traits::{DeserializeParametrized, FheEncoder};
use std::sync::Arc;

pub(super) struct Kernel {
    parameters: Arc<BfvParameters>,
    relin: RelinearizationKey,
    rotations: EvaluationKey,
}
struct Counters {
    products: usize,
    rotations: usize,
}
impl Kernel {
    pub(super) fn from_public(
        parameters: Arc<BfvParameters>,
        relin: &[u8],
        rotations: &[u8],
    ) -> Result<Self> {
        Ok(Self {
            relin: RelinearizationKey::from_bytes(relin, &parameters).map_err(backend)?,
            rotations: EvaluationKey::from_bytes(rotations, &parameters).map_err(backend)?,
            parameters,
        })
    }
    pub(super) fn parameters(&self) -> &Arc<BfvParameters> {
        &self.parameters
    }
    fn multiply(&self, a: &Ciphertext, b: &Ciphertext, n: &mut Counters) -> Result<Ciphertext> {
        let mut product = a * b;
        self.relin.relinearizes(&mut product).map_err(backend)?;
        n.products += 1;
        Ok(product)
    }
    fn rotate(&self, a: &Ciphertext, shift: usize, n: &mut Counters) -> Result<Ciphertext> {
        n.rotations += 1;
        self.rotations.rotates_columns_by(a, shift).map_err(backend)
    }
    fn ones(&self) -> Result<Plaintext> {
        Plaintext::try_encode(
            &vec![1u64; self.parameters.degree()],
            Encoding::simd(),
            &self.parameters,
        )
        .map_err(backend)
    }
    fn bit_equal(
        &self,
        a: &Ciphertext,
        b: &Ciphertext,
        n: &mut Counters,
    ) -> Result<(Ciphertext, Ciphertext)> {
        let ab = self.multiply(a, b, n)?;
        let mut equal = &ab + &ab;
        equal += &self.ones()?;
        equal -= a;
        equal -= b;
        let greater = a - &ab;
        Ok((equal, greater))
    }
    fn equal(
        &self,
        a: &Ciphertext,
        b: &Ciphertext,
        stride: usize,
        n: &mut Counters,
    ) -> Result<Ciphertext> {
        let (mut equal, _) = self.bit_equal(a, b, n)?;
        for shift in [stride, 2 * stride, 4 * stride] {
            let low = self.rotate(&equal, shift, n)?;
            equal = self.multiply(&equal, &low, n)?;
        }
        Ok(equal)
    }
    fn greater_equal(
        &self,
        a: &Ciphertext,
        b: &Ciphertext,
        stride: usize,
        n: &mut Counters,
    ) -> Result<Ciphertext> {
        let (mut equal, mut greater) = self.bit_equal(a, b, n)?;
        for shift in [stride, 2 * stride, 4 * stride] {
            // Both products use OLD E/G and combine MSB blocks before LSB blocks.
            let low_greater = self.rotate(&greater, shift, n)?;
            let propagated = self.multiply(&equal, &low_greater, n)?;
            let low_equal = self.rotate(&equal, shift, n)?;
            let new_equal = self.multiply(&equal, &low_equal, n)?;
            greater += &propagated;
            equal = new_equal;
        }
        Ok(&greater + &equal)
    }
    /// Exact-index operation only: values already encode caller-authorized selected weights.
    /// The eight rotations still perform the pinned library's Galois key switches.
    pub(super) fn aggregate_selected(
        &self,
        values: &Ciphertext,
    ) -> Result<(Ciphertext, usize, usize)> {
        let mut n = Counters {
            products: 0,
            rotations: 0,
        };
        let mut sums = values.clone();
        for shift in [1, 2, 4, 8, 16, 32, 64, 128] {
            let rotated = self.rotate(&sums, shift, &mut n)?;
            sums += &rotated;
        }
        Ok((sums, n.products, n.rotations))
    }
    /// Slotwise encrypted projection/active mask; retain per-row values, never aggregate.
    pub(super) fn project_selected(
        &self,
        rows: &Ciphertext,
        mask: &Ciphertext,
    ) -> Result<(Ciphertext, usize)> {
        let mut counters = Counters {
            products: 0,
            rotations: 0,
        };
        let projected = self.multiply(rows, mask, &mut counters)?;
        Ok((projected, counters.products))
    }
    pub(super) fn evaluate(
        &self,
        predicate: PredicateKind,
        a: &Ciphertext,
        lower: &Ciphertext,
        upper: Option<&Ciphertext>,
        values: &Ciphertext,
        stride: usize,
    ) -> Result<(Ciphertext, usize, usize)> {
        let mut n = Counters {
            products: 0,
            rotations: 0,
        };
        let selected = match predicate {
            PredicateKind::Equal => self.equal(a, lower, stride, &mut n)?,
            PredicateKind::AtLeast => self.greater_equal(a, lower, stride, &mut n)?,
            PredicateKind::Range => {
                let low = self.greater_equal(a, lower, stride, &mut n)?;
                let high = self.greater_equal(
                    upper.ok_or(super::Error::InvalidShape)?,
                    a,
                    stride,
                    &mut n,
                )?;
                // Owner rejected reversed bounds; the closed-range bit is GElo+GEhi-1.
                let mut selected = &low + &high;
                selected -= &self.ones()?;
                selected
            }
        };
        let mut sums = self.multiply(&selected, values, &mut n)?;
        let mut shift = 1;
        while shift < stride {
            let rotated = self.rotate(&sums, shift, &mut n)?;
            sums += &rotated;
            shift *= 2;
        }
        Ok((sums, n.products, n.rotations))
    }
}
