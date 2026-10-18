//! Immutable borrowed syntax views; no polynomial transform or seed expansion.
use bfv_fixed_geometry::{DEGREE, MODULI};
use core::iter::FusedIterator;

/// A complete canonical wire borrowed from the caller, with both components checked.
///
/// The Ntt wire tag does not change the stored coefficients: every stored row is
/// PowerBasis. This view supplies neither native NTT values nor proof authority.
///
/// The original buffer must outlive the view:
/// ```compile_fail
/// use bfv_ciphertext_wire::{CiphertextView, parse};
/// fn escape(bytes: Vec<u8>) -> CiphertextView<'static> {
///     parse(&bytes).unwrap()
/// }
/// ```
#[derive(Clone, Copy)]
pub struct CiphertextView<'a> {
    original: &'a [u8],
    c0: StoredPowerBasis<'a>,
    second: SecondComponent<'a>,
}

impl<'a> CiphertextView<'a> {
    pub(super) fn new(
        original: &'a [u8],
        c0: StoredPowerBasis<'a>,
        second: SecondComponent<'a>,
    ) -> Self {
        Self {
            original,
            c0,
            second,
        }
    }

    /// Complete original bytes, including the seed or both stored polynomials.
    pub fn original_bytes(&self) -> &'a [u8] {
        self.original
    }

    /// The first stored polynomial, with its original variable-time metadata.
    pub fn c0(&self) -> StoredPowerBasis<'a> {
        self.c0
    }

    /// A second stored polynomial, or the original public seed without expansion.
    pub fn second(&self) -> SecondComponent<'a> {
        self.second
    }
}

/// The exact second-component encoding selected by the complete canonical wire.
#[derive(Clone, Copy)]
pub enum SecondComponent<'a> {
    /// Stored PowerBasis coefficients despite the polynomial's Ntt wire tag.
    Stored(StoredPowerBasis<'a>),
    /// A public seed. No polynomial coefficients or variable-time flag are stored here.
    Seed(&'a [u8; 32]),
}

/// Packed canonical PowerBasis coefficients and the stored boolean policy.
///
/// Fields and constructors are private. The borrowed bytes are read-only:
/// ```compile_fail
/// use bfv_ciphertext_wire::parse;
/// fn change(bytes: &[u8]) {
///     let view = parse(bytes).unwrap();
///     view.c0().packed_bytes()[0] = 1;
/// }
/// ```
#[derive(Clone, Copy)]
pub struct StoredPowerBasis<'a> {
    packed: &'a [u8],
    variable_time: bool,
}

impl<'a> StoredPowerBasis<'a> {
    pub(super) fn new(packed: &'a [u8], variable_time: bool) -> Self {
        Self {
            packed,
            variable_time,
        }
    }

    /// All five packed rows in the original Q0..Q4 order, without copying.
    pub fn packed_bytes(&self) -> &'a [u8] {
        self.packed
    }

    /// The stored flag: omitted proto3 false or explicitly encoded true.
    pub fn allow_variable_time(&self) -> bool {
        self.variable_time
    }

    /// Read exactly 8192 canonical coefficients at fixed modulus index 0..4.
    ///
    /// An unsupported index returns None. Iteration allocates no memory and
    /// performs no NTT; its lifetime follows the original wire, not this handle.
    pub fn row(&self, modulus_index: usize) -> Option<Coefficients<'a>> {
        packed_row(self.packed, modulus_index)
    }
}

/// The parser checks packed length before using this same reader for its range scan.
pub(super) fn packed_row(packed: &[u8], modulus_index: usize) -> Option<Coefficients<'_>> {
    let modulus = *MODULI.get(modulus_index)?;
    let width = (u64::BITS - (modulus - 1).leading_zeros()) as usize;
    let offset = MODULI[..modulus_index]
        .iter()
        .map(|q| (u64::BITS - (q - 1).leading_zeros()) as usize * DEGREE / 8)
        .sum::<usize>();
    let length = width * DEGREE / 8;
    Some(Coefficients {
        packed: packed.get(offset..offset + length)?,
        width,
        next: 0,
    })
}

/// A fixed complete PowerBasis row, decoded lazily from the original packed bytes.
#[derive(Clone)]
pub struct Coefficients<'a> {
    packed: &'a [u8],
    width: usize,
    next: usize,
}

impl Iterator for Coefficients<'_> {
    type Item = u64;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next == DEGREE {
            return None;
        }
        let bit = self.next * self.width;
        let first = bit / 8;
        let shift = bit % 8;
        let count = (shift + self.width).div_ceil(8);
        let word = self.packed[first..first + count]
            .iter()
            .enumerate()
            .fold(0u64, |value, (i, byte)| {
                value | (u64::from(*byte) << (8 * i))
            });
        self.next += 1;
        Some((word >> shift) & ((1u64 << self.width) - 1))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = DEGREE - self.next;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for Coefficients<'_> {}
impl FusedIterator for Coefficients<'_> {}
