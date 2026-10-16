//! Two fixed experiment-owned layouts. No wire, dynamic layout or production API.
#[derive(Clone, Copy)]
pub(super) struct Columns {
    pub packed: bool,
    pub buffers: usize,
    pub banks: usize,
    pub master: usize,
    pub subkey: usize,
    pub polykey: usize,
    pub polykey_bits: usize,
    pub poly: usize,
    pub poseidon: usize,
    pub checkpoint: usize,
    pub carry: usize,
    pub salts: usize,
    pub width: usize,
}
impl Columns {
    pub(super) const fn new(packed: bool) -> Self {
        let buffers = 7 * crate::chacha::air::WIDTH;
        let banks = buffers + 7 * if packed { 16 } else { 512 };
        let master = banks;
        let subkey = master + if packed { 8 } else { 256 };
        let polykey = subkey + if packed { 16 } else { 512 };
        let polykey_bits = polykey + if packed { 16 } else { 512 };
        let poly = polykey_bits + if packed { 256 } else { 0 };
        let poseidon = poly + crate::poly1305::arithmetic::WIDTH;
        let checkpoint = poseidon + super::poseidon::WIDTH;
        let carry = checkpoint + 12;
        let salts = carry + 2;
        Self {
            packed,
            buffers,
            banks,
            master,
            subkey,
            polykey,
            polykey_bits,
            poly,
            poseidon,
            checkpoint,
            carry,
            salts,
            width: salts + 8,
        }
    }
    pub(super) const fn key_stride(self) -> usize {
        if self.packed { 8 } else { 256 }
    }
    pub(super) const fn buffer_stride(self) -> usize {
        if self.packed { 16 } else { 512 }
    }
}

#[derive(Clone, Copy)]
pub(super) struct CanonicalColumns {
    pub ages: usize,
    pub permutation: usize,
    pub sort: usize,
    pub header: usize,
    pub identity: usize,
    pub table_half: usize,
    pub width: usize,
}
impl CanonicalColumns {
    pub(super) const fn new(packed: bool) -> Self {
        let ages = Columns::new(packed).width;
        let permutation = ages + 32;
        let sort = permutation + 16;
        let header = sort + 30;
        // TableId inverse, four ID-sum inverses and six pair-count inverses;
        // packed additionally needs 48 word-zero flags and 48 word inverses.
        let identity = header + 352;
        let table_half = identity + if packed { 107 } else { 11 };
        Self {
            ages,
            permutation,
            sort,
            header,
            identity,
            table_half,
            width: table_half + 1,
        }
    }
}
pub(crate) const PACKED_WIDTH: usize = CanonicalColumns::new(true).width;
const _: () = {
    assert!(Columns::new(false).width == 11079);
    assert!(CanonicalColumns::new(false).width == 11521);
    assert!(Columns::new(true).width == 6623);
    assert!(PACKED_WIDTH == 7161);
};
