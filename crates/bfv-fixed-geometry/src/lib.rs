//! The unchanged level-zero geometry shared by the fixed BFV arithmetic libraries.
//! These public constants are a prototype contract, not key or security approval.
#![forbid(unsafe_code)]

/// Degree of the fixed negacyclic encryption ring.
pub const DEGREE: usize = 8192;
/// Ordered original level-zero coefficient moduli.
pub const MODULI: [u64; 5] = [
    8796092858369,
    8796092792833,
    17592186028033,
    17592185438209,
    17592184717313,
];
/// Plaintext modulus of the existing byte-limb BFV profile.
pub const PLAINTEXT: u64 = 114_689;
/// Components of an input ciphertext or a relinearized result. Tensor
/// intermediates have three components and must not use this input shape.
pub const CIPHERTEXT_COMPONENTS: usize = 2;
/// Ordered auxiliary multiplication basis from the pinned SDK prime generator.
pub const AUXILIARY_MODULI: [u64; 5] = [
    4611686018427322369,
    4611686018427289601,
    4611686018426454017,
    4611686018426257409,
    4611686018425815041,
];
/// Original basis followed by the auxiliary basis, without reordering.
pub const EXTENDED_MODULI: [u64; 10] = [
    MODULI[0],
    MODULI[1],
    MODULI[2],
    MODULI[3],
    MODULI[4],
    AUXILIARY_MODULI[0],
    AUXILIARY_MODULI[1],
    AUXILIARY_MODULI[2],
    AUXILIARY_MODULI[3],
    AUXILIARY_MODULI[4],
];
