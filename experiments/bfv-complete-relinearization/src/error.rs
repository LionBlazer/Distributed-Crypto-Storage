//! Public arithmetic/stream errors contain no private key material.
#[derive(Debug)]
pub enum Error {
    Shape,
    Identity,
    Stage,
    Cancelled,
    ResourceLimit,
    Incomplete,
    Component,
    NttCircuit(bfv_ntt_circuit::Error),
    RelinCircuit(bfv_relinearization_circuit::Error),
    NttProof(bfv_ntt_witness_proof::Error),
    RelinProof(bfv_relinearization_multilinear_proof::Error),
    PreparedKey(bfv_relinearization_key_source::PreparedKeyError),
    Core(bfv_query_core::Error),
    Io(std::io::Error),
    Oracle,
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "complete relinearization experiment rejected {self:?}")
    }
}
impl std::error::Error for Error {}
macro_rules! conversion {
    ($source:path, $variant:ident) => {
        impl From<$source> for Error {
            fn from(value: $source) -> Self {
                Self::$variant(value)
            }
        }
    };
}
conversion!(bfv_ntt_circuit::Error, NttCircuit);
conversion!(bfv_relinearization_circuit::Error, RelinCircuit);
conversion!(bfv_ntt_witness_proof::Error, NttProof);
conversion!(bfv_relinearization_multilinear_proof::Error, RelinProof);
conversion!(
    bfv_relinearization_key_source::PreparedKeyError,
    PreparedKey
);
conversion!(bfv_query_core::Error, Core);
conversion!(std::io::Error, Io);
pub type Result<T> = core::result::Result<T, Error>;
