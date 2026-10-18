//! Independent complete Encoding136 and ordered Basis claims, never a Return168 cast.
use super::*;
use crate::primitive::PublicStatement;
#[derive(Clone)]
pub(in crate::opening) struct Expected {
    pub(super) encoding: encoding::Statement,
    pub(super) mathematical: bfv_ciphertext_formation::Expected,
}
impl Expected {
    pub(in crate::opening) fn new(
        encoding: encoding::Statement,
        bases: [bfv_basis_convolution::Statement; 5],
    ) -> Result<Self, Error> {
        let mathematical =
            bfv_ciphertext_formation::Expected::new(encoding.formation_commitment()?, bases)?;
        if mathematical.request() != encoding.formation_source().request
            || mathematical.key().expected.descriptor.database.as_slice()
                != &encoding.formation_source().heads[0][8..24]
        {
            return Err(Error::Shape);
        }
        Ok(Self {
            encoding,
            mathematical,
        })
    }
    pub(super) fn require_decoded(&self, decoded: &encoding::Statement) -> Result<(), Error> {
        self.encoding
            .require_complete_formation_statement(decoded)?;
        // Explicit FULL136 equality includes independently pinned Cenc, which require_expected alone omits.
        if decoded.public_values() != self.encoding.public_values() {
            return Err(Error::Shape);
        }
        if decoded.formation_commitment()? != *self.mathematical.encoding() {
            return Err(Error::Shape);
        }
        Ok(())
    }
}
