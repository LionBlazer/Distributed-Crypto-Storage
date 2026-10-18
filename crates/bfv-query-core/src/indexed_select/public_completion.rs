//! Owner-only decoding of the existing exact public projection wire. No proof or SQL authority.
use super::*;

impl Owner {
    /// Decode an existing exact public-projection response with this original Owner.
    ///
    /// This checks the complete request/response metadata and canonical ciphertext,
    /// then returns all 8192 decrypted SIMD slots. It performs no proof, freshness,
    /// selection or authorization check. The caller must establish those separately.
    /// Returned plaintext is caller-owned and is never a peer request or an accepted SQL result.
    pub fn decrypt_public_select_unverified_for_experiment(
        &self,
        request: &[u8],
        response: &[u8],
    ) -> Result<Vec<u64>> {
        // Fixed canonical ciphertext plus the existing small public metadata envelope.
        if request.len() > MAX_PUBLIC_SELECT_CIPHERTEXT_BYTES + 512
            || response.len() > MAX_PUBLIC_SELECT_CIPHERTEXT_BYTES + 512
        {
            return Err(Error::WireLimit);
        }
        let original = checked_exact_request(self.geometry, self.keyset_id, request)?;
        let response: Response = decode(response)?;
        if response.magic != RESPONSE_MAGIC
            || response.version != SELECT_VERSION
            || response.operation != original.operation
            || response.keyset_id != original.keyset_id
            || response.context != original.context
            || response.geometry != original.geometry
            || response.projection != original.projection
        {
            return Err(Error::BindingMismatch);
        }
        // checked_ciphertext owns the shared fixed borrowed wire preflight before
        // SDK construction. The original complete byte identity remains canonical.
        let input = checked_ciphertext(&original.rows, &self.parameters)?;
        let ciphertext = checked_ciphertext(&response.projected, &self.parameters)?;
        if input.to_bytes() != original.rows || ciphertext.to_bytes() != response.projected {
            return Err(Error::InvalidShape);
        }
        let plaintext = Zeroizing::new(self.key.try_decrypt(&ciphertext).map_err(backend)?);
        let decoded = Vec::<u64>::try_decode(&plaintext, Encoding::simd()).map_err(backend)?;
        if decoded.len() != DEGREE {
            return Err(Error::InvalidShape);
        }
        Ok(decoded)
    }
}

#[cfg(test)]
mod tests;
