//! Read-only diagnostics of an SDK separator's actual public seed observations.
//!
//! The caller owns the association between a separator and a protocol instance.
//! Inspecting a supplied separator does not authenticate that association, verify
//! a proof, or establish operation admission or composed transcript security.

use crate::Val;
mod argument;
pub use argument::{ArgumentManifest, CommitmentGeometry, MatrixGeometry, inspect_argument};
use p3_challenger::{
    CanObserve,
    fs::{DomainSeparator, FieldUnit},
};

/// Public metadata copied from one SDK separator and its actual seeding stream.
/// This freely clonable snapshot is a diagnostic report, not a capability.
#[derive(Clone, Debug)]
pub struct SeedBinding {
    protocol_id: [u8; 64],
    pattern_hash: [u8; 32],
    instance_label: Vec<u8>,
    observed_fields: Vec<Val>,
}

impl SeedBinding {
    #[must_use]
    pub fn protocol_id(&self) -> &[u8; 64] {
        &self.protocol_id
    }

    #[must_use]
    pub fn pattern_hash(&self) -> &[u8; 32] {
        &self.pattern_hash
    }

    /// The SDK's delimited instance-label bytes, including chunk length prefixes.
    #[must_use]
    pub fn instance_label(&self) -> &[u8] {
        &self.instance_label
    }

    /// Exactly the field elements observed by `DomainSeparator::seed`.
    #[must_use]
    pub fn observed_fields(&self) -> &[Val] {
        &self.observed_fields
    }
}

struct SeedTap(Vec<Val>);

impl CanObserve<Val> for SeedTap {
    fn observe(&mut self, value: Val) {
        self.0.push(value);
    }
}

/// Capture the SDK's actual field-packed seed without constructing a challenger,
/// configuration, RNG or proof. The supplied separator is not authenticated here;
/// its protocol/AIR/instance association remains the trusted caller's obligation.
#[must_use]
pub fn inspect_separator(separator: &DomainSeparator<FieldUnit<Val>>) -> SeedBinding {
    let mut tap = SeedTap(Vec::new());
    separator.seed(&mut tap);
    SeedBinding {
        protocol_id: *separator.protocol_id(),
        pattern_hash: separator.pattern().pattern_hash(),
        instance_label: separator.instance_label().to_vec(),
        observed_fields: tap.0,
    }
}

#[cfg(test)]
mod tests;
