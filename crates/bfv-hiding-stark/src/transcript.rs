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
    fs::{DomainSeparator, FieldUnit, Hierarchy, InteractionPattern, Kind, Length, TypeTag},
};
use p3_field::PrimeField64;
use std::sync::Arc;

/// Public metadata copied from one SDK separator and its actual seeding stream.
/// This freely clonable snapshot is a diagnostic report, not a capability.
#[derive(Clone, Debug)]
pub struct SeedBinding {
    protocol_id: [u8; 64],
    pattern_hash: [u8; 32],
    instance_label: Vec<u8>,
    observed_fields: Vec<Val>,
    pattern: Arc<InteractionPattern>,
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

    /// Base-field draws in each consecutive challenge group of this SDK pattern.
    ///
    /// Adjacent extension challenges share a group. So do all index draws before
    /// the next observation. Zero grinding, hints and structural markers do not
    /// absorb data and cannot split a group. A domain separator seeds an actual
    /// observation between parent/PCS/FRI patterns, so owners concatenate their
    /// separately inspected groups without merging across those boundaries.
    ///
    /// This fixed Gold/EF5 diagnostic rejects unsupported or variable sampling
    /// shapes. Counts measure Gold draws, not uniform bits or cryptographic
    /// security. In particular, projecting a Gold draw to low index bits keeps
    /// the bias accounted for separately by the algebraic analyzer.
    pub fn challenge_group_base_draws(&self) -> Result<Vec<usize>, crate::Error> {
        let mut groups = Vec::new();
        let mut pending = 0usize;
        for step in self.pattern.interactions() {
            if step.hierarchy() != Hierarchy::Atomic || step.kind() == Kind::Hint {
                continue;
            }
            let length = match step.length() {
                Length::Scalar => 1,
                Length::Fixed(n) => n,
                Length::None => 0,
                Length::Bounded(_) => return Err(crate::Error::Shape),
            };
            match step.kind() {
                Kind::Challenge => {
                    let degree = match step.type_tag() {
                        TypeTag::Algebra {
                            modulus, degree, ..
                        } if modulus == Val::ORDER_U64 && matches!(degree, 1 | 5) => degree,
                        TypeTag::Bits { width } if width < 64 => 1,
                        _ => return Err(crate::Error::Shape),
                    };
                    pending = degree
                        .checked_mul(length)
                        .and_then(|n| pending.checked_add(n))
                        .ok_or(crate::Error::Shape)?;
                }
                Kind::Public | Kind::Message | Kind::Salt if length != 0 => {
                    if pending != 0 {
                        groups.push(core::mem::take(&mut pending));
                    }
                }
                Kind::Pow if length != 0 => return Err(crate::Error::Shape),
                _ => {}
            }
        }
        if pending != 0 {
            groups.push(pending);
        }
        Ok(groups)
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
        pattern: separator.pattern().clone(),
    }
}

#[cfg(test)]
mod tests;
