//! Nonaccepting two-AIR metadata candidate. No MAIN, proof, codec or admission API.
mod air;
mod assessment;
mod layout;
mod plan;
mod public;
mod tests;
use super::pp as old_pp;
use crate::gold::{Error, Result, Val, data, fft, graph, relation::RelationKind};
use layout::*;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use sha2::{Digest, Sha256, Sha512};
