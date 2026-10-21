//! Standalone private-wire primitive experiment; no database or SQL admission.
#![forbid(unsafe_code)]
mod air;
mod assessment;
mod setup;
#[cfg(test)]
mod tests;
mod wire;

use bfv_hiding_stark::{Config, Val};
use p3_batch_stark::{BatchProof, StarkInstance, prove_batch, verify_batch};
use p3_field::PrimeCharacteristicRing;
use sha2::{Digest, Sha512};
use std::panic::{AssertUnwindSafe, catch_unwind};
use zeroize::Zeroize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Error {
    Shape,
    Resource,
    Randomness,
    Security,
    Proving,
    Verification,
    Encoding,
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}
type Result<T> = std::result::Result<T, Error>;

const MAX_OUTPUT: u32 = 255 * 255 + 3 + 65535;

/// Independently retained public expectation, not supplied by a proof frame.
#[derive(Clone, PartialEq, Eq)]
struct Expected {
    context: [u8; 32],
    output: u32,
}
impl Expected {
    fn new(context: [u8; 32], output: u32) -> Result<Self> {
        if output > MAX_OUTPUT {
            return Err(Error::Shape);
        }
        Ok(Self { context, output })
    }
    fn values(&self) -> Vec<Val> {
        let mut values = Vec::with_capacity(air::PUBLIC_VALUES);
        for bytes in [profile(), self.context] {
            values.extend(
                bytes
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .map(|b| Val::from_u32(u32::from_le_bytes(*b))),
            );
        }
        values.push(Val::from_u32(self.output));
        values
    }
}

struct Witness {
    x: u8,
    z: u16,
}
impl Witness {
    fn new(x: u8, z: u16) -> Self {
        Self { x, z }
    }
    fn output(&self) -> u32 {
        u32::from(self.x).pow(2) + 3 + u32::from(self.z)
    }
}
impl Drop for Witness {
    fn drop(&mut self) {
        self.x.zeroize();
        self.z.zeroize();
    }
}

/// A mathematical result exists only after this frontend's actual native verifier.
struct Verified {
    output: u32,
}
impl Verified {
    fn output(&self) -> u32 {
        self.output
    }
}

fn profile() -> [u8; 32] {
    let mut hash = Sha512::new();
    hash.update(b"dcs/experiment/hiding-logup-wire/v1\0");
    hash.update(b"Gold/EF5/H512/ZK10/blowup3/Q192/salt4/random5/zero-grinding/default-pack\0");
    hash.update(b"main19/pp3/pv17/no-main-next/no-pp-next/one-air\0");
    hash.update(b"row0:a=x^2+3,x8;row1:b=in+z,z16;row2:in=publicY;other-cells-zero\0");
    hash.update(air::BUS.as_bytes());
    hash.update(b"/node1:row0+row1-/node2:row1+row2-/count-bound1\0");
    hash.update(b"publicPP-only-sha512-seeds-v1/native-batch0.8.0/full-symbolic-logup-floor128\0");
    hash.update((wire::MAX_PAYLOAD as u64).to_le_bytes());
    hash.update((wire::HEADER_BYTES as u64).to_le_bytes());
    hash.update((wire::MAX_SEQUENCE as u64).to_le_bytes());
    hash.update((wire::MAX_SLOTS as u64).to_le_bytes());
    hash.finalize()[..32]
        .try_into()
        .expect("fixed digest length")
}

fn private_config() -> Result<Config> {
    bfv_hiding_stark::config().map_err(|_| Error::Randomness)
}

fn prove(expected: &Expected, witness: Witness) -> Result<Vec<u8>> {
    if witness.output() != expected.output {
        return Err(Error::Shape);
    }
    let air = air::FixedAir::new(expected);
    air.preflight()?;
    let data = setup::public_data(&air, expected)?;
    let assessment = assessment::assess(&air, &data.common)?;
    assessment.log();
    let trace = air.trace(&witness);
    let proof = prove_trace(expected, &air, &trace, &data)?;
    wire::encode(expected, &proof, &assessment)
}

fn prove_trace(
    expected: &Expected,
    air: &air::FixedAir,
    trace: &air::PrivateTrace,
    data: &p3_batch_stark::ProverData<Config>,
) -> Result<BatchProof<Config>> {
    let config = private_config()?;
    let instances = [StarkInstance {
        air,
        trace: &trace.0,
        public_values: expected.values(),
    }];
    catch_unwind(AssertUnwindSafe(|| prove_batch(&config, &instances, data)))
        .map_err(|_| Error::Proving)?
        .map_err(|_| Error::Proving)
}

fn verify(expected: &Expected, frame: &[u8]) -> Result<Verified> {
    // Header/length/Expected checks precede any SDK setup or decoding allocation.
    let payload = wire::payload(expected, frame)?;
    let air = air::FixedAir::new(expected);
    air.preflight()?;
    let data = setup::public_data(&air, expected)?;
    let assessment = assessment::assess(&air, &data.common)?;
    let proof = wire::decode(payload, &assessment)?;
    let common = data.common;
    drop(data.prover_only); // Rebuilt public PP prover buffers are not verifier authority.
    verify_native(expected, &air, &proof, &common)?;
    Ok(Verified {
        output: expected.output,
    })
}

fn verify_native(
    expected: &Expected,
    air: &air::FixedAir,
    proof: &BatchProof<Config>,
    common: &p3_batch_stark::CommonData<Config>,
) -> Result<()> {
    let config = private_config()?;
    catch_unwind(AssertUnwindSafe(|| {
        verify_batch(
            &config,
            std::slice::from_ref(air),
            proof,
            &[expected.values()],
            common,
        )
    }))
    .map_err(|_| Error::Verification)?
    .map_err(|_| Error::Verification)
}

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.is_empty() || args == ["--show-profile"] {
        let digest: String = profile().iter().map(|byte| format!("{byte:02x}")).collect();
        println!(
            "kind=hiding_logup_wire_profile profile={} proof_verified=false fhe=false sql=false freshness=false",
            digest
        );
        return Ok(());
    }
    if args != ["--public-fixture"] {
        return Err(Error::Shape.into());
    }
    // Explicit non-secret fixture. No witness values, masks or private trace are printed.
    let whole_start = std::time::Instant::now();
    let witness = Witness::new(17, 211);
    let expected = Expected::new([0x51; 32], witness.output())?;
    let start = std::time::Instant::now();
    let frame = prove(&expected, witness)?;
    let proving = start.elapsed();
    let start = std::time::Instant::now();
    let verified = verify(&expected, &frame)?;
    let verifying = start.elapsed();
    println!(
        "actual_native_logup=true output={} frame_bytes={} prove_ms={} verify_ms={} whole_local_ms={} fhe=false sql=false freshness=false",
        verified.output(),
        frame.len(),
        proving.as_secs_f64() * 1000.,
        verifying.as_secs_f64() * 1000.,
        whole_start.elapsed().as_secs_f64() * 1000.
    );
    Ok(())
}
