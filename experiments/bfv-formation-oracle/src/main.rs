//! Native PUBLIC NONSECRET BFV formation oracle. No proof or accepting API.
mod ntt;
mod oracle;
mod packing;

#[cfg(test)]
mod tests;

type Result<T> = std::result::Result<T, String>;
const DEGREE: usize = 8192;
const LOG_DEGREE: u32 = 13;
const PLAINTEXT: u64 = 114_689;
const VARIANCE: usize = 10;
const CBD_U64_DRAWS: usize = DEGREE * 40 / 64;
const MODULI: [u64; 5] = [
    8_796_092_858_369,
    8_796_092_792_833,
    17_592_186_028_033,
    17_592_185_438_209,
    17_592_184_717_313,
];

fn main() {
    if std::env::args_os().len() != 1 {
        eprintln!("usage: bfv-formation-oracle (PUBLIC NONSECRET fixtures only)");
        std::process::exit(2);
    }
    if let Err(error) = run() {
        eprintln!("native oracle rejected: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    for layout in packing::Layout::ALL {
        let packed = packing::pack(layout, &packing::PUBLIC_ROWS)?;
        let fixture = oracle::Fixture::encrypt(&packed)?;
        fixture.check(&packed)?;
        println!(
            "{{\"stage\":\"native_bfv_formation_oracle\",\"layout\":\"{}\",\"degree\":8192,\"moduli\":5,\"plaintext_modulus\":114689,\"variance\":10,\"checked_b_residues\":40960,\"checked_plaintext_coefficients\":8192,\"caller_rng_u64_draws_per_sample\":{},\"public_nonsecret_fixture\":true,\"cryptographic_proof\":false}}",
            layout.name(),
            CBD_U64_DRAWS,
        );
    }
    Ok(())
}
