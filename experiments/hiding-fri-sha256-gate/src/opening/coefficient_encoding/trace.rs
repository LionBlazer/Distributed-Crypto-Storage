//! Explicit caller-owned private Source/mask openings; no Owner getters or private wire format.
use super::{Expected, Statement};
use crate::backend::{Error, TRACE_HEIGHT, Val};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_matrix::dense::RowMajorMatrix;
use registry200_proof::coefficient_encoding::{
    N, Role, SCALE, T, air::EncodingAir, commitment, layout::*,
};
use zeroize::Zeroizing;
pub(super) struct Witness {
    plain: Zeroizing<Vec<u8>>,
    mask: Zeroizing<[u8; 32]>,
    opening_salt: Zeroizing<[u64; 4]>,
    encoding_salt: Zeroizing<[u64; 4]>,
}
fn vals(x: [u64; 4]) -> Result<[Val; 4], Error> {
    if x.iter().any(|v| *v >= Val::ORDER_U64) {
        return Err(Error::Shape);
    }
    Ok(x.map(Val::from_u64))
}
pub(super) fn bits(out: &mut [Val], v: u64) {
    for (i, x) in out.iter_mut().enumerate() {
        *x = Val::from_u64((v >> i) & 1);
    }
}
impl Witness {
    pub fn source(
        e: &Expected,
        plain: Zeroizing<Vec<u8>>,
        opening_salt: [u64; 4],
        encoding_salt: [u64; 4],
    ) -> Result<Self, Error> {
        if e.role() != Role::SourceAllOriginal || plain.len() != 2348 {
            return Err(Error::Shape);
        }
        let salt = vals(opening_salt)?;
        let _ = vals(encoding_salt)?;
        if registry200_proof::source::commitment::digest(
            &registry200_proof::source::commitment::opening_fields(e.source_claim(), salt, &plain),
        ) != e.source_claim().open_commitment
        {
            return Err(Error::Shape);
        }
        Ok(Self {
            plain,
            mask: Zeroizing::new([0; 32]),
            opening_salt: Zeroizing::new(opening_salt),
            encoding_salt: Zeroizing::new(encoding_salt),
        })
    }
    pub fn private_mask(
        e: &Expected,
        mask: Zeroizing<[u8; 32]>,
        command_salt: [u64; 4],
        encoding_salt: [u64; 4],
    ) -> Result<Self, Error> {
        if e.role() != Role::PrivateMask {
            return Err(Error::Shape);
        }
        let salt = vals(command_salt)?;
        let _ = vals(encoding_salt)?;
        if commitment::command_digest(&commitment::command_fields(e, *mask, salt)) != e.command() {
            return Err(Error::Shape);
        }
        Ok(Self {
            plain: Zeroizing::new(Vec::new()),
            mask,
            opening_salt: Zeroizing::new(command_salt),
            encoding_salt: Zeroizing::new(encoding_salt),
        })
    }
    pub fn coefficients(&self, role: Role) -> Zeroizing<Vec<u64>> {
        let mut out = Zeroizing::new(vec![0; N]);
        match role {
            Role::SourceAllOriginal => {
                for i in 0..4 {
                    let age = self.plain[3 * i] as usize;
                    let amount =
                        u16::from_le_bytes(self.plain[3 * i + 1..3 * i + 3].try_into().unwrap());
                    for (f, v) in [1, age as u64, u64::from(amount)].into_iter().enumerate() {
                        out[(3 * i + f) * 512 + age] = v * SCALE % T;
                    }
                }
            }
            Role::PrivateMask => {
                for n in 0..256 {
                    let age = 255 - n;
                    out[n] = u64::from((self.mask[age / 8] >> (age % 8)) & 1) * SCALE;
                }
            }
        }
        out
    }
    pub fn statement(&self, e: &Expected) -> Statement {
        let coefficients = self.coefficients(e.role());
        let fields: Vec<_> = coefficients.iter().copied().map(Val::from_u64).collect();
        Statement {
            expected: e.clone(),
            encoded: bfv_key_transform::circuit::digest(
                e.encoding_context(),
                (*self.encoding_salt).map(Val::from_u64),
                &fields,
            ),
        }
    }
    pub fn trace(&self, s: &Statement) -> Result<RowMajorMatrix<Val>, Error> {
        let role = s.expected.role();
        let width = role.width();
        let mut values = Val::zero_vec(width * TRACE_HEIGHT);
        if role == Role::SourceAllOriginal {
            for (r, row) in values.chunks_exact_mut(width).enumerate() {
                for byte in 0..12 {
                    bits(
                        &mut row[DATA + 8 * byte..DATA + 8 * (byte + 1)],
                        u64::from(self.plain[byte]),
                    );
                }
                for (bank, first, count) in [(TABLE, 31, 8), (IDS, 555, 32)] {
                    for word in 0..count {
                        row[bank + word] = Val::from_u32(u32::from_le_bytes(
                            self.plain[4 * (first + word)..4 * (first + word + 1)]
                                .try_into()
                                .unwrap(),
                        ));
                    }
                }
                row[SOURCE_SALT..SOURCE_SALT + 4].copy_from_slice(&vals(*self.opening_salt)?);
                row[SOURCE_ENC_SALT..SOURCE_ENC_SALT + 4]
                    .copy_from_slice(&vals(*self.encoding_salt)?);
                if r < 85 {
                    for word in 0..8 {
                        let f = 8 * r + word;
                        if (87..674).contains(&f) {
                            bits(
                                &mut row[WORDS + 32 * word..WORDS + 32 * (word + 1)],
                                u64::from(u32::from_le_bytes(
                                    self.plain[4 * (f - 87)..4 * (f - 86)].try_into().unwrap(),
                                )),
                            );
                        }
                    }
                }
                for i in 0..4 {
                    for f in 0..2 {
                        let v = if f == 0 {
                            u64::from(self.plain[3 * i])
                        } else {
                            u64::from(u16::from_le_bytes(
                                self.plain[3 * i + 1..3 * i + 3].try_into().unwrap(),
                            ))
                        };
                        let w = v * SCALE % T;
                        let at = weight(i, f);
                        bits(&mut row[at..at + 17], w);
                        bits(&mut row[at + 17..at + 34], T - 1 - w);
                        bits(&mut row[at + 34..at + 50], v * SCALE / T);
                    }
                }
                for l in 0..16 {
                    let n = 16 * r + l;
                    let lane = n / 512;
                    let j = n % 512;
                    if lane < 12 && j < 256 {
                        let age = usize::from(self.plain[3 * (lane / 3)]);
                        let d = age + 256 - j;
                        let at = EQUALITY + 11 * l;
                        bits(&mut row[at..at + 8], (d % 256) as u64);
                        row[at + 8] = Val::from_usize(d / 256);
                        row[at + 9] = Val::from_bool(d % 256 == 0);
                        row[at + 10] = Val::from_usize(d % 256).try_inverse().unwrap_or(Val::ZERO);
                    }
                }
            }
        }
        if role == Role::PrivateMask {
            for row in values.as_chunks_mut::<QUERY_WIDTH>().0 {
                for i in 0..32 {
                    bits(
                        &mut row[MASK + 8 * i..MASK + 8 * i + 8],
                        u64::from(self.mask[i]),
                    );
                }
                row[COMMAND_SALT..COMMAND_SALT + 4].copy_from_slice(&vals(*self.opening_salt)?);
                row[QUERY_ENC_SALT..QUERY_ENC_SALT + 4]
                    .copy_from_slice(&vals(*self.encoding_salt)?);
            }
        }
        let mut trace = RowMajorMatrix::new(values, width);
        let words = self.coefficients(role);
        let _ = refresh(s, &mut trace, &words);
        Ok(trace)
    }
    /// Produces only an owned mathematical opening, never Source/SQL or key authority.
    pub fn formation_opening(
        &self,
        s: &Statement,
    ) -> Result<bfv_ciphertext_formation::EncodedOpening, Error> {
        let c = bfv_ciphertext_formation::EncodedCommitment::new(
            s.producer_identity(),
            s.expected.encoding_context().map(|v| v.as_canonical_u64()),
            s.encoded.map(|v| v.as_canonical_u64()),
        )?;
        bfv_ciphertext_formation::EncodedOpening::new(
            self.coefficients(s.expected.role()),
            *self.encoding_salt,
            c,
        )
    }
}
/// Rebuilt-test helper uses explicit caller-owned W; it cannot authorize a false trace.
pub(super) fn refresh(s: &Statement, trace: &mut RowMajorMatrix<Val>, words: &[u64]) -> [Val; 4] {
    assert_eq!(words.len(), N);
    let air = EncodingAir::new(s);
    let role = s.expected.role();
    let width = role.width();
    let context = s.expected.encoding_context();
    let salt = if role == Role::SourceAllOriginal {
        SOURCE_ENC_SALT
    } else {
        QUERY_ENC_SALT
    };
    let mut open = [Val::ZERO; 12];
    let mut vector = [Val::ZERO; 12];
    let mut carry = [Val::ZERO; 8];
    let mut root = [Val::ZERO; 4];
    for (r, row) in trace.values.chunks_exact_mut(width).enumerate() {
        row[OPEN_CP..OPEN_CP + 12].copy_from_slice(&open);
        let w = core::array::from_fn(|l| Val::from_u64(words[16 * r + l]));
        let enc_salt = row[salt..salt + 4].try_into().unwrap();
        let (result, digest) =
            commitment::write_vector(row, r, context, enc_salt, w, vector, carry);
        vector = result;
        carry = w[8..].try_into().unwrap();
        if r == 511 {
            root = digest;
        }
        row[3 * P2..4 * P2].fill(Val::ZERO);
        if r < (if role == Role::SourceAllOriginal {
            85
        } else {
            6
        }) {
            let mut input = [Val::ZERO; 12];
            for (word, v) in input[..8].iter_mut().enumerate() {
                *v = air.opening_field::<Val, _>(row, 8 * r + word, word);
            }
            input[8..].copy_from_slice(&open[8..]);
            open = bfv_hiding_stark::poseidon::write(&mut row[3 * P2..4 * P2], input);
        }
    }
    root
}
