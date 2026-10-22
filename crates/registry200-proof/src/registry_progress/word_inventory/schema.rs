//! Exact208/53 serialization addresses; semantic and hash users share these E IDs.
use super::expr::{Builder, E, Ty};
use super::recipes::Group;
pub(super) const REGISTRY: usize = 208;
pub(super) const SLOT: usize = 53;
pub(super) const TX_BASE: usize = 84;
pub(super) const PRESENT: usize = 0;
pub(super) const ID: usize = 1;
pub(super) const PRINCIPAL: usize = 3;
pub(super) const CONTROLLER: usize = 4;
pub(super) const SEQUENCE: usize = 12;
pub(super) const FAILED: usize = 14;
pub(super) const SNAPSHOT: usize = 15;
pub(super) const HELD: usize = 23;
pub(super) const FRAME0: usize = 27;
pub(super) const FRAME1: usize = 40;
#[derive(Clone)]
pub(super) struct Source<'a> {
    pub words: [E<'a>; 587],
    pub salt: [E<'a>; 4],
    pub ages: [E<'a>; 4],
    pub table: [E<'a>; 8],
    pub ids: [E<'a>; 32],
}
impl<'a> Source<'a> {
    pub fn new(b: &'a Builder) -> Self {
        let words = core::array::from_fn(|i| {
            b.input_primary(&format!("source/word/{i}"), Ty::U32, Group::SourceWord, i)
        });
        let salt = core::array::from_fn(|i| {
            b.input_primary(&format!("source/salt/{i}"), Ty::Gold, Group::SourceSalt, i)
        });
        let bytes: [E<'a>; 12] = core::array::from_fn(|i| {
            b.input_primary(
                &format!("source/age-byte/{i}"),
                Ty::Bits(8),
                Group::SourceByte,
                i,
            )
        });
        for w in 0..3 {
            b.eq(
                words[w],
                b.sum((0..4).map(|i| bytes[4 * w + i] * (1u64 << (8 * i)))),
            );
        }
        Self {
            ages: [bytes[0], bytes[3], bytes[6], bytes[9]],
            table: core::array::from_fn(|i| words[31 + i]),
            ids: core::array::from_fn(|i| words[555 + i]),
            words,
            salt,
        }
    }
}
#[derive(Clone)]
pub(super) struct Bank<'a> {
    pub f: [E<'a>; REGISTRY],
}
#[derive(Clone, Copy)]
pub(super) struct Tx<'a> {
    pub f: [E<'a>; SLOT],
}
impl<'a> Bank<'a> {
    pub fn new(
        b: &'a Builder,
        label: &str,
        header: [E<'a>; 33],
        enrollment: [E<'a>; 4],
        s: &Source<'a>,
    ) -> Self {
        let mut f = [b.c(0); 208];
        f[..33].copy_from_slice(&header);
        f[33..37].copy_from_slice(&enrollment);
        f[37..45].copy_from_slice(&s.table);
        f[45..77].copy_from_slice(&s.ids);
        f[77] = b.c(2);
        f[78] = b.c(4);
        f[79] = b.c(2);
        for (i, v) in f.iter_mut().enumerate().take(84).skip(80) {
            *v = b.input_primary(
                &format!("{label}/field/{i}"),
                Ty::U32,
                Group::Bank(label == "new"),
                i,
            );
        }
        for t in 0..2 {
            for p in 0..53 {
                let ty = match p {
                    0 | 14 | 27 | 40 => Ty::Bool,
                    3 => Ty::Bits(2),
                    23..=26 | 36..=39 | 49..=52 => Ty::Mode,
                    _ => Ty::U32,
                };
                f[TX_BASE + SLOT * t + p] = b.input_primary(
                    &format!("{label}/slot/{t}/{p}"),
                    ty,
                    Group::Bank(label == "new"),
                    TX_BASE + SLOT * t + p,
                );
            }
        }
        for (i, v) in f.iter_mut().enumerate().take(194).skip(190) {
            *v = b.input_primary(
                &format!("{label}/salt/{}", i - 190),
                Ty::Gold,
                Group::Bank(label == "new"),
                i,
            );
        }
        for t in 0..2 {
            f[194 + 5 * t] = b.input_primary(
                &format!("{label}/progress/{t}/present"),
                Ty::Bool,
                Group::Bank(label == "new"),
                194 + 5 * t,
            );
            for w in 0..4 {
                f[195 + 5 * t + w] = b.input_primary(
                    &format!("{label}/progress/{t}/root/{w}"),
                    Ty::Gold,
                    Group::Bank(label == "new"),
                    195 + 5 * t + w,
                );
            }
        }
        for (i, e) in f.iter().enumerate() {
            b.field(format!("{label}/serialized/{i}"), *e);
        }
        Self { f }
    }
    pub fn tx(&self, t: usize) -> Tx<'a> {
        Tx {
            f: self.f[TX_BASE + SLOT * t..TX_BASE + SLOT * (t + 1)]
                .try_into()
                .expect("fixed53"),
        }
    }
    pub fn revision(&self) -> [E<'a>; 2] {
        [self.f[80], self.f[81]]
    }
    pub fn allocator(&self) -> [E<'a>; 2] {
        [self.f[82], self.f[83]]
    }
    pub fn progress(&self, t: usize) -> [E<'a>; 5] {
        self.f[194 + 5 * t..199 + 5 * t].try_into().expect("fixed5")
    }
}
impl<'a> Tx<'a> {
    pub fn limbs(&self, p: usize) -> [E<'a>; 2] {
        [self.f[p], self.f[p + 1]]
    }
    pub fn words<const N: usize>(&self, p: usize) -> [E<'a>; N] {
        self.f[p..p + N].try_into().expect("fixed words")
    }
    pub fn frame(&self, f: usize) -> [E<'a>; 13] {
        let p = if f == 0 {
            FRAME0
        } else {
            assert_eq!(f, 1);
            FRAME1
        };
        self.f[p..p + 13].try_into().expect("fixed13")
    }
}
pub(super) fn controllers(b: &Builder) -> [[E<'_>; 8]; 2] {
    core::array::from_fn(|p| {
        core::array::from_fn(|w| {
            b.input_primary(
                &format!("enrollment/controller/{p}/{w}"),
                Ty::U32,
                Group::Controller(p),
                w,
            )
        })
    })
}
pub(super) fn select_tx<'a>(old: &Bank<'a>, actor: [E<'a>; 2]) -> Tx<'a> {
    Tx {
        f: core::array::from_fn(|i| actor[0] * old.tx(0).f[i] + actor[1] * old.tx(1).f[i]),
    }
}
pub(super) fn select_progress<'a>(old: &Bank<'a>, actor: [E<'a>; 2]) -> [E<'a>; 5] {
    core::array::from_fn(|i| actor[0] * old.progress(0)[i] + actor[1] * old.progress(1)[i])
}
