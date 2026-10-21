//! Typed private primary ownership and bounded PUBLIC honest examples.
//! Neither a model state, a hash nor this constructor establishes admission.
#[cfg(test)]
use super::{Metadata, domain, header};
use super::{
    Val,
    evaluate::{Error, Result},
    recipes::{CmdField, Group, Primary, SaltField, WalkField},
};
use crate::registry_progress::word::{CommandInput, WalkInput};
#[cfg(test)]
use crate::source::{self, version::SourceVersionExpected};
#[cfg(test)]
use bfv_hiding_stark::poseidon;
use p3_field::PrimeCharacteristicRing;
#[cfg(test)]
use sha2::{Digest, Sha512};
/// Fixed primary fields, never an external string map or arbitrary callback.
/// All values are private except the explicitly NONSECRET test fixture below.
pub(in crate::registry_progress) struct PrimaryInputs {
    pub source: [Val; 587],
    pub source_salt: [Val; 4],
    pub source_bytes: [u8; 12],
    pub controllers: [[Val; 8]; 2],
    pub banks: [[Val; 208]; 2],
    pub command: CommandInput,
    pub walk: WalkInput,
    pub mask: [u8; 32],
    pub salts: [[Val; 4]; 3],
}
fn limb(x: u64, i: usize) -> Result<Val> {
    if i >= 2 {
        return Err(Error::Shape);
    }
    Ok(Val::from_u32((x >> (32 * i)) as u32))
}
fn one(index: usize, selected: usize, n: usize) -> Result<Val> {
    if index >= n || selected >= n {
        return Err(Error::Shape);
    }
    Ok(Val::from_bool(index == selected))
}
fn at(a: &[Val], i: usize) -> Result<Val> {
    a.get(i).copied().ok_or(Error::Shape)
}
impl PrimaryInputs {
    pub(super) fn value(&self, p: Primary) -> Result<Val> {
        let i = p.index;
        let c = &self.command;
        let w = &self.walk;
        match p.group {
            Group::SourceWord => at(&self.source, i),
            Group::SourceSalt => at(&self.source_salt, i),
            Group::SourceByte => self
                .source_bytes
                .get(i)
                .copied()
                .map(Val::from_u8)
                .ok_or(Error::Shape),
            Group::Controller(n) => at(self.controllers.get(n).ok_or(Error::Shape)?, i),
            Group::Bank(new) => at(&self.banks[usize::from(new)], i),
            Group::Salt(s) => at(
                &self.salts[match s {
                    SaltField::Enrollment => 0,
                    SaltField::Command => 1,
                    SaltField::Result => 2,
                }],
                i,
            ),
            Group::Command(f) => match f {
                CmdField::Op => one(i, c.op, 7),
                CmdField::Actor => {
                    if i >= 2 {
                        return Err(Error::Shape);
                    }
                    Ok(Val::from_bool(c.actor == Some(i)))
                }
                CmdField::Principal => one(i, c.principal.checked_sub(1).ok_or(Error::Shape)?, 2),
                CmdField::Id => limb(c.id, i),
                CmdField::Name => c
                    .name
                    .get(i)
                    .copied()
                    .map(Val::from_u32)
                    .ok_or(Error::Shape),
                CmdField::Mode => one(
                    i,
                    usize::from(c.mode.checked_sub(1).ok_or(Error::Shape)?),
                    4,
                ),
                CmdField::Wait => one(i, usize::from(c.wait), 3),
                CmdField::Offset => one(i, usize::from(c.offset), 5),
                CmdField::Limit => one(i, usize::from(c.limit), 5),
                CmdField::Projection => {
                    if i >= 2 || !(1..=3).contains(&c.projection) {
                        return Err(Error::Shape);
                    }
                    Ok(Val::from_bool(c.projection & (1 << i) != 0))
                }
                CmdField::Abort => {
                    if i == 0 {
                        Ok(Val::from_bool(c.abort))
                    } else {
                        Err(Error::Shape)
                    }
                }
            },
            Group::Walk(f) => match f {
                WalkField::Client => at(&w.client, i),
                WalkField::Call => limb(w.call, i),
                WalkField::Invocation => at(&w.invocation, i),
                WalkField::Sql => at(&w.sql, i),
                WalkField::Cursor => one(i, usize::from(w.cursor), 5),
                WalkField::Micro => limb(w.micro, i),
                WalkField::Holder => limb(w.holder, i),
                WalkField::Revision => limb(w.revision, i),
                WalkField::Mode => {
                    if i == 0 {
                        Ok(Val::from_u8(w.mode))
                    } else {
                        Err(Error::Shape)
                    }
                }
                WalkField::OldSalt => at(&w.old_salt, i),
                WalkField::NewSalt => at(&w.new_salt, i),
                WalkField::StatementSalt => at(&w.statement_salt, i),
                WalkField::Visited => w
                    .visited
                    .get(i)
                    .copied()
                    .map(Val::from_bool)
                    .ok_or(Error::Shape),
                WalkField::Selected => w
                    .selected
                    .get(i)
                    .copied()
                    .map(Val::from_bool)
                    .ok_or(Error::Shape),
            },
        }
    }
}
impl Drop for PrimaryInputs {
    fn drop(&mut self) {
        self.source.fill(Val::ZERO);
        self.source_salt.fill(Val::ZERO);
        self.source_bytes.fill(0);
        self.controllers.iter_mut().for_each(|v| v.fill(Val::ZERO));
        self.banks.iter_mut().for_each(|v| v.fill(Val::ZERO));
        self.mask.fill(0);
        self.salts.iter_mut().for_each(|v| v.fill(Val::ZERO));
    }
}
/// Exact absorb rule, with guarded scratch, never a proof or a serialized status.
#[cfg(test)]
pub(super) fn hash(v: &[Val]) -> [Val; 4] {
    assert!(!v.is_empty() && v.len().is_multiple_of(8));
    let mut state = [Val::ZERO; 12];
    let mut scratch = [Val::ZERO; 248];
    for block in v.as_chunks::<8>().0 {
        state[..8].copy_from_slice(block);
        state = poseidon::write(&mut scratch, state);
    }
    scratch.fill(Val::ZERO);
    state[..4].try_into().expect("root4")
}
#[cfg(test)]
pub(super) fn words(bytes: &[u8]) -> Vec<Val> {
    source::statement::words(bytes).collect()
}
#[cfg(test)]
pub(super) fn append64(v: &mut Vec<Val>, x: u64) {
    v.extend([Val::from_u32(x as u32), Val::from_u32((x >> 32) as u32)]);
}
/// PUBLIC NONSECRET original ciphertext images from the golden fixture; NO proof
/// generator, FHE evaluator, Data admission, accepted bank or SQL answer is used.
/// Only two honest cases are generated here: Begin and Start/Done. The complete
/// evaluator still handles every recipe, input kind, hash and fixed lookup.
#[cfg(test)]
pub(super) fn public_case(predicate: bool) -> (Metadata, PrimaryInputs) {
    public_case_variant(predicate, 0)
}
#[cfg(test)]
pub(super) fn public_case_variant(predicate: bool, variant: u8) -> (Metadata, PrimaryInputs) {
    let mut m = Metadata::sample(predicate);
    m.parent[0] += Val::from_u8(variant);
    m.context[16..24].copy_from_slice(&m.parent);
    m.blind_sql[0] += Val::from_u8(variant);
    let s = m.source.statement();
    let mut plain = [0u8; 2348];
    plain[..12].copy_from_slice(&[0, 1, 0, 1, 2, 0, 128, 3, 0, 255, 4, 0]);
    let index = &mut plain[12..];
    index[..112].copy_from_slice(&s.heads[0]);
    index[112..144].fill(0x31);
    let ages = [0u8, 1, 128, 255];
    let mut count = 0u32;
    for age in 0..256 {
        let yes = ages.contains(&(age as u8));
        index[144 + 4 * age..148 + 4 * age].copy_from_slice(&u32::from(yes).to_le_bytes());
        index[1168 + 4 * age..1172 + 4 * age].copy_from_slice(&count.to_le_bytes());
        if yes {
            index[2196 + count as usize] =
                ages.iter().position(|a| usize::from(*a) == age).unwrap() as u8;
            count += 1;
        }
    }
    index[2192..2196].copy_from_slice(&count.to_le_bytes());
    for i in 0..4 {
        index[2208 + 32 * i] = i as u8 + 1;
    }
    let cstate = source::commitment::digest(&source::commitment::opening_fields(
        s,
        [Val::TWO; 4],
        &plain,
    ));
    let images: [Vec<u8>; 2] =
        core::array::from_fn(|i| s.heads[i].iter().chain(&s.packets[i]).copied().collect());
    let heads = core::array::from_fn::<_, 2, _>(|i| {
        compact_store::Commitment::decode(&s.heads[i], source::statement::limits()).unwrap()
    });
    m.source = SourceVersionExpected::checked(
        [&images[0], &images[1]],
        [&heads[0], &heads[1]],
        source::statement::encode_digest(s.key_commitment),
        source::statement::encode_digest(cstate),
    )
    .unwrap();
    let mut scope = Sha512::new();
    scope.update(super::PROFILE_DOMAIN);
    scope.update(m.source.version_id());
    scope.update(m.source.state_commitment());
    for image in &images {
        scope.update((image.len() as u64).to_le_bytes());
        scope.update(image);
    }
    scope.update(source::statement::encode_digest(
        m.source.statement().key_commitment,
    ));
    m.scope = words(&scope.finalize()).try_into().unwrap();
    m.context[36..40].copy_from_slice(&cstate);
    m.context[44..60].copy_from_slice(&m.scope);
    let controllers = [
        words(&[0x41; 32]).try_into().unwrap(),
        words(&[0x42; 32]).try_into().unwrap(),
    ];
    let mut p = PrimaryInputs {
        source: words(&plain).try_into().unwrap(),
        source_salt: [Val::TWO; 4],
        source_bytes: plain[..12].try_into().unwrap(),
        controllers,
        banks: [[Val::ZERO; 208]; 2],
        command: CommandInput::default(),
        walk: WalkInput::default(),
        mask: [0; 32],
        salts: [
            [Val::from_u8(3); 4],
            [Val::from_u8(4); 4],
            [Val::from_u8(5); 4],
        ],
    };
    plain.fill(0);
    let mut enrollment = m.enrollment_header.to_vec();
    enrollment.extend(&p.source[31..39]);
    enrollment.extend([Val::TWO, Val::ONE]);
    enrollment.extend(p.controllers[0]);
    enrollment.push(Val::TWO);
    enrollment.extend(p.controllers[1]);
    enrollment.extend(p.salts[0]);
    assert_eq!(enrollment.len(), 64);
    m.enrollment = hash(&enrollment);
    m.context[40..44].copy_from_slice(&m.enrollment);
    enrollment.fill(Val::ZERO);
    for bank in &mut p.banks {
        bank[..33].copy_from_slice(&m.registry_header);
        bank[33..37].copy_from_slice(&m.enrollment);
        bank[37..45].copy_from_slice(&p.source[31..39]);
        bank[45..77].copy_from_slice(&p.source[555..587]);
        bank[77..80].copy_from_slice(&[Val::TWO, Val::from_u8(4), Val::TWO]);
        bank[190..194].fill(Val::from_u8(6));
    }
    p.command.id = 1;
    p.command.principal = 1;
    if predicate {
        p.command.op = 1;
        p.command.actor = Some(0);
        p.command.mode = 4;
        p.command.limit = 2;
        p.command.offset = 1;
        p.command.projection = 3;
        p.mask.fill(255);
        for bank in &mut p.banks {
            bank[80] = Val::ONE;
            bank[82] = Val::ONE;
            let tx = &mut bank[84..137];
            tx[0] = Val::ONE;
            tx[1] = Val::ONE;
            tx[3] = Val::ONE;
            tx[4..12].copy_from_slice(&p.controllers[0]);
            tx[12] = Val::ONE;
            tx[15..23].copy_from_slice(&m.parent);
        }
        p.banks[1][80] = Val::TWO;
        p.banks[1][96] = Val::TWO;
        p.banks[1][107..110].fill(Val::from_u8(4));
        p.walk.client = words(&[0x51; 32]).try_into().unwrap();
        p.walk.call = 7;
        p.walk.invocation = words(&[0x52; 32]).try_into().unwrap();
        p.walk.sql = m.blind_sql;
        p.walk.statement_salt = [Val::from_u8(8); 4];
    } else {
        p.command.op = 0;
        p.banks[1][80] = Val::ONE;
        p.banks[1][82] = Val::ONE;
        let tx = &mut p.banks[1][84..137];
        tx[0] = Val::ONE;
        tx[1] = Val::ONE;
        tx[3] = Val::ONE;
        tx[4..12].copy_from_slice(&p.controllers[0]);
        tx[12] = Val::ONE;
        tx[15..23].copy_from_slice(&m.parent);
    }
    m.old = hash(&p.banks[0]);
    m.next = hash(&p.banks[1]);
    let mut command = domain("command").to_vec();
    command.push(Val::ONE);
    command.extend(m.context);
    command.extend(m.old);
    command.push(Val::from_usize(p.command.op));
    append64(&mut command, 1);
    command.push(Val::ONE);
    command.extend(p.controllers[0]);
    command.extend(&p.banks[0][80..82]);
    command.extend(if predicate {
        p.banks[0][96..98].to_vec()
    } else {
        vec![Val::ZERO; 2]
    });
    command.extend(words(&p.mask));
    command.extend([
        Val::from_u8(p.command.mode),
        Val::from_u8(p.command.wait),
        Val::from_u8(p.command.offset),
        Val::from_u8(p.command.limit),
        Val::from_u8(p.command.projection),
    ]);
    command.extend([Val::ZERO; 8]);
    command.extend(if predicate { [Val::ZERO; 8] } else { m.parent });
    command.push(Val::ZERO);
    command.extend(p.salts[1]);
    command.push(Val::ZERO);
    assert_eq!(command.len(), 160);
    m.command = hash(&command);
    command.fill(Val::ZERO);
    let mut statement = header("statement");
    statement.extend(m.scope);
    statement.extend(m.enrollment);
    statement.extend(p.walk.client);
    append64(&mut statement, p.walk.call);
    append64(&mut statement, 1);
    statement.push(Val::ONE);
    statement.extend(p.controllers[0]);
    statement.extend(p.walk.invocation);
    statement.extend(p.walk.sql);
    statement.extend(if predicate { m.parent } else { [Val::ZERO; 8] });
    statement.extend(words(&p.mask));
    statement.extend([
        Val::from_u8(p.command.mode),
        Val::from_u8(p.command.wait),
        Val::from_u8(p.command.offset),
        Val::from_u8(p.command.limit),
        Val::from_u8(p.command.projection),
    ]);
    statement.extend(p.walk.statement_salt);
    statement.push(Val::ZERO);
    assert_eq!(statement.len(), 96);
    m.statement = if predicate {
        hash(&statement)
    } else {
        [Val::ZERO; 4]
    };
    statement.fill(Val::ZERO);
    let mut result = domain("result").to_vec();
    result.push(Val::ONE);
    result.extend(m.context);
    result.extend(m.old);
    result.extend(m.next);
    result.extend(m.statement);
    result.extend([Val::from_u8(if predicate { 0 } else { 2 }), Val::ONE]);
    append64(&mut result, 1);
    result.extend([Val::ZERO, Val::from_u8(if predicate { 3 } else { 0 })]);
    result.extend(if predicate {
        [Val::ONE, Val::ONE, Val::ONE, Val::ZERO]
    } else {
        [Val::ZERO; 4]
    });
    result.extend(if predicate {
        [Val::ZERO, Val::ONE, Val::ONE, Val::ZERO]
    } else {
        [Val::ZERO; 4]
    });
    result.extend([Val::ZERO; 4 + 4 + 4 + 2 + 1]);
    append64(&mut result, if predicate { 7 } else { 0 });
    append64(&mut result, u64::from(predicate));
    result.extend(p.salts[2]);
    result.extend([Val::ZERO; 6]);
    assert_eq!(result.len(), 160);
    m.result = hash(&result);
    result.fill(Val::ZERO);
    (m, p)
}
