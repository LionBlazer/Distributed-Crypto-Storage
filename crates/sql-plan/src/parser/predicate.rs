//! Bounded schema-domain compilation; masks depend only on the owner's SQL, never data.
use super::{Parser, unsupported};
use crate::{Error, Predicate};

#[derive(Clone, Copy)]
struct Truth {
    yes: [u8; 32],
    no: [u8; 32],
}
impl Truth {
    const TRUE: Self = Self {
        yes: [255; 32],
        no: [0; 32],
    };
    const FALSE: Self = Self {
        yes: [0; 32],
        no: [255; 32],
    };
    const UNKNOWN: Self = Self {
        yes: [0; 32],
        no: [0; 32],
    };
    fn not(self) -> Self {
        Self {
            yes: self.no,
            no: self.yes,
        }
    }
    fn and(self, other: Self) -> Self {
        Self {
            yes: std::array::from_fn(|i| self.yes[i] & other.yes[i]),
            no: std::array::from_fn(|i| self.no[i] | other.no[i]),
        }
    }
    fn or(self, other: Self) -> Self {
        Self {
            yes: std::array::from_fn(|i| self.yes[i] | other.yes[i]),
            no: std::array::from_fn(|i| self.no[i] & other.no[i]),
        }
    }
    fn comparison(value: Option<i64>, op: fn(i64, i64) -> bool) -> Self {
        let Some(value) = value else {
            return Self::UNKNOWN;
        };
        let mut yes = [0; 32];
        for age in 0..=u8::MAX {
            if op(i64::from(age), value) {
                yes[usize::from(age) / 8] |= 1 << (age % 8);
            }
        }
        Self {
            yes,
            no: yes.map(|byte| !byte),
        }
    }
}
impl Parser {
    pub(super) fn predicate(&mut self) -> Result<Predicate, Error> {
        if !self.take("WHERE") {
            return Ok(Predicate::default());
        }
        Ok(Predicate(self.predicate_or()?.yes))
    }
    fn predicate_step(&mut self) -> Result<(), Error> {
        self.predicate_budget += 1;
        if self.predicate_budget > 128 {
            return Err(unsupported(
                "predicate exceeds the 128-node planning budget",
            ));
        }
        Ok(())
    }
    fn predicate_or(&mut self) -> Result<Truth, Error> {
        let mut value = self.predicate_and()?;
        while self.take("OR") {
            self.predicate_step()?;
            value = value.or(self.predicate_and()?);
        }
        Ok(value)
    }
    fn predicate_and(&mut self) -> Result<Truth, Error> {
        let mut value = self.predicate_atom()?;
        while self.take("AND") {
            self.predicate_step()?;
            value = value.and(self.predicate_atom()?);
        }
        Ok(value)
    }
    fn predicate_atom(&mut self) -> Result<Truth, Error> {
        self.predicate_step()?;
        if self.take("NOT") {
            return Ok(self.predicate_atom()?.not());
        }
        if self.take("(") {
            let value = self.predicate_or()?;
            self.expect(")")?;
            return Ok(value);
        }
        for (word, value) in [
            ("TRUE", Truth::TRUE),
            ("FALSE", Truth::FALSE),
            ("NULL", Truth::UNKNOWN),
        ] {
            if self.take(word) {
                return Ok(value);
            }
        }
        self.expect("AGE")?;
        if self.take("IS") {
            let negated = self.take("NOT");
            self.expect("NULL")?;
            return Ok(if negated { Truth::TRUE } else { Truth::FALSE });
        }
        let negated = self.take("NOT");
        let value = if self.take("BETWEEN") {
            let lower = self.predicate_integer()?;
            self.expect("AND")?;
            let upper = self.predicate_integer()?;
            Truth::comparison(lower, |a, b| a >= b).and(Truth::comparison(upper, |a, b| a <= b))
        } else if self.take("IN") {
            self.expect("(")?;
            let mut value = Truth::comparison(self.predicate_integer()?, |a, b| a == b);
            while self.take(",") {
                self.predicate_step()?;
                value = value.or(Truth::comparison(self.predicate_integer()?, |a, b| a == b));
            }
            self.expect(")")?;
            value
        } else {
            if negated {
                return Err(unsupported("NOT after age requires BETWEEN or IN"));
            }
            let op: fn(i64, i64) -> bool = if self.take("=") {
                |a, b| a == b
            } else if self.take("<>") || self.take("!=") {
                |a, b| a != b
            } else if self.take("<=") {
                |a, b| a <= b
            } else if self.take(">=") {
                |a, b| a >= b
            } else if self.take("<") {
                |a, b| a < b
            } else if self.take(">") {
                |a, b| a > b
            } else {
                return Err(unsupported(
                    "expected an age comparison, BETWEEN, IN or IS NULL",
                ));
            };
            return Ok(Truth::comparison(self.predicate_integer()?, op));
        };
        Ok(if negated { value.not() } else { value })
    }
    fn predicate_integer(&mut self) -> Result<Option<i64>, Error> {
        if self.take("NULL") {
            return Ok(None);
        }
        let negative = self.take("-");
        if !negative {
            self.take("+");
        }
        let magnitude = self.number::<u64>("comparison integer must fit signed i64")?;
        let value = if negative {
            if magnitude == (i64::MAX as u64) + 1 {
                i64::MIN
            } else {
                -i64::try_from(magnitude)
                    .map_err(|_| unsupported("comparison integer must fit signed i64"))?
            }
        } else {
            i64::try_from(magnitude)
                .map_err(|_| unsupported("comparison integer must fit signed i64"))?
        };
        Ok(Some(value))
    }
}
