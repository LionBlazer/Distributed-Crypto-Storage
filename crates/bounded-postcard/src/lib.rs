//! Per-call sequence/map budgets around the original Postcard representation.
//! Callers own frame-size, type-depth and application-specific acceptance policy.
#![forbid(unsafe_code)]

/// Container-slot limits checked before a Serde sequence/map consumer runs.
/// Every nested call shares one budget; a new decode starts a fresh budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_sequence_elements: usize,
    /// Includes sequence/tuple/array slots and both map keys and values.
    pub max_total_elements: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Encoding,
    ResourceLimit,
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Bounded Postcard decoding rejected {self:?}")
    }
}
impl std::error::Error for Error {}

use serde::de::{
    self, Deserialize, DeserializeSeed, Deserializer, EnumAccess, MapAccess, SeqAccess,
    VariantAccess, Visitor,
};
use std::fmt;

/// Decodes one value and returns the untouched trailing slice. Limits are caller
/// policy, not wire-format fields; this does not enforce canonical encoding or
/// reject trailing bytes. The caller must independently bound the input frame.
pub fn take_from_bytes<'de, T: Deserialize<'de>>(
    bytes: &'de [u8],
    limits: Limits,
) -> Result<(T, &'de [u8]), Error> {
    let mut decoder = postcard::Deserializer::from_bytes(bytes);
    let mut budget = Budget::new(limits.max_sequence_elements, limits.max_total_elements);
    let value = T::deserialize(Limited {
        inner: &mut decoder,
        budget: &mut budget,
    })
    .map_err(|_| {
        if budget.exceeded {
            Error::ResourceLimit
        } else {
            Error::Encoding
        }
    })?;
    let trailing = decoder.finalize().map_err(|_| Error::Encoding)?;
    Ok((value, trailing))
}

struct Budget {
    sequence_limit: usize,
    remaining: usize,
    exceeded: bool,
}

impl Budget {
    fn new(sequence_limit: usize, total: usize) -> Self {
        Self {
            sequence_limit,
            remaining: total,
            exceeded: false,
        }
    }

    // Runs before invoking the consumer's visit_seq/visit_map, including Vec's
    // capacity reservation. A map consumes one key and one value slot per entry.
    fn charge<E: de::Error>(&mut self, hint: Option<usize>, slots: usize) -> Result<(), E> {
        let amount = hint
            .filter(|&len| len <= self.sequence_limit)
            .and_then(|len| len.checked_mul(slots));
        if let Some(amount) = amount
            && let Some(remaining) = self.remaining.checked_sub(amount)
        {
            self.remaining = remaining;
            return Ok(());
        }
        self.exceeded = true;
        Err(E::custom("Postcard container decoder resource limit"))
    }
}

struct Limited<'a, D> {
    inner: D,
    budget: &'a mut Budget,
}

// Every entry point delegates to the original Postcard method. Wrapping its
// visitor preserves primitive/enum encodings and guards every container route.
macro_rules! delegate {
    ($($method:ident $(($($arg:ident: $ty:ty),* $(,)?))?;)*) => {
        $(fn $method<V>(self, $($($arg: $ty,)*)? visitor: V) -> Result<V::Value, Self::Error>
        where V: Visitor<'de> {
            self.inner.$method($($($arg,)*)? Limited {
                inner: visitor,
                budget: self.budget,
            })
        })*
    };
}

impl<'de, D: Deserializer<'de>> Deserializer<'de> for Limited<'_, D> {
    type Error = D::Error;

    delegate! {
        deserialize_any;
        deserialize_bool;
        deserialize_i8;
        deserialize_i16;
        deserialize_i32;
        deserialize_i64;
        deserialize_i128;
        deserialize_u8;
        deserialize_u16;
        deserialize_u32;
        deserialize_u64;
        deserialize_u128;
        deserialize_f32;
        deserialize_f64;
        deserialize_char;
        deserialize_str;
        deserialize_string;
        deserialize_bytes;
        deserialize_byte_buf;
        deserialize_option;
        deserialize_unit;
        deserialize_unit_struct(name: &'static str);
        deserialize_newtype_struct(name: &'static str);
        deserialize_seq;
        deserialize_tuple(len: usize);
        deserialize_tuple_struct(name: &'static str, len: usize);
        deserialize_map;
        deserialize_struct(name: &'static str, fields: &'static [&'static str]);
        deserialize_enum(name: &'static str, variants: &'static [&'static str]);
        deserialize_identifier;
        deserialize_ignored_any;
    }

    fn is_human_readable(&self) -> bool {
        self.inner.is_human_readable()
    }
}

macro_rules! visit_value {
    ($($method:ident($ty:ty);)*) => {
        $(fn $method<E: de::Error>(self, value: $ty) -> Result<Self::Value, E> {
            self.inner.$method(value)
        })*
    };
}

impl<'de, V: Visitor<'de>> Visitor<'de> for Limited<'_, V> {
    type Value = V::Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.expecting(formatter)
    }

    visit_value! {
        visit_bool(bool);
        visit_i8(i8);
        visit_i16(i16);
        visit_i32(i32);
        visit_i64(i64);
        visit_i128(i128);
        visit_u8(u8);
        visit_u16(u16);
        visit_u32(u32);
        visit_u64(u64);
        visit_u128(u128);
        visit_f32(f32);
        visit_f64(f64);
        visit_char(char);
        visit_str(&str);
        visit_borrowed_str(&'de str);
        visit_string(String);
        visit_bytes(&[u8]);
        visit_borrowed_bytes(&'de [u8]);
        visit_byte_buf(Vec<u8>);
    }

    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        self.inner.visit_none()
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        self.inner.visit_unit()
    }

    fn visit_some<D: Deserializer<'de>>(self, decoder: D) -> Result<Self::Value, D::Error> {
        self.inner.visit_some(Limited {
            inner: decoder,
            budget: self.budget,
        })
    }

    fn visit_newtype_struct<D: Deserializer<'de>>(
        self,
        decoder: D,
    ) -> Result<Self::Value, D::Error> {
        self.inner.visit_newtype_struct(Limited {
            inner: decoder,
            budget: self.budget,
        })
    }

    fn visit_seq<A: SeqAccess<'de>>(self, access: A) -> Result<Self::Value, A::Error> {
        self.budget.charge(access.size_hint(), 1)?;
        self.inner.visit_seq(Limited {
            inner: access,
            budget: self.budget,
        })
    }

    fn visit_map<A: MapAccess<'de>>(self, access: A) -> Result<Self::Value, A::Error> {
        self.budget.charge(access.size_hint(), 2)?;
        self.inner.visit_map(Limited {
            inner: access,
            budget: self.budget,
        })
    }

    fn visit_enum<A: EnumAccess<'de>>(self, access: A) -> Result<Self::Value, A::Error> {
        self.inner.visit_enum(Limited {
            inner: access,
            budget: self.budget,
        })
    }
}

impl<'de, S: DeserializeSeed<'de>> DeserializeSeed<'de> for Limited<'_, S> {
    type Value = S::Value;

    fn deserialize<D: Deserializer<'de>>(self, decoder: D) -> Result<Self::Value, D::Error> {
        self.inner.deserialize(Limited {
            inner: decoder,
            budget: self.budget,
        })
    }
}

impl<'de, A: SeqAccess<'de>> SeqAccess<'de> for Limited<'_, A> {
    type Error = A::Error;

    fn next_element_seed<S: DeserializeSeed<'de>>(
        &mut self,
        seed: S,
    ) -> Result<Option<S::Value>, A::Error> {
        self.inner.next_element_seed(Limited {
            inner: seed,
            budget: self.budget,
        })
    }

    fn size_hint(&self) -> Option<usize> {
        self.inner.size_hint()
    }
}

impl<'de, A: MapAccess<'de>> MapAccess<'de> for Limited<'_, A> {
    type Error = A::Error;

    fn next_key_seed<S: DeserializeSeed<'de>>(
        &mut self,
        seed: S,
    ) -> Result<Option<S::Value>, A::Error> {
        self.inner.next_key_seed(Limited {
            inner: seed,
            budget: self.budget,
        })
    }

    fn next_value_seed<S: DeserializeSeed<'de>>(&mut self, seed: S) -> Result<S::Value, A::Error> {
        self.inner.next_value_seed(Limited {
            inner: seed,
            budget: self.budget,
        })
    }

    fn size_hint(&self) -> Option<usize> {
        self.inner.size_hint()
    }
}

impl<'a, 'de, A: EnumAccess<'de>> EnumAccess<'de> for Limited<'a, A> {
    type Error = A::Error;
    type Variant = Limited<'a, A::Variant>;

    fn variant_seed<S: DeserializeSeed<'de>>(
        self,
        seed: S,
    ) -> Result<(S::Value, Self::Variant), A::Error> {
        let (value, variant) = self.inner.variant_seed(Limited {
            inner: seed,
            budget: &mut *self.budget,
        })?;
        Ok((
            value,
            Limited {
                inner: variant,
                budget: self.budget,
            },
        ))
    }
}

impl<'de, A: VariantAccess<'de>> VariantAccess<'de> for Limited<'_, A> {
    type Error = A::Error;

    fn unit_variant(self) -> Result<(), A::Error> {
        self.inner.unit_variant()
    }

    fn newtype_variant_seed<S: DeserializeSeed<'de>>(self, seed: S) -> Result<S::Value, A::Error> {
        self.inner.newtype_variant_seed(Limited {
            inner: seed,
            budget: self.budget,
        })
    }

    fn tuple_variant<V: Visitor<'de>>(self, len: usize, visitor: V) -> Result<V::Value, A::Error> {
        self.inner.tuple_variant(
            len,
            Limited {
                inner: visitor,
                budget: self.budget,
            },
        )
    }

    fn struct_variant<V: Visitor<'de>>(
        self,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, A::Error> {
        self.inner.struct_variant(
            fields,
            Limited {
                inner: visitor,
                budget: self.budget,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::collections::BTreeMap;
    const TEST_LIMITS: Limits = Limits {
        max_sequence_elements: 4096,
        max_total_elements: 1024 * 1024,
    };

    struct ConsumerEntered<'a>(&'a Cell<bool>);

    impl<'de> Visitor<'de> for ConsumerEntered<'_> {
        type Value = ();

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a sequence whose consumer must not run")
        }

        fn visit_seq<A: SeqAccess<'de>>(self, _access: A) -> Result<(), A::Error> {
            self.0.set(true);
            Ok(())
        }
    }

    #[test]
    fn oversized_sequence_is_rejected_before_the_consumers_reservation_can_run() {
        // A declared collection of 524,288 empty vectors must reject before reserve.
        let mut bytes = postcard::to_allocvec(&524_288_usize).unwrap();
        bytes.resize(bytes.len() + 524_288, 0);
        let entered = Cell::new(false);
        let mut decoder = postcard::Deserializer::from_bytes(&bytes);
        let mut budget = Budget::new(
            TEST_LIMITS.max_sequence_elements,
            TEST_LIMITS.max_total_elements,
        );

        let result = Limited {
            inner: &mut decoder,
            budget: &mut budget,
        }
        .deserialize_seq(ConsumerEntered(&entered));

        assert!(result.is_err());
        assert!(budget.exceeded);
        assert!(
            !entered.get(),
            "VecVisitor cannot reserve before this guard"
        );
    }

    #[test]
    fn enormous_declared_length_without_contents_is_rejected_without_entering_the_consumer() {
        // Canonical usize::MAX Postcard length, with no sequence elements.
        let bytes = postcard::to_allocvec(&usize::MAX).unwrap();
        let entered = Cell::new(false);
        let mut decoder = postcard::Deserializer::from_bytes(&bytes);
        let mut budget = Budget::new(
            TEST_LIMITS.max_sequence_elements,
            TEST_LIMITS.max_total_elements,
        );

        let result = Limited {
            inner: &mut decoder,
            budget: &mut budget,
        }
        .deserialize_seq(ConsumerEntered(&entered));

        assert!(result.is_err());
        assert!(budget.exceeded);
        assert!(!entered.get());
    }

    #[test]
    fn nested_sequence_lengths_are_limited_instead_of_only_checking_the_outer_length() {
        let bytes = postcard::to_allocvec(&Some(vec![vec![0_u8; 4097]])).unwrap();

        let result = take_from_bytes::<Option<Vec<Vec<u8>>>>(&bytes, TEST_LIMITS);

        assert_eq!(result.unwrap_err(), Error::ResourceLimit);
    }

    #[test]
    fn individually_small_sequences_share_one_total_budget() {
        // Every individual length (31, 4096, 8) is allowed and the encoded bytes
        // fit the frame cap, but their nested sequence slots exceed the budget.
        let bytes = postcard::to_allocvec(&vec![vec![[0_u8; 8]; 4096]; 31]).unwrap();
        assert!(bytes.len() + 8 < 2 * 1024 * 1024);

        let result = take_from_bytes::<Vec<Vec<[u8; 8]>>>(&bytes, TEST_LIMITS);

        assert_eq!(result.unwrap_err(), Error::ResourceLimit);
    }

    #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
    struct Wrapped(Option<Vec<Vec<u8>>>);

    #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
    enum Container {
        Newtype(Wrapped),
        Tuple(Vec<u8>, Vec<u8>),
        Struct { rows: Vec<Vec<u8>> },
    }

    #[test]
    fn bounded_composite_values_keep_the_original_postcard_encoding_and_trailing_bytes() {
        let values = [
            Container::Newtype(Wrapped(Some(vec![vec![1, 2]]))),
            Container::Tuple(vec![3], vec![4]),
            Container::Struct {
                rows: vec![vec![5]],
            },
        ];
        for expected in values {
            let mut bytes = postcard::to_allocvec(&expected).unwrap();
            bytes.push(99);

            let (actual, trailing) = take_from_bytes::<Container>(&bytes, TEST_LIMITS).unwrap();

            assert_eq!(actual, expected);
            assert_eq!(trailing, &[99]);
        }
    }

    #[test]
    fn enum_and_map_contents_cannot_bypass_the_nested_limits() {
        let enum_bytes = postcard::to_allocvec(&Container::Struct {
            rows: vec![vec![0; 4097]],
        })
        .unwrap();
        let map_bytes = postcard::to_allocvec(&BTreeMap::from([(0_u8, vec![0_u8; 4097])])).unwrap();

        assert_eq!(
            take_from_bytes::<Container>(&enum_bytes, TEST_LIMITS).unwrap_err(),
            Error::ResourceLimit
        );
        assert_eq!(
            take_from_bytes::<BTreeMap<u8, Vec<u8>>>(&map_bytes, TEST_LIMITS).unwrap_err(),
            Error::ResourceLimit
        );
    }

    #[test]
    fn exact_nested_budget_is_accepted_and_each_decode_has_a_fresh_budget() {
        let value = vec![vec![1_u8, 2]];
        let bytes = postcard::to_allocvec(&value).unwrap();
        let exact = Limits {
            max_sequence_elements: 2,
            max_total_elements: 3,
        };
        let too_small = Limits {
            max_total_elements: 2,
            ..exact
        };

        let first = take_from_bytes::<Vec<Vec<u8>>>(&bytes, exact);
        let rejected = take_from_bytes::<Vec<Vec<u8>>>(&bytes, too_small);
        let next = take_from_bytes::<Vec<Vec<u8>>>(&bytes, exact);

        assert_eq!(first.unwrap(), (value.clone(), &[][..]));
        assert_eq!(rejected.unwrap_err(), Error::ResourceLimit);
        assert_eq!(next.unwrap(), (value, &[][..]));
    }

    #[test]
    fn malformed_scalar_encoding_is_distinct_from_a_container_budget_rejection() {
        let limits = Limits {
            max_sequence_elements: 0,
            max_total_elements: 0,
        };

        let result = take_from_bytes::<u16>(&[0x80], limits);

        assert_eq!(result.unwrap_err(), Error::Encoding);
    }
}
