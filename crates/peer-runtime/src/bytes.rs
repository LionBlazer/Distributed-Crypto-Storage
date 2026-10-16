//! Shared bounded byte-sequence decoding before bincode can allocate a frame.
use serde::{Deserializer, de};
use std::fmt;

// A sequence visitor sees bincode's announced length BEFORE allocation. Using
// deserialize_bytes here would let bincode allocate an unchecked byte vector first.
pub(crate) fn deserialize_frame<'de, D: Deserializer<'de>>(
    deserializer: D,
    maximum: usize,
) -> std::result::Result<Vec<u8>, D::Error> {
    struct Frame(usize);
    impl<'de> de::Visitor<'de> for Frame {
        type Value = Vec<u8>;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a bounded RPC byte sequence")
        }
        fn visit_seq<A: de::SeqAccess<'de>>(
            self,
            mut sequence: A,
        ) -> std::result::Result<Self::Value, A::Error> {
            let length = sequence
                .size_hint()
                .ok_or_else(|| de::Error::custom("Missing RPC frame length"))?;
            if length > self.0 {
                return Err(de::Error::custom("RPC frame exceeds limit"));
            }
            let mut bytes = Vec::with_capacity(length);
            while let Some(byte) = sequence.next_element::<u8>()? {
                if bytes.len() == length {
                    return Err(de::Error::custom("RPC frame length mismatch"));
                }
                bytes.push(byte);
            }
            if bytes.len() != length {
                return Err(de::Error::custom("Truncated page frame"));
            }
            Ok(bytes)
        }
    }
    deserializer.deserialize_seq(Frame(maximum))
}
