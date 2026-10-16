//! Exact existing disk bytes and writer failures, not custody admission.
use super::*;
use std::io::{self, Write};

fn untrusted(length: usize) -> RawBundle {
    RawBundle {
        version: 2,
        nonce: [31; 32],
        data_head: vec![3; 112],
        index_head: vec![4; 112],
        data: (0u8..=255).cycle().take(length).collect(),
        index: vec![7; length / 2],
    }
}
// Preserve the pre-refactor plain-Vec encoding as an independent byte oracle.
fn plain_disk(raw: &RawBundle) -> Vec<u8> {
    let body = crate::wire::encode(&(
        raw.version,
        raw.nonce,
        &raw.data_head,
        &raw.index_head,
        &raw.data,
        &raw.index,
    ))
    .unwrap();
    let mut bytes = DISK_MAGIC.to_vec();
    bytes.extend_from_slice(&OBJECT_PROFILE_ID);
    bytes.extend_from_slice(&body);
    bytes
}

#[test]
fn disk_writer_and_owned_encoder_keep_exact_plain_vec_bytes_and_length() {
    for length in [0, 1, 255, 256, 65_536] {
        let mut raw = untrusted(length);
        // Encoding remains structural; malformed envelopes still need admission.
        if length == 1 {
            raw.version = 3;
            raw.data_head.pop();
        }
        let expected = plain_disk(&raw);
        let mut output = Vec::new();

        write_disk(&raw, &mut output).unwrap();

        assert_eq!(output, expected);
        assert_eq!(disk_encoded_len(&raw).unwrap(), expected.len());
        assert_eq!(encode_disk(&raw).unwrap(), expected);
        assert_eq!(decode_disk(&output).unwrap(), raw);
    }
}

#[derive(Default)]
struct CountWriter {
    bytes: usize,
}
impl Write for CountWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes += bytes.len();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn whole_disk_cap_includes_header_and_rejects_before_writing_any_byte() {
    let mut raw = untrusted(0);
    let overhead = plain_disk(&raw).len();
    let maximum_payload = MAX_FRAME_BYTES - overhead;
    for length in [maximum_payload - 1, maximum_payload, maximum_payload + 1] {
        raw.data.resize(length, 0x5a);
        let mut output = CountWriter::default();

        let result = write_disk(&raw, &mut output);

        if length <= maximum_payload {
            result.unwrap();
            assert_eq!(output.bytes, overhead + length);
            assert_eq!(disk_encoded_len(&raw).unwrap(), overhead + length);
        } else {
            assert!(result.is_err());
            assert!(matches!(
                disk_encoded_len(&raw),
                Err(RemoteError::ResourceLimit)
            ));
            assert_eq!(output.bytes, 0);
        }
    }
}

struct ShortWriter {
    bytes: Vec<u8>,
    maximum_chunk: usize,
    fail_after: Option<usize>,
    zero_at_failure: bool,
}
impl Write for ShortWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let remaining = self
            .fail_after
            .map_or(usize::MAX, |limit| limit.saturating_sub(self.bytes.len()));
        if remaining == 0 {
            return if self.zero_at_failure {
                Ok(0)
            } else {
                Err(io::Error::other("injected disk write failure"))
            };
        }
        let count = bytes.len().min(self.maximum_chunk).min(remaining);
        self.bytes.extend_from_slice(&bytes[..count]);
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn short_successful_writes_produce_the_complete_original_envelope() {
    let raw = untrusted(4096);
    let expected = plain_disk(&raw);
    let mut output = ShortWriter {
        bytes: Vec::new(),
        maximum_chunk: 7,
        fail_after: None,
        zero_at_failure: false,
    };

    write_disk(&raw, &mut output).unwrap();

    assert_eq!(output.bytes, expected);
}

#[test]
fn writer_error_or_zero_write_never_reports_a_complete_object() {
    let raw = untrusted(257);
    let expected = plain_disk(&raw);
    for fail_after in [
        0,
        1,
        DISK_HEADER_BYTES - 1,
        DISK_HEADER_BYTES,
        expected.len() - 1,
    ] {
        for zero_at_failure in [false, true] {
            let mut output = ShortWriter {
                bytes: Vec::new(),
                maximum_chunk: 7,
                fail_after: Some(fail_after),
                zero_at_failure,
            };

            assert!(write_disk(&raw, &mut output).is_err());

            assert_eq!(output.bytes, expected[..fail_after]);
        }
    }
}
