//! Tokio framed stream length-delimited codec for ONP wire packets.

use std::io;
use bytes::{Bytes, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

use onp_core::constants::ENVELOPE_HEADER_SIZE;
use onp_core::framing::EnvelopeHeader;

/// Framed stream codec for reading and writing variable-length ONP wire packets.
#[derive(Debug, Default, Clone)]
pub struct OnpCodec;

impl OnpCodec {
    pub fn new() -> Self {
        Self
    }
}

impl Decoder for OnpCodec {
    type Item = Bytes;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < ENVELOPE_HEADER_SIZE {
            return Ok(None);
        }

        let header = match EnvelopeHeader::decode(&src[..ENVELOPE_HEADER_SIZE]) {
            Ok(h) => h,
            Err(e) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("ONP header decoding failed: {e}"),
                ));
            }
        };

        let total_frame_len = ENVELOPE_HEADER_SIZE + header.payload_len as usize;

        if src.len() < total_frame_len {
            // Reserve necessary capacity to read the full frame
            src.reserve(total_frame_len - src.len());
            return Ok(None);
        }

        let frame_bytes = src.split_to(total_frame_len).freeze();
        Ok(Some(frame_bytes))
    }
}

impl Encoder<Bytes> for OnpCodec {
    type Error = io::Error;

    fn encode(&mut self, item: Bytes, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.extend_from_slice(&item);
        Ok(())
    }
}

impl Encoder<Vec<u8>> for OnpCodec {
    type Error = io::Error;

    fn encode(&mut self, item: Vec<u8>, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.extend_from_slice(&item);
        Ok(())
    }
}
