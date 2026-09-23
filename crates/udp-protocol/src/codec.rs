use crate::{
    checksum,
    crypto::{AEAD_TAG_LEN, PacketCrypto},
    error::ProtocolError,
    frame::{Frame, MAX_FRAME_BODY_LEN},
    packet::{
        ConnectionId, FIXED_HEADER_LEN, MAGIC, Packet, PacketFlags, PacketHeader, PacketNumber,
        PacketType, VERSION,
    },
    varint,
};

pub const DEFAULT_MAX_DATAGRAM_SIZE: usize = 1200;
pub const MAX_FRAME_COUNT: usize = 64;

pub fn encode_packet(packet: &Packet, max_datagram_size: usize) -> Result<Vec<u8>, ProtocolError> {
    if packet.flags.contains(PacketFlags::ENCRYPTED) {
        return Err(ProtocolError::EncryptionNotAllowed);
    }
    let payload = encode_frames(packet)?;
    encode_raw_packet(packet, packet.flags, &payload, max_datagram_size)
}

pub fn encode_packet_with_crypto(
    packet: &Packet,
    max_datagram_size: usize,
    crypto: &PacketCrypto,
) -> Result<Vec<u8>, ProtocolError> {
    if packet.flags.contains(PacketFlags::ENCRYPTED) {
        return Err(ProtocolError::EncryptionNotAllowed);
    }
    let plaintext = encode_frames(packet)?;
    let encrypted_payload_len =
        plaintext
            .len()
            .checked_add(AEAD_TAG_LEN)
            .ok_or(ProtocolError::DatagramTooLarge {
                maximum: max_datagram_size,
                actual: usize::MAX,
            })?;
    if encrypted_payload_len > usize::from(u16::MAX) {
        return Err(ProtocolError::FrameTooLarge {
            maximum: usize::from(u16::MAX),
            actual: encrypted_payload_len,
        });
    }
    validate_datagram_limit(max_datagram_size)?;
    let flags = packet.flags | PacketFlags::ENCRYPTED;
    let header = header_bytes(
        packet.packet_type,
        flags,
        packet.connection_id,
        packet.packet_number,
        encrypted_payload_len,
    );
    let ciphertext = crypto
        .seal(packet.packet_number, &header, &plaintext)
        .map_err(ProtocolError::Crypto)?;
    let mut output = Vec::with_capacity(FIXED_HEADER_LEN + ciphertext.len());
    output.extend_from_slice(&header);
    output.extend_from_slice(&ciphertext);
    ensure_datagram_size(output.len(), max_datagram_size)?;
    let checksum = checksum::crc32c_with_zeroed_range(&output, 26, 30);
    output[26..30].copy_from_slice(&checksum.to_be_bytes());
    Ok(output)
}

fn encode_frames(packet: &Packet) -> Result<Vec<u8>, ProtocolError> {
    if packet.frames.is_empty() {
        return Err(ProtocolError::EmptyPacket);
    }
    if packet.frames.len() > MAX_FRAME_COUNT {
        return Err(ProtocolError::TooManyFrames {
            maximum: MAX_FRAME_COUNT,
        });
    }

    let mut payload = Vec::new();
    for frame in &packet.frames {
        frame.encode(&mut payload)?;
    }
    if payload.len() > usize::from(u16::MAX) {
        return Err(ProtocolError::FrameTooLarge {
            maximum: usize::from(u16::MAX),
            actual: payload.len(),
        });
    }
    Ok(payload)
}

fn encode_raw_packet(
    packet: &Packet,
    flags: PacketFlags,
    payload: &[u8],
    max_datagram_size: usize,
) -> Result<Vec<u8>, ProtocolError> {
    validate_datagram_limit(max_datagram_size)?;
    let total_len =
        FIXED_HEADER_LEN
            .checked_add(payload.len())
            .ok_or(ProtocolError::DatagramTooLarge {
                maximum: max_datagram_size,
                actual: usize::MAX,
            })?;
    ensure_datagram_size(total_len, max_datagram_size)?;
    let header = header_bytes(
        packet.packet_type,
        flags,
        packet.connection_id,
        packet.packet_number,
        payload.len(),
    );
    let mut output = Vec::with_capacity(total_len);
    output.extend_from_slice(&header);
    output.extend_from_slice(payload);

    let checksum = checksum::crc32c_with_zeroed_range(&output, 26, 30);
    output[26..30].copy_from_slice(&checksum.to_be_bytes());
    Ok(output)
}

pub fn decode_packet(bytes: &[u8], max_datagram_size: usize) -> Result<Packet, ProtocolError> {
    let header = decode_header_and_lengths(bytes, max_datagram_size)?;
    if header.flags.contains(PacketFlags::ENCRYPTED) {
        return Err(ProtocolError::EncryptedPacketRequiresKeys);
    }
    decode_plain_packet(bytes, header)
}

pub fn decode_encrypted_packet(
    bytes: &[u8],
    max_datagram_size: usize,
    crypto: &mut PacketCrypto,
) -> Result<Packet, ProtocolError> {
    let header = decode_header_and_lengths(bytes, max_datagram_size)?;
    if !header.flags.contains(PacketFlags::ENCRYPTED) {
        return Err(ProtocolError::InvalidFlags {
            value: header.flags.bits(),
        });
    }
    let payload = &bytes[usize::from(header.header_len)..];
    if payload.len() < AEAD_TAG_LEN {
        return Err(ProtocolError::Crypto(
            crate::CryptoError::EncryptedPayloadTooShort,
        ));
    }
    verify_checksum(bytes, &header)?;
    let mut associated_data = [0_u8; FIXED_HEADER_LEN];
    associated_data.copy_from_slice(&bytes[..FIXED_HEADER_LEN]);
    associated_data[26..30].fill(0);
    let plaintext = crypto
        .open(header.packet_number, &associated_data, payload)
        .map_err(ProtocolError::Crypto)?;
    let frames = decode_frames(&plaintext)?;
    Ok(Packet::new(
        header.packet_type,
        header.flags,
        header.connection_id,
        header.packet_number,
        frames,
    ))
}

pub fn peek_connection_id(
    bytes: &[u8],
    max_datagram_size: usize,
) -> Result<ConnectionId, ProtocolError> {
    Ok(decode_header_and_lengths(bytes, max_datagram_size)?.connection_id)
}

pub fn peek_packet_flags(
    bytes: &[u8],
    max_datagram_size: usize,
) -> Result<PacketFlags, ProtocolError> {
    Ok(decode_header_and_lengths(bytes, max_datagram_size)?.flags)
}

fn decode_plain_packet(bytes: &[u8], header: PacketHeader) -> Result<Packet, ProtocolError> {
    verify_checksum(bytes, &header)?;
    let payload = &bytes[usize::from(header.header_len)..];
    if payload.is_empty() {
        return Err(ProtocolError::EmptyPacket);
    }
    let frames = decode_frames(payload)?;
    Ok(Packet::new(
        header.packet_type,
        header.flags,
        header.connection_id,
        header.packet_number,
        frames,
    ))
}

fn decode_header_and_lengths(
    bytes: &[u8],
    max_datagram_size: usize,
) -> Result<PacketHeader, ProtocolError> {
    validate_datagram_limit(max_datagram_size)?;
    if bytes.len() < FIXED_HEADER_LEN {
        return Err(ProtocolError::DatagramTooShort {
            minimum: FIXED_HEADER_LEN,
            actual: bytes.len(),
        });
    }
    if bytes.len() > max_datagram_size {
        return Err(ProtocolError::DatagramTooLarge {
            maximum: max_datagram_size,
            actual: bytes.len(),
        });
    }

    let header = decode_header(bytes)?;
    let header_len = usize::from(header.header_len);
    let payload_len = usize::from(header.payload_len);
    let actual_payload_len = bytes.len() - header_len;
    if payload_len != actual_payload_len {
        return Err(ProtocolError::PayloadLengthMismatch {
            declared: payload_len,
            actual: actual_payload_len,
        });
    }

    Ok(header)
}

fn verify_checksum(bytes: &[u8], header: &PacketHeader) -> Result<(), ProtocolError> {
    let expected_checksum = checksum::crc32c_with_zeroed_range(bytes, 26, 30);
    if expected_checksum != header.checksum {
        return Err(ProtocolError::ChecksumMismatch {
            expected: expected_checksum,
            actual: header.checksum,
        });
    }
    Ok(())
}

fn header_bytes(
    packet_type: PacketType,
    flags: PacketFlags,
    connection_id: ConnectionId,
    packet_number: PacketNumber,
    payload_len: usize,
) -> [u8; FIXED_HEADER_LEN] {
    let mut header = [0_u8; FIXED_HEADER_LEN];
    header[0..2].copy_from_slice(&MAGIC.to_be_bytes());
    header[2] = VERSION;
    header[3] = packet_type as u8;
    header[4..6].copy_from_slice(&flags.bits().to_be_bytes());
    header[6..8].copy_from_slice(&(FIXED_HEADER_LEN as u16).to_be_bytes());
    header[8..16].copy_from_slice(&connection_id.raw().to_be_bytes());
    header[16..24].copy_from_slice(&packet_number.raw().to_be_bytes());
    header[24..26].copy_from_slice(&(payload_len as u16).to_be_bytes());
    header
}

fn ensure_datagram_size(actual: usize, maximum: usize) -> Result<(), ProtocolError> {
    if actual > maximum {
        return Err(ProtocolError::DatagramTooLarge { maximum, actual });
    }
    Ok(())
}

fn decode_header(bytes: &[u8]) -> Result<PacketHeader, ProtocolError> {
    let magic = u16::from_be_bytes([bytes[0], bytes[1]]);
    if magic != MAGIC {
        return Err(ProtocolError::InvalidMagic {
            expected: MAGIC,
            actual: magic,
        });
    }
    let version = bytes[2];
    if version != VERSION {
        return Err(ProtocolError::UnsupportedVersion { version });
    }
    let packet_type = PacketType::try_from(bytes[3])?;
    let raw_flags = u16::from_be_bytes([bytes[4], bytes[5]]);
    let flags = PacketFlags::from_bits(raw_flags)?;
    let header_len = usize::from(u16::from_be_bytes([bytes[6], bytes[7]]));
    if header_len != FIXED_HEADER_LEN {
        return Err(ProtocolError::InvalidHeaderLength {
            expected: FIXED_HEADER_LEN,
            actual: header_len,
        });
    }
    let connection_id = u64::from_be_bytes([
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    ]);
    let packet_number = u64::from_be_bytes([
        bytes[16], bytes[17], bytes[18], bytes[19], bytes[20], bytes[21], bytes[22], bytes[23],
    ]);
    let payload_len = u16::from_be_bytes([bytes[24], bytes[25]]);
    let checksum = u32::from_be_bytes([bytes[26], bytes[27], bytes[28], bytes[29]]);
    Ok(PacketHeader {
        version,
        packet_type,
        flags,
        header_len: header_len as u16,
        connection_id: ConnectionId::new(connection_id),
        packet_number: PacketNumber::new(packet_number),
        payload_len,
        checksum,
    })
}

fn decode_frames(payload: &[u8]) -> Result<Vec<Frame>, ProtocolError> {
    let mut offset = 0;
    let mut frames = Vec::new();
    while offset < payload.len() {
        if frames.len() == MAX_FRAME_COUNT {
            return Err(ProtocolError::TooManyFrames {
                maximum: MAX_FRAME_COUNT,
            });
        }
        let frame_type = *payload.get(offset).ok_or(ProtocolError::Truncated {
            context: "frame type",
        })?;
        offset += 1;
        let body_len = varint::decode(payload, &mut offset)?;
        let body_len = usize::try_from(body_len).map_err(|_| ProtocolError::FrameTooLarge {
            maximum: MAX_FRAME_BODY_LEN,
            actual: usize::MAX,
        })?;
        if body_len > MAX_FRAME_BODY_LEN {
            return Err(ProtocolError::FrameTooLarge {
                maximum: MAX_FRAME_BODY_LEN,
                actual: body_len,
            });
        }
        let end = offset
            .checked_add(body_len)
            .ok_or(ProtocolError::Truncated {
                context: "frame body",
            })?;
        let body = payload.get(offset..end).ok_or(ProtocolError::Truncated {
            context: "frame body",
        })?;
        frames.push(Frame::decode(frame_type, body)?);
        offset = end;
    }
    if frames.is_empty() {
        return Err(ProtocolError::EmptyPacket);
    }
    Ok(frames)
}

fn validate_datagram_limit(max_datagram_size: usize) -> Result<(), ProtocolError> {
    if max_datagram_size < FIXED_HEADER_LEN {
        return Err(ProtocolError::InvalidValue {
            field: "max_datagram_size",
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{decode_packet, encode_packet};
    use crate::{ConnectionId, Frame, Packet, PacketFlags, PacketNumber, PacketType, Ping};

    fn packet() -> Packet {
        Packet::new(
            PacketType::Data,
            PacketFlags::ACK_ELICITING,
            ConnectionId::new(0x0102_0304),
            PacketNumber::new(9),
            vec![Frame::Ping(Ping { nonce: 77 })],
        )
    }

    #[test]
    fn encodes_and_decodes_a_packet() {
        let encoded = encode_packet(&packet(), 1200).unwrap();
        assert_eq!(decode_packet(&encoded, 1200).unwrap(), packet());
    }

    #[test]
    fn rejects_checksum_changes() {
        let mut encoded = encode_packet(&packet(), 1200).unwrap();
        let last = encoded.len() - 1;
        encoded[last] ^= 1;
        assert!(matches!(
            decode_packet(&encoded, 1200),
            Err(crate::ProtocolError::ChecksumMismatch { .. })
        ));
    }

    #[test]
    fn rejects_packets_above_the_configured_limit() {
        let encoded = encode_packet(&packet(), 1200).unwrap();
        assert!(matches!(
            decode_packet(&encoded, encoded.len() - 1),
            Err(crate::ProtocolError::DatagramTooLarge { .. })
        ));
    }

    #[test]
    fn rejects_unknown_flags_before_decoding_frames() {
        let mut encoded = encode_packet(&packet(), 1200).unwrap();
        encoded[4] |= 0x80;
        let checksum = crate::checksum::crc32c_with_zeroed_range(&encoded, 26, 30);
        encoded[26..30].copy_from_slice(&checksum.to_be_bytes());
        assert!(matches!(
            decode_packet(&encoded, 1200),
            Err(crate::ProtocolError::InvalidFlags { .. })
        ));
    }

    #[test]
    fn malformed_input_never_panics() {
        let mut state = 0x1234_5678_u64;
        for length in 0..=2048 {
            let mut input = vec![0_u8; length];
            for byte in &mut input {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                *byte = (state >> 56) as u8;
            }
            let result = std::panic::catch_unwind(|| decode_packet(&input, 1200));
            assert!(result.is_ok(), "decoder panicked for input length {length}");
        }
    }
}
