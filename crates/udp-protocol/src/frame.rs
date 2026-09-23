use crate::{
    ack::AckFrame,
    crypto::{FINISHED_TAG_LEN, X25519_PUBLIC_KEY_LEN},
    error::ProtocolError,
    packet::StreamId,
    varint,
};

pub const MAX_FRAME_BODY_LEN: usize = u16::MAX as usize;
pub const MAX_COOKIE_LEN: usize = 128;
pub const MAX_CLOSE_REASON_LEN: usize = 1024;
pub const MAX_RETRY_COOKIE_LEN: usize = 64;
pub const NONCE_LEN: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello {
    pub client_nonce: [u8; NONCE_LEN],
    pub client_public_key: [u8; X25519_PUBLIC_KEY_LEN],
    pub max_datagram_size: u16,
    pub max_streams: u32,
    pub initial_connection_window: u64,
    pub initial_stream_window: u64,
    pub cookie: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerHello {
    pub server_nonce: [u8; NONCE_LEN],
    pub server_public_key: [u8; X25519_PUBLIC_KEY_LEN],
    pub server_finished: [u8; FINISHED_TAG_LEN],
    pub max_datagram_size: u16,
    pub max_streams: u32,
    pub initial_connection_window: u64,
    pub initial_stream_window: u64,
    pub cookie: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeAck {
    pub cookie: Vec<u8>,
    pub client_finished: [u8; FINISHED_TAG_LEN],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Retry {
    pub cookie: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamOpen {
    pub stream_id: StreamId,
    pub initial_receive_window: u64,
    pub bidirectional: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamData {
    pub stream_id: StreamId,
    pub offset: u64,
    pub fin: bool,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResetStream {
    pub stream_id: StreamId,
    pub error_code: u32,
    pub final_offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaxStreamData {
    pub stream_id: StreamId,
    pub max_offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaxData {
    pub max_offset: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ping {
    pub nonce: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pong {
    pub nonce: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionClose {
    pub error_code: u32,
    pub frame_type: u8,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    ClientHello(ClientHello),
    ServerHello(ServerHello),
    HandshakeAck(HandshakeAck),
    Retry(Retry),
    Ack(AckFrame),
    StreamOpen(StreamOpen),
    StreamData(StreamData),
    ResetStream(ResetStream),
    MaxStreamData(MaxStreamData),
    MaxData(MaxData),
    Ping(Ping),
    Pong(Pong),
    ConnectionClose(ConnectionClose),
}

impl Frame {
    pub fn is_ack_eliciting(&self) -> bool {
        !matches!(self, Self::Ack(_) | Self::Retry(_))
    }

    pub(crate) fn type_code(&self) -> u8 {
        match self {
            Self::ClientHello(_) => 1,
            Self::ServerHello(_) => 2,
            Self::HandshakeAck(_) => 3,
            Self::Retry(_) => 13,
            Self::Ack(_) => 4,
            Self::StreamOpen(_) => 5,
            Self::StreamData(_) => 6,
            Self::ResetStream(_) => 7,
            Self::MaxStreamData(_) => 8,
            Self::MaxData(_) => 9,
            Self::Ping(_) => 10,
            Self::Pong(_) => 11,
            Self::ConnectionClose(_) => 12,
        }
    }

    pub(crate) fn encode(&self, output: &mut Vec<u8>) -> Result<(), ProtocolError> {
        let mut body = Vec::new();
        self.encode_body(&mut body)?;
        if body.len() > MAX_FRAME_BODY_LEN {
            return Err(ProtocolError::FrameTooLarge {
                maximum: MAX_FRAME_BODY_LEN,
                actual: body.len(),
            });
        }
        output.push(self.type_code());
        varint::encode(body.len() as u64, output)?;
        output.extend_from_slice(&body);
        Ok(())
    }

    pub(crate) fn decode(frame_type: u8, body: &[u8]) -> Result<Self, ProtocolError> {
        let mut reader = Reader::new(body);
        let frame = match frame_type {
            1 => Self::ClientHello(ClientHello::decode(&mut reader)?),
            2 => Self::ServerHello(ServerHello::decode(&mut reader)?),
            3 => Self::HandshakeAck(HandshakeAck::decode(&mut reader)?),
            13 => Self::Retry(Retry::decode(&mut reader)?),
            4 => Self::Ack(AckFrame::decode_from(body, &mut reader.offset)?),
            5 => Self::StreamOpen(StreamOpen::decode(&mut reader)?),
            6 => Self::StreamData(StreamData::decode(&mut reader)?),
            7 => Self::ResetStream(ResetStream::decode(&mut reader)?),
            8 => Self::MaxStreamData(MaxStreamData::decode(&mut reader)?),
            9 => Self::MaxData(MaxData::decode(&mut reader)?),
            10 => Self::Ping(Ping::decode(&mut reader)?),
            11 => Self::Pong(Pong::decode(&mut reader)?),
            12 => Self::ConnectionClose(ConnectionClose::decode(&mut reader)?),
            value => return Err(ProtocolError::UnknownFrameType { value }),
        };
        reader.finish()?;
        Ok(frame)
    }

    fn encode_body(&self, output: &mut Vec<u8>) -> Result<(), ProtocolError> {
        match self {
            Self::ClientHello(value) => value.encode(output),
            Self::ServerHello(value) => value.encode(output),
            Self::HandshakeAck(value) => value.encode(output),
            Self::Retry(value) => value.encode(output),
            Self::Ack(value) => value.encode_into(output),
            Self::StreamOpen(value) => value.encode(output),
            Self::StreamData(value) => value.encode(output),
            Self::ResetStream(value) => value.encode(output),
            Self::MaxStreamData(value) => value.encode(output),
            Self::MaxData(value) => value.encode(output),
            Self::Ping(value) => value.encode(output),
            Self::Pong(value) => value.encode(output),
            Self::ConnectionClose(value) => value.encode(output),
        }
    }
}

impl ClientHello {
    fn encode(&self, output: &mut Vec<u8>) -> Result<(), ProtocolError> {
        validate_hello(
            self.max_datagram_size,
            self.max_streams,
            self.initial_connection_window,
            self.initial_stream_window,
        )?;
        output.extend_from_slice(&self.client_nonce);
        output.extend_from_slice(&self.client_public_key);
        output.extend_from_slice(&self.max_datagram_size.to_be_bytes());
        output.extend_from_slice(&self.max_streams.to_be_bytes());
        output.extend_from_slice(&self.initial_connection_window.to_be_bytes());
        output.extend_from_slice(&self.initial_stream_window.to_be_bytes());
        write_blob(output, &self.cookie, MAX_COOKIE_LEN)
    }

    fn decode(reader: &mut Reader<'_>) -> Result<Self, ProtocolError> {
        let value = Self {
            client_nonce: reader.read_array()?,
            client_public_key: reader.read_array()?,
            max_datagram_size: reader.read_u16()?,
            max_streams: reader.read_u32()?,
            initial_connection_window: reader.read_u64()?,
            initial_stream_window: reader.read_u64()?,
            cookie: reader.read_blob(MAX_COOKIE_LEN, "client cookie")?,
        };
        validate_hello(
            value.max_datagram_size,
            value.max_streams,
            value.initial_connection_window,
            value.initial_stream_window,
        )?;
        Ok(value)
    }
}

impl ServerHello {
    fn encode(&self, output: &mut Vec<u8>) -> Result<(), ProtocolError> {
        validate_hello(
            self.max_datagram_size,
            self.max_streams,
            self.initial_connection_window,
            self.initial_stream_window,
        )?;
        output.extend_from_slice(&self.server_nonce);
        output.extend_from_slice(&self.server_public_key);
        output.extend_from_slice(&self.server_finished);
        output.extend_from_slice(&self.max_datagram_size.to_be_bytes());
        output.extend_from_slice(&self.max_streams.to_be_bytes());
        output.extend_from_slice(&self.initial_connection_window.to_be_bytes());
        output.extend_from_slice(&self.initial_stream_window.to_be_bytes());
        write_blob(output, &self.cookie, MAX_COOKIE_LEN)
    }

    fn decode(reader: &mut Reader<'_>) -> Result<Self, ProtocolError> {
        let value = Self {
            server_nonce: reader.read_array()?,
            server_public_key: reader.read_array()?,
            server_finished: reader.read_array()?,
            max_datagram_size: reader.read_u16()?,
            max_streams: reader.read_u32()?,
            initial_connection_window: reader.read_u64()?,
            initial_stream_window: reader.read_u64()?,
            cookie: reader.read_blob(MAX_COOKIE_LEN, "server cookie")?,
        };
        validate_hello(
            value.max_datagram_size,
            value.max_streams,
            value.initial_connection_window,
            value.initial_stream_window,
        )?;
        Ok(value)
    }
}

impl HandshakeAck {
    fn encode(&self, output: &mut Vec<u8>) -> Result<(), ProtocolError> {
        write_blob(output, &self.cookie, MAX_COOKIE_LEN)?;
        output.extend_from_slice(&self.client_finished);
        Ok(())
    }

    fn decode(reader: &mut Reader<'_>) -> Result<Self, ProtocolError> {
        Ok(Self {
            cookie: reader.read_blob(MAX_COOKIE_LEN, "handshake cookie")?,
            client_finished: reader.read_array()?,
        })
    }
}

impl Retry {
    fn encode(&self, output: &mut Vec<u8>) -> Result<(), ProtocolError> {
        write_blob(output, &self.cookie, MAX_RETRY_COOKIE_LEN)
    }

    fn decode(reader: &mut Reader<'_>) -> Result<Self, ProtocolError> {
        Ok(Self {
            cookie: reader.read_blob(MAX_RETRY_COOKIE_LEN, "retry cookie")?,
        })
    }
}

impl StreamOpen {
    fn encode(&self, output: &mut Vec<u8>) -> Result<(), ProtocolError> {
        if self.initial_receive_window == 0 {
            return Err(ProtocolError::InvalidValue {
                field: "initial_receive_window",
            });
        }
        varint::encode(self.stream_id.raw(), output)?;
        varint::encode(self.initial_receive_window, output)?;
        output.push(u8::from(self.bidirectional));
        Ok(())
    }

    fn decode(reader: &mut Reader<'_>) -> Result<Self, ProtocolError> {
        let value = Self {
            stream_id: StreamId::new(reader.read_varint()?),
            initial_receive_window: reader.read_varint()?,
            bidirectional: match reader.read_u8()? {
                0 => false,
                1 => true,
                _ => {
                    return Err(ProtocolError::InvalidValue {
                        field: "stream direction",
                    });
                }
            },
        };
        if value.initial_receive_window == 0 {
            return Err(ProtocolError::InvalidValue {
                field: "initial_receive_window",
            });
        }
        Ok(value)
    }
}

impl StreamData {
    fn encode(&self, output: &mut Vec<u8>) -> Result<(), ProtocolError> {
        varint::encode(self.stream_id.raw(), output)?;
        varint::encode(self.offset, output)?;
        output.push(u8::from(self.fin));
        write_blob(output, &self.data, MAX_FRAME_BODY_LEN)
    }

    fn decode(reader: &mut Reader<'_>) -> Result<Self, ProtocolError> {
        let value = Self {
            stream_id: StreamId::new(reader.read_varint()?),
            offset: reader.read_varint()?,
            fin: match reader.read_u8()? {
                0 => false,
                1 => true,
                _ => {
                    return Err(ProtocolError::InvalidValue {
                        field: "stream FIN flag",
                    });
                }
            },
            data: reader.read_blob(MAX_FRAME_BODY_LEN, "stream data")?,
        };
        value
            .offset
            .checked_add(value.data.len() as u64)
            .ok_or(ProtocolError::InvalidValue {
                field: "stream offset",
            })?;
        Ok(value)
    }
}

impl ResetStream {
    fn encode(&self, output: &mut Vec<u8>) -> Result<(), ProtocolError> {
        varint::encode(self.stream_id.raw(), output)?;
        output.extend_from_slice(&self.error_code.to_be_bytes());
        varint::encode(self.final_offset, output)
    }

    fn decode(reader: &mut Reader<'_>) -> Result<Self, ProtocolError> {
        Ok(Self {
            stream_id: StreamId::new(reader.read_varint()?),
            error_code: reader.read_u32()?,
            final_offset: reader.read_varint()?,
        })
    }
}

impl MaxStreamData {
    fn encode(&self, output: &mut Vec<u8>) -> Result<(), ProtocolError> {
        varint::encode(self.stream_id.raw(), output)?;
        varint::encode(self.max_offset, output)
    }

    fn decode(reader: &mut Reader<'_>) -> Result<Self, ProtocolError> {
        Ok(Self {
            stream_id: StreamId::new(reader.read_varint()?),
            max_offset: reader.read_varint()?,
        })
    }
}

impl MaxData {
    fn encode(&self, output: &mut Vec<u8>) -> Result<(), ProtocolError> {
        varint::encode(self.max_offset, output)
    }

    fn decode(reader: &mut Reader<'_>) -> Result<Self, ProtocolError> {
        Ok(Self {
            max_offset: reader.read_varint()?,
        })
    }
}

impl Ping {
    fn encode(self, output: &mut Vec<u8>) -> Result<(), ProtocolError> {
        output.extend_from_slice(&self.nonce.to_be_bytes());
        Ok(())
    }

    fn decode(reader: &mut Reader<'_>) -> Result<Self, ProtocolError> {
        Ok(Self {
            nonce: reader.read_u64()?,
        })
    }
}

impl Pong {
    fn encode(self, output: &mut Vec<u8>) -> Result<(), ProtocolError> {
        output.extend_from_slice(&self.nonce.to_be_bytes());
        Ok(())
    }

    fn decode(reader: &mut Reader<'_>) -> Result<Self, ProtocolError> {
        Ok(Self {
            nonce: reader.read_u64()?,
        })
    }
}

impl ConnectionClose {
    fn encode(&self, output: &mut Vec<u8>) -> Result<(), ProtocolError> {
        if self.reason.len() > MAX_CLOSE_REASON_LEN {
            return Err(ProtocolError::FrameTooLarge {
                maximum: MAX_CLOSE_REASON_LEN,
                actual: self.reason.len(),
            });
        }
        output.extend_from_slice(&self.error_code.to_be_bytes());
        output.push(self.frame_type);
        write_blob(output, self.reason.as_bytes(), MAX_CLOSE_REASON_LEN)
    }

    fn decode(reader: &mut Reader<'_>) -> Result<Self, ProtocolError> {
        let error_code = reader.read_u32()?;
        let frame_type = reader.read_u8()?;
        let reason = reader.read_blob(MAX_CLOSE_REASON_LEN, "close reason")?;
        let reason = String::from_utf8(reason).map_err(|_| ProtocolError::InvalidUtf8 {
            field: "close reason",
        })?;
        Ok(Self {
            error_code,
            frame_type,
            reason,
        })
    }
}

fn validate_hello(
    max_datagram_size: u16,
    max_streams: u32,
    initial_connection_window: u64,
    initial_stream_window: u64,
) -> Result<(), ProtocolError> {
    if usize::from(max_datagram_size) < crate::packet::FIXED_HEADER_LEN {
        return Err(ProtocolError::InvalidValue {
            field: "max_datagram_size",
        });
    }
    if max_streams == 0 {
        return Err(ProtocolError::InvalidValue {
            field: "max_streams",
        });
    }
    if initial_connection_window == 0 {
        return Err(ProtocolError::InvalidValue {
            field: "initial_connection_window",
        });
    }
    if initial_stream_window == 0 {
        return Err(ProtocolError::InvalidValue {
            field: "initial_stream_window",
        });
    }
    Ok(())
}

fn write_blob(output: &mut Vec<u8>, bytes: &[u8], maximum: usize) -> Result<(), ProtocolError> {
    if bytes.len() > maximum {
        return Err(ProtocolError::FrameTooLarge {
            maximum,
            actual: bytes.len(),
        });
    }
    varint::encode(bytes.len() as u64, output)?;
    output.extend_from_slice(bytes);
    Ok(())
}

struct Reader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn read_u8(&mut self) -> Result<u8, ProtocolError> {
        let byte = *self
            .input
            .get(self.offset)
            .ok_or(ProtocolError::Truncated { context: "frame" })?;
        self.offset += 1;
        Ok(byte)
    }

    fn read_u16(&mut self) -> Result<u16, ProtocolError> {
        let bytes = self.read_exact(2, "u16")?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn read_u32(&mut self) -> Result<u32, ProtocolError> {
        let bytes = self.read_exact(4, "u32")?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_u64(&mut self) -> Result<u64, ProtocolError> {
        let bytes = self.read_exact(8, "u64")?;
        Ok(u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn read_varint(&mut self) -> Result<u64, ProtocolError> {
        varint::decode(self.input, &mut self.offset)
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], ProtocolError> {
        let bytes = self.read_exact(N, "fixed-size field")?;
        let mut output = [0; N];
        output.copy_from_slice(bytes);
        Ok(output)
    }

    fn read_blob(
        &mut self,
        maximum: usize,
        context: &'static str,
    ) -> Result<Vec<u8>, ProtocolError> {
        let length = self.read_varint()?;
        let length = usize::try_from(length).map_err(|_| ProtocolError::FrameTooLarge {
            maximum,
            actual: usize::MAX,
        })?;
        if length > maximum {
            return Err(ProtocolError::FrameTooLarge {
                maximum,
                actual: length,
            });
        }
        Ok(self.read_exact(length, context)?.to_vec())
    }

    fn read_exact(
        &mut self,
        length: usize,
        context: &'static str,
    ) -> Result<&'a [u8], ProtocolError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(ProtocolError::Truncated { context })?;
        let bytes = self
            .input
            .get(self.offset..end)
            .ok_or(ProtocolError::Truncated { context })?;
        self.offset = end;
        Ok(bytes)
    }

    fn finish(&self) -> Result<(), ProtocolError> {
        if self.offset == self.input.len() {
            Ok(())
        } else {
            Err(ProtocolError::InvalidValue {
                field: "trailing frame bytes",
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use core::time::Duration;

    use super::{
        ClientHello, ConnectionClose, Frame, HandshakeAck, MaxData, MaxStreamData, Ping, Pong,
        ResetStream, Retry, ServerHello, StreamData, StreamOpen,
    };
    use crate::{
        AckFrame, AckRange, AckRanges, ConnectionId, Packet, PacketFlags, PacketNumber, PacketType,
        StreamId,
    };

    #[test]
    fn stream_data_round_trips_through_a_packet() {
        let packet = Packet::new(
            PacketType::Data,
            PacketFlags::ACK_ELICITING,
            ConnectionId::new(7),
            PacketNumber::new(8),
            vec![Frame::StreamData(StreamData {
                stream_id: StreamId::new(3),
                offset: 1024,
                fin: true,
                data: b"payload".to_vec(),
            })],
        );
        let decoded = Packet::decode(&packet.encode().unwrap()).unwrap();
        assert_eq!(decoded, packet);
    }

    #[test]
    fn hello_rejects_zero_window() {
        let frame = Frame::ClientHello(ClientHello {
            client_nonce: [0; 16],
            client_public_key: [0; 32],
            max_datagram_size: 1200,
            max_streams: 1,
            initial_connection_window: 0,
            initial_stream_window: 1,
            cookie: Vec::new(),
        });
        let packet = Packet::new(
            PacketType::Initial,
            PacketFlags::ACK_ELICITING,
            ConnectionId::new(1),
            PacketNumber::new(1),
            vec![frame],
        );
        assert!(packet.encode().is_err());
    }

    #[test]
    fn stream_open_rejects_invalid_direction() {
        let body = [1_u8, 1, 2];
        assert!(Frame::decode(5, &body).is_err());
    }

    #[test]
    fn reader_does_not_accept_trailing_bytes() {
        let body = [0_u8; 9];
        assert!(Frame::decode(10, &body).is_err());
    }

    #[test]
    fn stream_open_round_trips() {
        let packet = Packet::new(
            PacketType::Data,
            PacketFlags::empty(),
            ConnectionId::new(1),
            PacketNumber::new(2),
            vec![Frame::StreamOpen(StreamOpen {
                stream_id: StreamId::new(9),
                initial_receive_window: 4096,
                bidirectional: true,
            })],
        );
        assert_eq!(Packet::decode(&packet.encode().unwrap()).unwrap(), packet);
    }

    #[test]
    fn every_defined_frame_round_trips() {
        let ranges = AckRanges::new(vec![
            AckRange::new(PacketNumber::new(4), PacketNumber::new(4)).unwrap(),
        ])
        .unwrap();
        let packet = Packet::new(
            PacketType::Data,
            PacketFlags::ACK_ELICITING,
            ConnectionId::new(11),
            PacketNumber::new(12),
            vec![
                Frame::ClientHello(ClientHello {
                    client_nonce: [1; 16],
                    client_public_key: [2; 32],
                    max_datagram_size: 1200,
                    max_streams: 8,
                    initial_connection_window: 65_536,
                    initial_stream_window: 16_384,
                    cookie: vec![2, 3],
                }),
                Frame::ServerHello(ServerHello {
                    server_nonce: [4; 16],
                    server_public_key: [5; 32],
                    server_finished: [6; 16],
                    max_datagram_size: 1200,
                    max_streams: 8,
                    initial_connection_window: 65_536,
                    initial_stream_window: 16_384,
                    cookie: vec![7, 8],
                }),
                Frame::HandshakeAck(HandshakeAck {
                    cookie: vec![9],
                    client_finished: [10; 16],
                }),
                Frame::Retry(Retry { cookie: vec![11] }),
                Frame::Ack(AckFrame::new(Duration::from_millis(2), ranges).unwrap()),
                Frame::StreamOpen(StreamOpen {
                    stream_id: StreamId::new(1),
                    initial_receive_window: 16_384,
                    bidirectional: true,
                }),
                Frame::StreamData(StreamData {
                    stream_id: StreamId::new(1),
                    offset: 0,
                    fin: false,
                    data: b"data".to_vec(),
                }),
                Frame::ResetStream(ResetStream {
                    stream_id: StreamId::new(1),
                    error_code: 9,
                    final_offset: 4,
                }),
                Frame::MaxStreamData(MaxStreamData {
                    stream_id: StreamId::new(1),
                    max_offset: 32_768,
                }),
                Frame::MaxData(MaxData { max_offset: 65_536 }),
                Frame::Ping(Ping { nonce: 10 }),
                Frame::Pong(Pong { nonce: 10 }),
                Frame::ConnectionClose(ConnectionClose {
                    error_code: 11,
                    frame_type: 6,
                    reason: "done".to_owned(),
                }),
            ],
        );
        assert_eq!(
            Packet::decode(&packet.encode_with_limit(1200).unwrap()).unwrap(),
            packet
        );
    }
}
