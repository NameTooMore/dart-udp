use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use transfer_protocol::{
    DecodedMessage, MAX_CONTROL_MESSAGE_LEN, Message, MessageFlags, ProtocolError, decode_message,
    encode_message,
};

pub(crate) async fn read_message<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> io::Result<DecodedMessage> {
    let mut length = [0_u8; 4];
    reader.read_exact(&mut length).await?;
    let length = usize::try_from(u32::from_be_bytes(length))
        .map_err(|_| invalid_data("message length does not fit usize"))?;
    if !(transfer_protocol::ENVELOPE_LEN..=MAX_CONTROL_MESSAGE_LEN).contains(&length) {
        return Err(invalid_data("message length is outside configured limits"));
    }
    let mut bytes = vec![0_u8; length];
    bytes[..4].copy_from_slice(&(length as u32).to_be_bytes());
    reader.read_exact(&mut bytes[4..]).await?;
    decode_message(&bytes).map_err(protocol_error)
}

pub(crate) async fn write_message<W: AsyncWrite + Unpin>(
    writer: &mut W,
    message: &Message,
    request_id: u64,
) -> io::Result<()> {
    let bytes =
        encode_message(message, request_id, MessageFlags::empty()).map_err(protocol_error)?;
    writer.write_all(&bytes).await?;
    writer.flush().await
}

fn protocol_error(error: ProtocolError) -> io::Error {
    invalid_data(error.to_string())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}
