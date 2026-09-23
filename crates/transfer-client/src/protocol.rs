use std::io;

use reliable_udp::{Connection, ReliableStream};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::{Mutex, mpsc},
};
use transfer_protocol::{
    DecodedMessage, MAX_CONTROL_MESSAGE_LEN, Message, MessageFlags, ProtocolError, decode_message,
    encode_message,
};

const MAX_DATA_FRAME_LEN: usize = 1024 * 1024;

pub(crate) struct ClientConnection {
    connection: Connection,
    writer: Mutex<tokio::io::WriteHalf<ReliableStream>>,
    incoming: Mutex<mpsc::Receiver<DecodedMessage>>,
    request_id: std::sync::atomic::AtomicU64,
}

impl ClientConnection {
    pub(crate) async fn new(
        connection: Connection,
        stream: ReliableStream,
        capacity: usize,
    ) -> std::sync::Arc<Self> {
        let (mut reader, writer) = tokio::io::split(stream);
        let (sender, receiver) = mpsc::channel(capacity);
        tokio::spawn(async move {
            while let Ok(message) = read_message(&mut reader).await {
                if sender.send(message).await.is_err() {
                    break;
                }
            }
        });
        std::sync::Arc::new(Self {
            connection,
            writer: Mutex::new(writer),
            incoming: Mutex::new(receiver),
            request_id: std::sync::atomic::AtomicU64::new(1),
        })
    }

    pub(crate) async fn send(&self, message: &Message) -> Result<(), crate::ClientError> {
        let request_id = self
            .request_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut writer = self.writer.lock().await;
        write_message(&mut *writer, message, request_id)
            .await
            .map_err(Into::into)
    }

    pub(crate) async fn recv(&self) -> Result<DecodedMessage, crate::ClientError> {
        self.incoming
            .lock()
            .await
            .recv()
            .await
            .ok_or(crate::ClientError::Closed)
    }

    pub(crate) fn connection(&self) -> Connection {
        self.connection.clone()
    }
}

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

async fn write_message<W: AsyncWrite + Unpin>(
    writer: &mut W,
    message: &Message,
    request_id: u64,
) -> io::Result<()> {
    let bytes =
        encode_message(message, request_id, MessageFlags::empty()).map_err(protocol_error)?;
    writer.write_all(&bytes).await?;
    writer.flush().await
}

pub(crate) async fn write_data_frame(
    stream: &mut ReliableStream,
    offset: u64,
    fin: bool,
    data: &[u8],
) -> io::Result<()> {
    if data.len() > MAX_DATA_FRAME_LEN {
        return Err(invalid_data("data frame is too large"));
    }
    stream.write_all(&offset.to_be_bytes()).await?;
    stream.write_all(&[u8::from(fin)]).await?;
    stream
        .write_all(
            &(u32::try_from(data.len()).map_err(|_| invalid_data("data length"))?).to_be_bytes(),
        )
        .await?;
    stream.write_all(data).await
}

pub(crate) async fn read_data_frame(
    stream: &mut ReliableStream,
    buffer: &mut Vec<u8>,
) -> io::Result<Option<(u64, bool, Vec<u8>)>> {
    let mut offset = [0_u8; 8];
    match stream.read_exact(&mut offset).await {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }
    let mut fin = [0_u8; 1];
    stream.read_exact(&mut fin).await?;
    if fin[0] > 1 {
        return Err(invalid_data("invalid data frame FIN flag"));
    }
    let mut length = [0_u8; 4];
    stream.read_exact(&mut length).await?;
    let length = usize::try_from(u32::from_be_bytes(length))
        .map_err(|_| invalid_data("data frame length does not fit usize"))?;
    if length > MAX_DATA_FRAME_LEN {
        return Err(invalid_data("data frame is too large"));
    }
    buffer.resize(length, 0);
    stream.read_exact(buffer).await?;
    let data = std::mem::replace(buffer, Vec::with_capacity(length));
    Ok(Some((u64::from_be_bytes(offset), fin[0] != 0, data)))
}

fn protocol_error(error: ProtocolError) -> io::Error {
    invalid_data(error.to_string())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}
