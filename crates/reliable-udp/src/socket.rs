use std::net::SocketAddr;

use tokio::net::UdpSocket;

use crate::error::EndpointError;

pub(crate) async fn bind(addr: SocketAddr) -> Result<UdpSocket, EndpointError> {
    Ok(UdpSocket::bind(addr).await?)
}
