use std::time::Duration;

use reliable_udp::{Endpoint, EndpointConfig};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UdpSocket,
    time::timeout,
};

fn config() -> EndpointConfig {
    let mut config = EndpointConfig::new("127.0.0.1:0".parse().unwrap());
    config.connection.clock_granularity = Duration::from_millis(1);
    config.connection.ack_delay = Duration::ZERO;
    config.connection.handshake_timeout = Duration::from_millis(100);
    config.connection.initial_rto = Duration::from_millis(30);
    config.connection.min_rto = Duration::from_millis(5);
    config.connection.max_rto = Duration::from_millis(200);
    config.connection.idle_timeout = Duration::from_secs(2);
    config.connection.keepalive_interval = None;
    config
}

async fn connected() -> (
    Endpoint,
    Endpoint,
    reliable_udp::Connection,
    reliable_udp::Connection,
) {
    let server = Endpoint::bind(config()).await.unwrap();
    let client = Endpoint::bind(config()).await.unwrap();
    let server_addr = server.local_addr();
    let client_handle = client.handle();
    let (server_result, client_result) = timeout(Duration::from_secs(2), async {
        tokio::join!(server.accept(), client_handle.connect(server_addr))
    })
    .await
    .unwrap();
    (
        server,
        client,
        client_result.unwrap(),
        server_result.unwrap(),
    )
}

#[tokio::test]
async fn localhost_handshake_and_ordered_stream_transfer() {
    let (server, client, client_connection, server_connection) = connected().await;
    let mut sender = client_connection.open_stream().await.unwrap();
    let mut receiver = timeout(Duration::from_secs(1), server_connection.accept_stream())
        .await
        .unwrap()
        .unwrap();

    sender.write_all(b"reliable ").await.unwrap();
    sender.write_all(b"udp").await.unwrap();
    sender.shutdown().await.unwrap();

    let mut received = Vec::new();
    timeout(Duration::from_secs(2), receiver.read_to_end(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received, b"reliable udp");

    server.shutdown().await.unwrap();
    client.shutdown().await.unwrap();
}

#[tokio::test]
async fn streams_are_independent_and_keep_their_boundaries() {
    let (server, client, client_connection, server_connection) = connected().await;
    let mut first_sender = client_connection.open_stream().await.unwrap();
    let mut second_sender = client_connection.open_stream().await.unwrap();
    let mut first_receiver = server_connection.accept_stream().await.unwrap();
    let mut second_receiver = server_connection.accept_stream().await.unwrap();

    first_sender.write_all(b"first").await.unwrap();
    second_sender.write_all(b"second").await.unwrap();
    first_sender.shutdown().await.unwrap();
    second_sender.shutdown().await.unwrap();

    let (first, second) = timeout(Duration::from_secs(2), async {
        let mut first = Vec::new();
        let mut second = Vec::new();
        let (first_result, second_result) = tokio::join!(
            first_receiver.read_to_end(&mut first),
            second_receiver.read_to_end(&mut second)
        );
        first_result.unwrap();
        second_result.unwrap();
        (first, second)
    })
    .await
    .unwrap();
    assert_eq!(first, b"first");
    assert_eq!(second, b"second");

    server.shutdown().await.unwrap();
    client.shutdown().await.unwrap();
}

#[tokio::test]
async fn malformed_datagram_does_not_stop_accepting_connections() {
    let server = Endpoint::bind(config()).await.unwrap();
    let raw = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    raw.send_to(b"not a reliable udp packet", server.local_addr())
        .await
        .unwrap();

    let client = Endpoint::bind(config()).await.unwrap();
    let client_handle = client.handle();
    let server_addr = server.local_addr();
    let (server_result, client_result) = timeout(Duration::from_secs(2), async {
        tokio::join!(server.accept(), client_handle.connect(server_addr))
    })
    .await
    .unwrap();
    assert!(server_result.is_ok());
    assert!(client_result.is_ok());

    server.shutdown().await.unwrap();
    client.shutdown().await.unwrap();
}

#[tokio::test]
async fn close_frame_wakes_connection_commands() {
    let (server, client, client_connection, server_connection) = connected().await;
    server_connection.close(7, "test close").await.unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;

    let result = timeout(Duration::from_secs(1), client_connection.open_stream())
        .await
        .unwrap();
    assert!(result.is_err());

    server.shutdown().await.unwrap();
    client.shutdown().await.unwrap();
}

#[tokio::test]
async fn timer_wheel_drives_idle_timeout() {
    let mut endpoint_config = config();
    endpoint_config.connection.idle_timeout = Duration::from_millis(60);
    endpoint_config.connection.close_timeout = Duration::from_millis(10);
    let server = Endpoint::bind(endpoint_config.clone()).await.unwrap();
    let client = Endpoint::bind(endpoint_config).await.unwrap();
    let client_handle = client.handle();
    let server_addr = server.local_addr();
    let (server_result, client_result) = timeout(Duration::from_secs(2), async {
        tokio::join!(server.accept(), client_handle.connect(server_addr))
    })
    .await
    .unwrap();
    let server_connection = server_result.unwrap();
    let client_connection = client_result.unwrap();

    tokio::time::sleep(Duration::from_millis(120)).await;
    let result = timeout(Duration::from_secs(1), client_connection.open_stream())
        .await
        .unwrap();
    assert!(result.is_err());

    drop(server_connection);
    server.shutdown().await.unwrap();
    client.shutdown().await.unwrap();
}

#[tokio::test]
async fn endpoint_rejects_zero_capacity_configuration() {
    let mut config = config();
    config.command_capacity = 0;
    let error = match Endpoint::bind(config).await {
        Ok(_) => panic!("zero command capacity must be rejected"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        reliable_udp::EndpointError::InvalidCapacity {
            field: "command_capacity"
        }
    ));
}

#[tokio::test]
async fn invalid_initial_receives_retry_without_becoming_accepted() {
    let server = Endpoint::bind(config()).await.unwrap();
    let raw = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let connection_id = reliable_udp::ConnectionId::new(0x44);
    let hello = udp_protocol::Frame::ClientHello(udp_protocol::ClientHello {
        client_nonce: [3; 16],
        client_public_key: [4; 32],
        max_datagram_size: 1200,
        max_streams: 4,
        initial_connection_window: 65_536,
        initial_stream_window: 16_384,
        cookie: Vec::new(),
    });
    let initial = udp_protocol::Packet::new(
        udp_protocol::PacketType::Initial,
        udp_protocol::PacketFlags::ACK_ELICITING,
        connection_id,
        udp_protocol::PacketNumber::new(0),
        vec![hello],
    )
    .encode()
    .unwrap();
    raw.send_to(&initial, server.local_addr()).await.unwrap();
    let mut response = vec![0_u8; 1200];
    let (length, _) = timeout(Duration::from_secs(1), raw.recv_from(&mut response))
        .await
        .unwrap()
        .unwrap();
    let retry = udp_protocol::Packet::decode(&response[..length]).unwrap();
    assert_eq!(retry.packet_type, udp_protocol::PacketType::Retry);
    assert!(matches!(
        retry.frames.as_slice(),
        [udp_protocol::Frame::Retry(_)]
    ));
    assert!(
        timeout(Duration::from_millis(50), server.accept())
            .await
            .is_err()
    );
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn endpoint_can_take_ownership_of_an_existing_socket() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let local_addr = socket.local_addr().unwrap();
    let server = Endpoint::from_socket(socket, config()).await.unwrap();
    assert_eq!(server.local_addr(), local_addr);

    let client = Endpoint::bind(config()).await.unwrap();
    let client_connection = client.handle().connect(server.local_addr()).await.unwrap();
    let server_connection = timeout(Duration::from_secs(1), server.accept())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        client_connection.connection_id(),
        server_connection.connection_id()
    );

    server.shutdown().await.unwrap();
    client.shutdown().await.unwrap();
}
