use std::{fs, net::SocketAddr, path::PathBuf, time::Duration};

use transfer_client::{ClientConfig, ClientError, PairingOptions, ReceiveOptions, TransferClient};
use transfer_server::{RelayConfig, ServerConfig, TransferServer};

fn test_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("udp-transfer-stage4-{name}-{}", std::process::id()))
}

#[tokio::test]
async fn two_clients_complete_a_multi_file_relay_transfer() {
    let source = test_path("source");
    let destination = test_path("destination");
    let _ = fs::remove_dir_all(&source);
    let _ = fs::remove_dir_all(&destination);
    fs::create_dir_all(&source).expect("create source");
    fs::write(source.join("first.txt"), b"first file").expect("write first file");
    fs::write(source.join("second.txt"), b"second file with more bytes")
        .expect("write second file");

    let mut server_config = ServerConfig::new(SocketAddr::from(([127, 0, 0, 1], 0)));
    server_config.relay = RelayConfig {
        buffer_size: 1024,
        ..RelayConfig::default()
    };
    let server = TransferServer::bind(server_config)
        .await
        .expect("bind server");
    let address = server.local_addr();

    let client_a = TransferClient::connect(ClientConfig::new(address))
        .await
        .expect("connect offerer");
    let client_b = TransferClient::connect(ClientConfig::new(address))
        .await
        .expect("connect accepter");
    let offer = client_a
        .create_pairing(PairingOptions::default())
        .await
        .expect("create pairing");
    let code = offer.code().clone();
    let join_task = tokio::spawn(async move { client_b.join_pairing(code).await });
    let sender = offer
        .offer_files([source.clone()])
        .await
        .expect("start transfer");
    let incoming = join_task.await.expect("join task").expect("join result");
    let receiver = incoming
        .accept_offer(ReceiveOptions::new(destination.clone()))
        .await
        .expect("accept offer");

    let sender_summary = tokio::time::timeout(Duration::from_secs(10), sender.wait())
        .await
        .expect("sender timeout")
        .expect("sender result");
    let receiver_summary = tokio::time::timeout(Duration::from_secs(10), receiver.wait())
        .await
        .expect("receiver timeout")
        .expect("receiver result");

    assert_eq!(sender_summary.completed_files, 2);
    assert_eq!(receiver_summary.completed_files, 2);
    assert!(sender_summary.relay_used);
    let relative_root = source.file_name().expect("source root");
    assert_eq!(
        fs::read(destination.join(relative_root).join("first.txt")).expect("read first"),
        b"first file"
    );
    assert_eq!(
        fs::read(destination.join(relative_root).join("second.txt")).expect("read second"),
        b"second file with more bytes"
    );

    let metrics = server.metrics().await.snapshot();
    assert!(metrics.relay_bytes > 0);
    server.shutdown().await.expect("shutdown server");
    let _ = fs::remove_dir_all(&source);
    let _ = fs::remove_dir_all(&destination);
}

#[tokio::test]
async fn repeated_join_and_expired_pairing_return_explicit_errors() {
    let source = test_path("empty-source");
    let destination = test_path("empty-destination");
    let _ = fs::remove_dir_all(&source);
    let _ = fs::remove_dir_all(&destination);
    fs::create_dir_all(&source).expect("create empty source");

    let server = TransferServer::bind(ServerConfig::new(SocketAddr::from(([127, 0, 0, 1], 0))))
        .await
        .expect("bind server");
    let address = server.local_addr();
    let client_a = TransferClient::connect(ClientConfig::new(address))
        .await
        .expect("connect offerer");
    let client_b = TransferClient::connect(ClientConfig::new(address))
        .await
        .expect("connect first accepter");
    let client_c = TransferClient::connect(ClientConfig::new(address))
        .await
        .expect("connect duplicate accepter");
    let offer = client_a
        .create_pairing(PairingOptions::default())
        .await
        .expect("create pairing");
    let code = offer.code().clone();
    let join_task = tokio::spawn(async move { client_b.join_pairing(code).await });
    for _ in 0..50 {
        if server.metrics().await.snapshot().joined_pairings == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let duplicate_result = tokio::time::timeout(
        Duration::from_secs(2),
        client_c.join_pairing(offer.code().clone()),
    )
    .await
    .expect("duplicate join response timeout");
    let duplicate = match duplicate_result {
        Ok(_) => panic!("duplicate join must fail"),
        Err(error) => error,
    };
    assert!(matches!(duplicate, ClientError::Server { .. }));

    let sender = offer
        .offer_files([source.clone()])
        .await
        .expect("start empty transfer");
    let incoming = join_task.await.expect("join task").expect("join result");
    let receiver = incoming
        .accept_offer(ReceiveOptions::new(destination.clone()))
        .await
        .expect("accept empty offer");
    sender.wait().await.expect("sender result");
    receiver.wait().await.expect("receiver result");
    server.shutdown().await.expect("shutdown server");

    let expired_server =
        TransferServer::bind(ServerConfig::new(SocketAddr::from(([127, 0, 0, 1], 0))))
            .await
            .expect("bind expired server");
    let expired_client_a = TransferClient::connect(ClientConfig::new(expired_server.local_addr()))
        .await
        .expect("connect expired offerer");
    let expired_client_b = TransferClient::connect(ClientConfig::new(expired_server.local_addr()))
        .await
        .expect("connect expired accepter");
    let expired_offer = expired_client_a
        .create_pairing(PairingOptions {
            requested_ttl_seconds: 1,
        })
        .await
        .expect("create short pairing");
    tokio::time::sleep(Duration::from_millis(1_200)).await;
    let expired = match expired_client_b
        .join_pairing(expired_offer.code().clone())
        .await
    {
        Ok(_) => panic!("expired pairing must fail"),
        Err(error) => error,
    };
    assert!(matches!(expired, ClientError::Server { .. }));
    expired_server
        .shutdown()
        .await
        .expect("shutdown expired server");

    let _ = fs::remove_dir_all(&source);
    let _ = fs::remove_dir_all(&destination);
}

#[tokio::test]
async fn relay_session_quota_stops_data_without_reporting_bytes() {
    let source = test_path("quota-source");
    let destination = test_path("quota-destination");
    let _ = fs::remove_file(&source);
    let _ = fs::remove_dir_all(&destination);
    fs::write(&source, b"more bytes than the quota").expect("write quota source");

    let mut server_config = ServerConfig::new(SocketAddr::from(([127, 0, 0, 1], 0)));
    server_config.relay.max_bytes_per_session = 1;
    let server = TransferServer::bind(server_config)
        .await
        .expect("bind quota server");
    let address = server.local_addr();
    let client_a = TransferClient::connect(ClientConfig::new(address))
        .await
        .expect("connect quota offerer");
    let client_b = TransferClient::connect(ClientConfig::new(address))
        .await
        .expect("connect quota accepter");
    let offer = client_a
        .create_pairing(PairingOptions::default())
        .await
        .expect("create quota pairing");
    let code = offer.code().clone();
    let join_task = tokio::spawn(async move { client_b.join_pairing(code).await });
    let sender = offer
        .offer_files([source.clone()])
        .await
        .expect("start quota transfer");
    let incoming = join_task
        .await
        .expect("quota join task")
        .expect("quota join result");
    let receiver = incoming
        .accept_offer(ReceiveOptions::new(destination.clone()))
        .await
        .expect("accept quota offer");

    let sender_result = tokio::time::timeout(Duration::from_secs(5), sender.wait())
        .await
        .expect("quota sender timeout");
    assert!(sender_result.is_err());
    let receiver_result = tokio::time::timeout(Duration::from_secs(5), receiver.wait())
        .await
        .expect("quota receiver timeout");
    assert!(receiver_result.is_err());
    assert_eq!(server.metrics().await.snapshot().relay_bytes, 0);
    server.shutdown().await.expect("shutdown quota server");
    let _ = fs::remove_file(&source);
    let _ = fs::remove_dir_all(&destination);
}

#[tokio::test]
async fn sender_can_resume_from_a_saved_ticket_after_restart() {
    let source = test_path("resume-source");
    let destination = test_path("resume-destination");
    let _ = fs::remove_file(&source);
    let _ = fs::remove_dir_all(&destination);
    fs::write(&source, vec![0x5a; 16 * 1024]).expect("write resume source");

    let mut server_config = ServerConfig::new(SocketAddr::from(([127, 0, 0, 1], 0)));
    server_config.relay.buffer_size = 1024;
    let server = TransferServer::bind(server_config)
        .await
        .expect("bind resume server");
    let address = server.local_addr();
    let client_a = TransferClient::connect(ClientConfig::new(address))
        .await
        .expect("connect resume sender");
    let client_b = TransferClient::connect(ClientConfig::new(address))
        .await
        .expect("connect resume receiver");
    let offer = client_a
        .create_pairing(PairingOptions::default())
        .await
        .expect("create resume pairing");
    let code = offer.code().clone();
    let join_task = tokio::spawn(async move { client_b.join_pairing(code).await });
    let sender = offer
        .offer_files([source.clone()])
        .await
        .expect("start resume transfer");
    let ticket = sender.resume_ticket().await.expect("sender resume ticket");
    let incoming = join_task
        .await
        .expect("resume join task")
        .expect("resume join result");
    sender.abort().await.expect("abort old sender");
    drop(sender);
    drop(client_a);

    let receiver = incoming
        .accept_offer(ReceiveOptions::new(destination.clone()))
        .await
        .expect("accept resume offer");

    let resumed_client = TransferClient::connect(ClientConfig::new(address))
        .await
        .expect("connect resumed sender");
    let resumed_sender = resumed_client
        .resume_send(ticket, [source.clone()])
        .await
        .expect("resume sender");
    let (sender_result, receiver_result) = tokio::join!(
        tokio::time::timeout(Duration::from_secs(10), resumed_sender.wait()),
        tokio::time::timeout(Duration::from_secs(10), receiver.wait()),
    );
    sender_result
        .expect("resumed sender timeout")
        .expect("resumed sender result");
    receiver_result
        .expect("resumed receiver timeout")
        .expect("resumed receiver result");
    assert_eq!(
        fs::read(destination.join(source.file_name().expect("resume source file name")),)
            .expect("read resumed file"),
        vec![0x5a; 16 * 1024]
    );

    server.shutdown().await.expect("shutdown resume server");
    let _ = fs::remove_file(&source);
    let _ = fs::remove_dir_all(&destination);
}
