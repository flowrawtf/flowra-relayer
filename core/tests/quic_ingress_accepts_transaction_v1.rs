//! The relayer fronts the validator's TPU, so whatever its QUIC ingress refuses never reaches a
//! block we build. `QuicStreamerConfig` defaults both `stream_receive_window_size` and
//! `max_stream_data_bytes` to `PACKET_DATA_SIZE` (1232), which silently rejects every SIMD-0296
//! transaction-v1 packet as `invalid_stream_size`. `jito_core::tpu` raises both to
//! `MAX_TRANSACTION_SIZE`; this test is what says so.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::NonZeroUsize,
    sync::{Arc, RwLock},
    time::Duration,
};

use crossbeam_channel::unbounded;
use jito_core::tpu::quic_streamer_config;
use solana_keypair::Keypair;
use solana_message::v1::MAX_TRANSACTION_SIZE;
use solana_net_utils::sockets::{bind_to_with_config, SocketConfiguration};
use solana_packet::PACKET_DATA_SIZE;
use solana_streamer::{
    nonblocking::{swqos::SwQosConfig, testing_utilities::make_client_endpoint},
    quic::{spawn_stake_weighted_qos_server, QuicStreamerConfig},
    quic_socket::QuicSocket,
    streamer::{PacketBatchReceiver, StakedNodes},
};
use tokio_util::sync::CancellationToken;

/// Spawn a TPU-style QUIC server on an ephemeral port with the given config.
fn spawn(config: QuicStreamerConfig) -> (SocketAddr, PacketBatchReceiver, CancellationToken) {
    let socket = bind_to_with_config(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        0,
        SocketConfiguration::default(),
    )
    .expect("bind server socket");
    let addr = socket.local_addr().expect("local addr");

    let (sender, receiver) = unbounded();
    let cancel = CancellationToken::new();
    spawn_stake_weighted_qos_server(
        "quic_streamer_test",
        "quic_streamer_test",
        [QuicSocket::from(socket)],
        &Keypair::new(),
        sender,
        Arc::new(RwLock::new(StakedNodes::default())),
        config,
        SwQosConfig::default(),
        cancel.clone(),
    )
    .expect("spawn server");

    (addr, receiver, cancel)
}

/// Open one uni stream and write `len` bytes, the way a client submits a transaction.
///
/// Errors are swallowed rather than asserted: a server that rejects the size closes the
/// connection with `invalid_stream` mid-write, which is one of the outcomes under test. What the
/// packet channel receives is the assertion that matters.
async fn send_bytes(addr: SocketAddr, len: usize) {
    let connection = make_client_endpoint(&addr, None).await;
    if let Ok(mut stream) = connection.open_uni().await {
        if stream.write_all(&vec![7u8; len]).await.is_ok() {
            let _ = stream.finish();
        }
    }
    // The server acks at the QUIC layer; give it a moment to hand the packet to the channel.
    tokio::time::sleep(Duration::from_millis(500)).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_transaction_v1_sized_packet_survives_the_relayer_ingress() {
    let config = quic_streamer_config(NonZeroUsize::new(2).unwrap());
    assert_eq!(config.max_stream_data_bytes, MAX_TRANSACTION_SIZE as u32);
    assert_eq!(config.stream_receive_window_size, MAX_TRANSACTION_SIZE as u32);

    let (addr, receiver, cancel) = spawn(config);
    send_bytes(addr, MAX_TRANSACTION_SIZE).await;

    let batch = receiver
        .recv_timeout(Duration::from_secs(5))
        .expect("a 4096-byte packet must reach the packet channel");
    let sizes: Vec<usize> = batch.iter().map(|p| p.meta().size).collect();
    assert!(
        sizes.contains(&MAX_TRANSACTION_SIZE),
        "expected a {MAX_TRANSACTION_SIZE}-byte packet, got {sizes:?}"
    );
    cancel.cancel();
}

/// The failure this fixes, reproduced against the stock default so the test does not silently
/// stop proving anything if the default ever changes.
#[tokio::test(flavor = "multi_thread")]
async fn the_stock_default_would_have_dropped_it() {
    let config = QuicStreamerConfig::default();
    assert_eq!(config.max_stream_data_bytes, PACKET_DATA_SIZE as u32);

    let (addr, receiver, cancel) = spawn(config);
    send_bytes(addr, MAX_TRANSACTION_SIZE).await;

    assert!(
        receiver.recv_timeout(Duration::from_secs(2)).is_err(),
        "stock config is expected to reject an oversized stream"
    );
    cancel.cancel();
}
