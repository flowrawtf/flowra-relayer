//! The `tpu` module implements the Transaction Processing Unit, a
//! multi-stage transaction processing pipeline in software.
use std::{
    collections::HashMap,
    net::UdpSocket,
    num::NonZeroUsize,
    sync::{atomic::AtomicBool, Arc, RwLock},
    thread,
    thread::JoinHandle,
};

use crossbeam_channel::Receiver;
use jito_rpc::load_balancer::LoadBalancer;
use agave_banking_stage_ingress_types::BankingPacketBatch;
use solana_keypair::Keypair;
use solana_message::v1::MAX_TRANSACTION_SIZE;
use solana_pubkey::Pubkey;
use solana_streamer::{
    nonblocking::swqos::SwQosConfig,
    quic_socket::QuicSocket,
    quic::{spawn_stake_weighted_qos_server, QuicStreamerConfig},
    streamer::StakedNodes,
};
use tokio_util::sync::CancellationToken;

use crate::{
    fetch_stage::FetchStage, sigverify_stage::SigVerifyStage,
    staked_nodes_updater_service::StakedNodesUpdaterService,
};

// allow multiple connections for NAT and any open/close overlap
pub const MAX_QUIC_CONNECTIONS_PER_IP: usize = 8;
pub const MAX_CONNECTIONS_PER_IPADDR_PER_MIN: u64 = 64;
/// Matches the validator's own per-peer allowance.
pub const MAX_QUIC_CONNECTIONS_PER_PEER: usize = 8;
/// Number of threads verifying signatures on the TPU ingress.
const SIGVERIFY_WORKERS: usize = 4;

/// Per-stream QUIC limits for the TPU sockets.
///
/// Both fields default to `PACKET_DATA_SIZE` (1232), which silently rejects every SIMD-0296
/// transaction-v1 packet at the QUIC layer with `invalid_stream_size`. Since the relayer fronts
/// the validator's TPU, that rejection is the end of the line for those transactions: they never
/// reach a block we build. The validator sets the same two fields to MAX_TRANSACTION_SIZE, so we
/// match it.
pub fn quic_streamer_config(num_threads: NonZeroUsize) -> QuicStreamerConfig {
    QuicStreamerConfig {
        max_connections_per_ipaddr_per_min: MAX_CONNECTIONS_PER_IPADDR_PER_MIN,
        num_threads,
        stream_receive_window_size: MAX_TRANSACTION_SIZE as u32,
        max_stream_data_bytes: MAX_TRANSACTION_SIZE as u32,
        ..QuicStreamerConfig::default()
    }
}

#[derive(Debug)]
pub struct TpuSockets {
    pub transactions_quic_sockets: Vec<UdpSocket>,
    pub transactions_forwards_quic_sockets: Vec<UdpSocket>,
}

pub struct Tpu {
    fetch_stage: FetchStage,
    staked_nodes_updater_service: StakedNodesUpdaterService,
    sigverify_stage: SigVerifyStage,
    thread_handles: Vec<JoinHandle<()>>,
}

impl Tpu {
    pub const TPU_QUEUE_CAPACITY: usize = 10_000;

    pub fn new(
        sockets: TpuSockets,
        exit: &Arc<AtomicBool>,
        keypair: &Keypair,
        rpc_load_balancer: &Arc<LoadBalancer>,
        max_unstaked_connections: usize,
        max_staked_connections: usize,
        staked_nodes_overrides: HashMap<Pubkey, u64>,
    ) -> (Self, Receiver<BankingPacketBatch>) {
        let TpuSockets {
            transactions_quic_sockets,
            transactions_forwards_quic_sockets,
        } = sockets;

        let staked_nodes = Arc::new(RwLock::new(StakedNodes::default()));
        let staked_nodes_updater_service = StakedNodesUpdaterService::new(
            exit.clone(),
            rpc_load_balancer.clone(),
            staked_nodes.clone(),
            staked_nodes_overrides,
        );

        // sender tracked as fetch_stage-channel_stats.tpu_sender_len
        let (tpu_sender, tpu_receiver) = crossbeam_channel::bounded(Tpu::TPU_QUEUE_CAPACITY);

        // receiver tracked as fetch_stage-channel_stats.tpu_forwards_receiver_len
        let (tpu_forwards_sender, tpu_forwards_receiver) =
            crossbeam_channel::bounded(Tpu::TPU_QUEUE_CAPACITY);

        let num_threads = NonZeroUsize::new(num_cpus::get().max(1)).expect("at least one cpu");
        // The streamers shut down off this token rather than the process-wide `exit` flag.
        let cancel = CancellationToken::new();
        {
            let cancel = cancel.clone();
            let exit = exit.clone();
            thread::Builder::new()
                .name("relayer-quic-cancel".to_string())
                .spawn(move || {
                    while !exit.load(std::sync::atomic::Ordering::Relaxed) {
                        thread::sleep(std::time::Duration::from_millis(100));
                    }
                    cancel.cancel();
                })
                .unwrap();
        }
        let mut quic_tasks = transactions_quic_sockets
            .into_iter()
            .map(|sock| {
                spawn_stake_weighted_qos_server(
                    "quic_streamer_tpu",
                    "quic_streamer_tpu",
                    [QuicSocket::from(sock)],
                    keypair,
                    tpu_sender.clone(),
                    staked_nodes.clone(),
                    quic_streamer_config(num_threads),
                    SwQosConfig {
                        max_staked_connections,
                        max_unstaked_connections,
                        max_connections_per_staked_peer: MAX_QUIC_CONNECTIONS_PER_PEER,
                        max_connections_per_unstaked_peer: MAX_QUIC_CONNECTIONS_PER_PEER,
                        // Dedicated relayer box: lift per-interval stream budget well above the
                        // validator self-protective default (250) so legit staked TPU flow isn't
                        // throttled during leader windows. 1000/ms = 100k units / 100ms interval.
                        max_streams_per_ms: 1000,
                    },
                    cancel.clone(),
                )
                .unwrap()
                .thread
            })
            .collect::<Vec<_>>();

        quic_tasks.extend(
            transactions_forwards_quic_sockets
                .into_iter()
                .map(|sock| {
                    spawn_stake_weighted_qos_server(
                        "quic_streamer_tpu_forwards",
                        "quic_streamer_tpu_forwards",
                        [QuicSocket::from(sock)],
                        keypair,
                        tpu_forwards_sender.clone(),
                        staked_nodes.clone(),
                        quic_streamer_config(num_threads),
                        SwQosConfig {
                            max_staked_connections,
                            max_unstaked_connections: 0, // Prevent unstaked nodes from forwarding transactions
                            max_connections_per_staked_peer: MAX_QUIC_CONNECTIONS_PER_PEER,
                            max_connections_per_unstaked_peer: MAX_QUIC_CONNECTIONS_PER_PEER,
                            max_streams_per_ms: 1000, // match TPU socket; staked forwarders only
                        },
                        cancel.clone(),
                    )
                    .unwrap()
                    .thread
                })
                .collect::<Vec<_>>(),
        );

        let fetch_stage = FetchStage::new(tpu_forwards_receiver, tpu_sender, exit.clone());

        let (banking_packet_sender, banking_packet_receiver) =
            crossbeam_channel::bounded(Tpu::TPU_QUEUE_CAPACITY);
        let sigverify_stage = SigVerifyStage::new(
            tpu_receiver,
            banking_packet_sender,
            NonZeroUsize::new(SIGVERIFY_WORKERS).expect("non-zero"),
            exit.clone(),
        );

        (
            Tpu {
                fetch_stage,
                staked_nodes_updater_service,
                sigverify_stage,
                thread_handles: quic_tasks,
            },
            banking_packet_receiver,
        )
    }

    pub fn join(self) -> thread::Result<()> {
        self.fetch_stage.join()?;
        self.staked_nodes_updater_service.join()?;
        self.sigverify_stage.join()?;
        for t in self.thread_handles {
            t.join()?
        }
        Ok(())
    }
}
