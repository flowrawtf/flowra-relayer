use std::{
    collections::{hash_map::Entry, HashMap, HashSet},
    str::FromStr,
    net::IpAddr,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, RwLock,
    },
    thread,
    thread::JoinHandle,
    time::{Duration, Instant, SystemTime},
};

use crossbeam_channel::{bounded, Receiver, RecvError, Sender};
use dashmap::DashMap;
use histogram::Histogram;
use jito_core::{
    ofac::is_tx_ofac_related,
    pbp::{PacketSummary, PbpDrop, PbpFilter},
};
use jito_protos::{
    convert::packet_to_proto_packet,
    packet::{Packet as ProtoPacket, PacketBatch as ProtoPacketBatch},
    relayer::{
        relayer_server::Relayer, subscribe_packets_response, GetTpuConfigsRequest,
        GetTpuConfigsResponse, SubscribePacketsRequest, SubscribePacketsResponse,
    },
    shared::{Header, Heartbeat, PbpPolicy, ProvidePbpPolicyResponse, Socket},
};
use jito_rpc::load_balancer::LoadBalancer;
use log::*;
use prost_types::Timestamp;
use agave_banking_stage_ingress_types::BankingPacketBatch;
use solana_metrics::datapoint_info;
use solana_message::AddressLookupTableAccount;
use solana_clock::Slot;
use solana_pubkey::Pubkey;
use solana_transaction::versioned::VersionedTransaction;
use thiserror::Error;
use tokio::sync::mpsc::{channel, error::TrySendError, Sender as TokioSender};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use crate::{health_manager::HealthState, schedule_cache::LeaderScheduleUpdatingHandle};

#[derive(Default)]
struct PacketForwardStats {
    num_packets_forwarded: u64,
    num_packets_dropped: u64,
}

struct RelayerMetrics {
    pub highest_slot: u64,
    pub num_added_connections: u64,
    pub num_removed_connections: u64,
    pub num_current_connections: u64,
    pub num_heartbeats: u64,
    pub max_heartbeat_tick_latency_us: u64,
    pub metrics_latency_us: u64,
    pub num_try_send_channel_full: u64,
    pub packet_latencies_us: Histogram,

    // Pre-forward filtering, counted per metrics interval. Every one of these is a packet the
    // fronted validator never sees, so an unexplained fee or landing shortfall has to be
    // attributable here before it is blamed on anything downstream. `forward_packets` used to
    // drop all four silently.
    /// Survivors actually handed to validator subscriptions.
    pub num_packets_forwarded: u64,
    /// Dropped by the OFAC address filter.
    pub num_packets_dropped_ofac: u64,
    /// Dropped because the receiving validator's own PBP policy said so, split by which rule
    /// fired. These are per-recipient: the same packet can be dropped for one validator and
    /// forwarded to another, which is the point.
    pub num_packets_dropped_pbp: u64,
    pub num_packets_dropped_pbp_address: u64,
    pub num_packets_dropped_pbp_program: u64,
    pub num_packets_dropped_pbp_instruction: u64,
    /// Validators whose pushed policy is currently in force.
    pub num_validators_with_policy: u64,
    /// Dropped because the packet would not deserialize into a `VersionedTransaction`. Only
    /// reachable when a filter is configured — with no filter the packet is forwarded unparsed,
    /// so enabling a filter silently changes what happens to malformed packets.
    pub num_packets_dropped_deserialize: u64,
    /// Dropped converting to the protobuf packet (missing/oversized data).
    pub num_packets_dropped_proto_convert: u64,

    pub crossbeam_slot_receiver_processing_us: Histogram,
    pub crossbeam_delay_packet_receiver_processing_us: Histogram,
    pub crossbeam_subscription_receiver_processing_us: Histogram,
    pub crossbeam_heartbeat_tick_processing_us: Histogram,
    pub crossbeam_metrics_tick_processing_us: Histogram,

    // channel stats
    pub slot_receiver_max_len: usize,
    pub slot_receiver_capacity: usize,
    pub subscription_receiver_max_len: usize,
    pub subscription_receiver_capacity: usize,
    pub delay_packet_receiver_max_len: usize,
    pub delay_packet_receiver_capacity: usize,
    pub packet_subscriptions_total_queued: usize, // sum of all items currently queued
    packet_stats_per_validator: HashMap<Pubkey, PacketForwardStats>,
}

impl RelayerMetrics {
    fn new(
        slot_receiver_capacity: usize,
        subscription_receiver_capacity: usize,
        delay_packet_receiver_capacity: usize,
    ) -> Self {
        RelayerMetrics {
            highest_slot: 0,
            num_added_connections: 0,
            num_removed_connections: 0,
            num_current_connections: 0,
            num_heartbeats: 0,
            max_heartbeat_tick_latency_us: 0,
            metrics_latency_us: 0,
            num_try_send_channel_full: 0,
            packet_latencies_us: Histogram::default(),
            num_packets_forwarded: 0,
            num_packets_dropped_ofac: 0,
            num_packets_dropped_pbp: 0,
            num_packets_dropped_pbp_address: 0,
            num_packets_dropped_pbp_program: 0,
            num_packets_dropped_pbp_instruction: 0,
            num_validators_with_policy: 0,
            num_packets_dropped_deserialize: 0,
            num_packets_dropped_proto_convert: 0,
            crossbeam_slot_receiver_processing_us: Histogram::default(),
            crossbeam_delay_packet_receiver_processing_us: Histogram::default(),
            crossbeam_subscription_receiver_processing_us: Histogram::default(),
            crossbeam_heartbeat_tick_processing_us: Histogram::default(),
            crossbeam_metrics_tick_processing_us: Histogram::default(),
            slot_receiver_max_len: 0,
            slot_receiver_capacity,
            subscription_receiver_max_len: 0,
            subscription_receiver_capacity,
            delay_packet_receiver_max_len: 0,
            delay_packet_receiver_capacity,
            packet_subscriptions_total_queued: 0,
            packet_stats_per_validator: HashMap::new(),
        }
    }

    fn update_max_len(
        &mut self,
        slot_receiver_len: usize,
        subscription_receiver_len: usize,
        delay_packet_receiver_len: usize,
    ) {
        self.slot_receiver_max_len = std::cmp::max(self.slot_receiver_max_len, slot_receiver_len);
        self.subscription_receiver_max_len = std::cmp::max(
            self.subscription_receiver_max_len,
            subscription_receiver_len,
        );
        self.delay_packet_receiver_max_len = std::cmp::max(
            self.delay_packet_receiver_max_len,
            delay_packet_receiver_len,
        );
    }

    fn update_packet_subscription_total_capacity(
        &mut self,
        packet_subscriptions: &HashMap<
            Pubkey,
            TokioSender<Result<SubscribePacketsResponse, Status>>,
        >,
    ) {
        let packet_subscriptions_total_queued = packet_subscriptions
            .values()
            .map(|x| RelayerImpl::SUBSCRIBER_QUEUE_CAPACITY - x.capacity())
            .sum::<usize>();
        self.packet_subscriptions_total_queued = packet_subscriptions_total_queued;
    }

    /// Attribute a PBP drop to the rule that caused it. Which rule fired is the difference
    /// between "a program is blocked outright" and "one instruction of it is", and an operator
    /// reviewing a policy needs to tell those apart.
    fn increment_pbp_drop(&mut self, _validator_id: &Pubkey, reason: PbpDrop) {
        match reason {
            PbpDrop::Address => self.num_packets_dropped_pbp_address += 1,
            PbpDrop::Program => self.num_packets_dropped_pbp_program += 1,
            PbpDrop::Instruction => self.num_packets_dropped_pbp_instruction += 1,
        }
    }

    fn increment_packets_forwarded(&mut self, validator_id: &Pubkey, num_packets: u64) {
        self.packet_stats_per_validator
            .entry(*validator_id)
            .and_modify(|entry| {
                entry.num_packets_forwarded =
                    entry.num_packets_forwarded.saturating_add(num_packets)
            })
            .or_insert(PacketForwardStats {
                num_packets_forwarded: num_packets,
                num_packets_dropped: 0,
            });
    }

    fn increment_packets_dropped(&mut self, validator_id: &Pubkey, num_packets: u64) {
        self.packet_stats_per_validator
            .entry(*validator_id)
            .and_modify(|entry| {
                entry.num_packets_dropped =
                    entry.num_packets_dropped.saturating_add(num_packets)
            })
            .or_insert(PacketForwardStats {
                num_packets_forwarded: 0,
                num_packets_dropped: num_packets,
            });
    }

    fn report(&self) {
        for (pubkey, stats) in &self.packet_stats_per_validator {
            datapoint_info!("relayer_validator_metrics",
                "pubkey" => pubkey.to_string(),
                ("num_packets_forwarded", stats.num_packets_forwarded, i64),
                ("num_packets_dropped", stats.num_packets_dropped, i64),
            );
        }
        datapoint_info!(
            "relayer_metrics",
            ("highest_slot", self.highest_slot, i64),
            ("num_added_connections", self.num_added_connections, i64),
            ("num_removed_connections", self.num_removed_connections, i64),
            ("num_current_connections", self.num_current_connections, i64),
            ("num_heartbeats", self.num_heartbeats, i64),
            (
                "num_try_send_channel_full",
                self.num_try_send_channel_full,
                i64
            ),
            ("metrics_latency_us", self.metrics_latency_us, i64),
            // pre-forward filtering
            ("num_packets_forwarded", self.num_packets_forwarded, i64),
            ("num_packets_dropped_ofac", self.num_packets_dropped_ofac, i64),
            ("num_packets_dropped_pbp", self.num_packets_dropped_pbp, i64),
            (
                "num_packets_dropped_pbp_address",
                self.num_packets_dropped_pbp_address,
                i64
            ),
            (
                "num_packets_dropped_pbp_program",
                self.num_packets_dropped_pbp_program,
                i64
            ),
            (
                "num_packets_dropped_pbp_instruction",
                self.num_packets_dropped_pbp_instruction,
                i64
            ),
            (
                "num_validators_with_policy",
                self.num_validators_with_policy,
                i64
            ),
            (
                "num_packets_dropped_deserialize",
                self.num_packets_dropped_deserialize,
                i64
            ),
            (
                "num_packets_dropped_proto_convert",
                self.num_packets_dropped_proto_convert,
                i64
            ),
            (
                "max_heartbeat_tick_latency_us",
                self.max_heartbeat_tick_latency_us,
                i64
            ),
            // packet latencies
            (
                "packet_latencies_us_min",
                self.packet_latencies_us.minimum().unwrap_or_default(),
                i64
            ),
            (
                "packet_latencies_us_max",
                self.packet_latencies_us.maximum().unwrap_or_default(),
                i64
            ),
            (
                "packet_latencies_us_p50",
                self.packet_latencies_us
                    .percentile(50.0)
                    .unwrap_or_default(),
                i64
            ),
            (
                "packet_latencies_us_p90",
                self.packet_latencies_us
                    .percentile(90.0)
                    .unwrap_or_default(),
                i64
            ),
            (
                "packet_latencies_us_p99",
                self.packet_latencies_us
                    .percentile(99.0)
                    .unwrap_or_default(),
                i64
            ),
            // crossbeam arm latencies
            (
                "crossbeam_subscription_receiver_processing_us_p50",
                self.crossbeam_subscription_receiver_processing_us
                    .percentile(50.0)
                    .unwrap_or_default(),
                i64
            ),
            (
                "crossbeam_subscription_receiver_processing_us_p90",
                self.crossbeam_subscription_receiver_processing_us
                    .percentile(90.0)
                    .unwrap_or_default(),
                i64
            ),
            (
                "crossbeam_subscription_receiver_processing_us_p99",
                self.crossbeam_subscription_receiver_processing_us
                    .percentile(99.0)
                    .unwrap_or_default(),
                i64
            ),
            (
                "crossbeam_slot_receiver_processing_us_p50",
                self.crossbeam_slot_receiver_processing_us
                    .percentile(50.0)
                    .unwrap_or_default(),
                i64
            ),
            (
                "crossbeam_slot_receiver_processing_us_p90",
                self.crossbeam_slot_receiver_processing_us
                    .percentile(90.0)
                    .unwrap_or_default(),
                i64
            ),
            (
                "crossbeam_slot_receiver_processing_us_p99",
                self.crossbeam_slot_receiver_processing_us
                    .percentile(99.0)
                    .unwrap_or_default(),
                i64
            ),
            (
                "crossbeam_metrics_tick_processing_us_p50",
                self.crossbeam_metrics_tick_processing_us
                    .percentile(50.0)
                    .unwrap_or_default(),
                i64
            ),
            (
                "crossbeam_metrics_tick_processing_us_p90",
                self.crossbeam_metrics_tick_processing_us
                    .percentile(90.0)
                    .unwrap_or_default(),
                i64
            ),
            (
                "crossbeam_metrics_tick_processing_us_p99",
                self.crossbeam_metrics_tick_processing_us
                    .percentile(99.0)
                    .unwrap_or_default(),
                i64
            ),
            (
                "crossbeam_delay_packet_receiver_processing_us_p50",
                self.crossbeam_delay_packet_receiver_processing_us
                    .percentile(50.0)
                    .unwrap_or_default(),
                i64
            ),
            (
                "crossbeam_delay_packet_receiver_processing_us_p90",
                self.crossbeam_delay_packet_receiver_processing_us
                    .percentile(90.0)
                    .unwrap_or_default(),
                i64
            ),
            (
                "crossbeam_delay_packet_receiver_processing_us_p99",
                self.crossbeam_delay_packet_receiver_processing_us
                    .percentile(99.0)
                    .unwrap_or_default(),
                i64
            ),
            (
                "crossbeam_heartbeat_tick_processing_us_p50",
                self.crossbeam_heartbeat_tick_processing_us
                    .percentile(50.0)
                    .unwrap_or_default(),
                i64
            ),
            (
                "crossbeam_heartbeat_tick_processing_us_p90",
                self.crossbeam_heartbeat_tick_processing_us
                    .percentile(90.0)
                    .unwrap_or_default(),
                i64
            ),
            (
                "crossbeam_heartbeat_tick_processing_us_p99",
                self.crossbeam_heartbeat_tick_processing_us
                    .percentile(99.0)
                    .unwrap_or_default(),
                i64
            ),
            // channel lengths
            ("slot_receiver_len", self.slot_receiver_max_len, i64),
            ("slot_receiver_capacity", self.slot_receiver_capacity, i64),
            (
                "subscription_receiver_len",
                self.subscription_receiver_max_len,
                i64
            ),
            (
                "subscription_receiver_capacity",
                self.subscription_receiver_capacity,
                i64
            ),
            (
                "delay_packet_receiver_len",
                self.delay_packet_receiver_max_len,
                i64
            ),
            (
                "delay_packet_receiver_capacity",
                self.delay_packet_receiver_capacity,
                i64
            ),
            (
                "packet_subscriptions_total_queued",
                self.packet_subscriptions_total_queued,
                i64
            ),
        );
    }
}

pub struct RelayerPacketBatches {
    pub stamp: Instant,
    pub banking_packet_batch: BankingPacketBatch,
}

pub enum Subscription {
    ValidatorPacketSubscription {
        pubkey: Pubkey,
        sender: TokioSender<Result<SubscribePacketsResponse, Status>>,
    },
}

#[derive(Error, Debug)]
pub enum RelayerError {
    #[error("shutdown")]
    Shutdown(#[from] RecvError),
}

pub type RelayerResult<T> = Result<T, RelayerError>;

type PacketSubscriptions =
    Arc<RwLock<HashMap<Pubkey, TokioSender<Result<SubscribePacketsResponse, Status>>>>>;
pub struct RelayerHandle {
    packet_subscriptions: PacketSubscriptions,
}

impl RelayerHandle {
    pub fn new(packet_subscriptions: &PacketSubscriptions) -> RelayerHandle {
        RelayerHandle {
            packet_subscriptions: packet_subscriptions.clone(),
        }
    }

    pub fn connected_validators(&self) -> Vec<Pubkey> {
        self.packet_subscriptions
            .read()
            .unwrap()
            .keys()
            .cloned()
            .collect()
    }
}

pub struct RelayerImpl {
    tpu_quic_ports: Vec<u16>,
    tpu_fwd_quic_ports: Vec<u16>,
    public_ip: IpAddr,
    seq: AtomicU64,

    subscription_sender: Sender<Subscription>,
    threads: Vec<JoinHandle<()>>,
    health_state: Arc<RwLock<HealthState>>,
    packet_subscriptions: PacketSubscriptions,
    validator_policies: ValidatorPolicies,
}

/// PBP policy as the relayer holds it, per authenticated validator identity.
///
/// A relayer forwards the same packet batch to every validator whose leader slot is near, so a
/// drop has to be attributable to the validator it is being made for. The validator is the party
/// accountable for its own block; nothing here comes from a relayer-local config file.
pub struct StoredPolicy {
    pub filter: PbpFilter,
    /// Refreshed on every push. A policy that stops being refreshed expires, because the relayer
    /// has no standing to keep dropping on an authority that has gone quiet.
    pub updated_at: Instant,
    pub digest: String,
}

pub type ValidatorPolicies = Arc<DashMap<Pubkey, StoredPolicy>>;

/// How long a pushed policy stays in force without a refresh.
///
/// Expiry stops enforcing, it does not start dropping: losing a validator's policy must never
/// cost that validator its order flow.
pub const POLICY_TTL: Duration = Duration::from_secs(300);

impl RelayerImpl {
    pub const SUBSCRIBER_QUEUE_CAPACITY: usize = 50_000;

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        slot_receiver: Receiver<Slot>,
        delay_packet_receiver: Receiver<RelayerPacketBatches>,
        leader_schedule_cache: LeaderScheduleUpdatingHandle,
        public_ip: IpAddr,
        tpu_quic_ports: Vec<u16>,
        tpu_fwd_quic_ports: Vec<u16>,
        health_state: Arc<RwLock<HealthState>>,
        exit: Arc<AtomicBool>,
        ofac_addresses: HashSet<Pubkey>,
        validator_policies: ValidatorPolicies,
        address_lookup_table_cache: Arc<DashMap<Pubkey, AddressLookupTableAccount>>,
        validator_packet_batch_size: usize,
        forward_all: bool,
        slot_lookahead: u64,
        heartbeat_tick_time: u64,
    ) -> Self {
        // receiver tracked as relayer_metrics.subscription_receiver_len
        let (subscription_sender, subscription_receiver) =
            bounded(LoadBalancer::SLOT_QUEUE_CAPACITY);

        let packet_subscriptions = Arc::new(RwLock::new(HashMap::default()));
        // Shared with the forwarding thread; the gRPC handler writes, the thread reads.
        let thread_policies = validator_policies.clone();

        let thread = {
            let health_state = health_state.clone();
            let packet_subscriptions = packet_subscriptions.clone();
            thread::Builder::new()
                .name("relayer_impl-event_loop_thread".to_string())
                .spawn(move || {
                    let res = Self::run_event_loop(
                        slot_receiver,
                        subscription_receiver,
                        delay_packet_receiver,
                        leader_schedule_cache,
                        slot_lookahead,
                        health_state,
                        exit,
                        &packet_subscriptions,
                        ofac_addresses,
                        thread_policies,
                        address_lookup_table_cache,
                        validator_packet_batch_size,
                        forward_all,
                        heartbeat_tick_time,
                    );
                    warn!("RelayerImpl thread exited with result {res:?}")
                })
                .unwrap()
        };

        Self {
            tpu_quic_ports,
            tpu_fwd_quic_ports,
            subscription_sender,
            public_ip,
            threads: vec![thread],
            health_state,
            packet_subscriptions,
            validator_policies,
            seq: AtomicU64::new(0),
        }
    }

    pub fn handle(&self) -> RelayerHandle {
        RelayerHandle::new(&self.packet_subscriptions)
    }

    #[allow(clippy::too_many_arguments)]
    fn run_event_loop(
        slot_receiver: Receiver<Slot>,
        subscription_receiver: Receiver<Subscription>,
        delay_packet_receiver: Receiver<RelayerPacketBatches>,
        leader_schedule_cache: LeaderScheduleUpdatingHandle,
        slot_lookahead: u64,
        health_state: Arc<RwLock<HealthState>>,
        exit: Arc<AtomicBool>,
        packet_subscriptions: &PacketSubscriptions,
        ofac_addresses: HashSet<Pubkey>,
        validator_policies: ValidatorPolicies,
        address_lookup_table_cache: Arc<DashMap<Pubkey, AddressLookupTableAccount>>,
        validator_packet_batch_size: usize,
        forward_all: bool,
        heartbeat_tick_time: u64,
    ) -> RelayerResult<()> {
        let mut highest_slot = Slot::default();

        let heartbeat_tick = crossbeam_channel::tick(Duration::from_millis(heartbeat_tick_time));
        let metrics_tick = crossbeam_channel::tick(Duration::from_millis(1000));

        let mut relayer_metrics = RelayerMetrics::new(
            slot_receiver.capacity().unwrap(),
            subscription_receiver.capacity().unwrap(),
            delay_packet_receiver.capacity().unwrap(),
        );

        let mut slot_leaders = HashSet::new();

        while !exit.load(Ordering::Relaxed) {
            crossbeam_channel::select! {
                recv(slot_receiver) -> maybe_slot => {
                    let start = Instant::now();

                    Self::update_highest_slot(maybe_slot, &mut highest_slot, &mut relayer_metrics)?;

                    let slots: Vec<_> = (highest_slot..highest_slot + slot_lookahead).collect();
                    slot_leaders = leader_schedule_cache.leaders_for_slots(&slots);

                    let _ = relayer_metrics.crossbeam_slot_receiver_processing_us.increment(start.elapsed().as_micros() as u64);
                },
                recv(delay_packet_receiver) -> maybe_packet_batches => {
                    let start = Instant::now();
                    let failed_forwards = Self::forward_packets(maybe_packet_batches, packet_subscriptions, &slot_leaders, &mut relayer_metrics, &ofac_addresses, &validator_policies, &address_lookup_table_cache, validator_packet_batch_size, forward_all)?;
                    Self::drop_connections(failed_forwards, packet_subscriptions, &mut relayer_metrics);
                    let _ = relayer_metrics.crossbeam_delay_packet_receiver_processing_us.increment(start.elapsed().as_micros() as u64);
                },
                recv(subscription_receiver) -> maybe_subscription => {
                    let start = Instant::now();
                    Self::handle_subscription(maybe_subscription, packet_subscriptions, &mut relayer_metrics)?;
                    let _ = relayer_metrics.crossbeam_subscription_receiver_processing_us.increment(start.elapsed().as_micros() as u64);
                }
                recv(heartbeat_tick) -> time_generated => {
                    let start = Instant::now();
                    if let Ok(time_generated) = time_generated {
                        relayer_metrics.max_heartbeat_tick_latency_us = std::cmp::max(relayer_metrics.max_heartbeat_tick_latency_us, Instant::now().duration_since(time_generated).as_micros() as u64);
                    }

                    // heartbeat if state is healthy, drop all connections on unhealthy
                    let pubkeys_to_drop = match *health_state.read().unwrap() {
                        HealthState::Healthy => {
                            Self::handle_heartbeat(
                                packet_subscriptions,
                                &mut relayer_metrics,
                            )
                        },
                        HealthState::Unhealthy => packet_subscriptions.read().unwrap().keys().cloned().collect(),
                    };
                    Self::drop_connections(pubkeys_to_drop, packet_subscriptions, &mut relayer_metrics);
                    let _ = relayer_metrics.crossbeam_heartbeat_tick_processing_us.increment(start.elapsed().as_micros() as u64);
                }
                recv(metrics_tick) -> time_generated => {
                    let start = Instant::now();
                    let l_packet_subscriptions = packet_subscriptions.read().unwrap();
                    relayer_metrics.num_current_connections = l_packet_subscriptions.len() as u64;
                    relayer_metrics.update_packet_subscription_total_capacity(&l_packet_subscriptions);
                    drop(l_packet_subscriptions);

                    if let Ok(time_generated) = time_generated {
                        relayer_metrics.metrics_latency_us = time_generated.elapsed().as_micros() as u64;
                    }
                    let _ = relayer_metrics.crossbeam_metrics_tick_processing_us.increment(start.elapsed().as_micros() as u64);

                    relayer_metrics.report();
                    relayer_metrics = RelayerMetrics::new(
                        slot_receiver.capacity().unwrap(),
                        subscription_receiver.capacity().unwrap(),
                        delay_packet_receiver.capacity().unwrap(),
                    );
                }
            }

            relayer_metrics.update_max_len(
                slot_receiver.len(),
                subscription_receiver.len(),
                delay_packet_receiver.len(),
            );
        }
        Ok(())
    }

    fn drop_connections(
        disconnected_pubkeys: Vec<Pubkey>,
        subscriptions: &PacketSubscriptions,
        relayer_metrics: &mut RelayerMetrics,
    ) {
        relayer_metrics.num_removed_connections += disconnected_pubkeys.len() as u64;

        let mut l_subscriptions = subscriptions.write().unwrap();
        for disconnected in disconnected_pubkeys {
            if let Some(sender) = l_subscriptions.remove(&disconnected) {
                datapoint_info!(
                    "relayer_removed_subscription",
                    ("pubkey", disconnected.to_string(), String)
                );
                drop(sender);
            }
        }
    }

    fn handle_heartbeat(
        subscriptions: &PacketSubscriptions,
        relayer_metrics: &mut RelayerMetrics,
    ) -> Vec<Pubkey> {
        let failed_pubkey_updates = subscriptions
            .read()
            .unwrap()
            .iter()
            .filter_map(|(pubkey, sender)| {
                // try send because it's a bounded channel and we don't want to block if the channel is full
                match sender.try_send(Ok(SubscribePacketsResponse {
                    header: None,
                    msg: Some(subscribe_packets_response::Msg::Heartbeat(Heartbeat {
                        count: relayer_metrics.num_heartbeats,
                    })),
                })) {
                    Ok(_) => {}
                    Err(TrySendError::Closed(_)) => return Some(*pubkey),
                    Err(TrySendError::Full(_)) => {
                        relayer_metrics.num_try_send_channel_full += 1;
                        warn!("heartbeat channel is full for: {:?}", pubkey);
                    }
                }
                None
            })
            .collect();

        relayer_metrics.num_heartbeats += 1;

        failed_pubkey_updates
    }

    /// Returns pubkeys of subscribers that failed to send.
    ///
    /// Filtering runs twice over, and the split matters. OFAC and the parse/convert failures are
    /// properties of the packet: they hold no matter who receives it, so they are decided once.
    /// A PBP drop is a property of the *recipient* -- the validator whose policy asks for it --
    /// so it is decided per subscription, after the recipients are known. Applying one
    /// validator's policy to the whole batch would censor another validator's block by rules it
    /// never agreed to.
    ///
    /// Each surviving packet is parsed exactly once into a `PacketSummary`; every validator's
    /// policy is then evaluated against that. Parsing per (packet x validator) would multiply the
    /// expensive step by the tenant count.
    #[allow(clippy::too_many_arguments)]
    fn forward_packets(
        maybe_packet_batches: Result<RelayerPacketBatches, RecvError>,
        subscriptions: &PacketSubscriptions,
        slot_leaders: &HashSet<Pubkey>,
        relayer_metrics: &mut RelayerMetrics,
        ofac_addresses: &HashSet<Pubkey>,
        validator_policies: &ValidatorPolicies,
        address_lookup_table_cache: &Arc<DashMap<Pubkey, AddressLookupTableAccount>>,
        validator_packet_batch_size: usize,
        forward_all: bool,
    ) -> RelayerResult<Vec<Pubkey>> {
        let packet_batches = maybe_packet_batches?;

        let _ = relayer_metrics
            .packet_latencies_us
            .increment(packet_batches.stamp.elapsed().as_micros() as u64);

        // Which validators this batch is headed for, and which of them have a live policy.
        let recipients: Vec<Pubkey> = {
            let l_subscriptions = subscriptions.read().unwrap();
            if forward_all {
                l_subscriptions.keys().copied().collect()
            } else {
                slot_leaders
                    .iter()
                    .filter(|pubkey| l_subscriptions.contains_key(pubkey))
                    .copied()
                    .collect()
            }
        };
        let now = Instant::now();
        let live_policies: Vec<(Pubkey, PbpFilter)> = recipients
            .iter()
            .filter_map(|pubkey| {
                let entry = validator_policies.get(pubkey)?;
                // A policy that stopped being refreshed stops being enforced.
                (now.duration_since(entry.updated_at) < POLICY_TTL && !entry.filter.is_empty())
                    .then(|| (*pubkey, entry.filter.clone()))
            })
            .collect();

        // Pass one: recipient-independent drops.
        let (mut n_ofac, mut n_deser, mut n_proto) = (0u64, 0u64, 0u64);
        // Summary is only built when some recipient can actually act on it.
        let need_summaries = !live_policies.is_empty();
        let mut packets = Vec::new();
        let mut summaries: Vec<Option<PacketSummary>> = Vec::new();
        for batch in packet_batches.banking_packet_batch.iter() {
            for packet in batch.iter().filter(|p| !p.meta().discard()) {
                let mut summary = None;
                if !ofac_addresses.is_empty() || need_summaries {
                    let tx: VersionedTransaction = match packet
                        .data(..)
                        .ok_or(())
                        .and_then(|data| bincode::deserialize(data).map_err(|_| ()))
                    {
                        Ok(tx) => tx,
                        Err(_) => {
                            n_deser += 1;
                            continue;
                        }
                    };
                    if is_tx_ofac_related(&tx, ofac_addresses, address_lookup_table_cache) {
                        n_ofac += 1;
                        continue;
                    }
                    if need_summaries {
                        summary = Some(PacketSummary::extract(&tx, address_lookup_table_cache));
                    }
                }
                match packet_to_proto_packet(packet) {
                    Some(p) => {
                        packets.push(p);
                        summaries.push(summary);
                    }
                    None => n_proto += 1,
                }
            }
        }
        relayer_metrics.num_packets_dropped_ofac += n_ofac;
        relayer_metrics.num_packets_dropped_deserialize += n_deser;
        relayer_metrics.num_packets_dropped_proto_convert += n_proto;
        relayer_metrics.num_packets_forwarded += packets.len() as u64;

        // Pass two: per-recipient drops. Validators without a live policy share the unfiltered
        // batch, which is the common case and costs nothing extra.
        let per_validator: HashMap<Pubkey, Vec<ProtoPacket>> = live_policies
            .iter()
            .map(|(pubkey, filter)| {
                let mut kept = Vec::with_capacity(packets.len());
                let mut dropped = 0u64;
                for (packet, summary) in packets.iter().zip(summaries.iter()) {
                    match summary.as_ref().and_then(|s| filter.evaluate(s)) {
                        Some(reason) => {
                            dropped += 1;
                            // Per-drop detail only; the rate lives in the counters below, which
                            // is what an operator should watch. At TPU packet rates a warn per
                            // drop floods the log and slows the forward path.
                            debug!("PBP drop for {pubkey}: {reason:?}");
                            relayer_metrics.increment_pbp_drop(pubkey, reason);
                        }
                        None => kept.push(packet.clone()),
                    }
                }
                relayer_metrics.num_packets_dropped_pbp += dropped;
                (*pubkey, kept)
            })
            .collect();

        // Chunk once for the shared case, and once per validator that filtered its own view.
        let chunk = |packets: &[ProtoPacket]| -> Vec<ProtoPacketBatch> {
            packets
                .chunks(validator_packet_batch_size)
                .map(|packet_chunk| ProtoPacketBatch {
                    packets: packet_chunk.to_vec(),
                })
                .collect()
        };
        let shared_batches = chunk(&packets);
        let filtered_batches: HashMap<Pubkey, Vec<ProtoPacketBatch>> = per_validator
            .iter()
            .map(|(pubkey, kept)| (*pubkey, chunk(kept)))
            .collect();

        let l_subscriptions = subscriptions.read().unwrap();

        let senders = if forward_all {
            l_subscriptions.iter().collect::<Vec<(
                &Pubkey,
                &TokioSender<Result<SubscribePacketsResponse, Status>>,
            )>>()
        } else {
            slot_leaders
                .iter()
                .filter_map(|pubkey| l_subscriptions.get(pubkey).map(|sender| (pubkey, sender)))
                .collect()
        };

        let mut failed_forwards = Vec::new();
        for (pubkey, sender) in &senders {
            // A validator that filtered its own view gets that view; everyone else shares the
            // batch nobody's policy touched.
            let batches = filtered_batches.get(*pubkey).unwrap_or(&shared_batches);
            for batch in batches {
                // NOTE: this is important to avoid divide-by-0 inside the validator if packets
                // get routed to sigverify under the assumption theres > 0 packets in the batch
                if batch.packets.is_empty() {
                    continue;
                }

                // try send because it's a bounded channel and we don't want to block if the channel is full
                match sender.try_send(Ok(SubscribePacketsResponse {
                    header: Some(Header {
                        ts: Some(Timestamp::from(SystemTime::now())),
                    }),
                    msg: Some(subscribe_packets_response::Msg::Batch(batch.clone())),
                })) {
                    Ok(_) => {
                        relayer_metrics
                            .increment_packets_forwarded(pubkey, batch.packets.len() as u64);
                    }
                    Err(TrySendError::Full(_)) => {
                        error!("packet channel is full for pubkey: {:?}", pubkey);
                        relayer_metrics
                            .increment_packets_dropped(pubkey, batch.packets.len() as u64);
                    }
                    Err(TrySendError::Closed(_)) => {
                        error!("channel is closed for pubkey: {:?}", pubkey);
                        failed_forwards.push(**pubkey);
                        break;
                    }
                }
            }
        }
        Ok(failed_forwards)
    }

    fn handle_subscription(
        maybe_subscription: Result<Subscription, RecvError>,
        subscriptions: &PacketSubscriptions,
        relayer_metrics: &mut RelayerMetrics,
    ) -> RelayerResult<()> {
        match maybe_subscription? {
            Subscription::ValidatorPacketSubscription { pubkey, sender } => {
                match subscriptions.write().unwrap().entry(pubkey) {
                    Entry::Vacant(entry) => {
                        entry.insert(sender);

                        relayer_metrics.num_added_connections += 1;
                        datapoint_info!(
                            "relayer_new_subscription",
                            ("pubkey", pubkey.to_string(), String)
                        );
                    }
                    Entry::Occupied(mut entry) => {
                        datapoint_info!(
                            "relayer_duplicate_subscription",
                            ("pubkey", pubkey.to_string(), String)
                        );
                        error!("already connected, dropping old connection: {pubkey:?}");
                        entry.insert(sender);
                    }
                }
            }
        }
        Ok(())
    }

    fn update_highest_slot(
        maybe_slot: Result<u64, RecvError>,
        highest_slot: &mut Slot,
        relayer_metrics: &mut RelayerMetrics,
    ) -> RelayerResult<()> {
        *highest_slot = maybe_slot?;
        datapoint_info!("relayer-highest_slot", ("slot", *highest_slot as i64, i64));
        relayer_metrics.highest_slot = *highest_slot;
        Ok(())
    }

    /// Prevent validators from authenticating if the relayer is unhealthy
    fn check_health(health_state: &Arc<RwLock<HealthState>>) -> Result<(), Status> {
        if *health_state.read().unwrap() != HealthState::Healthy {
            Err(Status::internal("relayer is unhealthy"))
        } else {
            Ok(())
        }
    }

    pub fn join(self) -> thread::Result<()> {
        for t in self.threads {
            t.join()?;
        }
        Ok(())
    }
}

#[tonic::async_trait]
impl Relayer for RelayerImpl {
    /// Validator calls this to get the public IP of the relayers TPU and TPU forward sockets.
    async fn get_tpu_configs(
        &self,
        _: Request<GetTpuConfigsRequest>,
    ) -> Result<Response<GetTpuConfigsResponse>, Status> {
        let seq = self.seq.fetch_add(1, Ordering::Acquire);
        return Ok(Response::new(GetTpuConfigsResponse {
            tpu: Some(Socket {
                ip: self.public_ip.to_string(),
                port: (self.tpu_quic_ports[seq as usize % self.tpu_quic_ports.len()] - 6) as i64,
            }),
            tpu_forward: Some(Socket {
                ip: self.public_ip.to_string(),
                port: (self.tpu_fwd_quic_ports[seq as usize % self.tpu_fwd_quic_ports.len()] - 6)
                    as i64,
            }),
        }));
    }

    type SubscribePacketsStream = ReceiverStream<Result<SubscribePacketsResponse, Status>>;

    /// Validator calls this to subscribe to packets
    async fn subscribe_packets(
        &self,
        request: Request<SubscribePacketsRequest>,
    ) -> Result<Response<Self::SubscribePacketsStream>, Status> {
        Self::check_health(&self.health_state)?;

        let pubkey: &Pubkey = request
            .extensions()
            .get()
            .ok_or_else(|| Status::internal("internal error fetching public key"))?;

        let (sender, receiver) = channel(RelayerImpl::SUBSCRIBER_QUEUE_CAPACITY);
        self.subscription_sender
            .send(Subscription::ValidatorPacketSubscription {
                pubkey: *pubkey,
                sender,
            })
            .map_err(|_| Status::internal("internal error adding subscription"))?;
        Ok(Response::new(ReceiverStream::new(receiver)))
    }

    /// The validator pushes the policy the relayer must apply to that validator's own stream.
    ///
    /// Keyed by the authenticated identity on the connection, never by anything in the message:
    /// a relayer fronts several validators and forwards the same batch to each, so a policy that
    /// could name a subject other than its sender would let one tenant censor another's block.
    ///
    /// Unparseable entries are skipped rather than rejecting the whole policy, so one bad pubkey
    /// in a list cannot leave the previous policy in force by accident. The response carries the
    /// digest of what was actually stored, which is what the validator compares against the
    /// engine's digest to catch the two drifting apart.
    async fn provide_pbp_policy(
        &self,
        request: Request<PbpPolicy>,
    ) -> Result<Response<ProvidePbpPolicyResponse>, Status> {
        let pubkey: Pubkey = *request
            .extensions()
            .get()
            .ok_or_else(|| Status::internal("internal error fetching public key"))?;
        let policy = request.into_inner();

        let parse_set = |values: &[String], field: &str| -> HashSet<Pubkey> {
            values
                .iter()
                .filter_map(|value| match Pubkey::from_str(value) {
                    Ok(pubkey) => Some(pubkey),
                    Err(_) => {
                        warn!("PBP policy from {pubkey}: skipping unparseable {field} '{value}'");
                        None
                    }
                })
                .collect()
        };

        let mut instruction_blacklist: HashMap<Pubkey, Vec<Vec<u8>>> = HashMap::new();
        for rule in &policy.instruction_blacklist {
            let Ok(program_id) = Pubkey::from_str(&rule.program_id) else {
                warn!(
                    "PBP policy from {pubkey}: skipping unparseable instruction rule program id                      '{}'",
                    rule.program_id
                );
                continue;
            };
            let prefixes: Vec<Vec<u8>> = rule
                .data_prefixes
                .iter()
                .filter_map(|hex| match decode_hex(hex) {
                    Some(bytes) => Some(bytes),
                    None => {
                        warn!("PBP policy from {pubkey}: skipping bad hex prefix '{hex}'");
                        None
                    }
                })
                .collect();
            // A rule whose every prefix failed to parse would silently widen to match-any, which
            // is the opposite of what was asked for.
            if prefixes.is_empty() && !rule.data_prefixes.is_empty() {
                warn!("PBP policy from {pubkey}: dropping instruction rule for {program_id}, no \
                       usable prefixes");
                continue;
            }
            instruction_blacklist
                .entry(program_id)
                .or_default()
                .extend(prefixes);
        }

        let filter = PbpFilter {
            address_blacklist: parse_set(&policy.address_blacklist, "address_blacklist"),
            program_blacklist: parse_set(&policy.program_blacklist, "program_blacklist"),
            instruction_blacklist,
        };
        let digest = policy_digest(&filter);
        info!(
            "PBP policy from {pubkey}: {} addresses, {} programs, {} instruction rules, digest {}",
            filter.address_blacklist.len(),
            filter.program_blacklist.len(),
            filter.instruction_blacklist.len(),
            digest
        );
        self.validator_policies.insert(
            pubkey,
            StoredPolicy {
                filter,
                updated_at: Instant::now(),
                digest: digest.clone(),
            },
        );

        Ok(Response::new(ProvidePbpPolicyResponse {
            accepted: true,
            policy_digest: digest,
        }))
    }
}

/// Stable digest of a stored policy, so the validator can tell whether the relayer and the block
/// engine are holding the same thing. Sorted, because set iteration order is not stable and a
/// digest that changes on its own is worse than no digest.
fn policy_digest(filter: &PbpFilter) -> String {
    let mut parts: Vec<String> = Vec::new();
    let mut addresses: Vec<String> = filter
        .address_blacklist
        .iter()
        .map(|k| format!("a:{k}"))
        .collect();
    let mut programs: Vec<String> = filter
        .program_blacklist
        .iter()
        .map(|k| format!("p:{k}"))
        .collect();
    let mut rules: Vec<String> = filter
        .instruction_blacklist
        .iter()
        .map(|(program_id, prefixes)| {
            let mut hexes: Vec<String> = prefixes.iter().map(hex_encode).collect();
            hexes.sort();
            format!("i:{program_id}:{}", hexes.join(","))
        })
        .collect();
    addresses.sort();
    programs.sort();
    rules.sort();
    parts.extend(addresses);
    parts.extend(programs);
    parts.extend(rules);
    let digest = solana_sha256_hasher::hash(parts.join("|").as_bytes());
    digest.to_string()[..16].to_string()
}

fn hex_encode(bytes: &Vec<u8>) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Decode an even-length hex string, with an optional `0x` prefix.
fn decode_hex(value: &str) -> Option<Vec<u8>> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    if value.len() % 2 != 0 {
        return None;
    }
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).ok())
        .collect()
}

// Blacklist matching is unit-tested in `jito_core::blacklist`, next to the predicate itself.

#[cfg(test)]
mod digest_tests {
    use std::collections::{HashMap, HashSet};

    use jito_core::pbp::PbpFilter;
    use solana_pubkey::Pubkey;

    use super::policy_digest;

    /// Pins the digest format against a fixed policy.
    ///
    /// The block engine computes this independently, in another repository, and the validator
    /// compares the two to tell whether they are enforcing the same thing. If the formats drift
    /// the comparison silently stops meaning anything, so both sides assert the same constant.
    /// A change here must be made in the engine's `pbp::policy_digest` in the same breath.
    #[test]
    fn policy_digest_is_stable() {
        let program: Pubkey = "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi".parse().unwrap();
        let address: Pubkey = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR".parse().unwrap();
        let bad: Pubkey = "CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8".parse().unwrap();

        let filter = PbpFilter {
            address_blacklist: HashSet::from_iter([address]),
            program_blacklist: HashSet::from_iter([bad]),
            instruction_blacklist: HashMap::from_iter([(
                program,
                vec![vec![0xde, 0xad], vec![0xbe, 0xef]],
            )]),
        };
        assert_eq!(policy_digest(&filter), "2bwADPFjVuWcVKXP");
    }

    /// Set ordering must not change the digest, or it would flap on its own and every
    /// comparison would report a divergence that is not there.
    #[test]
    fn policy_digest_ignores_set_order() {
        let a: Pubkey = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR".parse().unwrap();
        let b: Pubkey = "CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8".parse().unwrap();
        let one = PbpFilter {
            address_blacklist: HashSet::from_iter([a, b]),
            ..Default::default()
        };
        let two = PbpFilter {
            address_blacklist: HashSet::from_iter([b, a]),
            ..Default::default()
        };
        assert_eq!(policy_digest(&one), policy_digest(&two));
    }
}
