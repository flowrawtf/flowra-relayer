//! Signature verification for the relayer's TPU ingress.
//!
//! We used to borrow `solana_core::sigverify_stage::SigVerifyStage`. As of 4.2 that stage
//! takes a `SharableBanks` and splits vote from non-vote traffic, which a relayer has no
//! business doing: it has no bank, no leader schedule of its own to consult, and forwards
//! everything it accepts. All it actually needs from that stage is "drop packets whose
//! signatures do not verify", which `solana_perf::sigverify` exposes directly.
//!
//! Keeping this here also drops `solana-core` from the relayer's dependency tree, which is
//! most of what made the 2.2 -> 4.2 bump painful in the first place.

use std::{
    num::NonZeroUsize,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::{self, Builder, JoinHandle},
    time::{Duration, Instant},
};

use agave_banking_stage_ingress_types::BankingPacketBatch;
use crossbeam_channel::{RecvTimeoutError, Sender};
use solana_metrics::datapoint_info;
use solana_perf::{packet::PacketBatch, sigverify::ed25519_verify};
use solana_streamer::streamer::PacketBatchReceiver;

/// How long to wait for a batch before looping to check `exit`.
const RECV_TIMEOUT: Duration = Duration::from_millis(100);
/// Batches drained per pass before verifying, so the thread pool gets useful-sized work.
const MAX_BATCHES_PER_PASS: usize = 64;

pub struct SigVerifyStage {
    thread_hdl: JoinHandle<()>,
}

impl SigVerifyStage {
    pub fn new(
        packet_receiver: PacketBatchReceiver,
        verified_sender: Sender<BankingPacketBatch>,
        num_workers: NonZeroUsize,
        exit: Arc<AtomicBool>,
    ) -> Self {
        let thread_pool = rayon::ThreadPoolBuilder::new()
            .num_threads(num_workers.get())
            .thread_name(|i| format!("solSigVerify{i:02}"))
            .build()
            .expect("sigverify thread pool");

        let thread_hdl = Builder::new()
            .name("relayer-sigverify".to_string())
            .spawn(move || {
                let mut stats = SigVerifyStats::default();
                while !exit.load(Ordering::Relaxed) {
                    match Self::verify_pass(&thread_pool, &packet_receiver, &verified_sender) {
                        Ok(pass) => stats.record(pass),
                        Err(RecvTimeoutError::Timeout) => {}
                        Err(RecvTimeoutError::Disconnected) => break,
                    }
                    stats.maybe_report();
                }
            })
            .unwrap();

        Self { thread_hdl }
    }

    fn verify_pass(
        thread_pool: &rayon::ThreadPool,
        packet_receiver: &PacketBatchReceiver,
        verified_sender: &Sender<BankingPacketBatch>,
    ) -> Result<PassStats, RecvTimeoutError> {
        let mut batches = vec![packet_receiver.recv_timeout(RECV_TIMEOUT)?];
        while batches.len() < MAX_BATCHES_PER_PASS {
            match packet_receiver.try_recv() {
                Ok(batch) => batches.push(batch),
                Err(_) => break,
            }
        }

        let received: usize = batches.iter().map(PacketBatch::len).sum();
        let start = Instant::now();
        // reject_non_vote = false: a relayer forwards votes too. enable_tx_v1 = true, or every
        // SIMD-0296 transaction is discarded here as malformed.
        ed25519_verify(thread_pool, &mut batches, false, received, true);
        let verify_us = start.elapsed().as_micros() as u64;

        let discarded: usize = batches
            .iter()
            .map(|batch| batch.iter().filter(|packet| packet.meta().discard()).count())
            .sum();

        // Sending on a dropped receiver means the relayer is shutting down; the outer loop's
        // exit flag will pick that up on the next pass.
        let _ = verified_sender.send(BankingPacketBatch::new(batches));

        Ok(PassStats {
            received,
            discarded,
            verify_us,
        })
    }

    pub fn join(self) -> thread::Result<()> {
        self.thread_hdl.join()
    }
}

struct PassStats {
    received: usize,
    discarded: usize,
    verify_us: u64,
}

#[derive(Default)]
struct SigVerifyStats {
    since: Option<Instant>,
    passes: u64,
    received: u64,
    discarded: u64,
    verify_us: u64,
}

impl SigVerifyStats {
    const REPORT_INTERVAL: Duration = Duration::from_secs(1);

    fn record(&mut self, pass: PassStats) {
        self.since.get_or_insert_with(Instant::now);
        self.passes += 1;
        self.received += pass.received as u64;
        self.discarded += pass.discarded as u64;
        self.verify_us += pass.verify_us;
    }

    fn maybe_report(&mut self) {
        let Some(since) = self.since else { return };
        if since.elapsed() < Self::REPORT_INTERVAL {
            return;
        }
        datapoint_info!(
            "relayer_sigverify",
            ("passes", self.passes, i64),
            ("num_packets_received", self.received, i64),
            // A packet dropped here failed signature verification and never reaches the
            // validator. A jump usually means someone is spraying us, not a bug.
            ("num_packets_discarded", self.discarded, i64),
            ("verify_us", self.verify_us, i64),
        );
        *self = Self::default();
    }
}
