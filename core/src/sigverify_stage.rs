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
//!
//! The stage also runs the same bloom-style deduper the validator's own sigverify runs, and
//! with the same parameters. Senders spray each transaction at the relayer many times over
//! (per slot of fanout, per retry, per RPC they use), and the fronted validator discards every
//! copy but the first at its own ingress anyway. Discarding them here instead keeps them out of
//! the per-validator stream, which is the one link in the path with a fixed ring and a
//! drop-oldest policy.

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
use solana_perf::{
    deduper::{dedup_packets_and_count_discards, Deduper},
    packet::PacketBatch,
    sigverify::ed25519_verify,
};
use solana_streamer::streamer::PacketBatchReceiver;

/// How long to wait for a batch before looping to check `exit`.
const RECV_TIMEOUT: Duration = Duration::from_millis(100);
/// Batches drained per pass before verifying, so the thread pool gets useful-sized work.
const MAX_BATCHES_PER_PASS: usize = 64;
/// Deduper sizing, matching agave's sigverify stage: ~8 MB of bits, two hashes, and a reset
/// once the filter is full enough to misfire on one packet in a thousand.
const DEDUPER_NUM_BITS: u64 = 63_999_979;
const DEDUPER_FALSE_POSITIVE_RATE: f64 = 0.001;

pub struct SigVerifyStage {
    thread_hdl: JoinHandle<()>,
}

impl SigVerifyStage {
    /// `dedup_window` is how long a packet's bytes stay remembered; a second copy inside that
    /// window is discarded before signature verification. `None` forwards every copy.
    pub fn new(
        packet_receiver: PacketBatchReceiver,
        verified_sender: Sender<BankingPacketBatch>,
        num_workers: NonZeroUsize,
        dedup_window: Option<Duration>,
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
                let mut rng = rand::rng();
                let mut deduper = dedup_window
                    .map(|window| (Deduper::<2, [u8]>::new(&mut rng, DEDUPER_NUM_BITS), window));
                let mut stats = SigVerifyStats::default();
                while !exit.load(Ordering::Relaxed) {
                    if let Some((deduper, window)) = deduper.as_mut() {
                        // Ages the filter out on the window, or early when it has filled up
                        // enough that unrelated packets start colliding.
                        if deduper.maybe_reset(&mut rng, DEDUPER_FALSE_POSITIVE_RATE, *window) {
                            stats.deduper_saturations += 1;
                        }
                    }
                    match Self::verify_pass(
                        &thread_pool,
                        &packet_receiver,
                        &verified_sender,
                        deduper.as_ref().map(|(deduper, _)| deduper),
                    ) {
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
        deduper: Option<&Deduper<2, [u8]>>,
    ) -> Result<PassStats, RecvTimeoutError> {
        let mut batches = vec![packet_receiver.recv_timeout(RECV_TIMEOUT)?];
        while batches.len() < MAX_BATCHES_PER_PASS {
            match packet_receiver.try_recv() {
                Ok(batch) => batches.push(batch),
                Err(_) => break,
            }
        }

        let received: usize = batches.iter().map(PacketBatch::len).sum();
        let count_discarded = |batches: &[PacketBatch]| -> usize {
            batches
                .iter()
                .map(|batch| batch.iter().filter(|packet| packet.meta().discard()).count())
                .sum()
        };

        // Dedup first so the (much more expensive) signature check only runs on the copies
        // that will actually go somewhere; a discarded packet is skipped by ed25519_verify.
        let already_discarded = count_discarded(&batches);
        let deduped = match deduper {
            Some(deduper) => {
                dedup_packets_and_count_discards(deduper, &mut batches) as usize
                    - already_discarded
            }
            None => 0,
        };

        let start = Instant::now();
        // reject_non_vote = false: a relayer forwards votes too. enable_tx_v1 = true, or every
        // SIMD-0296 transaction is discarded here as malformed.
        ed25519_verify(thread_pool, &mut batches, false, received, true);
        let verify_us = start.elapsed().as_micros() as u64;

        let discarded = count_discarded(&batches) - already_discarded - deduped;

        // Sending on a dropped receiver means the relayer is shutting down; the outer loop's
        // exit flag will pick that up on the next pass.
        let _ = verified_sender.send(BankingPacketBatch::new(batches));

        Ok(PassStats {
            received,
            deduped,
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
    deduped: usize,
    discarded: usize,
    verify_us: u64,
}

#[derive(Default)]
struct SigVerifyStats {
    since: Option<Instant>,
    passes: u64,
    received: u64,
    deduped: u64,
    discarded: u64,
    deduper_saturations: u64,
    verify_us: u64,
}

impl SigVerifyStats {
    const REPORT_INTERVAL: Duration = Duration::from_secs(1);

    fn record(&mut self, pass: PassStats) {
        self.since.get_or_insert_with(Instant::now);
        self.passes += 1;
        self.received += pass.received as u64;
        self.deduped += pass.deduped as u64;
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
            // A repeat of a packet seen inside the dedup window. The validator would have
            // discarded it at its own ingress; the count is what the stream was spared.
            ("num_packets_deduped", self.deduped, i64),
            // A packet dropped here failed signature verification and never reaches the
            // validator. A jump usually means someone is spraying us, not a bug.
            ("num_packets_discarded", self.discarded, i64),
            // Filter resets forced by fill level rather than age. Anything but zero means
            // the window is longer than the traffic can afford at this filter size.
            ("num_deduper_saturations", self.deduper_saturations, i64),
            ("verify_us", self.verify_us, i64),
        );
        *self = Self::default();
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use solana_hash::Hash;
    use solana_keypair::Keypair;
    use solana_message::{
        compiled_instruction::CompiledInstruction, v0, MessageHeader, VersionedMessage,
    };
    use solana_packet::Packet;
    use solana_perf::packet::{PacketBatch, RecycledPacketBatch};
    use solana_pubkey::Pubkey;
    use solana_signature::Signature;
    use solana_signer::Signer;
    use solana_transaction::versioned::VersionedTransaction;

    use super::*;

    fn signed_tx() -> VersionedTransaction {
        let payer = Keypair::new();
        let message = VersionedMessage::V0(v0::Message {
            header: MessageHeader {
                num_required_signatures: 1,
                num_readonly_signed_accounts: 0,
                num_readonly_unsigned_accounts: 0,
            },
            recent_blockhash: Hash::new_unique(),
            account_keys: vec![payer.pubkey(), Pubkey::new_unique()],
            address_table_lookups: vec![],
            instructions: vec![CompiledInstruction {
                program_id_index: 1,
                accounts: vec![0],
                data: vec![1, 2, 3],
            }],
        });
        VersionedTransaction::try_new(message, &[&payer]).expect("valid tx")
    }

    fn batch_of(txs: &[&VersionedTransaction]) -> PacketBatch {
        let packets: Vec<Packet> = txs
            .iter()
            .map(|tx| Packet::from_data(None, tx).expect("fits a packet"))
            .collect();
        PacketBatch::from(RecycledPacketBatch::new(packets))
    }

    fn run_stage(
        dedup_window: Option<Duration>,
        input: Vec<PacketBatch>,
    ) -> Vec<(bool, Option<Vec<u8>>)> {
        let (packet_sender, packet_receiver) = crossbeam_channel::unbounded();
        let (verified_sender, verified_receiver) = crossbeam_channel::unbounded();
        let exit = Arc::new(AtomicBool::new(false));
        let stage = SigVerifyStage::new(
            packet_receiver,
            verified_sender,
            NonZeroUsize::new(1).unwrap(),
            dedup_window,
            exit.clone(),
        );
        let expected: usize = input.iter().map(PacketBatch::len).sum();
        for batch in input {
            packet_sender.send(batch).unwrap();
        }

        let mut out = Vec::new();
        while out.len() < expected {
            let batches = verified_receiver
                .recv_timeout(Duration::from_secs(5))
                .expect("sigverify output");
            for batch in batches.iter() {
                for packet in batch.iter() {
                    // `data` is None once a packet is marked discard, so keep the flag too.
                    out.push((packet.meta().discard(), packet.data(..).map(<[u8]>::to_vec)));
                }
            }
        }
        exit.store(true, Ordering::Relaxed);
        drop(packet_sender);
        stage.join().unwrap();
        out
    }

    #[test]
    fn repeat_copies_are_discarded_inside_the_window() {
        let a = signed_tx();
        let b = signed_tx();
        // Three copies of `a` spread over two batches, one of `b`.
        let out = run_stage(
            Some(Duration::from_secs(60)),
            vec![batch_of(&[&a, &b, &a]), batch_of(&[&a])],
        );
        let kept: Vec<Vec<u8>> = out
            .iter()
            .filter(|(discard, _)| !discard)
            .map(|(_, data)| data.clone().expect("kept packets are readable"))
            .collect();
        assert_eq!(out.len(), 4);
        assert_eq!(kept.len(), 2);
        assert!(kept.contains(&bincode::serialize(&a).unwrap()));
        assert!(kept.contains(&bincode::serialize(&b).unwrap()));
    }

    #[test]
    fn dedup_off_forwards_every_copy() {
        let a = signed_tx();
        let out = run_stage(None, vec![batch_of(&[&a, &a]), batch_of(&[&a])]);
        assert_eq!(out.len(), 3);
        assert!(out.iter().all(|(discard, _)| !discard));
    }

    #[test]
    fn a_bad_signature_is_still_discarded() {
        let mut a = signed_tx();
        a.signatures[0] = Signature::from([7u8; 64]);
        let out = run_stage(Some(Duration::from_secs(60)), vec![batch_of(&[&a])]);
        assert_eq!(out.len(), 1);
        assert!(out[0].0);
    }
}
