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
    collections::{hash_map::RandomState, HashMap},
    hash::BuildHasher,
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
use solana_packet::PacketFlags;
use solana_perf::{packet::PacketBatch, sigverify::ed25519_verify};
use solana_streamer::streamer::PacketBatchReceiver;

/// How long to wait for a batch before looping to check `exit`.
const RECV_TIMEOUT: Duration = Duration::from_millis(100);
/// Batches drained per pass before verifying, so the thread pool gets useful-sized work.
const MAX_BATCHES_PER_PASS: usize = 64;

/// How long a verified packet is remembered: one generation, with the previous one kept
/// alongside, so a repeat is recognised for between one and two of these.
const VERIFIED_WINDOW: Duration = Duration::from_secs(10);
/// A generation is retired early at this many entries, bounding memory under a flood.
const VERIFIED_CAP: usize = 2_000_000;

/// Packets whose signatures already verified, by a keyed hash of their bytes.
///
/// A client that wants a transaction to land sends it again and again, and so does every
/// forwarder in front of it — the engine measured 5.1 copies per signature. Each copy used to
/// pay a full ed25519 verification here, even though identical bytes can only verify the
/// same way they did a moment ago. Remembering what verified lets a repeat skip the
/// verification and nothing else: it is still forwarded, and the forward step still decides
/// whether a copy has been delivered already.
///
/// Only bytes that *passed* are remembered, so a repeat of a bad packet is verified (and
/// dropped) again. The hash is 128 bits under two keys drawn at startup, so a packet cannot
/// be built to collide with a verified one.
struct VerifiedCache {
    keys: (RandomState, RandomState),
    current: HashMap<u128, bool>,
    previous: HashMap<u128, bool>,
    rotated: Instant,
}

impl VerifiedCache {
    fn new() -> Self {
        Self {
            keys: (RandomState::new(), RandomState::new()),
            current: HashMap::new(),
            previous: HashMap::new(),
            rotated: Instant::now(),
        }
    }

    fn key(&self, data: &[u8]) -> u128 {
        (u128::from(self.keys.0.hash_one(data)) << 64) | u128::from(self.keys.1.hash_one(data))
    }

    /// `Some(is_simple_vote)` if these exact bytes verified within the window.
    fn get(&self, key: u128) -> Option<bool> {
        self.current.get(&key).or_else(|| self.previous.get(&key)).copied()
    }

    fn insert(&mut self, key: u128, is_simple_vote: bool) {
        self.current.insert(key, is_simple_vote);
    }

    fn maybe_rotate(&mut self, now: Instant) {
        if now.duration_since(self.rotated) >= VERIFIED_WINDOW || self.current.len() >= VERIFIED_CAP {
            self.previous = std::mem::take(&mut self.current);
            self.rotated = now;
        }
    }
}

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
                let mut verified = VerifiedCache::new();
                while !exit.load(Ordering::Relaxed) {
                    match Self::verify_pass(
                        &thread_pool,
                        &packet_receiver,
                        &verified_sender,
                        &mut verified,
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
        verified: &mut VerifiedCache,
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
        let skipped = Self::verify_new(thread_pool, &mut batches, verified, received);
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
            skipped,
            verify_us,
        })
    }

    /// Verify every packet that has not verified before, leaving failures marked discard as
    /// `ed25519_verify` does. Returns how many packets were recognised and skipped.
    fn verify_new(
        thread_pool: &rayon::ThreadPool,
        batches: &mut [PacketBatch],
        verified: &mut VerifiedCache,
        received: usize,
    ) -> usize {
        verified.maybe_rotate(Instant::now());

        // Pass one: hash each live packet. A recognised one is hidden from the verifier (which
        // skips discarded packets) and un-hidden afterwards.
        enum Seen {
            /// Arrived already discarded; leave it alone.
            Dead,
            /// Verified before, with this simple-vote flag.
            Known(bool),
            /// New: verify it, and remember it under this key if it passes.
            New(u128),
        }
        let mut seen: Vec<Seen> = Vec::with_capacity(received);
        let mut skipped = 0;
        for batch in batches.iter_mut() {
            for mut packet in batch.iter_mut() {
                let key = match packet.data(..) {
                    Some(data) if !packet.meta().discard() => verified.key(data),
                    _ => {
                        seen.push(Seen::Dead);
                        continue;
                    }
                };
                match verified.get(key) {
                    Some(is_simple_vote) => {
                        packet.meta_mut().set_discard(true);
                        seen.push(Seen::Known(is_simple_vote));
                        skipped += 1;
                    }
                    None => seen.push(Seen::New(key)),
                }
            }
        }

        // reject_non_vote = false: a relayer forwards votes too. enable_tx_v1 = true, or every
        // SIMD-0296 transaction is discarded here as malformed.
        ed25519_verify(thread_pool, batches, false, received, true);

        // Pass two, same order: restore what was hidden, remember what just passed.
        let mut seen = seen.into_iter();
        for batch in batches.iter_mut() {
            for mut packet in batch.iter_mut() {
                match seen.next().expect("one entry per packet") {
                    Seen::Dead => {}
                    Seen::Known(is_simple_vote) => {
                        packet.meta_mut().set_discard(false);
                        // The verifier sets this flag as a side effect; a skipped packet
                        // must carry the same one.
                        if is_simple_vote {
                            packet.meta_mut().flags |= PacketFlags::SIMPLE_VOTE_TX;
                        }
                    }
                    Seen::New(key) => {
                        if !packet.meta().discard() {
                            let is_simple_vote =
                                packet.meta().flags.contains(PacketFlags::SIMPLE_VOTE_TX);
                            verified.insert(key, is_simple_vote);
                        }
                    }
                }
            }
        }
        skipped
    }

    pub fn join(self) -> thread::Result<()> {
        self.thread_hdl.join()
    }
}

struct PassStats {
    received: usize,
    discarded: usize,
    /// Recognised as already verified, and so not verified again.
    skipped: usize,
    verify_us: u64,
}

#[derive(Default)]
struct SigVerifyStats {
    since: Option<Instant>,
    passes: u64,
    received: u64,
    discarded: u64,
    skipped: u64,
    verify_us: u64,
}

impl SigVerifyStats {
    const REPORT_INTERVAL: Duration = Duration::from_secs(1);

    fn record(&mut self, pass: PassStats) {
        self.since.get_or_insert_with(Instant::now);
        self.passes += 1;
        self.received += pass.received as u64;
        self.discarded += pass.discarded as u64;
        self.skipped += pass.skipped as u64;
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
            // Repeats of a packet that already verified: forwarded, not re-verified.
            ("num_packets_verify_skipped", self.skipped, i64),
            ("verify_us", self.verify_us, i64),
        );
        *self = Self::default();
    }
}

#[cfg(test)]
mod tests {
    use solana_hash::Hash;
    use solana_instruction::{AccountMeta, Instruction};
    use solana_keypair::Keypair;
    use solana_packet::Packet;
    use solana_perf::packet::RecycledPacketBatch;
    use solana_pubkey::Pubkey;
    use solana_signer::Signer;
    use solana_transaction::Transaction;

    use super::*;

    fn signed_tx() -> Transaction {
        let payer = Keypair::new();
        Transaction::new_signed_with_payer(
            &[Instruction::new_with_bytes(
                Pubkey::new_unique(),
                &[1, 2, 3],
                vec![AccountMeta::new(Pubkey::new_unique(), false)],
            )],
            Some(&payer.pubkey()),
            &[&payer],
            Hash::new_unique(),
        )
    }

    fn batch_of(txs: &[&Transaction]) -> Vec<PacketBatch> {
        let packets: Vec<Packet> = txs
            .iter()
            .map(|tx| Packet::from_data(None, tx).expect("fits a packet"))
            .collect();
        vec![PacketBatch::from(RecycledPacketBatch::new(packets))]
    }

    fn pool() -> rayon::ThreadPool {
        rayon::ThreadPoolBuilder::new().num_threads(2).build().unwrap()
    }

    fn discards(batches: &[PacketBatch]) -> Vec<bool> {
        batches
            .iter()
            .flat_map(|b| b.iter().map(|p| p.meta().discard()))
            .collect()
    }

    #[test]
    fn a_repeat_of_a_verified_packet_is_forwarded_without_verifying_it_again() {
        let pool = pool();
        let mut verified = VerifiedCache::new();
        let good = signed_tx();
        let other = signed_tx();

        // First sight: both are verified, both pass, nothing is skipped.
        let mut first = batch_of(&[&good, &other]);
        assert_eq!(SigVerifyStage::verify_new(&pool, &mut first, &mut verified, 2), 0);
        assert_eq!(discards(&first), vec![false, false]);

        // Again, alongside a packet never seen: the repeat is skipped and still live.
        let fresh = signed_tx();
        let mut second = batch_of(&[&good, &fresh]);
        assert_eq!(SigVerifyStage::verify_new(&pool, &mut second, &mut verified, 2), 1);
        assert_eq!(discards(&second), vec![false, false]);
    }

    #[test]
    fn only_packets_that_verified_are_remembered() {
        let pool = pool();
        let mut verified = VerifiedCache::new();

        // Same signature, different message: the signature no longer covers the bytes.
        let good = signed_tx();
        let mut tampered = good.clone();
        tampered.message.instructions[0].data = vec![9, 9, 9];

        for _ in 0..2 {
            // A bad packet is verified, and dropped, every time it is seen.
            let mut batches = batch_of(&[&tampered]);
            assert_eq!(SigVerifyStage::verify_new(&pool, &mut batches, &mut verified, 1), 0);
            assert_eq!(discards(&batches), vec![true]);
        }

        // Remembering the genuine packet does not let its tampered twin ride along.
        let mut batches = batch_of(&[&good]);
        SigVerifyStage::verify_new(&pool, &mut batches, &mut verified, 1);
        assert_eq!(discards(&batches), vec![false]);
        let mut batches = batch_of(&[&good, &tampered]);
        assert_eq!(SigVerifyStage::verify_new(&pool, &mut batches, &mut verified, 2), 1);
        assert_eq!(discards(&batches), vec![false, true]);
    }

    #[test]
    fn a_packet_that_arrived_discarded_stays_discarded() {
        let pool = pool();
        let mut verified = VerifiedCache::new();
        let good = signed_tx();
        let mut batches = batch_of(&[&good]);
        SigVerifyStage::verify_new(&pool, &mut batches, &mut verified, 1);

        // Known bytes, but something upstream already discarded this copy.
        let mut batches = batch_of(&[&good]);
        for mut packet in batches[0].iter_mut() {
            packet.meta_mut().set_discard(true);
        }
        assert_eq!(SigVerifyStage::verify_new(&pool, &mut batches, &mut verified, 1), 0);
        assert_eq!(discards(&batches), vec![true]);
    }

    #[test]
    fn the_cache_forgets_after_two_generations() {
        let mut verified = VerifiedCache::new();
        let key = verified.key(b"packet");
        verified.insert(key, false);
        let t0 = verified.rotated;

        verified.maybe_rotate(t0 + VERIFIED_WINDOW);
        assert_eq!(verified.get(key), Some(false), "still known for one more generation");
        verified.maybe_rotate(t0 + VERIFIED_WINDOW * 2);
        assert_eq!(verified.get(key), None);
    }
}
