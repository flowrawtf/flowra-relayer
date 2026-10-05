use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, RwLock,
    },
    thread,
    thread::{Builder, JoinHandle},
    time::{Duration, Instant},
};

use crossbeam_channel::{select, tick, Receiver, Sender};
use log::error;
use solana_metrics::{datapoint_error, datapoint_info};
use solana_clock::Slot;

#[derive(PartialEq, Eq, Copy, Clone)]
pub enum HealthState {
    Unhealthy = 0,
    Healthy = 1,
}

pub struct HealthManager {
    state: Arc<RwLock<HealthState>>,
    manager_thread: JoinHandle<()>,
}

/// Manages health status of the relayer. Reports to metrics and other parts of system health
/// status so they can react accordingly.
impl HealthManager {
    /// Exit code used when the slot stream stalls past `slot_stall_restart_threshold`.
    /// systemd (Restart=always) brings us back with fresh subscriptions.
    pub const SLOT_STALL_EXIT_CODE: i32 = 17;

    pub fn new(
        slot_receiver: Receiver<Slot>,
        slot_sender: Sender<Slot>,
        missing_slot_unhealthy_threshold: Duration,
        slot_stall_restart_threshold: Option<Duration>,
        exit: Arc<AtomicBool>,
    ) -> HealthManager {
        let health_state = Arc::new(RwLock::new(HealthState::Unhealthy));
        HealthManager {
            state: health_state.clone(),
            manager_thread: Builder::new()
                .name("health_manager".to_string())
                .spawn(move || {
                    let mut last_update = Instant::now();
                    let mut slot_sender_max_len = 0usize;
                    let channel_len_tick = tick(Duration::from_secs(5));
                    let check_and_metrics_tick = tick(missing_slot_unhealthy_threshold / 2);

                    while !exit.load(Ordering::Relaxed) {
                        select! {
                            recv(check_and_metrics_tick) -> _ => {
                                let new_health_state =
                                    match last_update.elapsed() <= missing_slot_unhealthy_threshold {
                                        true => HealthState::Healthy,
                                        false => HealthState::Unhealthy,
                                    };
                                *health_state.write().unwrap() = new_health_state;
                                datapoint_info!(
                                    "relayer-health-state",
                                    ("health_state", new_health_state, i64)
                                );

                                // Being unhealthy is recoverable; a slot stream that never comes
                                // back is not. The websocket supervisor can wedge in ways it
                                // cannot see (e.g. a blocking teardown on a half-open socket),
                                // so if we have gone this long without a single slot from any
                                // endpoint, exit and let systemd rebuild every connection.
                                if let Some(threshold) = slot_stall_restart_threshold {
                                    let stalled_for = last_update.elapsed();
                                    if stalled_for >= threshold {
                                        datapoint_error!(
                                            "relayer-slot_stall_restart",
                                            ("stalled_secs", stalled_for.as_secs(), i64)
                                        );
                                        error!(
                                            "no slot received in {stalled_for:?} (threshold {threshold:?}); \
                                             exiting so the slot subscriptions are rebuilt"
                                        );
                                        solana_metrics::flush();
                                        std::process::exit(Self::SLOT_STALL_EXIT_CODE);
                                    }
                                }
                            }
                            recv(slot_receiver) -> maybe_slot => {
                                let slot = maybe_slot.expect("error receiving slot, exiting");
                                slot_sender.send(slot).expect("error forwarding slot, exiting");
                                last_update = Instant::now();
                            }
                            recv(channel_len_tick) -> _ => {
                                datapoint_info!(
                                    "health_manager-channel_stats",
                                    ("slot_sender_len", slot_sender_max_len, i64),
                                    ("slot_sender_capacity", slot_sender.capacity().unwrap(), i64),
                                );
                                slot_sender_max_len = 0;
                            }
                        }
                        slot_sender_max_len = std::cmp::max(slot_sender_max_len, slot_sender.len());
                    }
                })
                .unwrap(),
        }
    }

    /// Return a handle to the health manager state
    pub fn handle(&self) -> Arc<RwLock<HealthState>> {
        self.state.clone()
    }

    pub fn join(self) -> thread::Result<()> {
        self.manager_thread.join()
    }
}
