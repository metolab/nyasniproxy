use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[cfg(not(test))]
pub(crate) const ACCEPT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(1);
#[cfg(test)]
pub(crate) const ACCEPT_HEARTBEAT_INTERVAL: Duration = Duration::from_millis(20);

#[cfg(not(test))]
pub(crate) const WATCHDOG_STALL_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(test)]
pub(crate) const WATCHDOG_STALL_TIMEOUT: Duration = Duration::from_millis(150);

#[cfg(not(test))]
pub(crate) const WATCHDOG_POLL_INTERVAL: Duration = Duration::from_secs(1);
#[cfg(test)]
pub(crate) const WATCHDOG_POLL_INTERVAL: Duration = Duration::from_millis(20);

pub(crate) struct Heartbeat {
    origin: Instant,
    last_ms: AtomicU64,
}

impl Heartbeat {
    pub(crate) fn new() -> Arc<Self> {
        let this = Arc::new(Self {
            origin: Instant::now(),
            last_ms: AtomicU64::new(0),
        });
        this.beat();
        this
    }

    pub(crate) fn beat(&self) {
        let ms = self.origin.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
        self.last_ms.store(ms, Ordering::Release);
    }

    pub(crate) fn last_ms(&self) -> u64 {
        self.last_ms.load(Ordering::Acquire)
    }

    pub(crate) fn stalled_for(&self, limit: Duration) -> bool {
        let last = Duration::from_millis(self.last_ms());
        self.origin.elapsed().saturating_sub(last) > limit
    }
}

pub(crate) fn spawn_watchdog(
    heartbeat: Arc<Heartbeat>,
    stall_timeout: Duration,
    poll_interval: Duration,
    on_stall: impl FnOnce() + Send + 'static,
) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("nyasniproxy-watchdog".into())
        .spawn(move || loop {
            std::thread::sleep(poll_interval);
            if heartbeat.stalled_for(stall_timeout) {
                on_stall();
                return;
            }
        })
        .expect("spawn nyasniproxy-watchdog thread")
}

pub(crate) fn watchdog_suicide() -> ! {
    const MSG: &[u8] =
        b"nyasniproxy watchdog: accept loop stalled; exiting so launchd KeepAlive can restart\n";
    unsafe {
        libc::write(libc::STDERR_FILENO, MSG.as_ptr().cast(), MSG.len());
        libc::_exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn watchdog_trips_when_heartbeat_stops() {
        let heartbeat = Heartbeat::new();
        let (tx, rx) = mpsc::channel();
        let _wd = spawn_watchdog(
            Arc::clone(&heartbeat),
            WATCHDOG_STALL_TIMEOUT,
            WATCHDOG_POLL_INTERVAL,
            move || {
                let _ = tx.send(());
            },
        );
        rx.recv_timeout(Duration::from_millis(300))
            .expect("watchdog should fire after the seed beat ages past stall_timeout");
    }

    #[test]
    fn watchdog_stays_quiet_when_beating() {
        let heartbeat = Heartbeat::new();
        let (tx, rx) = mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let beater = {
            let heartbeat = Arc::clone(&heartbeat);
            let stop = Arc::clone(&stop);
            thread::spawn(move || {
                while !stop.load(AtomicOrdering::Relaxed) {
                    heartbeat.beat();
                    thread::sleep(WATCHDOG_POLL_INTERVAL);
                }
            })
        };
        let _wd = spawn_watchdog(
            Arc::clone(&heartbeat),
            WATCHDOG_STALL_TIMEOUT,
            WATCHDOG_POLL_INTERVAL,
            move || {
                let _ = tx.send(());
            },
        );
        thread::sleep(Duration::from_millis(400));
        stop.store(true, AtomicOrdering::Relaxed);
        assert!(
            rx.try_recv().is_err(),
            "watchdog must not fire while the heartbeat is being beaten"
        );
        let _ = beater.join();
    }
}
