//! A warm pool of pre-booted execution slots.
//!
//! # Why this is the only way sub-200 ms happens
//!
//! Booting a virtual machine to run one shell command cannot be done in 200 ms.
//! Firecracker's well-known ~125 ms figure is a stripped kernel on KVM and
//! counts kernel boot alone; Apple's Virtualization.framework carries more
//! overhead and takes closer to a second for a minimal Linux guest. Any design
//! that boots per command has already lost, by a factor of five to fifty.
//!
//! So the boot is moved off the critical path. Slots are booted ahead of
//! demand and parked; acquiring one is popping a queue. The latency target
//! becomes an *acquisition* SLA rather than a boot time, which is both
//! achievable and the honest thing to measure — [`PoolStats`] reports warm hits
//! and cold boots separately so a pool that is quietly too small shows up as
//! cold boots rather than as an unexplained latency tail.
//!
//! This is what production sandboxes do. It is not a shortcut around the
//! requirement; it is the requirement's only real implementation.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use crate::runtime::RuntimeError;

/// Something that can be booted ahead of time and reused.
pub trait Warm: Send + Sync + 'static {
    /// A booted, idle execution slot.
    type Slot: Send + 'static;

    /// Boot one. Expensive by definition — this is the cost being hidden.
    fn boot(&self) -> Result<Self::Slot, RuntimeError>;

    /// Whether a returned slot can serve another command.
    ///
    /// Reuse is where a sandbox leaks: a slot that ran one command and kept
    /// its filesystem writes would hand them to the next. An implementation
    /// that cannot cheaply guarantee a clean slot should return `false` and
    /// take the boot.
    fn healthy(&self, slot: &Self::Slot) -> bool {
        let _ = slot;
        true
    }

    fn shutdown(&self, slot: Self::Slot);
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PoolStats {
    /// Acquisitions served from the pool.
    pub warm_hits: u64,
    /// Acquisitions that had to boot, because the pool was empty.
    pub cold_boots: u64,
    /// Slots retired instead of being returned.
    pub retired: u64,
    pub max_acquire: Duration,
    total_acquire: Duration,
}

impl PoolStats {
    pub fn acquisitions(&self) -> u64 {
        self.warm_hits + self.cold_boots
    }

    pub fn mean_acquire(&self) -> Duration {
        let n = self.acquisitions();
        if n == 0 {
            Duration::ZERO
        } else {
            self.total_acquire / n as u32
        }
    }

    /// Share of acquisitions served warm. A number below 1.0 under steady load
    /// means the pool is too small for the arrival rate.
    pub fn hit_rate(&self) -> f64 {
        let n = self.acquisitions();
        if n == 0 {
            0.0
        } else {
            self.warm_hits as f64 / n as f64
        }
    }
}

struct Inner<W: Warm> {
    warm: W,
    ready: Mutex<VecDeque<W::Slot>>,
    /// Signalled when a slot is taken, so the refiller tops the pool back up.
    wake: Condvar,
    target: usize,
    booting: AtomicUsize,
    stopping: AtomicBool,
    stats: Mutex<PoolStats>,
}

impl<W: Warm> Inner<W> {
    fn note(&self, warm: bool, took: Duration) {
        let mut s = self.stats.lock().unwrap_or_else(|e| e.into_inner());
        if warm {
            s.warm_hits += 1;
        } else {
            s.cold_boots += 1;
        }
        s.total_acquire += took;
        s.max_acquire = s.max_acquire.max(took);
    }
}

/// A pool of pre-booted slots.
pub struct Pool<W: Warm> {
    inner: Arc<Inner<W>>,
    refiller: Option<std::thread::JoinHandle<()>>,
}

impl<W: Warm> std::fmt::Debug for Pool<W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pool")
            .field("target", &self.inner.target)
            .field("ready", &self.ready_count())
            .field("stats", &self.stats())
            .finish()
    }
}

impl<W: Warm> Pool<W> {
    /// Start a pool and its refiller.
    ///
    /// Returns immediately; slots boot in the background. A caller that needs
    /// the pool hot before serving traffic waits with [`Pool::wait_ready`].
    pub fn new(warm: W, target: usize) -> Self {
        let inner = Arc::new(Inner {
            warm,
            ready: Mutex::new(VecDeque::with_capacity(target)),
            wake: Condvar::new(),
            target,
            booting: AtomicUsize::new(0),
            stopping: AtomicBool::new(false),
            stats: Mutex::new(PoolStats::default()),
        });

        let refiller = {
            let inner = Arc::clone(&inner);
            std::thread::Builder::new()
                .name("shellguard-pool-refill".into())
                .spawn(move || refill_loop(inner))
                .ok()
        };

        Pool { inner, refiller }
    }

    pub fn target(&self) -> usize {
        self.inner.target
    }

    pub fn ready_count(&self) -> usize {
        self.inner.ready.lock().map(|r| r.len()).unwrap_or(0)
    }

    pub fn stats(&self) -> PoolStats {
        *self.inner.stats.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Block until the pool holds `n` slots, or the deadline passes.
    pub fn wait_ready(&self, n: usize, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if self.ready_count() >= n {
                return true;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        self.ready_count() >= n
    }

    /// Take a slot, booting one inline if the pool is empty.
    ///
    /// Booting inline rather than waiting for the refiller is deliberate: a
    /// caller that arrives at an empty pool should pay the boot once, not queue
    /// behind a thread that may itself be mid-boot. The cost shows up as a cold
    /// boot in [`PoolStats`], which is exactly the signal that the pool is
    /// undersized.
    pub fn acquire(&self) -> Result<Lease<W>, RuntimeError> {
        let t0 = Instant::now();

        if let Some(slot) = self.inner.ready.lock().ok().and_then(|mut r| r.pop_front()) {
            let took = t0.elapsed();
            self.inner.note(true, took);
            self.inner.wake.notify_one();
            return Ok(Lease { inner: Arc::clone(&self.inner), slot: Some(slot), acquire: took });
        }

        let slot = self.inner.warm.boot()?;
        let took = t0.elapsed();
        self.inner.note(false, took);
        self.inner.wake.notify_one();
        Ok(Lease { inner: Arc::clone(&self.inner), slot: Some(slot), acquire: took })
    }

    /// Stop refilling and shut down every parked slot.
    pub fn shutdown(mut self) {
        self.stop();
    }

    fn stop(&mut self) {
        self.inner.stopping.store(true, Ordering::SeqCst);
        self.inner.wake.notify_all();
        if let Some(h) = self.refiller.take() {
            let _ = h.join();
        }
        if let Ok(mut ready) = self.inner.ready.lock() {
            while let Some(slot) = ready.pop_front() {
                self.inner.warm.shutdown(slot);
            }
        }
    }
}

impl<W: Warm> Drop for Pool<W> {
    fn drop(&mut self) {
        self.stop();
    }
}

fn refill_loop<W: Warm>(inner: Arc<Inner<W>>) {
    while !inner.stopping.load(Ordering::SeqCst) {
        let have =
            inner.ready.lock().map(|r| r.len()).unwrap_or(0) + inner.booting.load(Ordering::SeqCst);

        if have >= inner.target {
            // Nothing to do. Wait to be woken by an acquisition, with a timeout
            // so a missed notification cannot park the refiller forever.
            let Ok(guard) = inner.ready.lock() else { return };
            let _ = inner.wake.wait_timeout(guard, Duration::from_millis(100));
            continue;
        }

        inner.booting.fetch_add(1, Ordering::SeqCst);
        let booted = inner.warm.boot();
        inner.booting.fetch_sub(1, Ordering::SeqCst);

        match booted {
            Ok(slot) => {
                if inner.stopping.load(Ordering::SeqCst) {
                    inner.warm.shutdown(slot);
                    return;
                }
                if let Ok(mut ready) = inner.ready.lock() {
                    ready.push_back(slot);
                } else {
                    return;
                }
            }
            Err(_) => {
                // Booting failed. Back off rather than spinning on a broken
                // hypervisor: acquisitions still work by booting inline, and
                // they will surface the same error to a caller who can report
                // it, which a background thread cannot.
                std::thread::sleep(Duration::from_millis(250));
            }
        }
    }
}

/// A borrowed slot. Returns itself to the pool when dropped.
pub struct Lease<W: Warm> {
    inner: Arc<Inner<W>>,
    slot: Option<W::Slot>,
    acquire: Duration,
}

// Hand-written rather than derived: the slot type is opaque and a derive would
// force every backend's slot to be Debug for no benefit.
impl<W: Warm> std::fmt::Debug for Lease<W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Lease")
            .field("held", &self.slot.is_some())
            .field("acquire", &self.acquire)
            .finish()
    }
}

impl<W: Warm> Lease<W> {
    pub fn get(&self) -> &W::Slot {
        self.slot.as_ref().expect("slot is present until drop")
    }

    pub fn get_mut(&mut self) -> &mut W::Slot {
        self.slot.as_mut().expect("slot is present until drop")
    }

    /// How long acquiring took — the number the SLA is about.
    pub fn acquire_time(&self) -> Duration {
        self.acquire
    }

    /// Retire this slot instead of returning it, for a slot that ran something
    /// that may have dirtied it.
    pub fn discard(mut self) {
        if let Some(slot) = self.slot.take() {
            if let Ok(mut s) = self.inner.stats.lock() {
                s.retired += 1;
            }
            self.inner.warm.shutdown(slot);
        }
    }
}

impl<W: Warm> Drop for Lease<W> {
    fn drop(&mut self) {
        let Some(slot) = self.slot.take() else { return };

        if self.inner.stopping.load(Ordering::SeqCst) || !self.inner.warm.healthy(&slot) {
            if let Ok(mut s) = self.inner.stats.lock() {
                s.retired += 1;
            }
            self.inner.warm.shutdown(slot);
            return;
        }

        match self.inner.ready.lock() {
            Ok(mut ready) if ready.len() < self.inner.target => ready.push_back(slot),
            _ => {
                if let Ok(mut s) = self.inner.stats.lock() {
                    s.retired += 1;
                }
                self.inner.warm.shutdown(slot);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU32;

    /// A slot whose boot is deliberately slow, standing in for a VM.
    struct SlowBoot {
        boot_time: Duration,
        booted: Arc<AtomicU32>,
        shut: Arc<AtomicU32>,
        reusable: bool,
    }

    #[derive(Debug)]
    struct Slot {
        id: u32,
    }

    impl Warm for SlowBoot {
        type Slot = Slot;

        fn boot(&self) -> Result<Slot, RuntimeError> {
            std::thread::sleep(self.boot_time);
            let id = self.booted.fetch_add(1, Ordering::SeqCst);
            Ok(Slot { id })
        }

        fn healthy(&self, _slot: &Slot) -> bool {
            self.reusable
        }

        fn shutdown(&self, _slot: Slot) {
            self.shut.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn pool(
        boot_ms: u64,
        target: usize,
        reusable: bool,
    ) -> (Pool<SlowBoot>, Arc<AtomicU32>, Arc<AtomicU32>) {
        let booted = Arc::new(AtomicU32::new(0));
        let shut = Arc::new(AtomicU32::new(0));
        let w = SlowBoot {
            boot_time: Duration::from_millis(boot_ms),
            booted: Arc::clone(&booted),
            shut: Arc::clone(&shut),
            reusable,
        };
        (Pool::new(w, target), booted, shut)
    }

    #[test]
    fn a_warm_acquisition_is_orders_of_magnitude_faster_than_a_boot() {
        // The entire justification for the pool, as a test.
        let (p, _, _) = pool(120, 2, true);
        assert!(p.wait_ready(2, Duration::from_secs(10)), "pool never filled");

        let lease = p.acquire().unwrap();
        assert!(
            lease.acquire_time() < Duration::from_millis(5),
            "warm acquisition took {:?}, boot is 120ms",
            lease.acquire_time()
        );
        assert_eq!(p.stats().warm_hits, 1);
        assert_eq!(p.stats().cold_boots, 0);
    }

    #[test]
    fn warm_acquisition_meets_the_two_hundred_millisecond_target() {
        let (p, _, _) = pool(150, 3, true);
        assert!(p.wait_ready(3, Duration::from_secs(10)));

        for _ in 0..3 {
            let lease = p.acquire().unwrap();
            assert!(
                lease.acquire_time() < Duration::from_millis(200),
                "acquisition took {:?}",
                lease.acquire_time()
            );
            drop(lease);
        }
        assert!(p.stats().max_acquire < Duration::from_millis(200));
    }

    #[test]
    fn an_empty_pool_boots_inline_and_records_a_cold_boot() {
        // Target 0, so the refiller never parks anything.
        let (p, _, _) = pool(60, 0, true);
        let t = Instant::now();
        let lease = p.acquire().unwrap();
        assert!(t.elapsed() >= Duration::from_millis(50), "did not actually boot");
        assert_eq!(p.stats().cold_boots, 1);
        assert_eq!(p.stats().warm_hits, 0);
        assert!(p.stats().hit_rate() < 0.5);
        drop(lease);
    }

    #[test]
    fn the_pool_refills_after_an_acquisition() {
        let (p, _, _) = pool(40, 2, true);
        assert!(p.wait_ready(2, Duration::from_secs(10)));

        let lease = p.acquire().unwrap();
        // The lease is still out, so one slot is missing until it returns.
        std::mem::forget(lease);
        assert!(p.wait_ready(2, Duration::from_secs(10)), "pool did not refill");
    }

    #[test]
    fn a_returned_slot_goes_back_to_the_pool() {
        let (p, booted, _) = pool(30, 1, true);
        assert!(p.wait_ready(1, Duration::from_secs(10)));
        let before = booted.load(Ordering::SeqCst);

        let id = {
            let lease = p.acquire().unwrap();
            lease.get().id
        };
        assert!(p.wait_ready(1, Duration::from_secs(5)));

        let lease = p.acquire().unwrap();
        assert_eq!(lease.get().id, id, "the same slot should have been reused");
        assert_eq!(booted.load(Ordering::SeqCst), before, "it booted a new one instead");
    }

    #[test]
    fn an_unhealthy_slot_is_retired_rather_than_reused() {
        // The leak this prevents: a dirty slot serving the next command.
        let (p, _, shut) = pool(20, 1, false);
        assert!(p.wait_ready(1, Duration::from_secs(10)));

        let lease = p.acquire().unwrap();
        drop(lease);
        std::thread::sleep(Duration::from_millis(100));

        assert!(shut.load(Ordering::SeqCst) >= 1, "unhealthy slot was reused");
        assert!(p.stats().retired >= 1);
    }

    #[test]
    fn discarding_a_lease_retires_the_slot() {
        let (p, _, shut) = pool(20, 1, true);
        assert!(p.wait_ready(1, Duration::from_secs(10)));
        let before = shut.load(Ordering::SeqCst);
        p.acquire().unwrap().discard();
        assert_eq!(shut.load(Ordering::SeqCst), before + 1);
        assert_eq!(p.stats().retired, 1);
    }

    #[test]
    fn concurrent_acquisitions_all_get_a_slot() {
        let (p, _, _) = pool(30, 4, true);
        assert!(p.wait_ready(4, Duration::from_secs(10)));
        let p = Arc::new(p);

        let handles: Vec<_> = (0..8)
            .map(|_| {
                let p = Arc::clone(&p);
                std::thread::spawn(move || {
                    let lease = p.acquire().unwrap();
                    std::thread::sleep(Duration::from_millis(5));
                    lease.get().id
                })
            })
            .collect();

        let ids: Vec<u32> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert_eq!(ids.len(), 8);
        assert_eq!(p.stats().acquisitions(), 8);
    }

    #[test]
    fn shutdown_disposes_of_parked_slots() {
        let (p, _, shut) = pool(20, 3, true);
        assert!(p.wait_ready(3, Duration::from_secs(10)));
        p.shutdown();
        assert!(shut.load(Ordering::SeqCst) >= 3, "parked slots were leaked");
    }

    #[test]
    fn stats_report_hit_rate_honestly() {
        let (p, _, _) = pool(25, 1, true);
        assert!(p.wait_ready(1, Duration::from_secs(10)));

        // Hold two leases at once, so the second must boot cold.
        let a = p.acquire().unwrap();
        let b = p.acquire().unwrap();
        let s = p.stats();
        assert_eq!(s.acquisitions(), 2);
        assert_eq!(s.warm_hits, 1);
        assert_eq!(s.cold_boots, 1);
        assert!((s.hit_rate() - 0.5).abs() < 1e-9);
        assert!(s.mean_acquire() > Duration::ZERO);
        drop((a, b));
    }
}
