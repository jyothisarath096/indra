//! Fail-closed wrappers for node-owned synchronization primitives.

use std::sync::{Condvar, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard, WaitTimeoutResult};

use crate::{supervisor, NodeError, NodeResult};

#[cfg(test)]
static REPORT_COUNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static TEST_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub(crate) fn poisoned(name: &'static str) -> NodeError {
    #[cfg(test)]
    REPORT_COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    supervisor::report_unexpected("poisoned-lock", format!("lock {name} is poisoned"));
    NodeError::LockPoisoned { name }
}

/// Lock a mutex, reporting poison before returning a fatal node error.
pub fn lock<'a, T>(mutex: &'a Mutex<T>, name: &'static str) -> NodeResult<MutexGuard<'a, T>> {
    mutex.lock().map_err(|_| poisoned(name))
}

/// Read-lock an RwLock, reporting poison before returning a fatal node error.
pub fn read<'a, T>(rwlock: &'a RwLock<T>, name: &'static str) -> NodeResult<RwLockReadGuard<'a, T>> {
    rwlock.read().map_err(|_| poisoned(name))
}

/// Write-lock an RwLock, reporting poison before returning a fatal node error.
pub fn write<'a, T>(rwlock: &'a RwLock<T>, name: &'static str) -> NodeResult<RwLockWriteGuard<'a, T>> {
    rwlock.write().map_err(|_| poisoned(name))
}

/// Wait on a condition variable while preserving the same poison policy.
pub fn wait_timeout<'a, T>(
    condvar: &Condvar,
    guard: MutexGuard<'a, T>,
    timeout: std::time::Duration,
    name: &'static str,
) -> NodeResult<(MutexGuard<'a, T>, WaitTimeoutResult)> {
    condvar.wait_timeout(guard, timeout).map_err(|_| poisoned(name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;
    use std::sync::{Arc, Mutex, RwLock};
    use std::thread;

    #[test]
    fn poisoned_mutex_and_rwlock_report_once_each() {
        let _serial = TEST_SERIAL.lock().unwrap();
        REPORT_COUNT.store(0, Ordering::SeqCst);
        let mutex = Arc::new(Mutex::new(()));
        let poisoned_mutex = Arc::clone(&mutex);
        thread::spawn(move || {
            let _guard = poisoned_mutex.lock().unwrap();
            panic!("poison mutex");
        })
        .join()
        .unwrap_err();

        let error = lock(&mutex, "test-mutex").unwrap_err();
        assert!(matches!(error, NodeError::LockPoisoned { name: "test-mutex" }));
        assert!(REPORT_COUNT.load(Ordering::SeqCst) >= 1);

        let rwlock = Arc::new(RwLock::new(()));
        let poisoned_rwlock = Arc::clone(&rwlock);
        thread::spawn(move || {
            let _guard = poisoned_rwlock.write().unwrap();
            panic!("poison rwlock");
        })
        .join()
        .unwrap_err();

        let error = write(&rwlock, "test-rwlock").unwrap_err();
        assert!(matches!(error, NodeError::LockPoisoned { name: "test-rwlock" }));
        assert!(REPORT_COUNT.load(Ordering::SeqCst) >= 2);
    }

    #[test]
    fn poisoned_lock_in_spawned_task_reports_once_and_returns_error() {
        let _serial = TEST_SERIAL.lock().unwrap();
        REPORT_COUNT.store(0, Ordering::SeqCst);
        let mutex = Arc::new(Mutex::new(()));
        let poison = Arc::clone(&mutex);
        thread::spawn(move || {
            let _guard = poison.lock().unwrap();
            panic!("poison spawned mutex");
        })
        .join()
        .unwrap_err();

        let task = thread::spawn(move || {
            matches!(lock(&mutex, "spawned-task-mutex"), Err(NodeError::LockPoisoned { name: "spawned-task-mutex" }))
        });
        assert!(task.join().unwrap());
        assert!(REPORT_COUNT.load(Ordering::SeqCst) >= 1);
    }

    #[test]
    fn simultaneous_poisoned_locks_report_without_deadlock() {
        let _serial = TEST_SERIAL.lock().unwrap();
        REPORT_COUNT.store(0, Ordering::SeqCst);
        let first = Arc::new(Mutex::new(()));
        let second = Arc::new(Mutex::new(()));
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let workers = [Arc::clone(&first), Arc::clone(&second)]
            .into_iter()
            .map(|mutex| {
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    let _guard = mutex.lock().unwrap();
                    panic!("simultaneous poison");
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        for worker in workers {
            worker.join().unwrap_err();
        }
        assert!(matches!(lock(&first, "simultaneous-first"), Err(NodeError::LockPoisoned { .. })));
        assert!(matches!(lock(&second, "simultaneous-second"), Err(NodeError::LockPoisoned { .. })));
        assert!(REPORT_COUNT.load(Ordering::SeqCst) >= 2);
    }

    #[test]
    fn production_lock_inventory_has_no_direct_lock_calls() {
        let sources = [
            ("bin/node.rs", include_str!("bin/node.rs")),
            ("bin/observer.rs", include_str!("bin/observer.rs")),
            ("metrics.rs", include_str!("metrics.rs")),
            ("hardened_read_rpc.rs", include_str!("hardened_read_rpc.rs")),
            ("qc_verification.rs", include_str!("qc_verification.rs")),
            ("rpc_snapshot.rs", include_str!("rpc_snapshot.rs")),
        ];
        let forbidden = [
            ".lock().ok(", ".lock().map(", ".lock().unwrap_or", ".read().ok(",
            ".write().ok(",
        ];
        for (name, source) in sources {
            let production = source
                .rsplit_once("#[cfg(test)]")
                .map_or(source, |(production, _)| production);
            for needle in forbidden {
                assert!(!production.contains(needle), "{name} contains {needle}");
            }
            for needle in [".lock()", ".read()", ".write()"] {
                assert!(!production.contains(needle), "{name} contains direct {needle}");
            }
        }
    }
}
