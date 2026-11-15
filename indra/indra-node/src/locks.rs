//! Fail-closed wrappers for node-owned synchronization primitives.

use std::sync::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::{supervisor, NodeError, NodeResult};

#[cfg(test)]
static REPORT_COUNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn poisoned(name: &'static str) -> NodeError {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;
    use std::sync::{Arc, Mutex, RwLock};
    use std::thread;

    #[test]
    fn poisoned_mutex_and_rwlock_report_once_each() {
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
        assert_eq!(REPORT_COUNT.load(Ordering::SeqCst), 1);

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
        assert_eq!(REPORT_COUNT.load(Ordering::SeqCst), 2);
    }
}
