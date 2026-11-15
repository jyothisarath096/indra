//! Supervision primitives for node-owned critical tasks.

use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};
use std::sync::OnceLock;

static GLOBAL_REPORTER: OnceLock<Sender<CriticalTaskOutcome>> = OnceLock::new();

/// Outcome reported when a critical task stops.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CriticalTaskOutcome {
    /// The process is intentionally shutting down.
    Shutdown,
    /// A task stopped unexpectedly.
    TaskExited {
        /// Stable task name.
        name: String,
        /// Return or panic reason.
        reason: String,
    },
}

/// Decide whether a task stop is expected or fatal.
pub fn critical_task_decision(
    shutdown_requested: bool,
    name: &str,
    reason: impl Into<String>,
) -> CriticalTaskOutcome {
    if shutdown_requested {
        CriticalTaskOutcome::Shutdown
    } else {
        CriticalTaskOutcome::TaskExited {
            name: name.to_string(),
            reason: reason.into(),
        }
    }
}

/// Owns the handles and stop notifications for critical node tasks.
pub struct CriticalTasks {
    tx: Sender<CriticalTaskOutcome>,
    rx: Receiver<CriticalTaskOutcome>,
    handles: Vec<(String, JoinHandle<()>)>,
}

impl CriticalTasks {
    /// Create an empty supervisor.
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel();
        if GLOBAL_REPORTER.set(tx.clone()).is_err() {
            eprintln!("[supervisor] global reporter already installed");
        }
        Self { tx, rx, handles: Vec::new() }
    }

    /// Spawn a task whose unexpected return or panic is reported by name.
    pub fn spawn<F>(&mut self, name: impl Into<String>, task: F)
    where
        F: FnOnce() + Send + 'static,
    {
        let name = name.into();
        let task_name = name.clone();
        let tx = self.tx.clone();
        let handle = match thread::Builder::new()
            .name(name.clone())
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(task));
                let reason = match result {
                    Ok(()) => "returned".to_string(),
                    Err(payload) => panic_reason(payload),
                };
                if let Err(error) = tx.send(critical_task_decision(false, &task_name, reason)) {
                    eprintln!("[supervisor] failed to report task exit: {error}");
                }
            })
        {
            Ok(handle) => handle,
            Err(error) => {
                if let Err(report_error) = self.tx.send(critical_task_decision(
                    false,
                    &name,
                    format!("thread start failed: {error}"),
                )) {
                    eprintln!("[supervisor] failed to report thread-start failure: {report_error}");
                }
                return;
            }
        };
        self.handles.push((name, handle));
    }

    /// Receive an unexpected task stop, if one has occurred.
    pub fn try_recv(&self) -> Result<CriticalTaskOutcome, mpsc::TryRecvError> {
        self.rx.try_recv()
    }
}

impl Default for CriticalTasks {
    fn default() -> Self {
        Self::new()
    }
}

/// Report a fatal event from a component that cannot own the main loop.
pub fn report_unexpected(name: &str, reason: impl Into<String>) {
    if let Some(reporter) = GLOBAL_REPORTER.get() {
        if let Err(error) = reporter.send(critical_task_decision(false, name, reason)) {
            eprintln!("[supervisor] failed to report fatal event: {error}");
        }
    }
}

fn panic_reason(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_string()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "panic with non-string payload".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decision_reports_task_panic() {
        assert_eq!(
            critical_task_decision(false, "consensus", "panic"),
            CriticalTaskOutcome::TaskExited { name: "consensus".into(), reason: "panic".into() }
        );
    }

    #[test]
    fn decision_reports_task_error() {
        assert_eq!(
            critical_task_decision(false, "p2p", "channel closed"),
            CriticalTaskOutcome::TaskExited { name: "p2p".into(), reason: "channel closed".into() }
        );
    }

    #[test]
    fn clean_shutdown_is_not_fatal() {
        assert_eq!(
            critical_task_decision(true, "consensus", "returned"),
            CriticalTaskOutcome::Shutdown
        );
    }
}
