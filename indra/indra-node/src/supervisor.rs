//! Supervision primitives for node-owned critical tasks.

use std::fmt::Display;
use std::io::Write;
#[cfg(any(test, feature = "test-support"))]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::OnceLock;
use std::thread::{self, JoinHandle};

use futures_util::FutureExt;

use crate::NodeResult;

static GLOBAL_REPORTER: OnceLock<Sender<CriticalTaskOutcome>> = OnceLock::new();
#[cfg(any(test, feature = "test-support"))]
static REPORT_COUNT: AtomicUsize = AtomicUsize::new(0);

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
        Self {
            tx,
            rx,
            handles: Vec::new(),
        }
    }

    /// Spawn a task whose unexpected return or panic is reported by name.
    pub fn spawn<F>(&mut self, name: impl Into<String>, task: F)
    where
        F: FnOnce() + Send + 'static,
    {
        let name = name.into();
        let task_name = name.clone();
        let tx = self.tx.clone();
        let handle = match thread::Builder::new().name(name.clone()).spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(task));
            let reason = match result {
                Ok(()) => "returned".to_string(),
                Err(payload) => panic_reason(payload),
            };
            if let Err(error) = tx.send(critical_task_decision(false, &task_name, reason)) {
                eprintln!("[supervisor] failed to report task exit: {error}");
            }
        }) {
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

    /// Adopt an already-spawned critical task and report its termination.
    pub fn adopt(&mut self, name: impl Into<String>, handle: JoinHandle<()>) {
        let name = name.into();
        let task_name = name.clone();
        let tx = self.tx.clone();
        let watcher_name = format!("{name}-watcher");
        let watcher = thread::Builder::new()
            .name(watcher_name.clone())
            .spawn(move || {
                let reason = match handle.join() {
                    Ok(()) => "returned".to_string(),
                    Err(payload) => panic_reason(payload),
                };
                if let Err(error) = tx.send(critical_task_decision(false, &task_name, reason)) {
                    eprintln!("[supervisor] failed to report adopted task exit: {error}");
                }
            });
        match watcher {
            Ok(watcher) => self.handles.push((watcher_name, watcher)),
            Err(error) => {
                let _ = self.tx.send(critical_task_decision(
                    false,
                    &name,
                    format!("watcher start failed: {error}"),
                ));
            }
        }
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
    #[cfg(any(test, feature = "test-support"))]
    REPORT_COUNT.fetch_add(1, Ordering::SeqCst);
    if let Some(reporter) = GLOBAL_REPORTER.get() {
        if let Err(error) = reporter.send(critical_task_decision(false, name, reason)) {
            eprintln!("[supervisor] failed to report fatal event: {error}");
        }
    }
}

/// Reset the fatal-report counter used by focused node tests.
#[cfg(any(test, feature = "test-support"))]
pub fn reset_report_count() {
    REPORT_COUNT.store(0, Ordering::SeqCst);
}

/// Return the number of fatal reports emitted by this process.
#[cfg(any(test, feature = "test-support"))]
pub fn report_count() -> usize {
    REPORT_COUNT.load(Ordering::SeqCst)
}

/// Terminate the process after routing a fatal runtime error through the supervisor.
pub fn terminate_fatal(name: &str, error: impl Display) -> ! {
    let reason = error.to_string();
    report_unexpected(name, reason.clone());
    eprintln!("ERROR: {reason}");
    let _ = std::io::stderr().flush();
    std::process::exit(1)
}

/// Spawn a Tokio task whose termination is always reported to the node
/// supervisor. These tasks are expected to live for the process lifetime.
pub fn spawn_critical<F>(name: &'static str, task: F) -> tokio::task::JoinHandle<()>
where
    F: std::future::Future<Output = NodeResult<()>> + Send + 'static,
{
    let reporter = GLOBAL_REPORTER.get().cloned();
    tokio::spawn(async move {
        let joined = tokio::spawn(task).await;
        let reason = match joined {
            Ok(Ok(())) => "returned".to_string(),
            Ok(Err(error)) => error.to_string(),
            Err(error) if error.is_cancelled() => "cancelled".to_string(),
            Err(error) => format!("panic: {error}"),
        };
        if let Some(reporter) = reporter {
            if let Err(error) = reporter.send(critical_task_decision(false, name, reason)) {
                eprintln!("[supervisor] failed to report critical task exit: {error}");
            }
        } else {
            eprintln!("[supervisor] CRITICAL: task {name} exited unexpectedly: {reason}");
        }
    })
}

#[cfg(test)]
fn spawn_critical_with_reporter<F>(
    name: &'static str,
    task: F,
    reporter: Sender<CriticalTaskOutcome>,
) -> tokio::task::JoinHandle<()>
where
    F: std::future::Future<Output = NodeResult<()>> + Send + 'static,
{
    tokio::spawn(async move {
        let joined = tokio::spawn(task).await;
        let reason = match joined {
            Ok(Ok(())) => "returned".to_string(),
            Ok(Err(error)) => error.to_string(),
            Err(error) if error.is_cancelled() => "cancelled".to_string(),
            Err(error) => format!("panic: {error}"),
        };
        reporter
            .send(critical_task_decision(false, name, reason))
            .unwrap();
    })
}

/// Spawn a per-connection task and isolate its panic from the node runtime.
pub fn spawn_connection<F>(
    component: &'static str,
    metrics: std::sync::Arc<crate::metrics::MetricsState>,
    task: F,
) -> tokio::task::JoinHandle<()>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        if let Err(payload) = std::panic::AssertUnwindSafe(task).catch_unwind().await {
            eprintln!("[{component}] handler panicked: {}", panic_reason(payload));
            if let Err(error) = metrics.record_handler_panic(component) {
                eprintln!("[{component}] failed to record handler panic: {error}");
            }
        }
    })
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
            CriticalTaskOutcome::TaskExited {
                name: "consensus".into(),
                reason: "panic".into()
            }
        );
    }

    #[test]
    fn decision_reports_task_error() {
        assert_eq!(
            critical_task_decision(false, "p2p", "channel closed"),
            CriticalTaskOutcome::TaskExited {
                name: "p2p".into(),
                reason: "channel closed".into()
            }
        );
    }

    #[test]
    fn clean_shutdown_is_not_fatal() {
        assert_eq!(
            critical_task_decision(true, "consensus", "returned"),
            CriticalTaskOutcome::Shutdown
        );
    }

    #[test]
    fn adopted_task_exit_is_reported() {
        let mut tasks = CriticalTasks::new();
        let handle = thread::spawn(|| {});
        tasks.adopt("writer", handle);
        let outcome = loop {
            match tasks.try_recv() {
                Ok(outcome) => break outcome,
                Err(mpsc::TryRecvError::Empty) => thread::yield_now(),
                Err(mpsc::TryRecvError::Disconnected) => panic!("supervisor disconnected"),
            }
        };
        assert_eq!(
            outcome,
            CriticalTaskOutcome::TaskExited {
                name: "writer".into(),
                reason: "returned".into()
            }
        );
    }

    #[tokio::test]
    async fn critical_task_return_is_reported_once() {
        let (tx, rx) = mpsc::channel();
        let handle = spawn_critical_with_reporter("returning", async { Ok(()) }, tx);
        handle.await.unwrap();
        assert_eq!(rx.try_iter().count(), 1);
    }

    #[tokio::test]
    async fn critical_task_panic_is_reported_once() {
        let (tx, rx) = mpsc::channel();
        let handle = spawn_critical_with_reporter(
            "panicking",
            async {
                panic!("test panic");
            },
            tx,
        );
        handle.await.unwrap();
        assert_eq!(rx.try_iter().count(), 1);
    }

    #[tokio::test]
    async fn connection_task_panic_is_counted_without_stopping_runtime() {
        let metrics = std::sync::Arc::new(crate::metrics::MetricsState::new());
        let handle = spawn_connection("test-connection", std::sync::Arc::clone(&metrics), async {
            panic!("test connection panic");
        });
        handle.await.unwrap();
        assert_eq!(
            metrics
                .handler_panics_total
                .lock()
                .unwrap()
                .get("test-connection"),
            Some(&1)
        );
    }

    #[test]
    fn terminate_fatal_subprocess_exits_one_and_reports_once() {
        const CHILD: &str = "INDRA_SUPERVISOR_TERMINATE_FATAL_CHILD";
        if std::env::var_os(CHILD).is_some() {
            terminate_fatal("test-fatal", "supervisor test cause");
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "supervisor::tests::terminate_fatal_subprocess_exits_one_and_reports_once",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            stderr.matches("ERROR: supervisor test cause").count(),
            1,
            "{stderr}"
        );
        assert!(!stderr.contains("panicked at"), "{stderr}");
    }
}
