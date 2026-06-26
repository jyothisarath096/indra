//! Simple wall-clock timer for benchmarks.

use std::time::{Duration, Instant};

/// Run a closure N times and report timing statistics.
pub struct BenchResult {
    /// Name of the benchmark.
    pub name: String,
    /// Number of iterations.
    pub iterations: u64,
    /// Total elapsed time.
    pub total: Duration,
}

impl BenchResult {
    /// Average time per iteration.
    pub fn per_op(&self) -> Duration {
        self.total / self.iterations as u32
    }

    /// Operations per second.
    pub fn ops_per_sec(&self) -> f64 {
        self.iterations as f64 / self.total.as_secs_f64()
    }

    /// Print a one-line summary.
    pub fn print(&self) {
        println!(
            "[{}] {} iters in {:.1}ms → {:.3}ms/op ({:.0} ops/sec)",
            self.name,
            self.iterations,
            self.total.as_secs_f64() * 1000.0,
            self.per_op().as_secs_f64() * 1000.0,
            self.ops_per_sec(),
        );
    }

    /// Assert that the average operation time is below a threshold.
    /// Prints a warning if exceeded but does not fail the test
    /// (hardware varies too much to hard-fail on timing).
    pub fn assert_faster_than(&self, threshold: Duration) {
        let per_op = self.per_op();
        if per_op > threshold {
            println!(
                "  ⚠ SLOW: {:.3}ms/op exceeds target {:.3}ms/op",
                per_op.as_secs_f64() * 1000.0,
                threshold.as_secs_f64() * 1000.0,
            );
        } else {
            println!(
                "  ✓ FAST: {:.3}ms/op within target {:.3}ms/op",
                per_op.as_secs_f64() * 1000.0,
                threshold.as_secs_f64() * 1000.0,
            );
        }
    }
}

/// Run a benchmark: execute `f` `iterations` times and return results.
pub fn bench<F: FnMut()>(name: &str, iterations: u64, mut f: F) -> BenchResult {
    // Warmup: 10% of iterations, minimum 3
    let warmup = (iterations / 10).max(3);
    for _ in 0..warmup {
        f();
    }

    let start = Instant::now();
    for _ in 0..iterations {
        f();
    }
    let total = start.elapsed();

    BenchResult {
        name: name.to_string(),
        iterations,
        total,
    }
}
