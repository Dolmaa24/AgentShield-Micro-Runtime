//! Where a command actually runs, and how to undo it.
//!
//! `shellguard-gate` decides. `shellguard-enforce` confines. This crate covers
//! the two things left over: putting the workspace back the way it was when
//! something goes wrong, and providing the isolated place a command runs in.
//!
//! The two are related. Isolation that is strong enough to be useful is
//! expensive to create, and rollback is what lets a *cheap* isolation level be
//! acceptable for most commands — if a mistake is undoable, it does not have to
//! be prevented.

pub mod audit;
pub mod engine;
pub mod json;
pub mod local;
pub mod pool;
pub mod redact;
pub mod rollback;
pub mod runtime;
mod sha256;
pub mod vm;

pub use engine::{Engine, GuardedRun};
pub use local::{run_profile, scratch_parent, LocalRuntime};
pub use pool::{Lease, Pool, PoolStats, Warm};
pub use rollback::{
    Checkpoint, ExecOutcome, GuardOutcome, HealthCheck, HealthReport, ProtectedDigest,
    RollbackError, RollbackPolicy, RollbackReport, StateManager, Untracked,
};
pub use runtime::{Availability, ExecResult, Isolation, Payload, Runtime, RuntimeError};
pub use sha256::{hash as sha256_hash, hash_file as sha256_file, hex as sha256_hex, Sha256};
pub use vm::{FirecrackerRuntime, GvisorRuntime, VzRuntime};
