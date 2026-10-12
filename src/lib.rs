mod client;
mod collector;
mod platform;
mod protocol;
mod spool;
mod transport;
mod watchdog;

pub use client::{
    BusyGuard, Config, Frame, Scope, busy_registered, clear_pending_frame,
    clear_pending_input, event, frame_budget, init, input_received, redraw_requested,
    register_activity, report_panic, scope_registered, set_frame_budget, set_state, shutdown,
};
pub use collector::{
    CollectorConfig, run as run_collector, tailnet_or_loopback, validate_bind,
};
pub use protocol::{Field, Value};
pub use watchdog::run_from_args as run_watchdog_from_args;
