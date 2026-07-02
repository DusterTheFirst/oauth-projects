use std::{
    num::NonZeroUsize,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::extract::State;
use tokio::{
    sync::Notify,
    time::{Instant, timeout_at},
};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy)]
enum ServerState {
    /// Zero active connections. Holds the exact time the last connection closed.
    Idle { since: Instant },
    /// At least one active connection. The timestamp ceases to exist.
    Active { connections: NonZeroUsize },
}

pub struct ActivityTracker {
    // We must wrap the entire enum in a Mutex to mutate it safely across threads.
    state: Mutex<ServerState>,
    notify: Notify,

    cancellation: CancellationToken,
    idle_timeout: Duration,
}

impl ActivityTracker {
    pub fn new(idle_timeout: Duration) -> Self {
        Self {
            state: Mutex::new(ServerState::Idle {
                since: Instant::now(),
            }),
            notify: Notify::new(),

            cancellation: CancellationToken::new(),
            idle_timeout,
        }
    }

    pub fn increment(&self) {
        let mut state = self.lock_state();

        *state = match *state {
            // If idle, transition to Active with exactly 1 connection
            ServerState::Idle { .. } => ServerState::Active {
                connections: NonZeroUsize::new(1).unwrap(),
            },
            // If already active, increment the non-zero counter safely
            ServerState::Active { connections } => ServerState::Active {
                connections: connections
                    .checked_add(1)
                    .expect("active connections should fit within a usize"),
            },
        };
    }

    pub fn decrement(&self) {
        let mut state = self.lock_state();

        *state = match *state {
            ServerState::Idle { .. } => {
                unreachable!("Axum middleware tried to decrement an idle server!");
            }
            ServerState::Active { connections } => {
                if connections.get() == 1 {
                    // The last connection just closed. Transition back to Idle.
                    ServerState::Idle {
                        since: Instant::now(),
                    }
                } else {
                    ServerState::Active {
                        connections: NonZeroUsize::new(connections.get() - 1).unwrap(),
                    }
                }
            }
        };

        // If we just became Idle, wake up the watchdog.
        if let ServerState::Idle { .. } = *state {
            drop(state); // Unlock first!
            self.notify.notify_one();
        }
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, ServerState> {
        self.state.lock().expect("mutex should not be poisoned")
    }

    pub fn cancellation_token(&self) -> CancellationToken {
        self.cancellation.child_token()
    }
}

pub async fn watchdog(tracker: Arc<ActivityTracker>) {
    loop {
        // 1. Determine our deadline based on the current state.
        let deadline = {
            let state = tracker.lock_state();
            match *state {
                ServerState::Idle { since } => Some(since + tracker.idle_timeout),
                ServerState::Active { .. } => None,
            }
        };

        if let Some(deadline) = deadline {
            if timeout_at(deadline, tracker.notify.notified())
                .await
                .is_err()
            {
                // The timeout fired,
                // Let's verify we are STILL idle (to prevent edge-case races).
                let state = tracker.lock_state();
                if let ServerState::Idle { .. } = *state {
                    tracker.cancellation.cancel();
                    break;
                }
            }
        } else {
            tracker.notify.notified().await;
        }
    }
}

pub async fn idle_tracking_middleware(
    State(tracker): State<Arc<ActivityTracker>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    tracker.increment();

    let response = next.run(req).await;

    tracker.decrement();

    response
}
