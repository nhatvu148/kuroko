//! Emergency stop.
//!
//! An elevated automation server reachable over the network needs a halt that
//! does not depend on the network, the model, or the MCP client being
//! responsive. Parking the physical mouse in the top-left corner is that halt:
//! it needs no keyboard focus, no window, and no cooperation from whatever is
//! currently running.
//!
//! The latch matters as much as the trip. If the stop released the instant the
//! cursor moved, nudging the mouse away would immediately re-arm the agent -
//! so it stays engaged for a cooldown after the corner is vacated, which is
//! long enough to actually take control back.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

/// How close to (0,0) counts as "parked".
const CORNER_PX: i32 = 10;
/// How long it must stay parked before the stop engages.
const HOLD: Duration = Duration::from_millis(500);
/// How long the stop stays engaged after the corner is vacated.
const COOLDOWN: Duration = Duration::from_secs(30);

static ENGAGED: AtomicBool = AtomicBool::new(false);
/// Millis-since-start when the cooldown expires. Compared against a monotonic
/// counter the watcher owns, so no wall-clock dependency.
static RELEASE_AT: AtomicU64 = AtomicU64::new(0);

pub fn engaged() -> bool {
    ENGAGED.load(Ordering::Relaxed)
}

/// The message tools return when the stop is engaged. Deliberately explicit
/// about how to release it - a halted agent should not have to guess.
pub fn refusal() -> String {
    "EMERGENCY STOP engaged: the mouse is parked in the top-left corner. \
     All input is refused. Move the cursor away and wait 30s to resume."
        .to_string()
}

#[cfg(windows)]
pub fn spawn_watcher() {
    use windows::Win32::Foundation::POINT;
    use windows::Win32::UI::WindowsAndMessaging::GetCursorPos;

    std::thread::Builder::new()
        .name("kuroko-estop".into())
        .spawn(|| {
            let tick = Duration::from_millis(100);
            let mut elapsed_ms: u64 = 0;
            let mut parked_ms: u64 = 0;
            loop {
                std::thread::sleep(tick);
                elapsed_ms += tick.as_millis() as u64;

                let mut pt = POINT::default();
                let in_corner = unsafe { GetCursorPos(&mut pt) }.is_ok()
                    && pt.x.abs() <= CORNER_PX
                    && pt.y.abs() <= CORNER_PX;

                if in_corner {
                    parked_ms += tick.as_millis() as u64;
                    if parked_ms >= HOLD.as_millis() as u64 {
                        if !ENGAGED.swap(true, Ordering::Relaxed) {
                            tracing::warn!("EMERGENCY STOP engaged (cursor parked at origin)");
                        }
                        RELEASE_AT.store(elapsed_ms + COOLDOWN.as_millis() as u64, Ordering::Relaxed);
                    }
                } else {
                    parked_ms = 0;
                    if ENGAGED.load(Ordering::Relaxed)
                        && elapsed_ms >= RELEASE_AT.load(Ordering::Relaxed)
                    {
                        ENGAGED.store(false, Ordering::Relaxed);
                        tracing::warn!("emergency stop released");
                    }
                }
            }
        })
        .expect("spawn estop watcher");
}

#[cfg(not(windows))]
pub fn spawn_watcher() {}

/// Apps `launch` is permitted to start. Absent file means nothing is allowed -
/// failing closed is the only sane default for a tool that spawns processes
/// from a High-integrity, network-reachable server.
pub fn load_allowlist() -> Vec<String> {
    let path = std::env::var("LOCALAPPDATA")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir())
        .join("kuroko")
        .join("launch-allowlist.txt");
    std::fs::read_to_string(path)
        .map(|s| {
            s.lines()
                .map(|l| l.trim().to_lowercase())
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .collect()
        })
        .unwrap_or_default()
}
