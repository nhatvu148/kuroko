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

/// Apps `launch` is permitted to start.
///
/// Two failure-closed properties matter here. An absent file permits nothing,
/// and a file we cannot protect permits nothing either: this process holds an
/// admin token, so an allowlist a Medium-integrity process could append to is a
/// direct privilege-escalation path, not a config inconvenience.
pub fn load_allowlist() -> Vec<String> {
    let path = allowlist_path();
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if !path.exists() {
        return Vec::new();
    }
    if let Err(e) = protect_high_integrity(&path) {
        tracing::error!(
            "refusing to load the launch allowlist: cannot apply a High mandatory label to {} ({e}). \
             `launch` will permit nothing.",
            path.display()
        );
        return Vec::new();
    }
    std::fs::read_to_string(&path)
        .map(|s| {
            s.lines()
                .map(|l| l.trim().to_lowercase())
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .collect()
        })
        .unwrap_or_default()
}

fn allowlist_path() -> std::path::PathBuf {
    std::env::var("LOCALAPPDATA")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir())
        .join("kuroko")
        .join("launch-allowlist.txt")
}

/// Stamp a "no write up" mandatory label at High integrity on the file, so a
/// process below High cannot modify it even though it runs as the same user.
/// Default ACLs do not do this - integrity level and user identity are separate
/// axes, and only the mandatory label constrains the former.
#[cfg(windows)]
fn protect_high_integrity(path: &std::path::Path) -> anyhow::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::{BOOL, PCWSTR};
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW,
        SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows::Win32::Security::{
        GetSecurityDescriptorSacl, ACL, LABEL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    };

    unsafe {
        // ML = mandatory label, NW = no write up, HI = high integrity.
        let sddl: Vec<u16> = "S:(ML;;NW;;;HI)\0".encode_utf16().collect();
        let mut psd = PSECURITY_DESCRIPTOR::default();
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            SDDL_REVISION_1,
            &mut psd,
            None,
        )?;

        let mut sacl: *mut ACL = std::ptr::null_mut();
        let (mut present, mut defaulted) = (BOOL(0), BOOL(0));
        GetSecurityDescriptorSacl(psd, &mut present, &mut sacl, &mut defaulted)?;

        let mut wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let rc = SetNamedSecurityInfoW(
            PCWSTR(wide.as_mut_ptr()),
            SE_FILE_OBJECT,
            LABEL_SECURITY_INFORMATION,
            None,
            None,
            None,
            Some(sacl),
        );
        if rc.is_err() {
            anyhow::bail!("SetNamedSecurityInfoW failed: {rc:?}");
        }
    }
    Ok(())
}

#[cfg(not(windows))]
fn protect_high_integrity(_p: &std::path::Path) -> anyhow::Result<()> {
    anyhow::bail!("mandatory labels are Windows-only")
}
