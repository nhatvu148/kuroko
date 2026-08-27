//! Synthetic mouse input.
//!
//! Everything else in this crate acts through UI Automation control patterns:
//! `Invoke()` reaches a control without stealing focus, moving the cursor, or
//! requiring the window to be on top. This module is the exception, and it
//! exists only because OCR returns a rectangle rather than a control - there is
//! no pattern to invoke on a word read off the screen.
//!
//! It is therefore strictly worse than the pattern path and should only run
//! when that path has already failed:
//!
//!   - it moves the user's real cursor
//!   - it clicks whatever is topmost at that point, which may not be the thing
//!     the OCR read if a window moved in between
//!   - it needs the target visible and unobscured
//!
//! Callers opt in explicitly. Nothing here is reachable by default.

use anyhow::{anyhow, Result};

/// Map a screen coordinate into `SendInput`'s normalised 0..65535 space.
///
/// Deliberately a free function rather than a closure inside the unsafe block:
/// it is the only arithmetic here that can be wrong in a way nothing catches,
/// and it is the single place multi-monitor geometry is handled anywhere in
/// this crate. `origin` is negative when a monitor sits left of or above the
/// primary, which is exactly the case no hardware here can exercise - so it is
/// tested instead.
pub(crate) fn to_normalized(v: i32, origin: i32, span: i32) -> i32 {
    (((v - origin) as f64) * 65535.0 / ((span - 1).max(1) as f64)).round() as i32
}

/// Click once at a screen coordinate.
///
/// `SendInput` with `MOUSEEVENTF_ABSOLUTE` addresses the *virtual desktop* in a
/// normalised 0..65535 space, not pixels - so the conversion has to divide by
/// the virtual screen's size and offset by its origin, which is negative when a
/// monitor sits left of or above the primary.
#[cfg(windows)]
pub fn click_at(x: i32, y: i32) -> Result<()> {
    use windows::Win32::UI::Input::KeyboardAndMouse::{
        SendInput, INPUT, INPUT_0, INPUT_MOUSE, MOUSEEVENTF_ABSOLUTE, MOUSEEVENTF_LEFTDOWN,
        MOUSEEVENTF_LEFTUP, MOUSEEVENTF_MOVE, MOUSEEVENTF_VIRTUALDESK, MOUSEINPUT,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        GetSystemMetrics, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN,
        SM_YVIRTUALSCREEN,
    };

    unsafe {
        let (vx, vy, vw, vh) = (
            GetSystemMetrics(SM_XVIRTUALSCREEN),
            GetSystemMetrics(SM_YVIRTUALSCREEN),
            GetSystemMetrics(SM_CXVIRTUALSCREEN),
            GetSystemMetrics(SM_CYVIRTUALSCREEN),
        );
        if vw <= 0 || vh <= 0 {
            return Err(anyhow!(
                "virtual screen is {vw}x{vh} - no desktop to click on (session 0?)"
            ));
        }
        if x < vx || y < vy || x >= vx + vw || y >= vy + vh {
            return Err(anyhow!(
                "({x},{y}) is outside the virtual desktop ({vx},{vy} {vw}x{vh})"
            ));
        }

        let (nx, ny) = (to_normalized(x, vx, vw), to_normalized(y, vy, vh));

        let mk = |flags| INPUT {
            r#type: INPUT_MOUSE,
            Anonymous: INPUT_0 {
                mi: MOUSEINPUT {
                    dx: nx,
                    dy: ny,
                    mouseData: 0,
                    dwFlags: flags,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        };
        // Move, press, release as one batch: sending them separately lets other
        // input interleave between the move and the press, which is how a click
        // lands somewhere the caller never asked for.
        let events = [
            mk(MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK),
            mk(MOUSEEVENTF_LEFTDOWN | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK),
            mk(MOUSEEVENTF_LEFTUP | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK),
        ];
        let sent = SendInput(&events, std::mem::size_of::<INPUT>() as i32);
        if sent as usize != events.len() {
            return Err(anyhow!(
                "SendInput accepted {sent} of {} events - blocked by UIPI?",
                events.len()
            ));
        }
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn click_at(_x: i32, _y: i32) -> Result<()> {
    Err(anyhow!("synthetic input requires Windows"))
}

/// Sends a sequence of chords as synthetic keyboard input.
///
/// Keyboard input goes to whatever has focus - there is no per-element
/// keyboard equivalent of `InvokePattern`. So the caller must focus the
/// resolved element first, and `act` says so in its result rather than
/// pretending the keystroke was delivered to a control by contract the way a
/// pattern call is.
///
/// Modifiers are released in reverse order: releasing Ctrl before the key it
/// modifies can deliver a different keystroke to the application.
#[cfg(windows)]
pub fn send_keys(chords: &[crate::keys::Chord]) -> Result<()> {
    use windows::Win32::UI::Input::KeyboardAndMouse::{
        SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT, KEYBD_EVENT_FLAGS, KEYEVENTF_KEYUP,
        VIRTUAL_KEY,
    };

    let mut events: Vec<INPUT> = Vec::with_capacity(chords.len() * 6);
    let mk = |vk: u16, up: bool| INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: VIRTUAL_KEY(vk),
                wScan: 0,
                dwFlags: if up {
                    KEYEVENTF_KEYUP
                } else {
                    KEYBD_EVENT_FLAGS(0)
                },
                time: 0,
                dwExtraInfo: 0,
            },
        },
    };
    for c in chords {
        let mods = c.modifiers();
        for m in &mods {
            events.push(mk(*m, false));
        }
        events.push(mk(c.key, false));
        events.push(mk(c.key, true));
        for m in mods.iter().rev() {
            events.push(mk(*m, true));
        }
    }
    // One batch, so nothing can interleave between a modifier press and the
    // key it modifies.
    let sent = unsafe { SendInput(&events, std::mem::size_of::<INPUT>() as i32) };
    if sent as usize != events.len() {
        anyhow::bail!(
            "SendInput accepted {sent} of {} keyboard events",
            events.len()
        );
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn send_keys(_c: &[crate::keys::Chord]) -> Result<()> {
    anyhow::bail!("synthetic keyboard input requires Windows")
}

#[cfg(test)]
mod tests {
    use super::to_normalized;

    #[test]
    fn maps_the_span_to_the_full_range() {
        assert_eq!(to_normalized(0, 0, 1920), 0);
        assert_eq!(to_normalized(1919, 0, 1920), 65535);
    }

    /// The case no display here can produce: a monitor left of the primary puts
    /// the virtual-screen origin at a negative x, and a point on it is negative
    /// too. Both must still land inside 0..65535.
    #[test]
    fn handles_a_negative_virtual_origin() {
        // Two 1920-wide monitors, secondary on the left: origin -1920, span 3840.
        assert_eq!(to_normalized(-1920, -1920, 3840), 0);
        assert_eq!(to_normalized(1919, -1920, 3840), 65535);
        // The primary's left edge sits halfway across the virtual desktop.
        let mid = to_normalized(0, -1920, 3840);
        assert!((32750..=32790).contains(&mid), "midpoint was {mid}");
    }

    #[test]
    fn handles_a_negative_origin_on_the_y_axis() {
        // A monitor above the primary.
        assert_eq!(to_normalized(-1080, -1080, 2160), 0);
        assert_eq!(to_normalized(1079, -1080, 2160), 65535);
    }

    /// A degenerate span must not divide by zero.
    #[test]
    fn survives_a_one_pixel_span() {
        assert_eq!(to_normalized(0, 0, 1), 0);
        assert_eq!(to_normalized(0, 0, 0), 0);
    }

    #[test]
    fn is_monotonic_across_the_span() {
        let mut last = i32::MIN;
        for x in (-1920..1920).step_by(97) {
            let n = to_normalized(x, -1920, 3840);
            assert!(n > last, "not monotonic at {x}");
            last = n;
        }
    }
}
