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

        let norm = |v: i32, origin: i32, span: i32| -> i32 {
            (((v - origin) as f64) * 65535.0 / ((span - 1).max(1) as f64)).round() as i32
        };
        let (nx, ny) = (norm(x, vx, vw), norm(y, vy, vh));

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
