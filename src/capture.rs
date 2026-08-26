//! Screen capture.
//!
//! GDI `BitBlt` rather than DXGI duplication or Windows.Graphics.Capture: it is
//! a few dozen lines, has no device-lost handling, no WinRT dependency, and
//! works identically across sessions and remote desktops. Capture is not the
//! bottleneck here - a UIA tree walk costs an order of magnitude more - so the
//! simpler API wins until measurement says otherwise.

use anyhow::{anyhow, Result};
use image::ImageEncoder;
use schemars::JsonSchema;
use serde::Serialize;
use std::sync::Mutex;

#[cfg(windows)]
use windows::Win32::Graphics::Gdi::{
    BitBlt, CreateCompatibleBitmap, CreateCompatibleDC, DeleteDC, DeleteObject, GetDC, GetDIBits,
    ReleaseDC, SelectObject, BITMAPINFO, BITMAPINFOHEADER, BI_RGB, DIB_RGB_COLORS, SRCCOPY,
};
#[cfg(windows)]
use windows::Win32::UI::WindowsAndMessaging::{
    GetSystemMetrics, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN,
};

pub struct Frame {
    pub w: u32,
    pub h: u32,
    /// Screen coordinate of this frame's top-left. NOT always (0,0): a monitor
    /// placed left of or above the primary gives the virtual screen a negative
    /// origin, and a region reported without it points at the wrong place.
    pub origin: (i32, i32),
    /// Row-major RGB, top-down.
    pub rgb: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct Observation {
    pub width: u32,
    pub height: u32,
    /// Scale applied before encoding; 1.0 means native.
    pub scale: f64,
    pub png_bytes: usize,
    /// Roughly what the image will cost in context: (w*h)/750.
    pub approx_tokens: u32,
    /// diff mode only: fraction of pixels that changed since the last capture.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed_fraction: Option<f64>,
    /// diff mode only: the changed region in SCREEN coordinates (x and y may be
    /// negative on a multi-monitor desktop), so it can be compared directly
    /// against an entity's `bounds` or `click_at`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed_region: Option<(i32, i32, u32, u32)>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub elapsed_ms: f64,
}

/// Previous frame, kept so `diff` can answer "nothing moved" without sending an
/// image at all - by far the cheapest useful answer during a wait loop.
static LAST: Mutex<Option<Frame>> = Mutex::new(None);

#[cfg(windows)]
pub fn grab() -> Result<Frame> {
    unsafe {
        let (x, y, w, h) = (
            GetSystemMetrics(SM_XVIRTUALSCREEN),
            GetSystemMetrics(SM_YVIRTUALSCREEN),
            GetSystemMetrics(SM_CXVIRTUALSCREEN),
            GetSystemMetrics(SM_CYVIRTUALSCREEN),
        );
        if w <= 0 || h <= 0 {
            return Err(anyhow!(
                "virtual screen is {w}x{h} - almost certainly running in session 0, which has no desktop"
            ));
        }

        let screen = GetDC(None);
        if screen.is_invalid() {
            return Err(anyhow!("GetDC failed"));
        }
        let mem = CreateCompatibleDC(Some(screen));
        let bmp = CreateCompatibleBitmap(screen, w, h);
        let old = SelectObject(mem, bmp.into());

        let blit = BitBlt(mem, 0, 0, w, h, Some(screen), x, y, SRCCOPY);

        // Negative height requests a top-down DIB, saving a row flip later.
        let mut bi = BITMAPINFO {
            bmiHeader: BITMAPINFOHEADER {
                biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: w,
                biHeight: -h,
                biPlanes: 1,
                biBitCount: 32,
                biCompression: BI_RGB.0,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut bgra = vec![0u8; (w as usize) * (h as usize) * 4];
        let rows = GetDIBits(
            mem,
            bmp,
            0,
            h as u32,
            Some(bgra.as_mut_ptr() as *mut _),
            &mut bi,
            DIB_RGB_COLORS,
        );

        SelectObject(mem, old);
        let _ = DeleteObject(bmp.into());
        let _ = DeleteDC(mem);
        ReleaseDC(None, screen);

        blit?;
        if rows == 0 {
            return Err(anyhow!("GetDIBits returned no scanlines"));
        }

        // Indexed rather than chunks_exact(4): newer clippy denies a constant
        // chunk size, and the suggested replacements are not stable across the
        // toolchain range this has to build on.
        let mut rgb = Vec::with_capacity((w as usize) * (h as usize) * 3);
        for i in (0..bgra.len()).step_by(4) {
            rgb.extend_from_slice(&[bgra[i + 2], bgra[i + 1], bgra[i]]);
        }
        Ok(Frame {
            w: w as u32,
            h: h as u32,
            origin: (x, y),
            rgb,
        })
    }
}

#[cfg(not(windows))]
pub fn grab() -> Result<Frame> {
    Err(anyhow!("capture requires Windows"))
}

/// Bounding box of everything that changed, plus what fraction of the frame it
/// covers. One box, not a region list: a caller wants "look here", and merging
/// scattered boxes into their hull is both cheaper and easier to act on.
fn changed_box(a: &Frame, b: &Frame, tol: u8) -> Option<(u32, u32, u32, u32, f64, u64)> {
    if a.w != b.w || a.h != b.h {
        return Some((0, 0, b.w, b.h, 1.0, (b.w as u64) * (b.h as u64)));
    }
    let (mut x0, mut y0, mut x1, mut y1) = (u32::MAX, u32::MAX, 0u32, 0u32);
    let mut changed = 0u64;
    for y in 0..b.h {
        let row = (y as usize) * (b.w as usize) * 3;
        for x in 0..b.w {
            let i = row + (x as usize) * 3;
            let d = (a.rgb[i] as i16 - b.rgb[i] as i16).unsigned_abs()
                + (a.rgb[i + 1] as i16 - b.rgb[i + 1] as i16).unsigned_abs()
                + (a.rgb[i + 2] as i16 - b.rgb[i + 2] as i16).unsigned_abs();
            if d > tol as u16 {
                changed += 1;
                x0 = x0.min(x);
                y0 = y0.min(y);
                x1 = x1.max(x);
                y1 = y1.max(y);
            }
        }
    }
    if changed == 0 {
        return None;
    }
    let frac = changed as f64 / ((b.w as f64) * (b.h as f64));
    Some((x0, y0, x1 - x0 + 1, y1 - y0 + 1, frac, changed))
}

fn crop(f: &Frame, x: u32, y: u32, w: u32, h: u32) -> Frame {
    let mut out = Vec::with_capacity((w as usize) * (h as usize) * 3);
    for row in y..(y + h).min(f.h) {
        let s = (row as usize) * (f.w as usize) * 3 + (x as usize) * 3;
        let e = s + (w.min(f.w - x) as usize) * 3;
        out.extend_from_slice(&f.rgb[s..e]);
    }
    Frame {
        w,
        h,
        origin: (f.origin.0 + x as i32, f.origin.1 + y as i32),
        rgb: out,
    }
}

fn encode_png(f: &Frame, max_width: u32) -> Result<(Vec<u8>, u32, u32, f64)> {
    let img = image::RgbImage::from_raw(f.w, f.h, f.rgb.clone())
        .ok_or_else(|| anyhow!("frame buffer size does not match {}x{}", f.w, f.h))?;
    let (img, scale) = if max_width > 0 && f.w > max_width {
        let s = max_width as f64 / f.w as f64;
        let nh = ((f.h as f64) * s).round().max(1.0) as u32;
        (
            image::imageops::resize(&img, max_width, nh, image::imageops::FilterType::Triangle),
            s,
        )
    } else {
        (img, 1.0)
    };
    let (w, h) = (img.width(), img.height());
    let mut png = Vec::new();
    image::codecs::png::PngEncoder::new(&mut png).write_image(
        img.as_raw(),
        w,
        h,
        image::ExtendedColorType::Rgb8,
    )?;
    Ok((png, w, h, scale))
}

/// `image` mode: whole screen. `diff` mode: only what moved, or nothing at all.
pub fn observe_bytes(diff: bool, max_width: u32) -> Result<(Observation, Vec<u8>)> {
    let t0 = std::time::Instant::now();
    let frame = grab()?;

    let (target, changed_fraction, changed_region, note) =
        if diff {
            let mut last = LAST.lock().map_err(|_| anyhow!("frame lock poisoned"))?;
            match last.as_ref().and_then(|p| changed_box(p, &frame, 12)) {
                None if last.is_some() => {
                    *last = Some(Frame {
                        w: frame.w,
                        h: frame.h,
                        origin: frame.origin,
                        rgb: frame.rgb.clone(),
                    });
                    return Ok((
                        Observation {
                            width: 0,
                            height: 0,
                            scale: 1.0,
                            png_bytes: 0,
                            approx_tokens: 0,
                            changed_fraction: Some(0.0),
                            changed_region: None,
                            note: Some("no change since last observation".into()),
                            elapsed_ms: t0.elapsed().as_secs_f64() * 1000.0,
                        },
                        Vec::new(),
                    ));
                }
                Some((x, y, w, h, frac, changed_px)) => {
                    *last = Some(Frame {
                        w: frame.w,
                        h: frame.h,
                        origin: frame.origin,
                        rgb: frame.rgb.clone(),
                    });
                    // A single hull around scattered changes is mostly unchanged
                    // pixels - a caret in one corner and a clock in the other yields
                    // a near-fullscreen box for a handful of moved pixels. When the
                    // box is that unrepresentative, the coordinates ARE the answer;
                    // sending 259KB to show 200 changed pixels helps nobody.
                    let hull = (w as u64) * (h as u64);
                    if frac < 0.005 && hull > changed_px.saturating_mul(25) {
                        return Ok((
                            Observation {
                                width: 0,
                                height: 0,
                                scale: 1.0,
                                png_bytes: 0,
                                approx_tokens: 0,
                                changed_fraction: Some(frac),
                                changed_region: Some((
                                    frame.origin.0 + x as i32,
                                    frame.origin.1 + y as i32,
                                    w,
                                    h,
                                )),
                                note: Some(format!(
                            "{changed_px} scattered pixels changed ({:.3}%) - image withheld, \
                             the region hull is {}x larger than the change itself",
                            frac * 100.0, hull / changed_px.max(1))),
                                elapsed_ms: t0.elapsed().as_secs_f64() * 1000.0,
                            },
                            Vec::new(),
                        ));
                    }
                    (
                        crop(&frame, x, y, w, h),
                        Some(frac),
                        Some((frame.origin.0 + x as i32, frame.origin.1 + y as i32, w, h)),
                        None,
                    )
                }
                None => {
                    *last = Some(Frame {
                        w: frame.w,
                        h: frame.h,
                        origin: frame.origin,
                        rgb: frame.rgb.clone(),
                    });
                    (
                        frame,
                        None,
                        None,
                        Some("first observation - full frame".into()),
                    )
                }
            }
        } else {
            (frame, None, None, None)
        };

    let (png, w, h, scale) = encode_png(&target, max_width)?;
    let obs = Observation {
        width: w,
        height: h,
        scale,
        png_bytes: png.len(),
        approx_tokens: (w * h) / 750,
        changed_fraction,
        changed_region,
        note,
        elapsed_ms: t0.elapsed().as_secs_f64() * 1000.0,
    };
    Ok((obs, png))
}

/// CLI convenience wrapper: same thing, but writes the PNG to disk.
pub fn observe(diff: bool, max_width: u32, out_path: Option<&str>) -> Result<Observation> {
    let (obs, png) = observe_bytes(diff, max_width)?;
    if let (Some(p), false) = (out_path, png.is_empty()) {
        std::fs::write(p, &png)?;
    }
    Ok(obs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(w: u32, h: u32, fill: u8) -> Frame {
        frame_at(w, h, fill, (0, 0))
    }

    fn frame_at(w: u32, h: u32, fill: u8, origin: (i32, i32)) -> Frame {
        Frame {
            w,
            h,
            origin,
            rgb: vec![fill; (w as usize) * (h as usize) * 3],
        }
    }

    fn set(f: &mut Frame, x: u32, y: u32, v: u8) {
        let i = ((y as usize) * (f.w as usize) + x as usize) * 3;
        f.rgb[i] = v;
        f.rgb[i + 1] = v;
        f.rgb[i + 2] = v;
    }

    /// The cheapest and most common answer during a wait loop.
    #[test]
    fn identical_frames_report_no_change() {
        assert!(changed_box(&frame(8, 8, 10), &frame(8, 8, 10), 12).is_none());
    }

    #[test]
    fn sub_tolerance_change_is_not_a_change() {
        let a = frame(8, 8, 10);
        let mut b = frame(8, 8, 10);
        set(&mut b, 3, 3, 13); // 3 per channel = 9 total, under tol 12
        assert!(changed_box(&a, &b, 12).is_none());
    }

    #[test]
    fn one_changed_pixel_yields_a_tight_box() {
        let a = frame(8, 8, 0);
        let mut b = frame(8, 8, 0);
        set(&mut b, 5, 2, 255);
        let (x, y, w, h, _, n) = changed_box(&a, &b, 12).unwrap();
        assert_eq!((x, y, w, h), (5, 2, 1, 1));
        assert_eq!(n, 1);
    }

    /// The case that motivates withholding the image: a handful of scattered
    /// pixels produce a hull covering nearly the whole frame.
    #[test]
    fn scattered_changes_produce_a_hull_far_larger_than_the_change() {
        let a = frame(100, 100, 0);
        let mut b = frame(100, 100, 0);
        set(&mut b, 1, 1, 255);
        set(&mut b, 98, 98, 255);
        let (x, y, w, h, frac, n) = changed_box(&a, &b, 12).unwrap();
        assert_eq!((x, y, w, h), (1, 1, 98, 98));
        assert_eq!(n, 2);
        assert!(frac < 0.001, "frac was {frac}");
        let hull = (w as u64) * (h as u64);
        assert!(
            hull > n * 25,
            "hull {hull} should dwarf {n} changed pixels - this is the withhold trigger"
        );
    }

    #[test]
    fn a_resize_counts_as_a_full_change() {
        let (x, y, w, h, frac, _) = changed_box(&frame(8, 8, 0), &frame(16, 16, 0), 12).unwrap();
        assert_eq!((x, y, w, h), (0, 0, 16, 16));
        assert_eq!(frac, 1.0);
    }

    #[test]
    fn crop_extracts_the_requested_region() {
        let mut f = frame(10, 10, 0);
        set(&mut f, 4, 4, 200);
        let c = crop(&f, 4, 4, 2, 2);
        assert_eq!((c.w, c.h), (2, 2));
        assert_eq!(c.rgb[0], 200);
        assert_eq!(c.rgb.len(), 2 * 2 * 3);
    }

    /// A monitor left of the primary gives a negative virtual-screen origin;
    /// a crop taken from it must still describe where it came from on screen.
    #[test]
    fn crop_carries_the_screen_origin() {
        let f = frame_at(100, 100, 0, (-1920, -200));
        let c = crop(&f, 10, 20, 5, 5);
        assert_eq!(c.origin, (-1910, -180));
    }

    #[test]
    fn crop_clamps_at_the_frame_edge() {
        let f = frame(10, 10, 0);
        let c = crop(&f, 8, 8, 4, 4);
        assert!(c.rgb.len() <= 4 * 4 * 3);
    }
}
