//! Text on screen, for applications that expose no UI tree.
//!
//! `discover` returns nothing useful for an app that draws its own interface -
//! Abaqus/CAE reports six elements, all window chrome. This is the fallback for
//! that class: read the pixels, return the words, and hand back coordinates a
//! caller can act on.
//!
//! The engine is the operating system's. `Windows.Media.Ocr` is present on every
//! supported Windows, returns per-word bounding boxes, and adds nothing to the
//! binary. Bundling Tesseract or an ONNX model would undo the single-binary
//! property that is half the point of this crate.

use anyhow::{anyhow, Result};
use schemars::JsonSchema;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct TextMatch {
    pub text: String,
    /// Screen coordinates, directly usable as a click target.
    pub click_at: (i32, i32),
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
    /// "word" when a single token matched, "line" when the query spans words.
    pub granularity: String,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct TextResult {
    /// The recognizer language actually used. OCR quality depends on which
    /// language packs are installed, so a caller should be able to see it.
    pub language: String,
    pub matches: Vec<TextMatch>,
    /// Total lines recognised, so an empty match set can be told apart from
    /// an empty screen.
    pub lines_seen: usize,
    /// Magnification applied before recognition.
    pub scale: f32,
    pub elapsed_ms: f64,
}

/// Glyphs that OCR cannot reliably tell apart in UI fonts, folded to one
/// representative each.
///
/// This is a *matching* fix, not a recognition one. `1` and `I` are genuinely
/// near-identical in most UI typefaces, so no amount of better recognition
/// makes `Steps (1)` come back as anything other than `Steps (I)` some of the
/// time. Folding both sides of the comparison means a caller can ask for what
/// is actually on screen and still get a hit.
fn fold_confusables(s: &str) -> String {
    s.chars()
        .map(|c| match c.to_ascii_lowercase() {
            'i' | 'l' | '1' | '|' => '1',
            'o' | '0' => '0',
            's' | '5' => '5',
            'b' | '8' => '8',
            'z' | '2' => '2',
            'g' | '9' => '9',
            other => other,
        })
        .collect()
}

/// Case-insensitive substring, tolerant of the glyph confusions above.
fn matches_text(haystack: &str, needle: &str) -> bool {
    haystack.to_lowercase().contains(needle)
        || fold_confusables(haystack).contains(&fold_confusables(needle))
}

pub struct FindArgs<'a> {
    pub query: Option<&'a str>,
    pub max_matches: usize,
    /// Restrict OCR to one window's rectangle. Fewer pixels means the upscale
    /// budget buys more magnification, and it stops a query matching text
    /// elsewhere on the desktop.
    pub hwnd: Option<isize>,
    /// Multiply the image before recognition. Windows.Media.Ocr is tuned for
    /// document-scale text, not 9px UI chrome; magnifying first is the single
    /// biggest lever on small-text accuracy. 0 selects automatically.
    pub scale: f32,
    /// OCR this PNG instead of the screen. Makes accuracy measurable against a
    /// fixed image rather than a live desktop that changes between runs.
    pub image: Option<&'a std::path::Path>,
}

#[cfg(windows)]
pub fn find_text(args: FindArgs<'_>) -> Result<TextResult> {
    use windows::Graphics::Imaging::BitmapDecoder;
    use windows::Media::Ocr::OcrEngine;
    use windows::Storage::Streams::{DataWriter, InMemoryRandomAccessStream};

    let t0 = std::time::Instant::now();

    // Native resolution, deliberately. Downscaling first would shrink every
    // coordinate the OCR reports, and the whole value here is coordinates.
    let mut frame = match args.image {
        Some(p) => crate::capture::frame_from_png(p)?,
        None => crate::capture::grab()?,
    };

    // Region of interest, when a window was named.
    if let Some(h) = args.hwnd {
        if args.image.is_some() {
            return Err(anyhow!("--hwnd and --image are mutually exclusive"));
        }
        let b = crate::uia::window_bounds(h)?;
        let (fx, fy) = frame.origin;
        let x = (b.x - fx).max(0) as u32;
        let y = (b.y - fy).max(0) as u32;
        let w = (b.w as u32).min(frame.w.saturating_sub(x));
        let h2 = (b.h as u32).min(frame.h.saturating_sub(y));
        if w == 0 || h2 == 0 {
            return Err(anyhow!("window {h} has no on-screen area (minimised?)"));
        }
        frame = crate::capture::crop_frame(&frame, x, y, w, h2);
    }

    // 1.5x by default, measured rather than guessed. On an Abaqus screen:
    //
    //   scale  ms     menu bar  model tree
    //   1.0    217    6/9       14/15
    //   1.5    494    6/9       15/15
    //   2.0    710    6/9       15/15
    //   3.0    1409   6/9       15/15
    //
    // 1.5 recovers the last tree label ("BCs") and everything above it costs
    // more for nothing - 3x is 6.5x the time at identical accuracy.
    //
    // Note what magnification does NOT fix: the menu bar sits at 6/9 no matter
    // how large the image gets. Upscaling helps when the recognizer's minimum
    // feature size is the binding constraint; it cannot recover detail the
    // source raster never captured.
    let max_dim = OcrEngine::MaxImageDimension().unwrap_or(4096) as f32;
    let scale = if args.scale > 0.0 {
        args.scale
    } else {
        let longest = frame.w.max(frame.h) as f32;
        (max_dim / longest).clamp(1.0, 1.5)
    };
    // The scale that was actually applied, which is not always the one asked
    // for - a fractional request resizes nothing, and rounding to whole pixels
    // shifts the ratio slightly either way.
    let (png, scale) = crate::capture::encode_png_scaled(&frame, scale)?;

    // .join() blocks; this whole function runs inside spawn_blocking, so there is
    // no runtime to starve. IAsyncOperation also implements IntoFuture if this
    // ever needs to move onto the async side.
    let bitmap = {
        let stream = InMemoryRandomAccessStream::new()?;
        let writer = DataWriter::CreateDataWriter(&stream.GetOutputStreamAt(0)?)?;
        writer.WriteBytes(&png)?;
        writer.StoreAsync()?.join()?;
        writer.FlushAsync()?.join()?;
        writer.DetachStream()?;
        stream.Seek(0)?;

        let decoder = BitmapDecoder::CreateAsync(&stream)?.join()?;
        decoder.GetSoftwareBitmapAsync()?.join()?
    };

    let engine = OcrEngine::TryCreateFromUserProfileLanguages()
        .map_err(|e| anyhow!("no OCR engine for this profile's languages: {e}"))?;
    let language = engine
        .RecognizerLanguage()
        .and_then(|l| l.DisplayName())
        .map(|s| s.to_string())
        .unwrap_or_else(|_| "unknown".into());

    let result = engine.RecognizeAsync(&bitmap)?.join()?;
    let lines = result.Lines()?;
    let lines_seen = lines.Size()? as usize;

    let needle = args
        .query
        .map(|q| q.trim().to_lowercase())
        .unwrap_or_default();
    let multiword = needle.split_whitespace().count() > 1;
    let (ox, oy) = frame.origin;
    // OCR ran on a magnified image, so every box it reports is in that space.
    let unscale = |v: f64| (v / scale as f64) as i32;
    let mut matches = Vec::new();

    for line in lines {
        if matches.len() >= args.max_matches {
            break;
        }
        let line_text = line.Text()?.to_string();

        // A multi-word query is matched against the line, because word boxes
        // cannot express a phrase. A single token is matched per word, which
        // gives a far tighter click target than the whole line.
        if needle.is_empty() || (multiword && matches_text(&line_text, &needle)) {
            let words = line.Words()?;
            // Checked before the subtraction, not inside the tuple below: both
            // operands of a tuple literal are evaluated before any pattern can
            // short-circuit, so `Size() - 1` on an empty line would underflow
            // (panic in debug, wrap in release) regardless of the match arms.
            let n = words.Size()?;
            if n == 0 {
                continue;
            }
            if let (Ok(first), Ok(last)) = (words.GetAt(0), words.GetAt(n - 1)) {
                let (a, b) = (first.BoundingRect()?, last.BoundingRect()?);
                let x = unscale(a.X as f64);
                let y = unscale(a.Y.min(b.Y) as f64);
                let w = unscale((b.X + b.Width - a.X) as f64);
                let h = unscale(a.Height.max(b.Height) as f64);
                matches.push(TextMatch {
                    text: line_text,
                    click_at: (ox + x + w / 2, oy + y + h / 2),
                    x: ox + x,
                    y: oy + y,
                    w,
                    h,
                    granularity: "line".into(),
                });
            }
            continue;
        }

        if multiword {
            continue;
        }
        for word in line.Words()? {
            if matches.len() >= args.max_matches {
                break;
            }
            let wt = word.Text()?.to_string();
            if matches_text(&wt, &needle) {
                let r = word.BoundingRect()?;
                let (x, y, w, h) = (
                    unscale(r.X as f64),
                    unscale(r.Y as f64),
                    unscale(r.Width as f64),
                    unscale(r.Height as f64),
                );
                matches.push(TextMatch {
                    text: wt,
                    click_at: (ox + x + w / 2, oy + y + h / 2),
                    x: ox + x,
                    y: oy + y,
                    w,
                    h,
                    granularity: "word".into(),
                });
            }
        }
    }

    Ok(TextResult {
        language,
        matches,
        lines_seen,
        scale,
        elapsed_ms: t0.elapsed().as_secs_f64() * 1000.0,
    })
}

#[cfg(not(windows))]
pub fn find_text(_a: FindArgs<'_>) -> Result<TextResult> {
    anyhow::bail!("OCR requires Windows")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folds_glyphs_ocr_cannot_separate() {
        assert_eq!(fold_confusables("Steps (1)"), fold_confusables("Steps (I)"));
        assert_eq!(fold_confusables("Model-1"), fold_confusables("Model-l"));
        assert_eq!(fold_confusables("B0"), fold_confusables("80"));
    }

    #[test]
    fn matches_through_a_digit_letter_confusion() {
        assert!(matches_text("Steps (I)", "steps (1)"));
        assert!(matches_text("Model-I", "model-1"));
        assert!(matches_text("Job-l", "job-1"));
    }

    #[test]
    fn exact_matching_still_works() {
        assert!(matches_text("Materials", "materials"));
        assert!(matches_text("Assembly", "assem"));
    }

    /// Folding must not collapse genuinely different words into each other.
    #[test]
    fn does_not_match_unrelated_text() {
        assert!(!matches_text("Materials", "assembly"));
        assert!(!matches_text("Parts", "loads"));
    }
}
