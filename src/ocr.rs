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
    pub elapsed_ms: f64,
}

#[cfg(windows)]
pub fn find_text(query: Option<&str>, max_matches: usize) -> Result<TextResult> {
    use windows::Graphics::Imaging::BitmapDecoder;
    use windows::Media::Ocr::OcrEngine;
    use windows::Storage::Streams::{DataWriter, InMemoryRandomAccessStream};

    let t0 = std::time::Instant::now();

    // Native resolution, deliberately. Downscaling first would shrink every
    // coordinate the OCR reports, and the whole value here is coordinates.
    let frame = crate::capture::grab()?;
    let png = crate::capture::encode_png_native(&frame)?;

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

    let needle = query.map(|q| q.trim().to_lowercase()).unwrap_or_default();
    let multiword = needle.split_whitespace().count() > 1;
    let (ox, oy) = frame.origin;
    let mut matches = Vec::new();

    for line in lines {
        if matches.len() >= max_matches {
            break;
        }
        let line_text = line.Text()?.to_string();

        // A multi-word query is matched against the line, because word boxes
        // cannot express a phrase. A single token is matched per word, which
        // gives a far tighter click target than the whole line.
        if needle.is_empty() || (multiword && line_text.to_lowercase().contains(&needle)) {
            let words = line.Words()?;
            if let (Ok(first), Ok(last)) = (words.GetAt(0), words.GetAt(words.Size()? - 1)) {
                let (a, b) = (first.BoundingRect()?, last.BoundingRect()?);
                let x = a.X as i32;
                let y = a.Y.min(b.Y) as i32;
                let w = (b.X + b.Width - a.X) as i32;
                let h = a.Height.max(b.Height) as i32;
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
            if matches.len() >= max_matches {
                break;
            }
            let wt = word.Text()?.to_string();
            if wt.to_lowercase().contains(&needle) {
                let r = word.BoundingRect()?;
                let (x, y, w, h) = (r.X as i32, r.Y as i32, r.Width as i32, r.Height as i32);
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
        elapsed_ms: t0.elapsed().as_secs_f64() * 1000.0,
    })
}

#[cfg(not(windows))]
pub fn find_text(_q: Option<&str>, _m: usize) -> Result<TextResult> {
    anyhow::bail!("OCR requires Windows")
}
