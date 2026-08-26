//! UI Automation engine.
//!
//! COM apartment rules force the whole design here: `IUIAutomation` and every
//! element it hands back are single-threaded COM objects that are neither `Send`
//! nor `Sync`, so they can never cross an await point or move between tokio
//! worker threads. We therefore pin all of UIA to one dedicated OS thread that
//! initialises MTA once and lives for the process lifetime; async callers talk
//! to it over a channel and get their answers back through a oneshot.

use anyhow::{anyhow, Result};
use schemars::JsonSchema;
use serde::Serialize;
use std::sync::mpsc::{self, Sender};
use tokio::sync::oneshot;

#[cfg(windows)]
mod win;

/// A top-level window as seen by UI Automation.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct WindowInfo {
    pub name: String,
    pub class_name: String,
    pub control_type: String,
    pub hwnd: isize,
    pub pid: i32,
    pub bounds: Bounds,
}

#[derive(Debug, Clone, Copy, Serialize, JsonSchema)]
pub struct Bounds {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
}

/// One actionable element, with the signed handle needed to act on it.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct Entity {
    pub name: String,
    pub control_type: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub automation_id: String,
    /// Full rect is rarely what a caller needs and doubles the per-entity cost,
    /// so it rides along only in verbose mode. `click_at` is the useful part.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bounds: Option<Bounds>,
    /// Centre point, precomputed so callers never do coordinate maths.
    pub click_at: (i32, i32),
    pub actions: Vec<String>,
    /// Omitted when true - disabled is the exceptional, interesting case.
    #[serde(default, skip_serializing_if = "is_true")]
    pub enabled: bool,
    /// Child-index chain from the window root, relative to `Discovery::scope`.
    /// `act` takes the scope plus this to re-find the element.
    pub path: Vec<u32>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct Discovery {
    pub window: WindowInfo,
    /// Signed, expiring authorisation for this window at this generation.
    /// Pass it back to `act` together with an entity's `path`.
    pub scope: String,
    pub generation: u64,
    pub entities: Vec<Entity>,
    /// Set when a depth or count cap stopped the walk, so a caller is never
    /// silently handed a partial view.
    pub truncated: Option<String>,
    pub elapsed_ms: f64,
}

fn is_true(b: &bool) -> bool {
    *b
}

/// What a caller wants back. `Actionable` is the default because a model asking
/// "what can I do here" is served badly by a wall of layout containers.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Filter {
    /// Things you can actually click, type into, toggle, expand or select.
    Actionable,
    /// Everything the tree filter surfaced that exposes at least one control
    /// pattern, containers and unnamed elements included. Elements with no
    /// pattern at all are never returned: there is nothing to act on and no
    /// action list to hand back.
    All,
}

impl std::str::FromStr for Filter {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "actionable" => Ok(Filter::Actionable),
            "all" => Ok(Filter::All),
            other => Err(format!("unknown filter '{other}' (actionable|all)")),
        }
    }
}

pub struct DiscoverArgs {
    pub hwnd: Option<isize>,
    pub max_depth: u32,
    pub max_elements: usize,
    pub ttl_secs: u64,
    pub filter: Filter,
    pub verbose: bool,
}

/// What `act` did, and what it saw afterwards.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct ActResult {
    pub ok: bool,
    pub action: String,
    /// `ok` | `identity_changed` | `moved` | `disabled` | `pattern_gone` | `not_found`
    pub status: String,
    pub target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    pub elapsed_ms: f64,
}

pub struct ActArgs {
    pub scope: String,
    pub path: Vec<u32>,
    pub action: String,
    pub value: Option<String>,
}

/// Commands the COM thread understands. Each carries its own reply channel.
enum Cmd {
    ListWindows(oneshot::Sender<Result<Vec<WindowInfo>>>),
    Discover(DiscoverArgs, oneshot::Sender<Result<Discovery>>),
    Act(ActArgs, oneshot::Sender<Result<ActResult>>),
}

/// Handle to the UIA thread. Cloneable; the thread stops when all handles drop
/// and the channel closes.
#[derive(Clone)]
pub struct Engine {
    tx: Sender<Cmd>,
}

/// HMAC key for lease signing, loaded once and shared with the COM thread.
pub struct EngineConfig {
    pub lease_key: Vec<u8>,
}

impl Engine {
    /// Start the COM thread. Returns once the thread has successfully created
    /// its `IUIAutomation` instance, so a failure here is reported to the
    /// caller rather than surfacing later as a mysterious timeout.
    pub fn spawn(cfg: EngineConfig) -> Result<Self> {
        let (tx, rx) = mpsc::channel::<Cmd>();
        let (ready_tx, ready_rx) = mpsc::channel::<Result<()>>();

        std::thread::Builder::new()
            .name("kuroko-uia".into())
            .spawn(move || {
                #[cfg(windows)]
                win::run(rx, ready_tx, cfg);
                #[cfg(not(windows))]
                {
                    let _ = (rx, cfg);
                    let _ = ready_tx.send(Err(anyhow!("kuroko requires Windows")));
                }
            })?;

        ready_rx
            .recv()
            .map_err(|_| anyhow!("UIA thread died during startup"))??;

        Ok(Self { tx })
    }

    pub async fn discover(&self, args: DiscoverArgs) -> Result<Discovery> {
        let (rtx, rrx) = oneshot::channel();
        self.tx
            .send(Cmd::Discover(args, rtx))
            .map_err(|_| anyhow!("UIA thread is gone"))?;
        rrx.await
            .map_err(|_| anyhow!("UIA thread dropped the reply"))?
    }

    pub async fn act(&self, args: ActArgs) -> Result<ActResult> {
        let (rtx, rrx) = oneshot::channel();
        self.tx
            .send(Cmd::Act(args, rtx))
            .map_err(|_| anyhow!("UIA thread is gone"))?;
        rrx.await
            .map_err(|_| anyhow!("UIA thread dropped the reply"))?
    }

    pub async fn list_windows(&self) -> Result<Vec<WindowInfo>> {
        let (rtx, rrx) = oneshot::channel();
        self.tx
            .send(Cmd::ListWindows(rtx))
            .map_err(|_| anyhow!("UIA thread is gone"))?;
        rrx.await
            .map_err(|_| anyhow!("UIA thread dropped the reply"))?
    }
}

// Engine is Clone, so it deliberately has no Drop impl. Sending Cmd::Shutdown
// from one would be a per-clone action with a process-wide effect: the HTTP
// transport builds a Kuroko (and so an Engine clone) per session, and the first
// session to end would take down the COM thread every other session shares.
// The thread already stops on its own - `rx.recv()` returns Err once the last
// Sender is dropped, which is exactly the "no owners left" condition wanted.
