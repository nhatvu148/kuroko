//! Windows-only half of the UIA engine. Everything in here runs on the single
//! `wincrust-uia` thread, so the COM pointers never escape their apartment.

use super::{
    ActArgs, ActResult, Bounds, Cmd, DiscoverArgs, Discovery, EngineConfig, Entity, Filter,
    Selector, WindowInfo,
};
use crate::lease::{now, Scope};
use crate::text::MatchTier;
use anyhow::{anyhow, Result};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::mpsc::{Receiver, Sender};
use windows::core::BSTR;
use windows::Win32::Foundation::HWND;
use windows::Win32::Foundation::RECT;
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED,
};
use windows::Win32::UI::Accessibility::{
    CUIAutomation, IUIAutomation, IUIAutomationElement, IUIAutomationExpandCollapsePattern,
    IUIAutomationInvokePattern, IUIAutomationSelectionItemPattern, IUIAutomationTogglePattern,
    IUIAutomationValuePattern, TreeScope, TreeScope_Children, TreeScope_Element, TreeScope_Subtree,
    UIA_AutomationIdPropertyId, UIA_BoundingRectanglePropertyId, UIA_ButtonControlTypeId,
    UIA_CheckBoxControlTypeId, UIA_ClassNamePropertyId, UIA_ComboBoxControlTypeId,
    UIA_ControlTypePropertyId, UIA_CustomControlTypeId, UIA_DocumentControlTypeId,
    UIA_EditControlTypeId, UIA_ExpandCollapsePatternId, UIA_GroupControlTypeId,
    UIA_HyperlinkControlTypeId, UIA_ImageControlTypeId, UIA_InvokePatternId,
    UIA_IsEnabledPropertyId, UIA_IsOffscreenPropertyId, UIA_ListControlTypeId,
    UIA_ListItemControlTypeId, UIA_MenuBarControlTypeId, UIA_MenuItemControlTypeId,
    UIA_NamePropertyId, UIA_NativeWindowHandlePropertyId, UIA_PaneControlTypeId,
    UIA_ProcessIdPropertyId, UIA_RadioButtonControlTypeId, UIA_ScrollItemPatternId,
    UIA_SelectionItemPatternId, UIA_SplitButtonControlTypeId, UIA_StatusBarControlTypeId,
    UIA_TabControlTypeId, UIA_TabItemControlTypeId, UIA_TextControlTypeId,
    UIA_TitleBarControlTypeId, UIA_TogglePatternId, UIA_ToolBarControlTypeId,
    UIA_TreeControlTypeId, UIA_TreeItemControlTypeId, UIA_ValuePatternId, UIA_WindowControlTypeId,
    UIA_CONTROLTYPE_ID,
};
use windows::Win32::UI::WindowsAndMessaging::GetForegroundWindow;
use windows::Win32::UI::WindowsAndMessaging::IsWindow;

pub(super) fn run(rx: Receiver<Cmd>, ready: Sender<Result<()>>, cfg: EngineConfig) {
    // MTA, not STA: UIA clients are explicitly documented to use the
    // multithreaded apartment, and an STA here would need a message pump.
    if let Err(e) = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED).ok() } {
        let _ = ready.send(Err(anyhow!("CoInitializeEx failed: {e}")));
        return;
    }

    let automation: IUIAutomation =
        match unsafe { CoCreateInstance(&CUIAutomation, None, CLSCTX_INPROC_SERVER) } {
            Ok(a) => a,
            Err(e) => {
                let _ = ready.send(Err(anyhow!("CoCreateInstance(CUIAutomation) failed: {e}")));
                unsafe { CoUninitialize() };
                return;
            }
        };

    let _ = ready.send(Ok(()));

    while let Ok(cmd) = rx.recv() {
        match cmd {
            // Reads retry; `act` deliberately does not. Retrying a read costs
            // a few hundred milliseconds, while retrying an action that has
            // already sent input could click twice - and a caller cannot tell
            // a doubled click from a single one afterwards.
            Cmd::ListWindows(reply) => {
                let _ = reply.send(retry_transient(|| list_windows(&automation)));
            }
            Cmd::Discover(args, reply) => {
                let _ = reply.send(retry_transient(|| {
                    discover(&automation, &args, &cfg.lease_key)
                }));
            }
            Cmd::Act(args, reply) => {
                let _ = reply.send(act(&automation, &args, &cfg.lease_key));
            }
        }
    }

    unsafe { CoUninitialize() };
}

/// One cross-process call, not one per property.
///
/// `FindAllBuildCache` hands back every child with the requested properties
/// already marshalled, so the `Cached*` getters below are local reads. Using
/// the uncached `Current*` getters instead would cost a COM round trip per
/// property per element - the difference between ~100ms and ~450ms.
fn list_windows(a: &IUIAutomation) -> Result<Vec<WindowInfo>> {
    unsafe {
        let root = a.GetRootElement()?;
        let cond = a.CreateTrueCondition()?;
        let cache = a.CreateCacheRequest()?;
        for prop in [
            UIA_NamePropertyId,
            UIA_ClassNamePropertyId,
            UIA_ControlTypePropertyId,
            UIA_NativeWindowHandlePropertyId,
            UIA_ProcessIdPropertyId,
            UIA_BoundingRectanglePropertyId,
        ] {
            cache.AddProperty(prop)?;
        }

        let arr = root.FindAllBuildCache(TreeScope_Children, &cond, &cache)?;
        let n = arr.Length()?;
        let mut out = Vec::with_capacity(n as usize);

        for i in 0..n {
            let el = arr.GetElement(i)?;
            let r: RECT = el.CachedBoundingRectangle().unwrap_or_default();
            out.push(WindowInfo {
                name: el.CachedName().map(|b| b.to_string()).unwrap_or_default(),
                class_name: el
                    .CachedClassName()
                    .map(|b| b.to_string())
                    .unwrap_or_default(),
                control_type: control_type_name(
                    el.CachedControlType().unwrap_or(UIA_CONTROLTYPE_ID(0)),
                ),
                hwnd: el
                    .CachedNativeWindowHandle()
                    .map(|h| h.0 as isize)
                    .unwrap_or(0),
                pid: el.CachedProcessId().unwrap_or(0),
                bounds: Bounds {
                    x: r.left,
                    y: r.top,
                    w: r.right - r.left,
                    h: r.bottom - r.top,
                },
            });
        }
        Ok(out)
    }
}

#[allow(non_upper_case_globals)] // windows-rs constants are not UPPER_CASE
fn control_type_name(id: UIA_CONTROLTYPE_ID) -> String {
    let s = match id {
        UIA_WindowControlTypeId => "window",
        UIA_ButtonControlTypeId => "button",
        UIA_EditControlTypeId => "edit",
        UIA_MenuBarControlTypeId => "menu bar",
        UIA_MenuItemControlTypeId => "menu item",
        UIA_PaneControlTypeId => "pane",
        UIA_TextControlTypeId => "text",
        UIA_ListControlTypeId => "list",
        UIA_TabItemControlTypeId => "tab item",
        UIA_ToolBarControlTypeId => "tool bar",
        UIA_TreeControlTypeId => "tree",
        UIA_GroupControlTypeId => "group",
        UIA_TreeItemControlTypeId => "tree item",
        UIA_ImageControlTypeId => "image",
        UIA_CheckBoxControlTypeId => "checkbox",
        UIA_ComboBoxControlTypeId => "combobox",
        UIA_HyperlinkControlTypeId => "link",
        UIA_ListItemControlTypeId => "list item",
        UIA_RadioButtonControlTypeId => "radio",
        UIA_SplitButtonControlTypeId => "split button",
        UIA_TabControlTypeId => "tab",
        UIA_CustomControlTypeId => "custom",
        UIA_DocumentControlTypeId => "document",
        UIA_TitleBarControlTypeId => "title bar",
        UIA_StatusBarControlTypeId => "status bar",
        _ => return format!("type#{}", id.0),
    };
    s.to_string()
}

/// Walk one window's subtree and return everything worth acting on.
///
/// The expensive part is deliberately a single call: `SetTreeScope(Subtree)` on
/// the cache request means `BuildUpdatedCache` marshals the whole subtree - every
/// node, every requested property - in one cross-process hop. The recursive walk
/// below then touches only local memory. Fetching the same data through
/// `GetCurrentPropertyValue` would be one round trip per property per node.
fn discover(a: &IUIAutomation, args: &DiscoverArgs, key: &[u8]) -> Result<Discovery> {
    let t0 = std::time::Instant::now();
    unsafe {
        let hwnd = match args.hwnd {
            Some(h) => HWND(h as *mut core::ffi::c_void),
            None => GetForegroundWindow(),
        };
        if hwnd.0.is_null() {
            return Err(anyhow!("no target window (nothing focused?)"));
        }

        let root = a.ElementFromHandle(hwnd)?;

        let cache = a.CreateCacheRequest()?;
        cache.SetTreeScope(TreeScope_Subtree)?;
        cache.SetTreeFilter(&a.ControlViewCondition()?)?;
        for prop in [
            UIA_NamePropertyId,
            UIA_ClassNamePropertyId,
            UIA_ControlTypePropertyId,
            UIA_AutomationIdPropertyId,
            UIA_BoundingRectanglePropertyId,
            UIA_NativeWindowHandlePropertyId,
            UIA_ProcessIdPropertyId,
            UIA_IsEnabledPropertyId,
            UIA_IsOffscreenPropertyId,
        ] {
            cache.AddProperty(prop)?;
        }
        // Caching the pattern objects themselves kills two birds: pattern
        // availability becomes a local `is_ok()` (no VARIANT unwrapping), and
        // `act` gets the pattern it needs without a second round trip.
        for pat in [
            UIA_InvokePatternId,
            UIA_ValuePatternId,
            UIA_TogglePatternId,
            UIA_ExpandCollapsePatternId,
            UIA_SelectionItemPatternId,
            UIA_ScrollItemPatternId,
        ] {
            cache.AddPattern(pat)?;
        }

        let cached = root.BuildUpdatedCache(&cache)?;

        let wr: RECT = cached.CachedBoundingRectangle().unwrap_or_default();
        let window = WindowInfo {
            name: cached
                .CachedName()
                .map(|b| b.to_string())
                .unwrap_or_default(),
            class_name: cached
                .CachedClassName()
                .map(|b| b.to_string())
                .unwrap_or_default(),
            control_type: control_type_name(
                cached.CachedControlType().unwrap_or(UIA_CONTROLTYPE_ID(0)),
            ),
            hwnd: hwnd.0 as isize,
            pid: cached.CachedProcessId().unwrap_or(0),
            bounds: Bounds {
                x: wr.left,
                y: wr.top,
                w: wr.right - wr.left,
                h: wr.bottom - wr.top,
            },
        };
        let generation = generation_of(&window);

        let mut entities = Vec::new();
        let mut truncated = None;
        let exp = now() + args.ttl_secs;
        let scope = Scope {
            hwnd: window.hwnd,
            generation,
            exp,
        }
        .encode(key)?;

        walk(
            &cached,
            &mut Vec::new(),
            0,
            args,
            &mut entities,
            &mut truncated,
        )?;

        Ok(Discovery {
            window,
            scope,
            generation,
            entities,
            truncated,
            elapsed_ms: t0.elapsed().as_secs_f64() * 1000.0,
        })
    }
}

unsafe fn walk(
    el: &IUIAutomationElement,
    path: &mut Vec<u32>,
    depth: u32,
    args: &DiscoverArgs,
    out: &mut Vec<Entity>,
    truncated: &mut Option<String>,
) -> Result<()> {
    if out.len() >= args.max_elements {
        *truncated = Some(format!("element cap {} reached", args.max_elements));
        return Ok(());
    }
    if depth > args.max_depth {
        *truncated = Some(format!("depth cap {} reached", args.max_depth));
        return Ok(());
    }

    if depth > 0 {
        // Offscreen elements are real but unclickable; surfacing them invites
        // the model to aim at something the user cannot see.
        let offscreen = el.CachedIsOffscreen().map(|b| b.as_bool()).unwrap_or(false);
        if !offscreen {
            if let Some(e) = to_entity(el, path, args)? {
                out.push(e);
            }
        }
    }

    let kids = match el.GetCachedChildren() {
        Ok(k) => k,
        Err(_) => return Ok(()), // leaf, or filtered out by the tree filter
    };
    let n = kids.Length().unwrap_or(0);
    for i in 0..n {
        let child = kids.GetElement(i)?;
        path.push(i as u32);
        walk(&child, path, depth + 1, args, out, truncated)?;
        path.pop();
    }
    Ok(())
}

unsafe fn to_entity(
    el: &IUIAutomationElement,
    path: &[u32],
    args: &DiscoverArgs,
) -> Result<Option<Entity>> {
    let name = el.CachedName().map(|b| b.to_string()).unwrap_or_default();
    let automation_id = el
        .CachedAutomationId()
        .map(|b| b.to_string())
        .unwrap_or_default();
    let control_type = control_type_name(el.CachedControlType().unwrap_or(UIA_CONTROLTYPE_ID(0)));

    let mut actions = Vec::new();
    if el.GetCachedPattern(UIA_InvokePatternId).is_ok() {
        actions.push("click".to_string());
    }
    if el.GetCachedPattern(UIA_ValuePatternId).is_ok() {
        actions.push("type".to_string());
    }
    if el.GetCachedPattern(UIA_TogglePatternId).is_ok() {
        actions.push("toggle".to_string());
    }
    if el.GetCachedPattern(UIA_ExpandCollapsePatternId).is_ok() {
        actions.push("expand".to_string());
    }
    if el.GetCachedPattern(UIA_SelectionItemPatternId).is_ok() {
        actions.push("select".to_string());
    }
    // ScrollItem is available on essentially every list row; naming it on each
    // one costs tokens and tells a caller nothing they would act on.
    if args.filter == Filter::All && el.GetCachedPattern(UIA_ScrollItemPatternId).is_ok() {
        actions.push("scroll_into_view".to_string());
    }
    if actions.is_empty() {
        return Ok(None); // pure decoration - not worth a lease or a token
    }

    if args.filter == Filter::Actionable {
        // "Can be scrolled into view" is not something a caller ever asks for
        // on its own - it is a property of nearly every list row.
        let only_scroll = actions.len() == 1 && actions[0] == "scroll_into_view";
        // Groups and panes with no invoke/value pattern are layout, not targets.
        let bare_container = matches!(control_type.as_str(), "group" | "pane" | "custom")
            && !actions.iter().any(|a| a == "click" || a == "type");
        if only_scroll || bare_container {
            return Ok(None);
        }
    }

    let r: RECT = el.CachedBoundingRectangle().unwrap_or_default();
    let bounds = Bounds {
        x: r.left,
        y: r.top,
        w: r.right - r.left,
        h: r.bottom - r.top,
    };
    if bounds.w <= 0 || bounds.h <= 0 {
        return Ok(None);
    }

    // An element with neither a name nor an automation id cannot be referred to
    // by a caller and is almost always layout scaffolding - most of the payload
    // bloat lived here. Only dropped in Actionable mode: `all` means all.
    if args.filter == Filter::Actionable && name.trim().is_empty() && automation_id.is_empty() {
        return Ok(None);
    }

    Ok(Some(Entity {
        click_at: (bounds.x + bounds.w / 2, bounds.y + bounds.h / 2),
        name,
        control_type,
        automation_id,
        bounds: if args.verbose { Some(bounds) } else { None },
        actions,
        enabled: el.CachedIsEnabled().map(|b| b.as_bool()).unwrap_or(true),
        path: path.to_vec(),
    }))
}

/// A scope for the window as it stands right now.
///
/// Acting often changes the very properties `generation_of` hashes - typing
/// into a document adds a modified marker to the title - so the scope a caller
/// just used is frequently stale the instant the action succeeds. Re-reading
/// here costs one cached property fetch and saves the caller a full
/// re-`discover`, which on a heavy window is 400-500 ms per action.
///
/// Returns `None` rather than failing the action: the action already happened,
/// and a caller that cannot get a fresh scope can still re-discover.
unsafe fn fresh_scope(a: &IUIAutomation, hwnd: HWND, key: &[u8]) -> Option<String> {
    let req = a.CreateCacheRequest().ok()?;
    req.SetTreeScope(TreeScope_Element).ok()?;
    for prop in [
        UIA_NamePropertyId,
        UIA_ClassNamePropertyId,
        UIA_ProcessIdPropertyId,
        UIA_BoundingRectanglePropertyId,
    ] {
        req.AddProperty(prop).ok()?;
    }
    let el = a
        .ElementFromHandle(hwnd)
        .ok()?
        .BuildUpdatedCache(&req)
        .ok()?;
    let wr: RECT = el.CachedBoundingRectangle().unwrap_or_default();
    let w = WindowInfo {
        name: el.CachedName().map(|b| b.to_string()).unwrap_or_default(),
        class_name: el
            .CachedClassName()
            .map(|b| b.to_string())
            .unwrap_or_default(),
        control_type: String::new(),
        hwnd: hwnd.0 as isize,
        pid: el.CachedProcessId().unwrap_or(0),
        bounds: Bounds {
            x: wr.left,
            y: wr.top,
            w: wr.right - wr.left,
            h: wr.bottom - wr.top,
        },
    };
    Scope {
        hwnd: w.hwnd,
        generation: generation_of(&w),
        exp: now() + crate::lease::DEFAULT_TTL_SECS,
    }
    .encode(key)
    .ok()
}

/// HRESULTs that mean "try again", not "this cannot work".
///
/// `EVENT_E_ALL_SUBSCRIBERS_FAILED` (0x80040201) shows up while an application
/// is starting and UI Automation is registering and unregistering event
/// handlers underneath us. It was observed on a plain window enumeration that
/// takes no handle at all, so it cannot be blamed on a stale one: the call is
/// simply unlucky in its timing.
///
/// The rest are the usual COM apartment transients - a server busy, a call
/// rejected, an element that went away mid-walk.
fn is_transient(e: &windows::core::Error) -> bool {
    matches!(
        e.code().0 as u32,
        0x8004_0201 // EVENT_E_ALL_SUBSCRIBERS_FAILED
            | 0x8001_010A // RPC_E_SERVERCALL_RETRYLATER
            | 0x8001_0001 // RPC_E_CALL_REJECTED
            | 0x8004_0200 // EVENT_E_FIRST / element vanished mid-walk
    )
}

/// Runs a READ and retries it through a transient COM failure.
///
/// Three attempts with a short pause: the observed failure recovered on the
/// very next call, so this is about surviving a moment rather than waiting out
/// a condition. Anything still failing after that is reported as it is - a
/// retry loop that hides a real fault is worse than the raw error it replaced.
fn retry_transient<T>(mut f: impl FnMut() -> Result<T>) -> Result<T> {
    const ATTEMPTS: u32 = 3;
    let mut last = None;
    for attempt in 0..ATTEMPTS {
        match f() {
            Ok(v) => return Ok(v),
            Err(e) => {
                let transient = e
                    .downcast_ref::<windows::core::Error>()
                    .is_some_and(is_transient);
                if !transient {
                    return Err(e);
                }
                tracing::warn!("transient COM failure on attempt {}: {e}", attempt + 1);
                last = Some(e);
                // No pause after the last attempt - there is nothing left to
                // wait for, and it would only delay the error by 120 ms.
                if attempt + 1 < ATTEMPTS {
                    std::thread::sleep(std::time::Duration::from_millis(120));
                }
            }
        }
    }
    Err(last.expect("a failure was recorded before the loop ended"))
}

/// Cheap fingerprint of a window's identity. `act` compares this against the
/// lease so a replaced or resized window is caught before input is sent.
fn generation_of(w: &WindowInfo) -> u64 {
    let mut h = DefaultHasher::new();
    w.hwnd.hash(&mut h);
    w.pid.hash(&mut h);
    w.class_name.hash(&mut h);
    w.name.hash(&mut h);
    (w.bounds.w, w.bounds.h).hash(&mut h);
    h.finish()
}

/// The same as [`guard!`], for failures that happen *after* an element was
/// found. These carry `matched_by`, because "found it, but it is disabled" is
/// a different situation from "no such element" and the status alone cannot
/// tell them apart. It also makes the match ladder observable without
/// performing an action: asking a control for a pattern it does not have
/// resolves the selector, reports the tier, and changes nothing.
macro_rules! guard_found {
    ($status:expr, $action:expr, $target:expr, $t0:expr, $detail:expr, $by:expr, $tier:expr) => {
        return Ok(ActResult {
            ok: false,
            action: $action.to_string(),
            status: $status.to_string(),
            target: $target,
            resolved_by: $by.to_string(),
            matched_by: $tier,
            next_scope: None,
            screen_changed: None,
            detail: Some($detail),
            elapsed_ms: $t0.elapsed().as_secs_f64() * 1000.0,
        })
    };
}

macro_rules! guard {
    ($status:expr, $action:expr, $target:expr, $t0:expr, $detail:expr, $by:expr) => {
        return Ok(ActResult {
            ok: false,
            action: $action.to_string(),
            status: $status.to_string(),
            target: $target,
            resolved_by: $by.to_string(),
            matched_by: None,
            next_scope: None,
            detail: Some($detail),
            // The UIA path has real perception guards; this field exists for
            // the coordinate path, which has none.
            screen_changed: None,
            elapsed_ms: $t0.elapsed().as_secs_f64() * 1000.0,
        })
    };
}

/// Re-find an element from a signed scope plus a path, verify the world still
/// looks the way it did at discovery, then act through the UIA control pattern.
///
/// Patterns, not synthetic input: `Invoke()` reaches a control without stealing
/// focus, moving the user's cursor, or depending on the window being on top -
/// all of which make `SendInput` fragile and rude. Synthetic input is only the
/// right tool for elements that expose no pattern at all.
fn act(a: &IUIAutomation, args: &ActArgs, key: &[u8]) -> Result<ActResult> {
    let t0 = std::time::Instant::now();
    let scope = Scope::decode(&args.scope, key)?;
    let by = match &args.select {
        Some(s) if !s.is_empty() => "selector",
        _ => "path",
    };

    unsafe {
        let hwnd = HWND(scope.hwnd as *mut core::ffi::c_void);
        if !IsWindow(Some(hwnd)).as_bool() {
            guard!(
                "identity_changed",
                args.action,
                String::new(),
                t0,
                "the window no longer exists".to_string(),
                by
            );
        }

        // Walk the path one level at a time instead of marshalling the whole
        // subtree. `act` needs exactly the nodes along `path` - on a window with
        // 174 elements, a Subtree cache pulls all 174 to reach one of them, which
        // is what made act as expensive as a full discover.
        let nav = a.CreateCacheRequest()?;
        // A path walk needs one level at a time; a selector needs the whole
        // subtree to search. Paying for the subtree only when asked keeps the
        // fast route fast - which is why `path` remains supported at all.
        //
        // Element AND Children, not Children alone: Children caches the kids
        // but leaves the node's own properties empty, which silently breaks the
        // generation check (a guard caught this, as designed).
        nav.SetTreeScope(if by == "selector" {
            TreeScope_Subtree
        } else {
            TreeScope(TreeScope_Element.0 | TreeScope_Children.0)
        })?;
        nav.SetTreeFilter(&a.ControlViewCondition()?)?;
        for prop in [
            UIA_NamePropertyId,
            UIA_ClassNamePropertyId,
            UIA_ControlTypePropertyId,
            UIA_BoundingRectanglePropertyId,
            UIA_ProcessIdPropertyId,
            // Required by selector matching. An uncached property errors, and
            // `unwrap_or_default()` turns that into an empty string - so
            // omitting it here does not fail loudly, it just makes every
            // automation_id selector silently never match.
            UIA_AutomationIdPropertyId,
        ] {
            nav.AddProperty(prop)?;
        }

        // The final element needs its state and its patterns; nothing above it does.
        let leaf = a.CreateCacheRequest()?;
        leaf.SetTreeScope(TreeScope_Element)?;
        for prop in [
            UIA_NamePropertyId,
            UIA_ControlTypePropertyId,
            UIA_BoundingRectanglePropertyId,
            UIA_IsEnabledPropertyId,
            UIA_IsOffscreenPropertyId,
        ] {
            leaf.AddProperty(prop)?;
        }
        for pat in [
            UIA_InvokePatternId,
            UIA_ValuePatternId,
            UIA_TogglePatternId,
            UIA_ExpandCollapsePatternId,
            UIA_SelectionItemPatternId,
        ] {
            leaf.AddPattern(pat)?;
        }

        let cached = a.ElementFromHandle(hwnd)?.BuildUpdatedCache(&nav)?;

        // Guard 1: is this still the same window we were handed a scope for?
        let wr: RECT = cached.CachedBoundingRectangle().unwrap_or_default();
        let win = WindowInfo {
            name: cached
                .CachedName()
                .map(|b| b.to_string())
                .unwrap_or_default(),
            class_name: cached
                .CachedClassName()
                .map(|b| b.to_string())
                .unwrap_or_default(),
            control_type: control_type_name(
                cached.CachedControlType().unwrap_or(UIA_CONTROLTYPE_ID(0)),
            ),
            hwnd: scope.hwnd,
            pid: cached.CachedProcessId().unwrap_or(0),
            bounds: Bounds {
                x: wr.left,
                y: wr.top,
                w: wr.right - wr.left,
                h: wr.bottom - wr.top,
            },
        };
        if generation_of(&win) != scope.generation {
            guard!(
                "identity_changed",
                args.action,
                win.name,
                t0,
                "window was replaced, retitled or resized since discovery - re-discover"
                    .to_string(),
                by
            );
        }

        // Guard 2: does the path still lead somewhere?
        let mut el = cached.clone();
        // Set only on the selector branch; an index path involves no name.
        let mut matched_by: Option<MatchTier> = None;

        if by == "selector" {
            let sel = args.select.as_ref().expect("selector present");
            let mut hits: Vec<(IUIAutomationElement, String, MatchTier)> = Vec::new();
            collect_matches(&cached, sel, &mut hits)?;
            // Keep only the tightest tier that matched anything. Without this,
            // adding leniency would turn selectors that used to resolve one
            // element into `ambiguous` as soon as a looser sibling existed.
            crate::text::keep_best(&mut hits, |h| h.2);
            match hits.len() {
                0 => guard!(
                    "not_found",
                    args.action,
                    win.name.clone(),
                    t0,
                    format!("nothing in this window matches {}", sel.describe()),
                    by
                ),
                1 => {}
                n => {
                    // Never guess. Two matching buttons means the caller was not
                    // specific enough, and quietly taking the first is precisely
                    // how automation clicks the wrong thing.
                    let names: Vec<&str> =
                        hits.iter().take(4).map(|(_, n, _)| n.as_str()).collect();
                    guard!(
                        "ambiguous",
                        args.action,
                        win.name.clone(),
                        t0,
                        format!(
                            "{n} elements match {} at the {} tier ({}). Add automation_id \
                             or control_type.",
                            sel.describe(),
                            hits[0].2.as_str(),
                            names.join(", ")
                        ),
                        by
                    )
                }
            }
            let hit = hits.remove(0);
            matched_by = Some(hit.2);
            el = hit.0.BuildUpdatedCache(&leaf)?;
        } else {
            let last = args.path.len().saturating_sub(1);
            for (i, idx) in args.path.iter().enumerate() {
                let kids = match el.GetCachedChildren() {
                    Ok(k) => k,
                    Err(_) => guard!(
                        "not_found",
                        args.action,
                        win.name,
                        t0,
                        format!("path ran out of children at depth {i}"),
                        by
                    ),
                };
                if *idx >= kids.Length().unwrap_or(0) as u32 {
                    guard!(
                        "not_found",
                        args.action,
                        win.name,
                        t0,
                        format!("path index {idx} out of range at depth {i}"),
                        by
                    );
                }
                let child = kids.GetElement(*idx as i32)?;
                // Re-cache as we descend: the child arrived with only its own
                // properties, so it needs its own children before the next step -
                // and the leaf needs patterns instead.
                el = if i == last {
                    child.BuildUpdatedCache(&leaf)?
                } else {
                    child.BuildUpdatedCache(&nav)?
                };
            }
        }

        let target = el.CachedName().map(|b| b.to_string()).unwrap_or_default();

        // Guard 3: is it in a state where acting makes sense?
        if !el.CachedIsEnabled().map(|b| b.as_bool()).unwrap_or(true) {
            guard_found!(
                "disabled",
                args.action,
                target,
                t0,
                "control is disabled".to_string(),
                by,
                matched_by
            );
        }
        if el.CachedIsOffscreen().map(|b| b.as_bool()).unwrap_or(false) {
            guard_found!(
                "moved",
                args.action,
                target,
                t0,
                "control is offscreen".to_string(),
                by,
                matched_by
            );
        }

        // Handled before the pattern table, because keyboard input has no
        // control pattern: it goes wherever focus is. That makes it the one
        // action here that is not a contract with a control, so it takes focus
        // explicitly and says so, rather than looking like an Invoke.
        if args.action == "key" {
            let spec = args.value.clone().unwrap_or_default();
            let chords = match crate::keys::parse(&spec) {
                Ok(c) => c,
                Err(e) => guard_found!(
                    "pattern_gone",
                    args.action,
                    target,
                    t0,
                    format!("{e}"),
                    by,
                    matched_by
                ),
            };
            if let Err(e) = el.SetFocus() {
                guard_found!(
                    "pattern_gone",
                    args.action,
                    target,
                    t0,
                    format!("could not focus the control to type into it: {e}"),
                    by,
                    matched_by
                );
            }
            if let Err(e) = crate::input::send_keys(&chords) {
                guard_found!(
                    "pattern_gone",
                    args.action,
                    target,
                    t0,
                    format!("focus was taken but the keystrokes failed: {e}"),
                    by,
                    matched_by
                );
            }
            return Ok(ActResult {
                ok: true,
                action: args.action.clone(),
                status: "ok".to_string(),
                target,
                resolved_by: by.to_string(),
                matched_by,
                next_scope: fresh_scope(a, hwnd, key),
                screen_changed: None,
                detail: Some(format!(
                    "focused the control and sent {} keystroke(s): {spec:?}. Keyboard input goes \
                     to whatever holds focus, so this reports that the keys were sent, not that \
                     the control consumed them - and taking focus is a visible side effect.",
                    chords.len()
                )),
                elapsed_ms: t0.elapsed().as_secs_f64() * 1000.0,
            });
        }

        let ok_detail = match args.action.as_str() {
            "click" => el
                .GetCachedPatternAs::<IUIAutomationInvokePattern>(UIA_InvokePatternId)
                .map(|p| p.Invoke().map(|_| "invoked".to_string())),
            "type" => {
                let v = args.value.clone().unwrap_or_default();
                el.GetCachedPatternAs::<IUIAutomationValuePattern>(UIA_ValuePatternId)
                    .map(|p| {
                        p.SetValue(&BSTR::from(v.as_str()))
                            .map(|_| format!("set {} chars", v.len()))
                    })
            }
            "toggle" => el
                .GetCachedPatternAs::<IUIAutomationTogglePattern>(UIA_TogglePatternId)
                .map(|p| p.Toggle().map(|_| "toggled".to_string())),
            "expand" => el
                .GetCachedPatternAs::<IUIAutomationExpandCollapsePattern>(
                    UIA_ExpandCollapsePatternId,
                )
                .map(|p| p.Expand().map(|_| "expanded".to_string())),
            "select" => el
                .GetCachedPatternAs::<IUIAutomationSelectionItemPattern>(UIA_SelectionItemPatternId)
                .map(|p| p.Select().map(|_| "selected".to_string())),
            other => guard_found!(
                "pattern_gone",
                args.action,
                target,
                t0,
                format!("unknown action '{other}'"),
                by,
                matched_by
            ),
        };

        match ok_detail {
            Err(_) => guard_found!(
                "pattern_gone",
                args.action,
                target,
                t0,
                format!("control no longer supports '{}'", args.action),
                by,
                matched_by
            ),
            Ok(Err(e)) => guard_found!(
                "pattern_gone",
                args.action,
                target,
                t0,
                format!("pattern call failed: {e}"),
                by,
                matched_by
            ),
            Ok(Ok(detail)) => Ok(ActResult {
                ok: true,
                action: args.action.clone(),
                status: "ok".to_string(),
                target,
                resolved_by: by.to_string(),
                matched_by,
                next_scope: fresh_scope(a, hwnd, key),
                screen_changed: None,
                detail: Some(detail),
                elapsed_ms: t0.elapsed().as_secs_f64() * 1000.0,
            }),
        }
    }
}

/// Depth-first search for every element matching a selector.
///
/// Collects all matches rather than stopping at the first, because the count is
/// the interesting part: one is a hit, several means the caller must be more
/// specific, and returning early would hide that.
unsafe fn collect_matches(
    el: &IUIAutomationElement,
    sel: &Selector,
    out: &mut Vec<(IUIAutomationElement, String, MatchTier)>,
) -> Result<()> {
    // A cap, because a runaway tree should degrade into "ambiguous" rather than
    // spending a minute proving it.
    if out.len() >= 64 {
        return Ok(());
    }
    let name = el.CachedName().map(|b| b.to_string()).unwrap_or_default();
    let aid = el
        .CachedAutomationId()
        .map(|b| b.to_string())
        .unwrap_or_default();
    let ct = control_type_name(el.CachedControlType().unwrap_or(UIA_CONTROLTYPE_ID(0)));

    // Name goes through the locale ladder in `crate::text`, which carries back
    // how much leniency it needed. A selector with no name constrains nothing,
    // so it contributes the tightest tier rather than excluding the element.
    let name_tier = match sel.name.as_ref() {
        None => Some(MatchTier::Exact),
        Some(n) => crate::text::tier_of(&name, n),
    };
    // automation_id is compared byte for byte: it is an identifier rather than
    // a label, and it is stable across locales precisely because no translator
    // ever touches it. control_type is this crate's own ASCII vocabulary.
    let ok_id = sel.automation_id.as_ref().is_none_or(|a| *a == aid);
    let ok_ct = sel
        .control_type
        .as_ref()
        .is_none_or(|c| c.eq_ignore_ascii_case(&ct));
    if let (Some(tier), true, true) = (name_tier, ok_id, ok_ct) {
        out.push((el.clone(), name, tier));
    }

    if let Ok(kids) = el.GetCachedChildren() {
        for i in 0..kids.Length().unwrap_or(0) {
            collect_matches(&kids.GetElement(i)?, sel, out)?;
        }
    }
    Ok(())
}
