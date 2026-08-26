//! Windows-only half of the UIA engine. Everything in here runs on the single
//! `kuroko-uia` thread, so the COM pointers never escape their apartment.

use super::{ActArgs, ActResult, Bounds, Cmd, DiscoverArgs, Discovery, EngineConfig, Entity, Filter, WindowInfo};
use crate::lease::{now, Scope};
use windows::core::BSTR;
use windows::Win32::UI::WindowsAndMessaging::IsWindow;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use anyhow::{anyhow, Result};
use std::sync::mpsc::{Receiver, Sender};
use windows::Win32::Foundation::RECT;
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED,
};
use windows::Win32::Foundation::HWND;
use windows::Win32::UI::WindowsAndMessaging::GetForegroundWindow;
use windows::Win32::UI::Accessibility::{
    TreeScope, TreeScope_Element,
    CUIAutomation, IUIAutomation, IUIAutomationElement, TreeScope_Children, TreeScope_Subtree,
    UIA_AutomationIdPropertyId, UIA_BoundingRectanglePropertyId, UIA_ButtonControlTypeId,
    UIA_ClassNamePropertyId, UIA_ControlTypePropertyId, UIA_CONTROLTYPE_ID,
    UIA_EditControlTypeId, UIA_ExpandCollapsePatternId, UIA_InvokePatternId,
    UIA_IsEnabledPropertyId, UIA_IsOffscreenPropertyId, UIA_ListControlTypeId,
    UIA_MenuBarControlTypeId, UIA_MenuItemControlTypeId, UIA_NamePropertyId,
    UIA_NativeWindowHandlePropertyId, UIA_PaneControlTypeId, UIA_ProcessIdPropertyId,
    UIA_ScrollItemPatternId, UIA_SelectionItemPatternId, UIA_TabItemControlTypeId,
    UIA_TextControlTypeId, UIA_TogglePatternId, UIA_ToolBarControlTypeId,
    UIA_TreeControlTypeId, UIA_ValuePatternId, UIA_WindowControlTypeId,
    UIA_GroupControlTypeId, UIA_TreeItemControlTypeId, UIA_ImageControlTypeId,
    UIA_CheckBoxControlTypeId, UIA_ComboBoxControlTypeId, UIA_HyperlinkControlTypeId,
    UIA_ListItemControlTypeId, UIA_RadioButtonControlTypeId, UIA_SplitButtonControlTypeId,
    UIA_TabControlTypeId, UIA_CustomControlTypeId, UIA_DocumentControlTypeId,
    UIA_TitleBarControlTypeId, UIA_StatusBarControlTypeId,
    IUIAutomationExpandCollapsePattern, IUIAutomationInvokePattern,
    IUIAutomationSelectionItemPattern, IUIAutomationTogglePattern, IUIAutomationValuePattern,
};

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
            Cmd::ListWindows(reply) => {
                let _ = reply.send(list_windows(&automation));
            }
            Cmd::Discover(args, reply) => {
                let _ = reply.send(discover(&automation, &args, &cfg.lease_key));
            }
            Cmd::Act(args, reply) => {
                let _ = reply.send(act(&automation, &args, &cfg.lease_key));
            }
            Cmd::Shutdown => break,
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
                class_name: el.CachedClassName().map(|b| b.to_string()).unwrap_or_default(),
                control_type: control_type_name(
                    el.CachedControlType().unwrap_or(UIA_CONTROLTYPE_ID(0)),
                ),
                hwnd: el.CachedNativeWindowHandle().map(|h| h.0 as isize).unwrap_or(0),
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
            name: cached.CachedName().map(|b| b.to_string()).unwrap_or_default(),
            class_name: cached.CachedClassName().map(|b| b.to_string()).unwrap_or_default(),
            control_type: control_type_name(
                cached.CachedControlType().unwrap_or(UIA_CONTROLTYPE_ID(0)),
            ),
            hwnd: hwnd.0 as isize,
            pid: cached.CachedProcessId().unwrap_or(0),
            bounds: Bounds { x: wr.left, y: wr.top, w: wr.right - wr.left, h: wr.bottom - wr.top },
        };
        let generation = generation_of(&window);

        let mut entities = Vec::new();
        let mut truncated = None;
        let exp = now() + args.ttl_secs;
        let scope = Scope { hwnd: window.hwnd, generation, exp }.encode(key)?;

        walk(
            &cached, &mut Vec::new(), 0, args, &mut entities, &mut truncated,
            &window, generation, exp, key,
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

#[allow(clippy::too_many_arguments)]
unsafe fn walk(
    el: &IUIAutomationElement,
    path: &mut Vec<u32>,
    depth: u32,
    args: &DiscoverArgs,
    out: &mut Vec<Entity>,
    truncated: &mut Option<String>,
    window: &WindowInfo,
    generation: u64,
    exp: u64,
    key: &[u8],
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
            if let Some(e) = to_entity(el, path, window, generation, exp, key, args)? {
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
        walk(&child, path, depth + 1, args, out, truncated, window, generation, exp, key)?;
        path.pop();
    }
    Ok(())
}

unsafe fn to_entity(
    el: &IUIAutomationElement,
    path: &[u32],
    window: &WindowInfo,
    generation: u64,
    exp: u64,
    key: &[u8],
    args: &DiscoverArgs,
) -> Result<Option<Entity>> {
    let name = el.CachedName().map(|b| b.to_string()).unwrap_or_default();
    let automation_id = el.CachedAutomationId().map(|b| b.to_string()).unwrap_or_default();
    let control_type =
        control_type_name(el.CachedControlType().unwrap_or(UIA_CONTROLTYPE_ID(0)));

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
    let bounds = Bounds { x: r.left, y: r.top, w: r.right - r.left, h: r.bottom - r.top };
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


macro_rules! guard {
    ($status:expr, $action:expr, $target:expr, $t0:expr, $detail:expr) => {
        return Ok(ActResult {
            ok: false,
            action: $action.to_string(),
            status: $status.to_string(),
            target: $target,
            detail: Some($detail),
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

    unsafe {
        let hwnd = HWND(scope.hwnd as *mut core::ffi::c_void);
        if !IsWindow(Some(hwnd)).as_bool() {
            guard!("identity_changed", args.action, String::new(), t0,
                   "the window no longer exists".to_string());
        }

        // Walk the path one level at a time instead of marshalling the whole
        // subtree. `act` needs exactly the nodes along `path` - on a window with
        // 174 elements, a Subtree cache pulls all 174 to reach one of them, which
        // is what made act as expensive as a full discover.
        let nav = a.CreateCacheRequest()?;
        // Element AND Children: Children alone caches the kids but leaves the
        // node's own properties empty, which silently breaks the generation
        // check (the guard caught this, as designed).
        nav.SetTreeScope(TreeScope(TreeScope_Element.0 | TreeScope_Children.0))?;
        nav.SetTreeFilter(&a.ControlViewCondition()?)?;
        for prop in [
            UIA_NamePropertyId, UIA_ClassNamePropertyId, UIA_ControlTypePropertyId,
            UIA_BoundingRectanglePropertyId, UIA_ProcessIdPropertyId,
        ] {
            nav.AddProperty(prop)?;
        }

        // The final element needs its state and its patterns; nothing above it does.
        let leaf = a.CreateCacheRequest()?;
        leaf.SetTreeScope(TreeScope_Element)?;
        for prop in [
            UIA_NamePropertyId, UIA_ControlTypePropertyId,
            UIA_BoundingRectanglePropertyId, UIA_IsEnabledPropertyId,
            UIA_IsOffscreenPropertyId,
        ] {
            leaf.AddProperty(prop)?;
        }
        for pat in [
            UIA_InvokePatternId, UIA_ValuePatternId, UIA_TogglePatternId,
            UIA_ExpandCollapsePatternId, UIA_SelectionItemPatternId,
        ] {
            leaf.AddPattern(pat)?;
        }

        let cached = a.ElementFromHandle(hwnd)?.BuildUpdatedCache(&nav)?;

        // Guard 1: is this still the same window we were handed a scope for?
        let wr: RECT = cached.CachedBoundingRectangle().unwrap_or_default();
        let win = WindowInfo {
            name: cached.CachedName().map(|b| b.to_string()).unwrap_or_default(),
            class_name: cached.CachedClassName().map(|b| b.to_string()).unwrap_or_default(),
            control_type: control_type_name(cached.CachedControlType().unwrap_or(UIA_CONTROLTYPE_ID(0))),
            hwnd: scope.hwnd,
            pid: cached.CachedProcessId().unwrap_or(0),
            bounds: Bounds { x: wr.left, y: wr.top, w: wr.right - wr.left, h: wr.bottom - wr.top },
        };
        if generation_of(&win) != scope.generation {
            guard!("identity_changed", args.action, win.name, t0,
                   "window was replaced, retitled or resized since discovery - re-discover".to_string());
        }

        // Guard 2: does the path still lead somewhere?
        let mut el = cached.clone();
        let last = args.path.len().saturating_sub(1);
        for (i, idx) in args.path.iter().enumerate() {
            let kids = match el.GetCachedChildren() {
                Ok(k) => k,
                Err(_) => guard!("not_found", args.action, win.name, t0,
                                 format!("path ran out of children at depth {i}")),
            };
            if *idx >= kids.Length().unwrap_or(0) as u32 {
                guard!("not_found", args.action, win.name, t0,
                       format!("path index {idx} out of range at depth {i}"));
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
        let target = el.CachedName().map(|b| b.to_string()).unwrap_or_default();

        // Guard 3: is it in a state where acting makes sense?
        if !el.CachedIsEnabled().map(|b| b.as_bool()).unwrap_or(true) {
            guard!("disabled", args.action, target, t0, "control is disabled".to_string());
        }
        if el.CachedIsOffscreen().map(|b| b.as_bool()).unwrap_or(false) {
            guard!("moved", args.action, target, t0, "control is offscreen".to_string());
        }

        let ok_detail = match args.action.as_str() {
            "click" => el.GetCachedPatternAs::<IUIAutomationInvokePattern>(UIA_InvokePatternId)
                .map(|p| p.Invoke().map(|_| "invoked".to_string())),
            "type" => {
                let v = args.value.clone().unwrap_or_default();
                el.GetCachedPatternAs::<IUIAutomationValuePattern>(UIA_ValuePatternId)
                    .map(|p| p.SetValue(&BSTR::from(v.as_str())).map(|_| format!("set {} chars", v.len())))
            }
            "toggle" => el.GetCachedPatternAs::<IUIAutomationTogglePattern>(UIA_TogglePatternId)
                .map(|p| p.Toggle().map(|_| "toggled".to_string())),
            "expand" => el.GetCachedPatternAs::<IUIAutomationExpandCollapsePattern>(UIA_ExpandCollapsePatternId)
                .map(|p| p.Expand().map(|_| "expanded".to_string())),
            "select" => el.GetCachedPatternAs::<IUIAutomationSelectionItemPattern>(UIA_SelectionItemPatternId)
                .map(|p| p.Select().map(|_| "selected".to_string())),
            other => guard!("pattern_gone", args.action, target, t0,
                            format!("unknown action '{other}'")),
        };

        match ok_detail {
            Err(_) => guard!("pattern_gone", args.action, target, t0,
                             format!("control no longer supports '{}'", args.action)),
            Ok(Err(e)) => guard!("pattern_gone", args.action, target, t0,
                                 format!("pattern call failed: {e}")),
            Ok(Ok(detail)) => Ok(ActResult {
                ok: true,
                action: args.action.clone(),
                status: "ok".to_string(),
                target,
                detail: Some(detail),
                elapsed_ms: t0.elapsed().as_secs_f64() * 1000.0,
            }),
        }
    }
}
