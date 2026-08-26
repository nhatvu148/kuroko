# wincrust

Windows desktop automation over MCP. Pure Rust, single binary, ~6 MB.

**win** for the platform, **crust** for the language — it contains *rust*, and
crustacean is where *Rustacean* comes from.

## Why

The obvious alternative, [Windows-MCP](https://github.com/CursorTouch/Windows-MCP), works well and is
worth using. wincrust exists for one reason: **integrity level**.

To reach UAC-adjacent dialogs, an automation server must run at High integrity. Windows-MCP at
High integrity means **95 Python packages and 105 native modules** loaded into a process holding an
admin token on a network socket, with tools including `PowerShell` and `Registry`.

wincrust has 16 direct dependencies and 168 transitive crates. That is not a small number, and
it would be dishonest to pretend otherwise — the difference is in kind, not count: Rust dependencies
are resolved at compile time and dead-code-eliminated, with no interpreter, no dynamic import and no
`eval` in the running process. And the tool surface is five, none of which is a shell.

Elevation itself is not the reason — that is a `-RunLevel Highest` flag on a scheduled task, no code
required. The reason is what elevation does to the cost of a large dependency tree.

## Tools

| tool | |
|---|---|
| `windows` | top-level windows with handles, pids, bounds |
| `discover` | actionable elements + a signed scope |
| `act` | click / type / toggle / expand / select, via UIA control patterns |
| `observe` | `text` \| `image` \| `diff` |
| `launch` | allowlist-only; fails closed |

No shell, no registry, no filesystem, no arbitrary process spawn. Use SSH for those — it does not
run with an admin token.

## Design

**One COM thread.** `IUIAutomation` and its elements are neither `Send` nor `Sync`, so they cannot
cross an await or migrate between tokio workers. All of UIA is pinned to one MTA thread for the
process lifetime; async callers reach it over `mpsc` + `oneshot`.

**One cross-process call per discovery.** `SetTreeScope(Subtree)` on the cache request means
`BuildUpdatedCache` marshals the whole subtree in a single hop; the `Cached*` getters are then local
reads. The uncached getters cost one round trip *per property per element*.

**Scopes, not coordinates.** `discover` returns one signed scope (window + generation + expiry) and
per-entity child-index paths. `act` re-finds the element and verifies the window is unchanged, the
path resolves, and the control is enabled — before doing anything. A non-`ok` status means nothing
happened.

**Patterns, not synthetic input.** `Invoke()` reaches a control without stealing focus, moving the
cursor, or requiring the window to be on top.

**Stateless.** The scope is a signed token, not a session key - there is no lease table to look up,
expire or garbage-collect. The signing key is generated per process and never written to disk, so a
restart does rotate it; scopes live 60 seconds, which makes that a non-event.

## Measured

Same window, same moment, against Windows-MCP:

| | Windows-MCP | wincrust |
|---|---|---|
| VS Code, 175 entities | 449 ms | **36 ms** |
| Task Manager, 174 entities | 5,477 ms | **665 ms** |
| deploy | 402 MB, 7,734 files | **6.4 MB, 1 file** |

Latency is app-dependent; Task Manager is slow for both.

## Safety

- **Emergency stop** — park the physical mouse within 10 px of the origin for 500 ms and all input is
  refused, latched for 30 s after you move away. `discover` and `observe` keep working: halting an
  agent should stop it touching things, not blind it.
- **Auth** — bearer token, constant-time compare, optional IP allowlist. Refuses to bind a
  non-loopback address without a key.
- **`launch`** — allowlist only. A missing allowlist permits nothing, and so does one that cannot be
  stamped with a High mandatory label: an allowlist a Medium-integrity process could append to is a
  privilege-escalation path, not a config inconvenience.

## What is actually verified

Everything below was exercised by hand on **one machine**: Windows 11 Home 25H2,
x86_64, a single 1920x1080 display at origin (0,0), en-US.

| | status |
|---|---|
| `discover` / `act` / `observe` | verified against VS Code, Task Manager and an elevated shell |
| emergency stop, allowlist fail-closed, HTTP auth | verified end to end |
| lease signing, diff heuristics, stop state machine | unit tested (21 tests) |
| **display scaling** | verified at **100%, 125%, 150% and 175%** — see below |
| **multiple monitors** | **NOT verified** — no second display available. Negative-origin handling is unit tested only ([#5](https://github.com/nhatvu148/wincrust/issues/5)) |
| Windows 10, Server, ARM64 | not tested ([#6](https://github.com/nhatvu148/wincrust/issues/6)) |
| non-English locale | not tested, and the most likely of these to actually break: `App`-by-name matches **localised** UIA `Name` values ([#6](https://github.com/nhatvu148/wincrust/issues/6)) |

### Display scaling

| scale | dpi | window bounds | a titlebar button's `click_at` | `act` |
|---|---|---|---|---|
| 100% | 96 | 1920x1080 | — | ok |
| 125% | 120 | 1936x1036 | (1777, 21) | ok, window minimised |
| 150% | 144 | 1936x1024 | (1749, 25) | ok, window minimised |
| 175% | 168 | 1936x1012 | (1722, 30) | ok, window minimised |

Two things make this more than four passing checks. The button moves left and
down monotonically as scale rises, because titlebar controls grow with it -
which is what physical-pixel reporting should produce, where a virtualised build
would report coordinates shrinking toward the origin. And 175% is the case that
could have failed: 1920 / 1.75 = 1097.14 does not divide cleanly, so rounding
artifacts would surface there.

`wincrust displays` prints the process's DPI awareness and each monitor's real
scale factor. If it reports `scale: 1.0` everywhere you have tested, you have not
tested scaling — and a DPI-unaware build looks entirely healthy at 100%.

## Limits

- Apps that draw their own UI expose no tree. Abaqus/CAE returns six elements, all window chrome.
  For those, use the application's scripting API over SSH.
- UAC *consent* prompts live on the Secure Desktop and are unreachable by any process, elevated or not.
- Must run in the interactive session. Session 0 has no desktop.

## Credits

Design informed by, but not derived from:
[desktop-touch-mcp](https://github.com/Harusame64/desktop-touch-mcp) (MIT) — leases and per-action
perception guards; [Windows-MCP](https://github.com/CursorTouch/Windows-MCP) (MIT) — tool surface and
the session-1 install pattern. No code from either is reused.
