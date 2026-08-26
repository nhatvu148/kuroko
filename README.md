# kuroko

Windows desktop automation over MCP. Pure Rust, single binary, ~6 MB.

Named for 黒子 — the kabuki stagehand who moves things unseen.

## Why

The obvious alternative, [Windows-MCP](https://github.com/CursorTouch/Windows-MCP), works well and is
worth using. kuroko exists for one reason: **integrity level**.

To reach UAC-adjacent dialogs, an automation server must run at High integrity. Windows-MCP at
High integrity means **95 Python packages and 105 native modules** loaded into a process holding an
admin token on a network socket, with tools including `PowerShell` and `Registry`.

kuroko has 16 direct dependencies and 168 transitive crates. That is not a small number, and
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

**Stateless.** The scope is a signed token, not a session key. A restart does not invalidate work in
flight.

## Measured

Same window, same moment, against Windows-MCP:

| | Windows-MCP | kuroko |
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
- **`launch`** — allowlist only; a missing allowlist file permits nothing.

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
