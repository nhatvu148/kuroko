---
name: wincrust
description: Drive a Windows desktop over MCP - inspect windows, click and type through UI Automation, read the screen with OCR. Use when a task needs the Windows GUI itself: seeing what is on screen, acting on a control, or reaching an elevated window. Do NOT use for files, processes, services, builds or commands on that machine - SSH is faster and is not running with an admin token.
---

# wincrust

An MCP server that acts on a Windows desktop. Seven tools: `windows`,
`discover`, `act`, `observe`, `wait_for`, `find_text`, `launch`.

## Decide first: SSH or wincrust

Most work on a Windows machine is not a wincrust job. It runs elevated on a
network socket, so it should earn that.

The line is **session 0**, not "GUI versus terminal". A process started over
SSH lands in session 0, which has its own window station and no desktop. It is
not a permissions problem and no flag fixes it. Measured on one machine at one
moment with a full desktop in use: SSH saw **0** processes with a window
title; wincrust saw **11**.

| SSH | wincrust |
|---|---|
| files, processes, services, registry | what is on the screen |
| commands, git, builds, installs | what is inside a window's UI tree |
| logs, config, scripts | clicking, typing, selecting |
| anything scriptable | screenshots, OCR |
| | elevated windows |

If the task can be expressed as a command, use SSH. Reach for wincrust when
the answer requires *looking at* or *touching* the desktop.

## Order of operations

1. **`windows`** - find the target and its `hwnd`. An **empty list is not an
   empty desktop**: it means the server is in session 0 and can see nothing.
   Say so rather than reporting "no windows are open".
2. **`discover`** with that `hwnd` - actionable elements plus a signed scope
   token that `act` requires. If it returns only window chrome (a title bar, a
   few panes, no named controls), the app draws its own interface and has no
   UI tree. That is the signal for step 4, not a reason to give up.
3. **`act`** with a selector. Prefer `automation_id` over `name`: identifiers
   are stable across locales, labels are translated. A successful `act` returns
   **`next_scope`** - use it for the following action rather than
   re-`discover`ing, because acting often changes the window's own identity
   (typing adds a modified marker to the title) and invalidates the scope you
   just used.
   - **`type` sets a value; `key` presses keys.** They are different. A console
     prompt is a text field *plus* Enter, so it usually needs both. Key specs
     are chords: `Enter`, `Ctrl+S`, `Home Shift+End Ctrl+C`.
   - `key` takes focus, because keyboard input goes wherever focus is. That is
     a visible side effect and the only action here that is not a contract with
     a control.
4. **`wait_for`** before acting on anything that takes time to appear - a
   dialog, a loaded file, a finished job. `until` is `appears` (default),
   `disappears` or `enabled`. It returns a scope, so you can act on what you
   waited for without racing it. Do not poll `discover` in a loop instead, and
   never poll with `observe detail=image`: that is ~2,700 tokens a shot against
   ~100 for a `wait_for` result.
5. **`find_text`** - OCR, for apps with no tree. Restrict it with `hwnd`:
   fewer pixels means more magnification and better accuracy, and it stops a
   query matching text elsewhere on the desktop.

## Reading what `act` returns

Do not report success from `ok: true` alone.

- **`resolved_by`** - `selector` or `path` means a UI Automation control
  pattern did the work: a contract with the control. **`ocr` means a
  coordinate was clicked** where OCR read the text, which is a hope about
  geometry, not a contract.
- **`screen_changed`** - present only on the OCR path. Absent means the click
  landed somewhere that did nothing visible, which usually means it missed.
  A control already in the requested state looks identical, so say which you
  cannot distinguish rather than asserting the action worked.
- **`matched_by`** - `exact`/`case` mean the label was found as written.
  `normalized` or `affix` mean text had to be reshaped to match; worth
  mentioning when a selector is being pinned down.

## Statuses that are not interchangeable

- **`not_found`** - the target is genuinely not there. Retrying is pointless;
  re-`discover` or try OCR.
- **`error`** - the lookup itself failed and says nothing about the target.
  Retrying is reasonable.
- **`ambiguous`** - more than one match, from `act` or `wait_for`. **Never pick one.** The tool refused
  on purpose; quietly taking the first is how automation clicks the wrong
  thing. Report the candidates and ask, or narrow with `automation_id` or
  `control_type`.
- **`identity_changed`** / **`moved`** - the window changed since `discover`.
  Re-discover; do not reuse the old scope.
- **`stopped`** - the emergency stop is engaged. Do not work around it.

## Refusals that are correct

- **UAC consent prompts are unreachable** by any process, elevated or not.
  They live on the Secure Desktop. This is not a gap to route around.
- **`launch` only accepts allowlisted names**, from a file on the host, and the
  file is empty until someone fills it. If a name is refused, say so and name
  the file - `%LOCALAPPDATA%\wincrust\launch-allowlist.txt`, or re-run setup
  with `-Allow <name>`. Do not look for another way to start a process.
- **A locked session** returns the lock screen, so capture and OCR refuse
  rather than returning a picture of nothing. The machine has to be unlocked.

## Acting on someone's live desktop

This is a machine a person may be using. Prefer read-only tools when they
answer the question. Before anything that changes state, prefer reversible
targets, and say what you are about to click. Do not close windows, dismiss
dialogs or type into fields that were not part of the request.

## Installing this skill

It lives in the repo so it is versioned with the tool. To use it anywhere:

```bash
cp -r skills/wincrust ~/.claude/skills/
```
