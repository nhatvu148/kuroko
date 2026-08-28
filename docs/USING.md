# Using it

## First, the question worth asking: SSH or wincrust?

If you already have SSH to the Windows machine, most of what you want is
better done there. wincrust is not a general remote-access tool and is not
trying to be - it runs elevated on a network socket, which is a real standing
cost, and it should earn that.

The line is not "GUI versus terminal". It is **session 0**.

A process started over SSH lands in session 0, which has its own window
station and no desktop. It is not a permissions problem and no flag fixes it.
Measured on the same machine, at the same moment, with a full desktop in use:

| | session | processes with a window title |
|---|---|---|
| plain SSH | 0 | **0** |
| wincrust (via the scheduled task) | 1 | **11** |

`explorer.exe` was running the whole time. From session 0 every
`MainWindowTitle` reads empty, and `Screen.PrimaryScreen.Bounds` reports a
phantom 1024x768. Nothing is broken; there is simply no desktop there to look
at.

So:

| use SSH for | use wincrust for |
|---|---|
| files, processes, services, registry | what is on the screen |
| running commands, git, builds | what is inside a window's UI tree |
| logs, package installs | clicking, typing, selecting |
| anything scriptable | screenshots and OCR |
| | elevated windows |

The README puts it more bluntly, and it is the rule the tool surface was
designed around: anything outside *"look at the desktop and act on a control"*
belongs on the SSH side, where it is not running with an admin token.

## Trying it

Ordered from read-only to acting. Ask in plain language; the agent picks the
tool.

### Does it see a real desktop

> What windows are open on my Windows machine?

The check that matters is not that it answers - it is that the answer is
non-empty. An empty list means the server is in session 0, which looks
identical to a healthy server with nothing running.

> Take a screenshot of my Windows desktop.

> What is in the UI tree of the Settings window?

`discover` returns actionable elements and a signed scope token. An app that
draws its own interface will return almost nothing here - six elements of
window chrome is typical - which is the signal to fall back to OCR.

### Waiting, instead of guessing at sleeps

> Open the File menu, then wait until the Save As dialog appears.

`wait_for` polls in-process and hands back a scope, so the thing you waited for
can be acted on without a second round trip that races it. `until` is `appears`
(default), `disappears` - for waiting out a progress dialog - or `enabled`, for
a button that exists but is greyed.

A timeout is reported as `timeout`, not an error: the target may be absent, or
merely slower than you allowed.

The round trips are not the main saving. The alternative to `wait_for` is
polling with `observe detail=image`, which costs roughly **2,700 tokens a
shot** against roughly **100** for a `wait_for` result. On a dialog that takes
a while, that is the difference between a wait costing twenty thousand tokens
and costing nothing.

### Typing, and pressing keys

These are different actions and the distinction matters.

> Type "hello" into the editor, then press Enter.

`type` sets a control's value through a pattern. `key` sends keystrokes:
`Enter`, `Ctrl+S`, `F5`, or a sequence like `Home Shift+End Ctrl+C`. A console
prompt is a text field *plus* Enter, so it usually needs both.

`key` takes focus first, because keyboard input goes wherever focus is - there
is no per-element keyboard equivalent of a control pattern. It is the one
action here that is not a contract with a control, and it says so in its
result.

### Reading a screen with no UI tree

> Use OCR to read what is on my Windows screen right now.

> Find the text "Settings" on my Windows screen and tell me where it is.

`find_text` is a survey: it returns every occurrence, each labelled with how
much leniency the match needed. `matched_by: "confusable"` means it only
matched after folding characters the recogniser mixes up, which is the weakest
evidence this tool produces.

### The elevation ceiling

> There is an elevated Administrator console open. Can you read its title?

A non-elevated automation tool cannot touch that window at all. This is the
UIPI boundary, and clearing it is why the scheduled task is registered with
`-RunLevel Highest`.

UAC *consent* prompts remain unreachable - they live on the Secure Desktop,
which no process can automate, elevated or not. That is not a gap to be closed.

### Acting

> Close the Start menu on my Windows machine.

> Click the Search button in the Windows taskbar.

Prefer reversible targets while you are learning what it does.

### Watching it refuse

Worth doing deliberately, because a tool that guesses is worse than one that
stops.

> Click something called "Save" on my Windows desktop.

Expect `ambiguous` with the candidates named, or `not_found`. Two matching
controls means the request was not specific enough, and quietly taking the
first is exactly how automation clicks the wrong thing.

> Click a button named "definitely-not-a-real-button".

Expect a clean `not_found` - the target is genuinely absent. Distinct from
`error`, which means the lookup itself failed and says nothing about the
target. A caller that retries on one should not retry on the other.

### Starting an application

> Launch Notepad on my Windows machine.

`launch` is the only tool here that starts a process, so it fails closed: with
no allowlist file, or an empty one, it permits nothing. That is deliberate, and
it means `launch` does nothing useful until someone fills the file -
`%LOCALAPPDATA%\wincrust\launch-allowlist.txt`, one name per line, or
`-Allow name1,name2` when running the setup script.

**Being allowlisted and being resolvable are two separate things.** The
allowlist decides whether the call is permitted; Windows then has to find the
application. A name resolves only if it is on `PATH` or registered under
`App Paths` in the registry - which is true of `notepad` and surprisingly
little else. Anything installed under `Program Files` with no PATH entry needs
its **full path** as the allowlist entry.

That distinction is worth stating because getting it wrong looks like success:
the allowlist accepts the name, and the launch fails anyway. If several
installed versions share an executable name, a bare name is ambiguous even
when it does resolve, and the full path is the only unambiguous answer.

**Prefer the launcher an application ships over the executable underneath it.**
Engineering software frequently starts through a `.bat` that sets a dozen
environment variables first - solver paths, schema directories, plugin
directories. Allowlisting the `.exe` skips all of that and brings the
application up subtly wrong rather than not at all, which is harder to
diagnose than a refusal.

**When a viewport reads flat, compare both capture paths before concluding
anything.** A desktop read picks up translucent overlays lying over the
viewport, and those blend with what is underneath - an overlay tinted with the
model's colour proves the content is being drawn even while the canvas reads
flat. The `hwnd` render is cleaner and loses that signal precisely because it
renders the window properly. Measured on one CAD viewport: the desktop read
showed toolbars tinted by the model, the window render showed them back to
their own colour, and both canvases were flat. The blind path carried the
evidence.

If neither reads it, the application's own export - Copy to Clipboard, a
save-image command - is the reliable route, and worth trying before drawing
any conclusion about what the application is displaying.

**`launch` starts an application; it does not promise a fresh one.** Windows 11
Notepad restores its previous tabs, including unsaved ones, so a launch can
surface somebody's in-progress work. Nothing here has gone wrong - it is what
starting that application does - but a tool whose contract reads "start an
app" can be surprising the first time it reopens a buffer from days ago.

## Reading the result

`act` returns more than success or failure.

- **`resolved_by`** - `selector` or `path` means a UI Automation control
  pattern did the work: a contract with the control. `ocr` means it clicked a
  coordinate where OCR read the text, which is a hope about geometry.
- **`matched_by`** - how closely your text matched what Windows reported.
  `exact` and `case` mean it was found as written. `normalized` means
  composition or width had to be folded - that is the tier that makes `Tệp`
  typed on a Mac meet the same word reported by Windows. `affix` means
  decoration was stripped, such as the `(F)` in a localised `ファイル(F)`.
- **`next_scope`** - present on success. Acting frequently changes the window
  properties the scope is bound to, so the scope you just used is often stale
  the moment the action lands. Chain on this instead of re-discovering.
- **`screen_changed`** - only on the OCR path, and only for a click that was
  actually sent. A control pattern is a contract; a coordinate click is not,
  so this reports what the screen did immediately afterwards. Absent means the
  click landed somewhere that did nothing visible - usually a miss, though a
  control already in the requested state looks identical.

## When it goes wrong

| symptom | cause |
|---|---|
| `401` | token wrong or missing |
| `403` | source IP not in `--ip-allowlist`, or the `Host` header is not the address the server was told to bind |
| connects, but zero windows | the server is in session 0 - it was not started through the scheduled task |
| OCR says "the session is locked" | the machine is locked; a capture there returns the lock screen |
| `launch` refuses | the name is not in the allowlist — the message reports how many entries were loaded, so `0 entries` means the file is missing or empty |
| `launch` is permitted but nothing starts | the name is allowlisted but Windows cannot resolve it; use the full path to the .exe |
| every `act` refuses | the emergency stop is engaged - see the README |

`task status` reports which session it is in. `task logs` tails the server log.

## Turning it off

It does not have to run permanently to be useful. `task stop` costs nothing
and `task start` brings it back in seconds. If weeks pass without needing the
desktop, leaving an elevated network-listening process up is a standing risk
with no matching benefit.
