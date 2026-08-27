<#
.SYNOPSIS
    Installs wincrust and runs it as an MCP server on the interactive desktop.

.DESCRIPTION
    wincrust is a single binary; `cargo install wincrust` is the whole install.
    What this script sets up is the awkward part around it: getting the server
    into the interactive desktop session, elevated, with a key, and keeping it
    there.

    The awkward part matters. A server started over SSH lands in session 0,
    which has no desktop. It binds the port, logs that it is listening, and
    then returns an empty window list forever - no error, anywhere. Task
    Scheduler with `-LogonType Interactive` is what crosses that boundary, and
    the same registration buys `-RunLevel Highest`, which clears UIPI so the
    server can act on elevated windows.

    The task deliberately runs `powershell.exe -WindowStyle Hidden` rather than
    `cmd.exe /c`. An interactive task with a console action puts a visible
    window on the desktop, and a visible window gets closed - which shows up
    later as a server that died with exit code 0xC000013A (Ctrl+C).

.PARAMETER ClientIp
    Tailscale IP(s) permitted to connect. Required, and not a formality: the
    bearer token is one secret away from an elevated desktop, and a tailnet
    often contains machines belonging to other people.

.PARAMETER ListenIp
    Address to bind. Defaults to this machine's Tailscale IP.

.PARAMETER Port
    Defaults to 8900.

.PARAMETER Allow
    Application names `launch` is permitted to start, e.g. `-Allow notepad,jupiter`.

    The allowlist fails closed: with no file, or an empty one, `launch` refuses
    everything. That is the right default - it is the only tool here that starts
    a process - but it also means `launch` never works until someone names
    something, and the file it wants is easy to not find. Naming them here
    writes the file; omitting this leaves whatever is already there.

.PARAMETER RotateKey
    Generate a new auth key. Existing clients will start getting 401 and must
    be reconfigured, so this is opt-in rather than the default.

.PARAMETER Uninstall
    Remove the task, the config directory and the key. Leaves the binary;
    `cargo uninstall wincrust` removes that.

.EXAMPLE
    .\wincrust-serve.ps1 -ClientIp 100.107.28.57

.EXAMPLE
    .\wincrust-serve.ps1 -Uninstall
#>
[CmdletBinding(DefaultParameterSetName = 'Install')]
param(
    [Parameter(ParameterSetName = 'Install', Mandatory = $true)]
    [string[]] $ClientIp,

    [Parameter(ParameterSetName = 'Install')]
    [string] $ListenIp,

    [Parameter(ParameterSetName = 'Install')]
    [ValidateRange(1, 65535)]
    [int] $Port = 8900,

    [Parameter(ParameterSetName = 'Install')]
    [switch] $RotateKey,

    [Parameter(ParameterSetName = 'Install')]
    [string[]] $Allow,

    [Parameter(ParameterSetName = 'Install')]
    [switch] $SkipInstall,

    [Parameter(ParameterSetName = 'Uninstall', Mandatory = $true)]
    [switch] $Uninstall,

    [Parameter(ParameterSetName = 'Status', Mandatory = $true)]
    [switch] $Status,

    [Parameter(ParameterSetName = 'Logs', Mandatory = $true)]
    [switch] $Logs,

    [Parameter(ParameterSetName = 'Start', Mandatory = $true)]
    [switch] $Start,

    [Parameter(ParameterSetName = 'Stop', Mandatory = $true)]
    [switch] $Stop
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$TaskName = 'wincrust-serve'
$Dir      = Join-Path $env:LOCALAPPDATA 'wincrust'
$KeyFile  = Join-Path $Dir 'auth-key.txt'
$AllowFile = Join-Path $Dir 'launch-allowlist.txt'
$Launcher = Join-Path $Dir 'serve.ps1'
$LogFile  = Join-Path $Dir 'serve.log'

function Write-Step { param([string] $m) Write-Host "==> $m" -ForegroundColor Cyan }
function Write-Warn { param([string] $m) Write-Host "  ! $m" -ForegroundColor Yellow }

function Test-TaskRegistered {
    # Start-ScheduledTask on a task that does not exist reports "The system
    # cannot find the file specified", which sends people looking for a missing
    # .ps1 rather than a missing task. Check first and say what is actually
    # wrong.
    $null -ne (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)
}

function Deny-NotRegistered {
    Write-Host "The scheduled task '$TaskName' is not registered." -ForegroundColor Yellow
    Write-Host ''
    Write-Host '  Set it up first:'
    Write-Host "    .\scripts\wincrust-serve.ps1 -ClientIp <your-client-tailscale-ip>"
    Write-Host '  or:'
    Write-Host '    task setup CLIENT_IP=<your-client-tailscale-ip>'
    exit 1
}

function Stop-Server {
    # Unregistering the task does NOT stop a running server, and the running
    # server holds serve.log open - which is why a plain Remove-Item on the
    # directory fails with "being used by another process".
    Get-Process wincrust -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
}

if ($Status) {
    $p = Get-Process wincrust -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($p) {
        # Session 0 means it is running but blind - the failure this whole
        # arrangement exists to avoid, and the one that looks healthy.
        $where = if ($p.SessionId -eq 0) { 'SESSION 0 - blind, see the README' } else { "session $($p.SessionId)" }
        Write-Host "running, $where"
    } else {
        Write-Host 'not running'
    }
    $listen = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Where-Object { $_.OwningProcess -and $p -and $_.OwningProcess -eq $p.Id } | Select-Object -First 1
    if ($listen) { Write-Host "listening on $($listen.LocalAddress):$($listen.LocalPort)" }
    $n = 0
    if (Test-Path $AllowFile) {
        $n = @(Get-Content $AllowFile |
            Where-Object { $_.Trim() -and -not $_.Trim().StartsWith('#') }).Count
    }
    Write-Host "launch allowlist: $n entries$(if ($n -eq 0) { ' - launch will refuse everything' })"
    if (Test-TaskRegistered) {
        Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction SilentlyContinue |
            Format-List TaskName, LastRunTime, LastTaskResult, NumberOfMissedRuns
    } else {
        Write-Host "scheduled task '$TaskName' is not registered - run setup to create it"
    }
    return
}

if ($Logs) {
    if (Test-Path $LogFile) { Get-Content $LogFile -Tail 40 } else { Write-Host "no log at $LogFile" }
    return
}

if ($Start) {
    if (-not (Test-TaskRegistered)) { Deny-NotRegistered }
    Start-ScheduledTask -TaskName $TaskName
    # Started is not running: the task can launch and the server still fail.
    $p = $null
    foreach ($i in 1..12) {
        Start-Sleep -Seconds 1
        $p = Get-Process wincrust -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($p) { break }
    }
    if ($p) {
        Write-Host "started - running in session $($p.SessionId)"
        if ($p.SessionId -eq 0) {
            Write-Warn 'SESSION 0: it will bind and return an empty window list forever.'
        }
    } else {
        Write-Warn 'Task started but no wincrust process appeared. Last lines of the log:'
        if (Test-Path $LogFile) { Get-Content $LogFile -Tail 10 | ForEach-Object { "    $_" } }
        Write-Warn 'If you are on SSH, the task cannot start until you are logged in at the desktop.'
        exit 1
    }
    return
}

if ($Stop) {
    # Deliberately NOT guarded on the task existing. Unregistering a task does
    # not stop a running server, so a stop that refuses when the task is gone
    # leaves an elevated, network-listening process alive - the one outcome
    # -Stop must never produce. The task is stopped if it is there; the
    # process is killed either way.
    if (Test-TaskRegistered) {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    } else {
        Write-Host "scheduled task '$TaskName' is not registered - stopping any orphaned process anyway"
    }
    $was = @(Get-Process wincrust -ErrorAction SilentlyContinue)
    Stop-Server
    if ($was.Count -gt 0) {
        Write-Host "stopped $($was.Count) running wincrust process(es)"
    } else {
        Write-Host 'no wincrust process was running'
    }
    return
}

if ($Uninstall) {
    Write-Step "Removing scheduled task '$TaskName'"
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-Step 'Stopping any running server'
    Stop-Server
    if (Test-Path $Dir) {
        Write-Step "Removing $Dir"
        Remove-Item -Recurse -Force $Dir
    }
    Write-Host ''
    Write-Host 'Removed. The binary is untouched; `cargo uninstall wincrust` removes it.'
    Write-Host 'On the client: claude mcp remove wincrust -s user'
    return
}

# --- elevation ---------------------------------------------------------------

# Checked before the install, because `cargo install` takes minutes and finding
# out afterwards is the expensive way to learn this. Registering a task with
# -RunLevel Highest needs an admin token; that flag is what clears UIPI, which
# is what lets the server act on elevated windows at all.
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$elevated = (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $elevated) {
    Write-Host 'This needs an elevated PowerShell.' -ForegroundColor Yellow
    Write-Host ''
    Write-Host '  The scheduled task is registered with -RunLevel Highest, which Windows will'
    Write-Host '  not let a non-elevated process create. That flag is not optional: it is what'
    Write-Host '  clears UIPI, and without it the server cannot act on elevated windows.'
    Write-Host ''
    Write-Host '  Open PowerShell as Administrator and run this again.'
    Write-Host ''
    Write-Host '  Only setup needs it. -Status, -Logs, -Start and -Stop do not.'
    exit 1
}

# --- the binary -------------------------------------------------------------

if (-not $SkipInstall) {
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        throw 'cargo not found. Install Rust from https://rustup.rs, then re-run.'
    }
    Write-Step 'Installing wincrust from crates.io'
    cargo install wincrust --force
    if ($LASTEXITCODE -ne 0) { throw "cargo install failed with exit code $LASTEXITCODE" }
}

$Exe = Join-Path $env:USERPROFILE '.cargo\bin\wincrust.exe'
if (-not (Test-Path $Exe)) { throw "wincrust.exe not found at $Exe" }
Write-Host "  binary: $Exe  ($(& $Exe --version))"

# --- addresses --------------------------------------------------------------

if (-not $ListenIp) {
    $ts = 'C:\Program Files\Tailscale\tailscale.exe'
    if (Test-Path $ts) {
        $ListenIp = (& $ts ip -4 2>$null | Select-Object -First 1)
    }
    if (-not $ListenIp) {
        throw 'Could not detect a Tailscale IP. Pass -ListenIp explicitly.'
    }
    Write-Host "  detected Tailscale IP: $ListenIp"
}

# Named $ipAllow, not $allow: PowerShell variable names are case-insensitive,
# so a local $allow silently becomes the $Allow parameter and vice versa. That
# is not a hypothetical - it wrote the client IP into the launch allowlist.
$ipAllow = ($ClientIp | ForEach-Object { $_.Trim() } | Where-Object { $_ }) -join ','
if (-not $ipAllow) { throw '-ClientIp resolved to nothing.' }

# --- the key ----------------------------------------------------------------

New-Item -ItemType Directory -Force -Path $Dir | Out-Null

if ($RotateKey -and (Test-Path $KeyFile)) {
    Write-Warn 'Rotating the key. Every configured client will start getting 401.'
    Remove-Item $KeyFile -Force
}

if (Test-Path $KeyFile) {
    Write-Step 'Reusing the existing auth key'
    $key = (Get-Content $KeyFile -Raw).Trim()
} else {
    Write-Step 'Generating an auth key'
    # RandomNumberGenerator::Fill is .NET Core only, so it throws under
    # Windows PowerShell 5.1 - which is what `powershell` resolves to, and
    # therefore what the Taskfile and most people actually run. Create() +
    # GetBytes exists in both .NET Framework 4.x and .NET 5+.
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    $key = [Convert]::ToBase64String($bytes)
    try {
        Set-Content -Path $KeyFile -Value $key -NoNewline -Encoding ASCII -ErrorAction Stop
    } catch {
        # The usual cause is a leftover key written by the elevated scheduled
        # task, which a non-elevated run cannot overwrite. Say that, rather
        # than leaving an UnauthorizedAccessException to be interpreted.
        Write-Host ''
        Write-Warn "Cannot write $KeyFile"
        Write-Warn $_.Exception.Message
        Write-Host ''
        Write-Host '  Usually a leftover file from a previous elevated run. Clear it and retry:'
        Write-Host "    .\scripts\wincrust-serve.ps1 -Uninstall"
        Write-Host "    Remove-Item -Recurse -Force `"$Dir`""
        Write-Host '  If that also says access denied, run it from an elevated PowerShell once.'
        exit 1
    }
}

# --- the launch allowlist ----------------------------------------------------

if ($Allow) {
    $names = $Allow |
        ForEach-Object { $_ -split ',' } |
        ForEach-Object { $_.Trim().ToLowerInvariant() } |
        Where-Object { $_ } |
        Select-Object -Unique
    Write-Step "Writing $AllowFile"
    $header = @(
        '# Applications `launch` may start. One name per line; # comments.',
        '# Matched exactly and case-insensitively - there is no way to run an',
        '# arbitrary command, and an absent or empty file permits nothing.'
    )
    Set-Content -Path $AllowFile -Value ($header + $names) -Encoding ASCII
    Write-Host "  permitted: $($names -join ', ')"
}

# --- the launcher -----------------------------------------------------------

Write-Step "Writing $Launcher"
$launcherBody = @"
# Generated by wincrust-serve.ps1. Edit the flags here, then:
#   Stop-ScheduledTask -TaskName $TaskName; Start-ScheduledTask -TaskName $TaskName
# The key is read from disk at launch, so it never appears in the task
# definition or in any process command line.
`$env:WINCRUST_AUTH_KEY = (Get-Content "$KeyFile" -Raw).Trim()
`$env:RUST_LOG = "info"
& "$Exe" serve --transport http --host $ListenIp --port $Port --ip-allowlist $ipAllow *>> "$LogFile"
"@
try {
    Set-Content -Path $Launcher -Value $launcherBody -Encoding UTF8 -ErrorAction Stop
} catch {
    Write-Warn "Cannot write $Launcher"
    Write-Warn $_.Exception.Message
    Write-Host "  Clear the directory and retry: Remove-Item -Recurse -Force `"$Dir`""
    exit 1
}

# --- the task ---------------------------------------------------------------

Write-Step "Registering scheduled task '$TaskName'"
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
Stop-Server

$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-WindowStyle Hidden -NonInteractive -ExecutionPolicy Bypass -File `"$Launcher`""
# Interactive: the desktop session, not session 0.
# Highest: clears UIPI, so elevated windows are reachable.
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME

Register-ScheduledTask -TaskName $TaskName -Action $action -Principal $principal `
    -Settings $settings -Trigger $trigger -Force | Out-Null

Write-Step 'Starting'
Start-ScheduledTask -TaskName $TaskName

$proc = $null
foreach ($i in 1..15) {
    Start-Sleep -Seconds 1
    $proc = Get-Process wincrust -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($proc) { break }
}

Write-Host ''
if (-not $proc) {
    Write-Warn 'The server did not start. Last lines of the log:'
    if (Test-Path $LogFile) { Get-Content $LogFile -Tail 10 | ForEach-Object { "    $_" } }
    Write-Warn 'If you ran this over SSH, the task cannot start until you are logged in at the desktop.'
    exit 1
}

# Session 0 is the failure this whole arrangement exists to avoid, and it does
# not announce itself - the server runs, binds and returns nothing. Check.
if ($proc.SessionId -eq 0) {
    Write-Warn "Running in SESSION 0. It will bind and return an empty window list forever."
    Write-Warn 'Log in at the desktop and re-run, or start the task from an interactive session.'
} else {
    Write-Host "  running in session $($proc.SessionId) - the interactive desktop" -ForegroundColor Green
}

# Match on the owning process, not just the port. Another process holding
# $Port would otherwise produce a confident "listening on ..." line for a
# server that never bound at all - the success message reporting someone
# else's socket.
$listening = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
    Where-Object { $_.OwningProcess -eq $proc.Id } | Select-Object -First 1
if ($listening) {
    Write-Host "  listening on $($listening.LocalAddress):$($listening.LocalPort)" -ForegroundColor Green
} else {
    Write-Warn "Process is up but is not listening on a port yet. Check the log:"
    Write-Warn "  Get-Content `"$LogFile`" -Tail 20"
}

$allowCount = 0
if (Test-Path $AllowFile) {
    $allowCount = @(Get-Content $AllowFile |
        Where-Object { $_.Trim() -and -not $_.Trim().StartsWith('#') }).Count
}
if ($allowCount -eq 0) {
    # Said out loud because the failure is otherwise discovered mid-task, when
    # `launch` refuses and the caller falls back to Start-Process.
    # Single-quoted: in a double-quoted string a backtick is the escape
    # character, so the quoting marks around `launch` were being eaten.
    Write-Warn 'launch allowlist is empty - `launch` will refuse every application.'
    Write-Warn "  Re-run with -Allow notepad,someapp  (or edit $AllowFile)"
} else {
    Write-Host "  launch allowlist: $allowCount entr$(if ($allowCount -eq 1) { 'y' } else { 'ies' })" -ForegroundColor Green
}

Write-Host ''
Write-Host 'On the client machine:' -ForegroundColor Cyan
Write-Host ''
Write-Host "  claude mcp add --transport http --scope user wincrust ``"
Write-Host "    `"http://${ListenIp}:${Port}/mcp`" ``"
Write-Host "    --header `"Authorization: Bearer $key`""
Write-Host ''
Write-Host 'Manage it with:'
Write-Host "  Start-ScheduledTask -TaskName $TaskName"
Write-Host "  Stop-ScheduledTask  -TaskName $TaskName"
Write-Host "  Get-Content `"$LogFile`" -Tail 20"
