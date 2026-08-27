# Mirrors the ceiling CI enforces. Single-binary deployment is a stated goal;
# a jump here means a dependency crept in that undercuts the reason this exists.
$ErrorActionPreference = 'Stop'
$exe = 'target/release/wincrust.exe'
if (-not (Test-Path $exe)) { throw "$exe not found - run a release build first" }
$mb = (Get-Item $exe).Length / 1MB
Write-Host ('wincrust.exe: {0:N2} MB' -f $mb)
if ($mb -gt 12) { throw "binary grew past 12 MB ($([math]::Round($mb, 2)) MB)" }
