#Requires -Version 7.2
# Build the admission helper and render the current-user Windows NSIS overlay.
# Emits exactly one config path on stdout; invoke under the release build wrapper.
[CmdletBinding()]
param(
  [ValidateSet('x86_64-pc-windows-msvc')][string]$Target = 'x86_64-pc-windows-msvc'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $IsWindows) { throw 'NSIS preparation requires Windows.' }
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$stage = Join-Path $repo "target/csq-nsis/$Target"
New-Item -ItemType Directory -Force -Path $stage | Out-Null
# Cargo's emitted executable is used only after this exact producing command succeeds.
$lines = @(& cargo build --manifest-path (Join-Path $repo 'Cargo.toml') --locked `
  --release --package csq-core --bin csq-installer-admission --no-default-features `
  --target $Target --message-format=json-render-diagnostics)
if ($LASTEXITCODE -ne 0) { throw 'Installer admission helper build failed.' }
$artifacts = @($lines | ForEach-Object {
  try { $event = $_ | ConvertFrom-Json } catch { return }
  if ($event.reason -eq 'compiler-artifact' -and $event.target.name -eq 'csq-installer-admission' `
      -and $event.executable) { $event.executable }
})
if ($artifacts.Count -ne 1) { throw 'Expected exactly one helper executable artifact.' }
$helper = [IO.Path]::GetFullPath($artifacts[0])
if (-not (Test-Path -LiteralPath $helper -PathType Leaf)) { throw 'Helper executable missing.' }
$helperBytes = [IO.File]::ReadAllBytes($helper)
if ($helperBytes.Length -lt 2 -or $helperBytes[0] -ne 0x4d -or $helperBytes[1] -ne 0x5a) {
  throw 'Helper executable is not a PE image.'
}
$digest = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($helperBytes)).ToLowerInvariant()
$payload = Join-Path $stage 'csq-installer-admission.exe'
[IO.File]::WriteAllBytes($payload, $helperBytes)
function Replace-Exactly([string]$Text, [string]$Token, [string]$Value, [int]$Expected) {
  $count = ([regex]::Matches($Text, [regex]::Escape($Token))).Count
  if ($count -ne $Expected) { throw "Template token $Token count $count, expected $Expected" }
  return $Text.Replace($Token, $Value)
}
function Escape-Nsis([string]$Value) {
  return $Value.Replace('$', '$$').Replace('"', '$\"').Replace('`', '$\`')
}
$gate = [IO.File]::ReadAllText((Join-Path $repo 'csq/windows/upgrade-gate.nsh'))
$gate = Replace-Exactly $gate '@CSQ_HELPER_SHA256@' $digest 3
$gate = Replace-Exactly $gate '@CSQ_HELPER_PAYLOAD@' (Escape-Nsis $payload) 1
$template = [IO.File]::ReadAllText((Join-Path $repo 'csq/windows/installer.nsi'))
$template = Replace-Exactly $template '@CSQ_UPGRADE_GATE_INLINE@' $gate 1
$templatePath = Join-Path $stage 'installer.nsi'
[IO.File]::WriteAllText($templatePath, $template, [Text.UTF8Encoding]::new($false))
# This is the single Windows override: explicitly removes MSI from this S2a build.
$overlay = @{
  bundle = @{
    targets = @('nsis')
    windows = @{
      nsis = @{ installMode = 'currentUser'; template = $templatePath }
    }
  }
}
$configPath = Join-Path $stage 'tauri.nsis.conf.json'
[IO.File]::WriteAllText($configPath, ($overlay | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
# Build integration consumes this path with `npx @tauri-apps/cli build --config PATH`.
# This script does not sign/build an installer. The installer is trusted as delivered:
# updater minisign covers its compiled helper hash; manual installers retain existing trust.
Write-Output $configPath
