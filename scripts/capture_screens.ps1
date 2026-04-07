param(
  [string]$OutDir,
  [string]$BaseUrl
)

$ErrorActionPreference = 'Stop'

if (-not $OutDir) { $OutDir = 'screens' }
if (-not $BaseUrl) { $BaseUrl = 'http://localhost:5000' }

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

# Prefer Edge if available; fallback to Chrome
$edge = "$Env:ProgramFiles (x86)\Microsoft\Edge\Application\msedge.exe"
$chrome = "$Env:ProgramFiles\Google\Chrome\Application\chrome.exe"
if (-not (Test-Path $edge) -and -not (Test-Path $chrome)) {
  throw 'Edge/Chrome not found. Please install Microsoft Edge or Google Chrome.'
}
$bin = if (Test-Path $edge) { $edge } else { $chrome }

function Shot($name, $url) {
  & $bin `
    --headless=new `
    --disable-gpu `
    --window-size=1280,800 `
    --screenshot="$OutDir/$name.png" `
    "$url" | Out-Null
}

Shot 'home'       "$BaseUrl/#home"
Shot 'samples'    "$BaseUrl/#samples"
Shot 'static'     "$BaseUrl/#static"
Shot 'deepstatic' "$BaseUrl/#deepstatic"
Shot 'dynamic'    "$BaseUrl/#dynamic"
Shot 'network'    "$BaseUrl/#network"
Shot 'yara'       "$BaseUrl/#yara"
Shot 'reports'    "$BaseUrl/#reports"

Write-Host "Screenshots saved to $OutDir"


