# Copy a demonstration profile into the working tree.
# Usage: .\scripts\reset-demo.ps1 -State <vulnerable|fixed|agent-secret-only|agent-image-only>
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("vulnerable", "fixed", "agent-secret-only", "agent-image-only")]
    [string]$State
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot

Copy-Item -Force (Join-Path $Root "demo-states\$State\app.py") (Join-Path $Root "app.py")
Copy-Item -Force (Join-Path $Root "demo-states\$State\Dockerfile") (Join-Path $Root "Dockerfile")

Write-Host "Working tree reset to the '$State' profile (app.py, Dockerfile)."
Write-Host "Next: git add app.py Dockerfile; git commit -m `"demo: $State state`"; git push"
