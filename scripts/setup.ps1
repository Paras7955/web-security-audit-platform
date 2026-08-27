[CmdletBinding()]
param(
    [switch]$BootstrapOnly,
    [switch]$SkipOsvUpdate,
    [ValidateNotNullOrEmpty()]
    [string]$EnvFile = ".env"
)

$ErrorActionPreference = "Stop"
$BootstrapImage = "python:3.12.13-slim-bookworm@sha256:8a7e7cc04fd3e2bd787f7f24e22d5d119aa590d429b50c95dfe12b3abe52f48b"
$RepoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$EnvironmentFileName = [System.IO.Path]::GetFileName($EnvFile)
if ($EnvironmentFileName -ne $EnvFile) {
    throw "The environment file must be a filename in the ScopeHarbor repository root."
}
$EnvironmentPath = [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $EnvFile))
$RootPrefix = $RepoRoot.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar

if (-not $EnvironmentPath.StartsWith($RootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "The environment file must be a filename in the ScopeHarbor repository root."
}

function Invoke-CheckedCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code $LASTEXITCODE: $FilePath"
    }
}

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw "Docker is required. Install Docker Desktop before continuing."
}

& docker compose version *> $null
if ($LASTEXITCODE -ne 0) {
    throw 'Docker Compose v2 is required (the "docker compose" command).'
}

& docker info *> $null
if ($LASTEXITCODE -ne 0) {
    throw "The Docker daemon is not available. Start Docker Desktop and retry."
}

Push-Location $RepoRoot
$BootstrapTemp = Join-Path ([System.IO.Path]::GetTempPath()) ("scopeharbor-bootstrap-" + [System.Guid]::NewGuid().ToString("N"))
try {
    Write-Host "Preparing ScopeHarbor environment with an isolated bootstrap container..."
    New-Item -ItemType Directory -Path $BootstrapTemp | Out-Null
    $BootstrapOutput = Join-Path $BootstrapTemp "environment"
    if (Test-Path -LiteralPath $EnvironmentPath -PathType Leaf) {
        Copy-Item -LiteralPath $EnvironmentPath -Destination $BootstrapOutput
    }
    $BootstrapArguments = @(
        "run", "--rm",
        "--network", "none",
        "--read-only",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges:true",
        "--tmpfs", "/tmp:size=16m,mode=0700",
        "--volume", "${RepoRoot}:/workspace:ro",
        "--volume", "${BootstrapTemp}:/output",
        "--workdir", "/workspace",
        $BootstrapImage,
        "python", "scripts/bootstrap_env.py",
        "--output", "/output/environment",
        "--template", ".env.example"
    )
    Invoke-CheckedCommand -FilePath "docker" -Arguments $BootstrapArguments
    Move-Item -LiteralPath $BootstrapOutput -Destination $EnvironmentPath -Force

    if ($BootstrapOnly) {
        Write-Host "Environment bootstrap complete."
        return
    }

    if (-not $SkipOsvUpdate) {
        Write-Host "Updating the isolated offline OSV advisory database..."
        Invoke-CheckedCommand -FilePath "docker" -Arguments @(
            "compose", "--env-file", $EnvFile, "--profile", "maintenance",
            "run", "--rm", "osv-db-update"
        )
    }
    else {
        Write-Host "Skipping the offline OSV update by explicit request."
    }

    Write-Host "Building and starting ScopeHarbor..."
    Invoke-CheckedCommand -FilePath "docker" -Arguments @(
        "compose", "--env-file", $EnvFile, "up", "--build", "--detach", "--wait"
    )

    Write-Host ""
    Write-Host "ScopeHarbor is ready."
    Write-Host "  UI:           http://localhost:3001"
    Write-Host "  API docs:     http://localhost:8000/docs"
    Write-Host "  Readiness:    http://localhost:8000/ready"
    Write-Host "  Demo target:  http://localhost:3000"
    Write-Host ""
    Write-Host "Stop without deleting data:"
    Write-Host "  docker compose down"
}
finally {
    Pop-Location
    if (Test-Path -LiteralPath $BootstrapTemp) {
        Remove-Item -LiteralPath $BootstrapTemp -Recurse -Force
    }
}
