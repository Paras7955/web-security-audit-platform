[CmdletBinding()]
param(
    [switch]$BootstrapOnly,
    [switch]$SkipOsvUpdate,
    [ValidateNotNullOrEmpty()]
    [string]$EnvFile = ".env",
    [ValidatePattern('^[a-z0-9][a-z0-9_-]*$')]
    [string]$ProjectName = "scopeharbor"
)

$ErrorActionPreference = "Stop"
$BootstrapImage = "python:3.12.13-slim-bookworm@sha256:8a7e7cc04fd3e2bd787f7f24e22d5d119aa590d429b50c95dfe12b3abe52f48b"
$RepoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$EnvironmentFilePattern = '^\.env(?:\.[A-Za-z0-9][A-Za-z0-9._-]*)?$'
if ($EnvFile -notmatch $EnvironmentFilePattern) {
    throw "The environment file must be .env or a .env.* filename in the ScopeHarbor repository root."
}
if ($EnvFile -ieq ".env.example") {
    throw ".env.example is the tracked public template and cannot be used as an output environment file."
}
$EnvironmentFileName = [System.IO.Path]::GetFileName($EnvFile)
if ($EnvironmentFileName -ne $EnvFile) {
    throw "The environment file must be a filename in the ScopeHarbor repository root."
}
$EnvironmentPath = [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $EnvFile))
$RootPrefix = $RepoRoot.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar

if (-not $EnvironmentPath.StartsWith($RootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "The environment file must be a filename in the ScopeHarbor repository root."
}
if (Test-Path -LiteralPath $EnvironmentPath) {
    $EnvironmentItem = Get-Item -LiteralPath $EnvironmentPath -Force
    if (-not (Test-Path -LiteralPath $EnvironmentPath -PathType Leaf) -or
        ($EnvironmentItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
        throw "The environment file path must be a regular file, not a directory or symbolic link."
    }
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
        throw "Command failed with exit code ${LASTEXITCODE}: $FilePath"
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
$PreviousScopeHarborEnvFile = [System.Environment]::GetEnvironmentVariable("SCOPEHARBOR_ENV_FILE", "Process")
try {
    [System.Environment]::SetEnvironmentVariable("SCOPEHARBOR_ENV_FILE", $EnvFile, "Process")
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
            "compose", "--project-name", $ProjectName, "--env-file", $EnvFile,
            "--profile", "maintenance",
            "run", "--rm", "osv-db-update"
        )
    }
    else {
        Write-Host "Skipping the offline OSV update by explicit request."
    }

    Write-Host "Building and starting ScopeHarbor..."
    Invoke-CheckedCommand -FilePath "docker" -Arguments @(
        "compose", "--project-name", $ProjectName, "--env-file", $EnvFile,
        "up", "--build", "--detach", "--wait"
    )

    $FrontendAddress = (Invoke-CheckedCommand -FilePath "docker" -Arguments @(
        "compose", "--project-name", $ProjectName, "--env-file", $EnvFile,
        "port", "frontend", "3000"
    ) | Select-Object -Last 1).Trim()
    $BackendAddress = (Invoke-CheckedCommand -FilePath "docker" -Arguments @(
        "compose", "--project-name", $ProjectName, "--env-file", $EnvFile,
        "port", "backend", "8000"
    ) | Select-Object -Last 1).Trim()
    $DemoAddress = (Invoke-CheckedCommand -FilePath "docker" -Arguments @(
        "compose", "--project-name", $ProjectName, "--env-file", $EnvFile,
        "port", "juice-shop", "3000"
    ) | Select-Object -Last 1).Trim()

    Write-Host ""
    Write-Host "ScopeHarbor is ready."
    Write-Host "  UI:           http://$FrontendAddress"
    Write-Host "  API docs:     http://$BackendAddress/docs"
    Write-Host "  Readiness:    http://$BackendAddress/ready"
    Write-Host "  Demo target:  http://$DemoAddress"
    Write-Host ""
    Write-Host "Stop without deleting data:"
    Write-Host "  `$env:SCOPEHARBOR_ENV_FILE='$EnvFile'; docker compose --project-name $ProjectName --env-file $EnvFile down"
}
finally {
    [System.Environment]::SetEnvironmentVariable("SCOPEHARBOR_ENV_FILE", $PreviousScopeHarborEnvFile, "Process")
    Pop-Location
    if (Test-Path -LiteralPath $BootstrapTemp) {
        Remove-Item -LiteralPath $BootstrapTemp -Recurse -Force
    }
}
