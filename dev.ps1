# Run a command in the GotAuth dev container (Windows PowerShell 5.1 or PowerShell 7).
#
#   .\dev.ps1 uv sync --locked --all-extras
#   .\dev.ps1 uv run poe check
#   .\dev.ps1                      interactive shell
#   .\dev.ps1 --ports <command>    also publish the dev server ports on 127.0.0.1
#   .\dev.ps1 --build <command>    rebuild the image first (after changes in docker/)
#   .\dev.ps1 --down               stop this worktree's containers (volumes are kept)
#
# The Compose project name is this folder's name, so each git worktree gets its own
# containers, virtual environment, Postgres and Redis. Git Bash: ./dev.sh

$ErrorActionPreference = 'Stop'

# Same normalization as Compose: lower case, only [a-z0-9_-], no leading "_" or "-".
$project = ((Split-Path -Leaf $PSScriptRoot).ToLowerInvariant() -replace '[^a-z0-9_-]', '').TrimStart('_', '-')
if (-not $project) { $project = 'gotauth' }

$runArgs = @('--rm')
$build = $false
$down = $false
$index = 0
while ($index -lt $args.Count) {
    $option = [string]$args[$index]
    if ($option -eq '--ports') { $runArgs += '--service-ports' }
    elseif ($option -eq '--build') { $build = $true }
    elseif ($option -eq '--down') { $down = $true }
    else { break }
    $index++
}
$command = @()
if ($index -lt $args.Count) { $command = @($args[$index..($args.Count - 1)]) }
if ($command.Count -eq 0) { $command = @('bash') }

# No TTY when input or output is redirected (agents, CI, pipes).
if ([Console]::IsInputRedirected -or [Console]::IsOutputRedirected) { $runArgs += '-T' }

$previousProject = $env:COMPOSE_PROJECT_NAME
$env:COMPOSE_PROJECT_NAME = $project
Push-Location $PSScriptRoot
try {
    if ($down) {
        docker compose down --remove-orphans
        exit $LASTEXITCODE
    }
    # Shared caches (see compose.yaml). "docker volume create" is a no-op if they exist.
    docker volume create gotauth-uv-cache | Out-Null
    docker volume create gotauth-pnpm-store | Out-Null
    if ($build) {
        docker compose build dev
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }
    docker compose run @runArgs dev @command
    exit $LASTEXITCODE
}
finally {
    Pop-Location
    $env:COMPOSE_PROJECT_NAME = $previousProject
}
