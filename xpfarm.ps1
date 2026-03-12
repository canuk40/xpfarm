# XPFarm - Unified CLI
# Usage: .\xpfarm.ps1 [build|up|onlyGo|down|help]

param(
    [Parameter(Position = 0)]
    [string]$Command = "help",

    [Parameter(Position = 1, ValueFromRemainingArguments)]
    [string[]]$ExtraArgs
)

$ErrorActionPreference = "Stop"

function Show-Banner {
    Write-Host " ____  ________________________                     " -ForegroundColor Magenta
    Write-Host " `u{2572}   `u{2572}`u{2571}  `u{2571}`u{2572}______   `u{2572}_   _____`u{2571}____ _______  _____  " -ForegroundColor Magenta
    Write-Host "  `u{2572}     `u{2571}  `u{2502}     ___`u{2571}`u{2502}    __) `u{2572}__  `u{2572}`u{2572}_  __ `u{2572}`u{2571}     `u{2572} " -ForegroundColor DarkMagenta
    Write-Host "  `u{2571}     `u{2572}  `u{2502}    `u{2502}    `u{2502}     `u{2572}   `u{2571} __ `u{2572}`u{2502}  `u{2502} `u{2572}`u{2571}  y y  `u{2572}" -ForegroundColor DarkCyan
    Write-Host " `u{2571}___`u{2571}`u{2572}  `u{2572} `u{2502}____`u{2502}    `u{2572}___  `u{2571}  (____  `u{2571}__`u{2502}  `u{2502}__`u{2502}_`u{2502}  `u{2571}" -ForegroundColor Cyan
    Write-Host "       `u{2572}_`u{2571}               `u{2572}`u{2571}        `u{2572}`u{2571}            `u{2572}`u{2571} " -ForegroundColor Green
    Write-Host "                                        github.com/A3-N" -ForegroundColor Green
    Write-Host ""
}

function Assert-Docker {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        Write-Host "Error: Docker is not installed" -ForegroundColor Red
        exit 1
    }
}

function Import-EnvFile {
    if (Test-Path ".env") {
        Write-Host "Loading environment variables from .env..."
        Get-Content ".env" | ForEach-Object {
            $line = $_.Trim()
            if ($line -and -not $line.StartsWith("#")) {
                $parts = $line -split "=", 2
                if ($parts.Count -eq 2) {
                    [Environment]::SetEnvironmentVariable($parts[0].Trim(), $parts[1].Trim(), "Process")
                }
            }
        }
    }
}

function Invoke-Build {
    Assert-Docker
    Show-Banner
    Import-EnvFile
    Write-Host "Building XPFarm + Overlord containers..." -ForegroundColor Yellow
    docker compose build
    Write-Host ""
    Write-Host "Build complete! Run .\xpfarm.ps1 up to start." -ForegroundColor Green
}

function Invoke-Up {
    Assert-Docker
    Show-Banner
    Import-EnvFile
    Write-Host "Starting XPFarm + Overlord..." -ForegroundColor Yellow
    docker compose up -d

    Write-Host ""
    Write-Host "Environment is running!" -ForegroundColor Green
    Write-Host "  XPFarm:   http://localhost:8888"
    Write-Host "  Overlord: Running (internal)"
    Write-Host ""
    docker compose ps
}

function Invoke-OnlyGo {
    param([string[]]$GoArgs = @())
    Show-Banner
    Write-Host "Building XPFarm (Go native, no Docker)..." -ForegroundColor Yellow
    Write-Host "Note: Overlord features require Docker." -ForegroundColor Yellow
    Write-Host ""

    go build -o xpfarm.exe main.go
    Write-Host "Build complete. Starting..." -ForegroundColor Green
    if ($GoArgs.Count -gt 0) {
        & .\xpfarm.exe @GoArgs
    } else {
        & .\xpfarm.exe
    }
}

function Invoke-Down {
    Assert-Docker
    Write-Host "Stopping all containers..." -ForegroundColor Yellow
    docker compose down
    Write-Host "Environment stopped." -ForegroundColor Green
}

function Show-Help {
    Show-Banner
    Write-Host "Usage: " -NoNewline
    Write-Host ".\xpfarm.ps1" -NoNewline -ForegroundColor White
    Write-Host " <command>"
    Write-Host ""
    Write-Host "Commands:"
    Write-Host "  build" -NoNewline -ForegroundColor White; Write-Host "       Build the Docker containers (XPFarm + Overlord)"
    Write-Host "  up" -NoNewline -ForegroundColor White; Write-Host "          Start the environment (docker compose up)"
    Write-Host "  onlyGo" -NoNewline -ForegroundColor White; Write-Host "      Compile and run Go binary directly (no Docker, no Overlord)"
    Write-Host "  down" -NoNewline -ForegroundColor White; Write-Host "        Stop all Docker containers"
    Write-Host "  help" -NoNewline -ForegroundColor White; Write-Host "        Show this help message"
    Write-Host ""
    Write-Host "Examples:"
    Write-Host "  .\xpfarm.ps1 build" -NoNewline; Write-Host "        # Build containers" -ForegroundColor Green
    Write-Host "  .\xpfarm.ps1 up" -NoNewline; Write-Host "           # Start full stack" -ForegroundColor Green
    Write-Host "  .\xpfarm.ps1 onlyGo" -NoNewline; Write-Host "       # Dev mode, Go only" -ForegroundColor Green
}

switch ($Command) {
    "build"    { Invoke-Build }
    "up"       { Invoke-Up }
    "onlyGo"   { Invoke-OnlyGo -GoArgs $ExtraArgs }
    "down"     { Invoke-Down }
    default    { Show-Help }
}
