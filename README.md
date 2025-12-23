# XPFarm

XPFarm is an automated target validation and testing tool designed for penetration testers.

## Features

- **Target Validation**: Validates Domains, IPs, and URLs.
- **Categorization**: Auto-categorizes targets (Domain, WebApp, Wildcard, IP).
- **Cloudflare Detection**: Automatically excludes and flags Cloudflare IPs.
- **Strict Tool Checks**: Ensures required tools are present (`nmap`, `nuclei`, `gowitness`, `ffuf`, `findomain`).
- **Source Builds**: Builds tools from source (Go/Rust) if not found locally.

## Requirements

- **Python 3.8+**
- **Go** (Required for building tools)
- **Rust/Cargo** (Recommended for `findomain`, but optional if tool is not used)

## Installation

1. Clone the repository.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

**Basic Scan:**
```bash
python xpfarm.py -t google.com,example.com
```

**Scan with Stats Table (`-s`)**:
```bash
python xpfarm.py -t targets.txt -s
```

**Allow Cloudflare Targets (`-cf`)**:
```bash
python xpfarm.py -t discord.com -cf
```

## Tools

The script will automatically attempt to setup the following tools if they are missing from your PATH:
- `nuclei` (Go)
- `gowitness` (Go)
- `ffuf` (Go)
- `findomain` (Rust/Cargo)

`nmap` must be installed manually on your system.
