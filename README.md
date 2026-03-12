# XPFarm

An open-source vulnerability scanner that wraps well-known open-source security tools behind a single web UI.

![Dashboard](img/dashboard.png)

## Why

Tools like [Assetnote](https://www.assetnote.io/) are great — well maintained, up to date, and transparent about vulnerability identification. But they're not open source. There's no need to reinvent the wheel either, as plenty of solid open-source tools already exist. XPFarm just wraps them together so you can have a vulnerability scanner that's open source and less corporate.

The focus was on building a vuln scanner where you can also see what fails or gets removed in the background, instead of wondering about that mystery.

## Wrapped Tools

- [Subfinder](https://github.com/projectdiscovery/subfinder) — subdomain discovery
- [Naabu](https://github.com/projectdiscovery/naabu) — port scanning
- [Httpx](https://github.com/projectdiscovery/httpx) — HTTP probing
- [Nuclei](https://github.com/projectdiscovery/nuclei) — vulnerability scanning
- [Nmap](https://nmap.org/) — network scanning
- [Katana](https://github.com/projectdiscovery/katana) — crawling
- [URLFinder](https://github.com/projectdiscovery/urlfinder) — URL discovery
- [Gowitness](https://github.com/sensepost/gowitness) — screenshots
- [Wappalyzer](https://github.com/projectdiscovery/wappalyzergo) — technology detection
- [CVEMap](https://github.com/projectdiscovery/cvemap) — CVE mapping

![Discovery Paths](img/Disc_Paths.png)

## Overlord — AI Binary Analysis

Overlord is a built-in AI agent powered by [OpenCode](https://opencode.ai) that can analyze binaries, archives, and other files. Upload a binary and chat with it — the agent uses tools like radare2, strings, file triage, and more to investigate your target.

- **Live streaming output** — see thinking, tool calls, and results as they happen
- **Session history** — switch between previous analysis sessions, auto-restored on page refresh
- **Multi-provider support** — Anthropic, OpenAI, Groq, Ollama (local), and 15+ more
- **Stop button** — abort long-running analysis at any time

![Overlord Status](img/O_status.png)

![Overlord Prompt](img/O_prompt.png)

## Setup

```bash
# Using the helper scripts (recommended)
./xpfarm.sh build     # Build all containers
./xpfarm.sh up        # Start everything

# Windows
.\xpfarm.ps1 build
.\xpfarm.ps1 up

# Standard Docker
docker compose up --build

# Build from source (no Overlord)
go build -o xpfarm
./xpfarm
./xpfarm -debug
```

## Screenshots

![Set Target](img/Set_target.png)

![Port Scan](img/Port_Scan.png)

![Raw Logs](img/Raw_logs.png)

## TODO

- [x] Agent Hell (Overlord)

### NTH
- [ ] SecretFinder JS
- [ ] Repo detect/scan
- [ ] Mobile scan
- [ ] Custom Module?
