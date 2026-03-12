# OpenCode Custom Tools for Reverse Engineering

This directory contains custom tools for binary analysis and reverse engineering.

## Available Tools

### Binary Analysis (radare2)
| Tool | Purpose |
|------|---------|
| `r2triage` | First-pass analysis: functions, imports, exports, strings, risk indicators |
| `r2analyze` | Targeted r2 commands with persistent session |
| `r2decompile` | Pseudocode generation via r2ghidra/pdc |
| `r2xref` | Cross-reference lookup (callers/callees) |

### Static Analysis
| Tool | Purpose |
|------|---------|
| `arch_check` | Architecture detection, format ID, container compatibility |
| `strings_extract` | Multi-encoding string extraction (ASCII/Unicode) |
| `objdump_disasm` | Intel-syntax disassembly, architecture-aware |
| `binwalk_analyze` | Embedded file extraction and entropy analysis |
| `yarascan` | YARA + heuristic scanning for languages, packers, crypto |
| `floss_extract` | FLARE FLOSS obfuscated string extraction |

### Dynamic Analysis
| Tool | Purpose |
|------|---------|
| `gdb_debug` | GDB command execution, breakpoints, register/memory inspection |
| `emulate` | Unicorn Engine emulation with register snapshots |
| `frida_hook` | Dynamic instrumentation via Frida |
| `fuzz_concolic` | Concolic fuzzing with symbolic inputs |
| `fuzz_harness_gen` | Generate fuzzing harnesses |

### Exploitation & Solving
| Tool | Purpose |
|------|---------|
| `symbolic_solve` | Symbolic execution to solve constraints |
| `generate_exploit_script` | Auto-generate exploit scripts |
| `crypto_solver` | Reverse custom encryption, decode obfuscated data |
| `hashcat_crack` | CPU-mode hash cracking with agent-generated wordlists |

### Network & Web
| Tool | Purpose |
|------|---------|
| `http_request_recreate` | Reconstruct HTTP requests from binary analysis |
| `raw_network_request` | Send raw TCP/UDP network requests |

### APK / Mobile
| Tool | Purpose |
|------|---------|
| `apk_analyze` | Decode APK via apktool (manifest, permissions, components) |
| `apk_extract_native` | Extract native libraries from APK |
| `jadx_decompile` | Decompile APK/DEX to Java source |
| `mobsf_scan` | Static analysis via MobSF |

## Shared Infrastructure (`lib/`)

| Module | Purpose |
|--------|---------|
| `r2session.ts` | Persistent radare2 HTTP sessions |
| `logger.ts` | Structured logging with correlation IDs |
| `json_utils.ts` | JSON extraction from mixed output |
| `tool_instrument.ts` | Auto-instrumentation wrapper |
| `py_runner.ts` | Python subprocess handler |
| `emulate_helper.py` | Unicorn emulation helper |

## Usage

Once the container is running, you can use these tools in OpenCode:

```
Analyze the binary at /workspace/binaries/target use r2analyze
Debug the main function use gdb_debug
Extract all strings from the binary use strings_extract
```
