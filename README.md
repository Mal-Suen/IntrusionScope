# IntrusionScope

A cross-platform fast host forensics and threat hunting tool.

## Overview

IntrusionScope is a powerful host-based forensic artifact collection and threat detection tool designed for incident responders and threat hunters. It provides:

- **Multi-platform Support**: Works on Windows, Linux, and macOS
- **Comprehensive Artifact Collection**: Processes, network connections, filesystem, registry, logs
- **Threat Detection**: IOC matching, Sigma rules, YARA patterns
- **Custom Query Language**: IFQL (IntrusionScope Forensic Query Language)
- **Extensible Architecture**: Plugin-based collectors and detectors

## Features

### Collectors

#### Process Collectors
- Running process list with full details (PID, PPID, name, exe, cmdline, user)
- Process tree with parent-child relationships
- Open files by process
- Memory usage information

#### Network Collectors
- Active TCP/UDP connections with process mapping
- Listening ports
- DNS cache entries
- ARP cache
- Hosts file entries

#### Filesystem Collectors
- Recently modified files
- File hash computation (MD5, SHA1, SHA256)
- Bash history (Linux)
- Cron jobs (Linux)
- Systemd services (Linux)
- Scheduled tasks (Windows)
- Autorun entries (Windows)
- SUID/SGID files (Linux)

#### Registry Collectors (Windows)
- Run/RunOnce keys
- Services configuration
- Persistence mechanisms
- USB device history
- UserAssist entries
- Installed software

#### Log Collectors
- Authentication logs (auth.log, secure)
- Syslog
- wtmp/btmp login history
- Auditd logs
- Systemd journal
- Windows Event Logs
- Web server logs

### Detection Engine

The Rust-based detection engine provides:
- **IOC Detection**: Hash, IP, domain, URL matching
- **Sigma Rules**: YAML-based detection rules
- **YARA Patterns**: Pattern matching for files and memory
- **Aho-Corasick Matcher**: Fast multi-pattern matching

### IFQL Query Language

Query collected data using SQL-like syntax:

```sql
SELECT name, pid, exe FROM process.list WHERE name LIKE '%powershell%'
SELECT * FROM network.connections WHERE state = 'ESTABLISHED' AND remote_port = 443
SELECT * FROM log.auth WHERE type = 'failed_login' LIMIT 100
```

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/Mal-Suen/IntrusionScope.git
cd IntrusionScope

# Build
go build -o intrusionscope ./cmd/intrusionscope

# Build Rust engine (optional, for advanced detection)
cd engine && cargo build --release
```

### Prerequisites

- Go 1.21 or later
- Rust 1.70 or later (for detection engine)
- Platform-specific build tools

## Usage

### Basic Commands

```bash
# Show help
intrusionscope --help

# Show version
intrusionscope version

# Collect all artifacts
intrusionscope collect --all

# Collect specific artifacts
intrusionscope collect --artifacts process.list,network.connections

# Run a playbook
intrusionscope run --playbook quick_triage.yaml

# Query collected data
intrusionscope query "SELECT * FROM process.list WHERE name LIKE '%cmd%'"

# Output formats
intrusionscope collect --all --output json --file results.json
intrusionscope collect --all --output csv --file results.csv
```

### Configuration

Configuration file: `configs/default.conf`

```yaml
output:
  format: json
  directory: ./output

collection:
  timeout: 300
  parallel: true

logging:
  level: info
  file: intrusionscope.log
```

## Project Structure

```
IntrusionScope/
├── cmd/
│   └── intrusionscope/     # Main CLI entry point
├── pkg/
│   ├── collector/          # Artifact collectors
│   ├── detector/           # Detection interfaces
│   ├── ifql/               # Query language parser & executor
│   ├── artifact/           # Artifact definitions
│   └── signature/          # Signature management
├── internal/
│   ├── config/             # Configuration handling
│   └── output/             # Output formatting
├── engine/                 # Rust detection engine
├── artifacts/
│   └── builtin/            # Built-in artifact definitions
├── configs/
│   └── playbooks/          # Investigation playbooks
└── README.md
```

## Development

### Adding a New Collector

1. Create a new file in `pkg/collector/`
2. Implement the `Collector` interface:

```go
type Collector interface {
    Name() string
    Description() string
    Platform() string
    IsAvailable() bool
    Collect(ctx context.Context, opts *Options) (*Result, error)
}
```

3. Register the collector in `registry.go`

### Adding Detection Rules

Place Sigma rules in `artifacts/builtin/` as YAML files:

```yaml
name: suspicious_powershell
description: Detects suspicious PowerShell execution
severity: high
detection:
  condition: selection
  selection:
    - process.name: powershell.exe
      process.cmdline|contains: '-enc'
```

## License

MIT License

## Contributing

Contributions are welcome! Please read the contributing guidelines before submitting PRs.

## Acknowledgments

Inspired by:
- [Velociraptor](https://github.com/Velocidex/velociraptor)
- [OSQuery](https://github.com/osquery/osquery)
- [Sigma](https://github.com/SigmaHQ/sigma)
