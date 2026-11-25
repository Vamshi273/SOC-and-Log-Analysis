# Apache Access Log Analyzer

A Python-based defensive security tool for analyzing Apache HTTP access logs, identifying suspicious web activity, and generating security reports.

## Features

- Apache Combined Access Log parsing
- HTTP request and response analysis
- URL decoding and suspicious payload inspection
- SQL injection detection
- Cross-Site Scripting (XSS) detection
- Directory traversal detection
- Automated web scanner identification
- Repeated authentication failure monitoring
- Possible brute-force attack detection
- Possible directory scanning detection
- MITRE ATT&CK technique mapping
- CSV and JSON report generation
- Command-line interface
- Automated testing with pytest

## Project Structure

```text
04_Apache_Access_Log_Analysis/
│
├── README.md
│
├── src/
│   ├── __init__.py
│   ├── parser.py
│   ├── detector.py
│   ├── reporter.py
│   └── main.py
│
├── sample_logs/
│   └── access.log
│
└── reports/
    ├── security_alerts.csv
    └── security_alerts.json
```

## Technologies Used

- **Python** – Log processing and security analysis
- **Regular Expressions** – Suspicious pattern detection
- **Apache Access Logs** – Web server log analysis
- **JSON** – Structured security reports
- **CSV** – Tabular security reports
- **pytest** – Automated testing
- **MITRE ATT&CK** – Threat technique mapping

## Detection Capabilities

### 1. SQL Injection Detection

Identifies suspicious SQL patterns in HTTP request URLs, including UNION SELECT, SELECT FROM, and suspicious OR-based conditions.

**Severity:** High  
**MITRE ATT&CK:** T1190 – Exploit Public-Facing Application

### 2. Cross-Site Scripting (XSS) Detection

Identifies potentially malicious script-related patterns in requested URLs.

Detection indicators include:

- `<script`
- `javascript:`
- `onerror=`
- `onload=`

**Severity:** High  
**MITRE ATT&CK:** T1190 – Exploit Public-Facing Application

### 3. Directory Traversal Detection

Identifies suspicious path traversal patterns and attempts to access sensitive system files.

Detection indicators include:

- `../`
- `..\`
- `/etc/passwd`
- `/etc/shadow`

**Severity:** High  
**MITRE ATT&CK:** T1190 – Exploit Public-Facing Application

### 4. Automated Web Scanner Detection

Identifies known web vulnerability scanner signatures through HTTP User-Agent fields.

Recognized tools include:

- sqlmap
- Nikto
- Nmap
- Gobuster
- DirBuster
- WPScan

**Severity:** Medium  
**MITRE ATT&CK:** T1595 – Active Scanning

### 5. Possible Login Brute Force Detection

Detects five or more HTTP 401 authentication responses from the same source IP address.

**Severity:** High  
**MITRE ATT&CK:** T1110 – Brute Force

### 6. Possible Directory Scanning Detection

Identifies three or more HTTP 404 responses from the same source IP address.

**Severity:** Medium  
**MITRE ATT&CK:** T1595.003 – Wordlist Scanning

## Installation

Run the following command from the main repository directory:

```bash
pip install pytest
```

## Usage

### Analyze the Sample Apache Access Logs

Run from the repository root:

```powershell
$env:PYTHONPATH = ".\04_Apache_Access_Log_Analysis"
python -m src.main
```

### Display Available Options

```powershell
$env:PYTHONPATH = ".\04_Apache_Access_Log_Analysis"
python -m src.main --help
```

### Analyze a Custom Log File

```powershell
$env:PYTHONPATH = ".\04_Apache_Access_Log_Analysis"
python -m src.main --log ".\04_Apache_Access_Log_Analysis\sample_logs\access.log"
```

### Specify a Custom Report Directory

```powershell
$env:PYTHONPATH = ".\04_Apache_Access_Log_Analysis"
python -m src.main --output ".\custom_reports"
```

## Generated Reports

The analyzer generates two report formats:

| File | Description |
|---|---|
| `security_alerts.csv` | Tabular security alerts |
| `security_alerts.json` | Structured JSON security alerts |

Reports are saved in the module's `reports/` directory.

## Testing

Run the Apache project automated tests from the repository root:

```powershell
$env:PYTHONPATH = ".\04_Apache_Access_Log_Analysis"

python -m pytest `
    .\tests\test_apache_log_analysis.py `
    .\tests\test_apache_detection.py `
    .\tests\test_apache_reporter.py `
    .\tests\test_apache_cli.py -v
```

**Test Results:** 25 tests passed.

## Limitations

- Detection depends on predefined patterns and thresholds.
- HTTP 401 responses alone do not prove brute-force activity.
- HTTP 404 responses may occur during normal browsing.
- User-Agent signatures can be spoofed.
- Suspicious requests do not prove successful exploitation.
- MITRE ATT&CK mappings are contextual associations.
- The project uses synthetic Apache access logs.
- This project is not a replacement for an enterprise SIEM solution.

## Security Notice

Use this tool only on systems and logs that you own or are authorized to analyze.

Do not publish real Apache access logs containing private IP information, session identifiers, or other sensitive data.

## Project Status

**Status:** Core implementation completed.

**Automated Tests:** 25 passed.

**Documentation:** Completed.
