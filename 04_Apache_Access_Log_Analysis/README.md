# Apache Access Log Analysis & Threat Detection

![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![Domain](https://img.shields.io/badge/Domain-Cybersecurity-red)
![Project](https://img.shields.io/badge/Project-SOC%20Analysis-purple)
![Testing](https://img.shields.io/badge/Testing-Pytest-green)

A Python-based Security Operations Center (SOC) project that analyzes Apache HTTP access logs, detects suspicious web activity, identifies potential attack patterns, and generates structured security reports.

---

## 1. Project Overview

Apache web servers generate access logs containing information about incoming HTTP requests, client IP addresses, timestamps, requested resources, response codes, and user agents.

Security analysts examine these logs to identify suspicious activities and investigate potential security incidents.

This project implements a rule-based Apache access log analyzer that:

- Parses Apache Combined Access Logs.
- Extracts HTTP request information.
- Decodes URL-encoded payloads.
- Detects SQL injection patterns.
- Identifies potential Cross-Site Scripting (XSS) attempts.
- Detects directory traversal patterns.
- Identifies automated web scanners.
- Detects repeated authentication failures.
- Identifies possible directory scanning.
- Generates JSON and CSV security reports.

The project uses a synthetic Apache access-log dataset for educational and testing purposes.

## 2. Project Objectives

1. Understand Apache access log formats.
2. Develop a Python-based log parser.
3. Identify suspicious HTTP request patterns.
4. Implement rule-based security detection.
5. Associate detected activities with relevant MITRE ATT&CK techniques.
6. Generate structured security reports.
7. Validate the implementation using automated tests.

## 3. Project Architecture

```text
             Apache Access Log
                     |
                     v
                Log Parser
                     |
                     v
              Parsed HTTP Events
                     |
                     v
               Detection Engine
                     |
          +----------+-----------+
          |          |           |
          v          v           v
       SQLi/XSS   Web Scanner  Authentication
      Traversal   Detection     Monitoring
          |          |           |
          +----------+-----------+
                     |
                     v
               Security Alerts
                     |
                     v
                Report Engine
                     |
                +----+----+
                |         |
                v         v
               JSON      CSV
```

## 4. Project Structure

```text
04_Apache_Access_Log_Analysis/
|
+-- src/
|   +-- __init__.py
|   +-- parser.py
|   +-- detector.py
|   +-- reporter.py
|   +-- main.py
|
+-- sample_logs/
|   +-- access.log
|
+-- reports/
|   +-- security_alerts.json
|   +-- security_alerts.csv
|
+-- README.md
```

Automated tests are maintained in the repository's central `tests/` directory.

## 5. Technologies Used

| Technology | Purpose |
|---|---|
| Python | Core implementation |
| Regular Expressions | Pattern-based detection |
| Apache Access Logs | Log analysis dataset |
| JSON | Structured security reports |
| CSV | Spreadsheet-compatible reports |
| Pytest | Automated testing |
| MITRE ATT&CK | Threat technique references |
| PowerShell | Windows development environment |

## 6. Detection Capabilities

### 6.1 SQL Injection Detection

Identifies suspicious SQL-related patterns in HTTP request URLs.

Detection indicators include:

- `UNION SELECT`
- `SELECT ... FROM`
- Suspicious `OR 1=1` conditions

**Severity:** HIGH

**MITRE ATT&CK:** T1190 – Exploit Public-Facing Application.

### 6.2 Cross-Site Scripting (XSS) Detection

Identifies suspicious script-related patterns in requested URLs.

Detection indicators include:

- `<script`
- `javascript:`
- `onerror=`
- `onload=`

**Severity:** HIGH

**MITRE ATT&CK:** T1190 – Exploit Public-Facing Application.

### 6.3 Directory Traversal Detection

Identifies suspicious path traversal patterns and attempts to reference sensitive system files.

Detection indicators include:

- `../`
- `..\`
- `/etc/passwd`
- `/etc/shadow`

**Severity:** HIGH

**MITRE ATT&CK:** T1190 – Exploit Public-Facing Application.

### 6.4 Automated Web Scanner Detection

Identifies known scanner signatures in HTTP User-Agent fields.

Recognized signatures:

- sqlmap
- Nikto
- Nmap
- Gobuster
- DirBuster
- WPScan

Repeated scanner events from the same source IP are aggregated into one alert.

**Severity:** MEDIUM

**MITRE ATT&CK:** T1595 – Active Scanning.

### 6.5 Possible Login Brute Force Detection

Tracks HTTP 401 authentication responses by source IP address.

Detection threshold:

- Five or more HTTP 401 responses from the same IP.

**Severity:** HIGH

**MITRE ATT&CK:** T1110 – Brute Force.

### 6.6 Possible Directory Scanning Detection

Tracks HTTP 404 responses by source IP address.

Detection threshold:

- Three or more HTTP 404 responses from the same IP.

**Severity:** MEDIUM

**MITRE ATT&CK:** T1595.003 – Wordlist Scanning.

These thresholds are simple detection heuristics and can be adjusted in the detection implementation.

## 7. Sample Dataset

The included synthetic dataset contains 17 Apache access-log entries.

It includes:

- Normal HTTP requests.
- HTTP 401 authentication failures.
- HTTP 403 forbidden responses.
- HTTP 404 missing-resource responses.
- SQL injection payloads.
- XSS payloads.
- Directory traversal attempts.
- Automated scanner User-Agent signatures.

The dataset uses documentation and private IP address ranges. It does not represent real-world attack traffic.

## 8. Installation

### Requirements

- Python 3.9 or later.
- pip.
- Git.

### Clone the Repository

```bash
git clone https://github.com/Vamshi273/SOC-and-Log-Analysis.git
cd SOC-and-Log-Analysis
```

### Install Testing Dependency

```bash
python -m pip install pytest
```

If you already have a virtual environment, activate it before running the project.

## 9. Running the Analyzer

Run these commands from the repository root.

### Windows PowerShell

Set the Python module search path:

```powershell
$env:PYTHONPATH = ".\04_Apache_Access_Log_Analysis"
```

Run the analyzer:

```powershell
python -m src.main
```

### Analyze a Custom Log File

```powershell
python -m src.main --log ".\04_Apache_Access_Log_Analysis\sample_logs\access.log"
```

### Specify a Custom Report Directory

```powershell
python -m src.main --output ".\custom_reports"
```

### Display Available CLI Options

```powershell
python -m src.main --help
```

## 10. Sample Analysis Results

Results from the included 17-line synthetic dataset:

| Metric | Result |
|---|---:|
| Total log entries | 17 |
| Successfully parsed | 17 |
| Malformed entries | 0 |
| Total security alerts | 6 |

### Detected Security Alerts

| Detection | Severity | MITRE ATT&CK | Event Count |
|---|---|---|---:|
| SQL Injection Attempt | HIGH | T1190 | 1 |
| Cross-Site Scripting | HIGH | T1190 | 1 |
| Directory Traversal | HIGH | T1190 | 1 |
| Automated Web Scanner | MEDIUM | T1595 | 3 |
| Possible Login Brute Force | HIGH | T1110 | 5 |
| Possible Directory Scanning | MEDIUM | T1595.003 | 3 |

## 11. Generated Security Reports

The reporting module generates two report formats.

### JSON Report

**File:** `reports/security_alerts.json`

Contains structured security alert information:

- Source IP address.
- Attack classification.
- Severity.
- Requested URL.
- MITRE ATT&CK reference.
- Detection evidence.
- Event count, where applicable.

### CSV Report

**File:** `reports/security_alerts.csv`

Provides spreadsheet-compatible security alerts for investigation, filtering, and analysis.

Both report files are generated by the analyzer.

## 12. Automated Testing

The project includes automated tests covering parsing, detection, reporting, and command-line execution.

Test files:

```text
tests/
|
+-- test_apache_log_analysis.py
+-- test_apache_detection.py
+-- test_apache_reporter.py
+-- test_apache_cli.py
```

Run the Apache project tests from the repository root:

```powershell
$env:PYTHONPATH = ".\04_Apache_Access_Log_Analysis"

python -m pytest `
    tests/test_apache_log_analysis.py `
    tests/test_apache_detection.py `
    tests/test_apache_reporter.py `
    tests/test_apache_cli.py -v
```

## 13. Detection Limitations

This project demonstrates basic rule-based security monitoring. It is not a production SIEM or a replacement for a full web application security monitoring solution.

Important limitations:

- Detection rules depend on predefined patterns.
- User-Agent signatures can be spoofed.
- HTTP 401 responses alone do not prove brute-force activity.
- HTTP 404 responses may occur during normal browsing.
- Threshold-based detection can miss low-frequency attacks.
- Suspicious requests do not prove successful exploitation.
- Detection is limited to information available in Apache access logs.
- MITRE ATT&CK mappings are contextual associations, not confirmation that a particular technique was successfully executed.

The dataset is synthetic and intended for educational use.

## 14. Future Improvements

Potential enhancements include:

- Real-time Apache log monitoring.
- Configurable detection thresholds.
- IP reputation enrichment.
- Geographic IP enrichment.
- Alert correlation across multiple log sources.
- HTML investigation reports.
- Security dashboard visualization.
- Integration with SIEM platforms.

## 15. Author

**Vamshi A N**

Cybersecurity | SOC Analyst Portfolio

GitHub Profile:  
https://github.com/Vamshi273

Project Repository:  
https://github.com/Vamshi273/SOC-and-Log-Analysis

---

*Educational cybersecurity project developed for authorized security analysis and SOC learning.*