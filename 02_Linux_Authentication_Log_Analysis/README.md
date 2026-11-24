# Linux Authentication Log Analysis

![Python](https://img.shields.io/badge/Python-3.x-blue)
![Domain](https://img.shields.io/badge/Domain-SOC%20Analysis-red)
![Status](https://img.shields.io/badge/Status-Completed-brightgreen)

## Overview

A Python-based Security Operations Center (SOC) project designed to analyze Linux authentication logs, identify suspicious authentication activity, classify security events, and generate structured security reports.

The tool processes Linux authentication logs and extracts useful information about SSH logins, failed authentication attempts, invalid usernames, root access, sudo commands, and PAM sessions.

## Objectives

- Understand Linux authentication log formats.
- Extract meaningful security events.
- Identify suspicious authentication activity.
- Monitor privileged account access.
- Track authentication activity by username and source IP.
- Generate structured security reports.

## Features

- Linux syslog authentication log parser.
- SSH successful login detection.
- SSH failed login detection.
- Invalid username identification.
- Successful root SSH login identification.
- Sudo command activity monitoring.
- PAM session monitoring.
- Account activity statistics.
- Source IP activity statistics.
- Security alert generation.
- JSON and CSV report exports.
- Command-line interface.
- Automated unit testing.

## Project Structure

```text
02_Linux_Authentication_Log_Analysis/
│
├── README.md
│
├── sample_logs/
│   └── auth.log
│
├── reports/
│   ├── linux_auth_report.json
│   ├── authentication_events.csv
│   └── security_alerts.csv
│
└── src/
    ├── main.py
    ├── parser.py
    ├── detector.py
    └── reporter.py
```

Automated tests:

```text
tests/
└── test_linux_auth_analysis.py
```

## Technologies Used

| Technology | Purpose |
|---|---|
| Python | Core implementation |
| Regular Expressions | Log parsing |
| CSV | Structured report export |
| JSON | Security report generation |
| Argparse | Command-line interface |
| Pytest | Automated testing |

## Event Classification

| Event Type | Description |
|---|---|
| SSH_LOGIN_SUCCESS | Successful SSH authentication |
| SSH_LOGIN_FAILURE | Failed SSH authentication |
| SSH_INVALID_USER | Authentication attempt involving an invalid username |
| SSH_ROOT_LOGIN | Successful SSH login as root |
| SUDO_COMMAND | Privileged command execution |
| PAM_SESSION | PAM session activity |
| AUTHENTICATION_FAILURE | Other authentication failure |
| OTHER | Unclassified authentication activity |

## Security Alert Classification

| Alert | Severity |
|---|---|
| Invalid Username Attempt | MEDIUM |
| Successful Root SSH Login | HIGH |
| Failed SSH Authentication | INFO |

These are initial alert classifications, not definitive judgments that an account or source IP is compromised.

## Installation

Create a virtual environment from the repository root:

```powershell
python -m venv .venv
```

Activate it:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install the testing dependency:

```powershell
python -m pip install pytest
```

## Execution

Run the analyzer:

```powershell
python .\02_Linux_Authentication_Log_Analysis\src\main.py --year 2026
```

Specify a custom input file:

```powershell
python .\02_Linux_Authentication_Log_Analysis\src\main.py --input "path/to/auth.log" --year 2026
```

Specify a custom report directory:

```powershell
python .\02_Linux_Authentication_Log_Analysis\src\main.py --output "custom_reports" --year 2026
```

## Generated Reports

### 1. Linux Authentication JSON Report

`linux_auth_report.json`

Includes:
- Report metadata.
- Total event count.
- Event classification summary.
- Account activity.
- Source IP activity.
- Generated security alerts.
- Parsed authentication events.

### 2. Authentication Events CSV

`authentication_events.csv`

Contains structured authentication events for further investigation and analysis.

### 3. Security Alerts CSV

`security_alerts.csv`

Contains:
- Alert severity.
- Alert type.
- Username.
- Source IP.
- Timestamp.
- Alert description.

## Testing

Run the automated tests:

```powershell
python -m pytest tests/test_linux_auth_analysis.py -v
```

## Sample Dataset

The included `auth.log` contains synthetic Linux authentication events.

The dataset includes:
- Successful SSH logins.
- Failed SSH logins.
- Invalid username attempts.
- Root SSH login.
- Sudo activity.
- PAM session activity.

Documentation IP ranges are used in the sample dataset. These entries are not evidence of real-world attacks.

## Detection Scope and Limitations

- This module focuses on Linux authentication log parsing and event classification.
- Failed authentication events are classified individually.
- Dedicated SSH brute-force correlation is handled separately in Module 03.
- Source IP addresses are not automatically classified as malicious.
- Traditional syslog timestamps may omit the year and timezone.
- The year must be supplied when interpreting the sample logs.
- Production deployments should account for log rotation, timezone configuration, and differences between Linux distributions.

## Future Improvements

- Support additional Linux authentication log formats.
- Add configurable detection rules.
- Improve alert severity scoring.
- Add time-based authentication correlation.
- Integrate threat intelligence.
- Add SIEM integration.

---

**Repository:** SOC-and-Log-Analysis  
**Module:** 02 - Linux Authentication Log Analysis
