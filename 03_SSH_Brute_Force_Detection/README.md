# SSH Brute-Force Detection

![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![Security](https://img.shields.io/badge/Domain-Cybersecurity-red)
![Project](https://img.shields.io/badge/Project-SOC%20Analysis-purple)
![Testing](https://img.shields.io/badge/Testing-Pytest-green)
![Status](https://img.shields.io/badge/Status-Completed-success)

A Python-based Security Operations Center (SOC) project designed to analyze Linux SSH authentication logs, identify suspicious authentication patterns, detect brute-force attacks, and generate structured security reports.

The project uses the Linux authentication log parser developed in **Module 02 — Linux Authentication Log Analysis** and implements a separate correlation and detection engine for SSH brute-force activity.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Objectives](#2-objectives)
3. [Key Features](#3-key-features)
4. [Project Architecture](#4-project-architecture)
5. [Project Structure](#5-project-structure)
6. [Detection Rules](#6-detection-rules)
7. [Severity Classification](#7-severity-classification)
8. [Technologies Used](#8-technologies-used)
9. [Requirements](#9-requirements)
10. [Installation](#10-installation)
11. [Running the Application](#11-running-the-application)
12. [Command-Line Arguments](#12-command-line-arguments)
13. [Generated Reports](#13-generated-reports)
14. [Sample Detection Results](#14-sample-detection-results)
15. [Automated Testing](#15-automated-testing)
16. [Sample Dataset](#16-sample-dataset)
17. [Security Analysis Workflow](#17-security-analysis-workflow)
18. [MITRE ATT&CK Mapping](#18-mitre-attck-mapping)
19. [Limitations](#19-limitations)
20. [Future Improvements](#20-future-improvements)
21. [Learning Outcomes](#21-learning-outcomes)
22. [Disclaimer](#22-disclaimer)

---

## 1. Project Overview

SSH (Secure Shell) is commonly used to access and manage Linux servers remotely.

Attackers may attempt to gain unauthorized access by repeatedly guessing usernames and passwords. These activities are commonly associated with brute-force attacks.

This project analyzes SSH authentication events and identifies suspicious patterns using configurable detection thresholds and time-based correlation.

The detection engine identifies:

- Repeated authentication failures from a single IP address.
- Attempts targeting multiple usernames.
- Distributed brute-force patterns involving multiple IP addresses.
- Successful authentication following repeated failures.

The application generates structured JSON and CSV reports to support security investigation and SOC analysis.

## 2. Objectives

The primary objectives are:

- Analyze Linux SSH authentication logs.
- Identify repeated failed SSH login attempts.
- Correlate authentication failures within configurable time windows.
- Detect multi-account brute-force patterns.
- Identify distributed authentication attacks.
- Detect successful logins following repeated failures.
- Classify alerts according to severity.
- Generate machine-readable security reports.
- Develop practical SOC investigation skills.

## 3. Key Features

| Feature | Description |
|---|---|
| SSH Log Analysis | Parses Linux authentication logs |
| Failed Login Detection | Identifies repeated authentication failures |
| IP Correlation | Groups failed attempts by source IP |
| Multi-Account Detection | Identifies attempts against multiple usernames |
| Distributed Attack Detection | Identifies multiple IPs targeting the same account |
| Success Correlation | Detects successful login after repeated failures |
| Configurable Thresholds | Allows custom attempt counts and time windows |
| Severity Classification | Assigns LOW, MEDIUM, HIGH, and CRITICAL levels |
| JSON Reporting | Generates structured security reports |
| CSV Reporting | Exports authentication events and alerts |
| CLI Support | Runs through PowerShell or a terminal |
| Automated Testing | Includes Pytest-based detection tests |

## 4. Project Architecture

The module follows a simple processing pipeline.

```text
          Linux SSH Authentication Logs
                       |
                       v
              Module 02 Parser
                       |
                       v
             Parsed Authentication
                    Events
                       |
                       v
              Module 03 Detector
                       |
          +------------+------------+
          |            |            |
          v            v            v
      Repeated      Multi-Account  Distributed
      Failures       Detection     Detection
          |            |            |
          +------------+------------+
                       |
                       v
              Success Correlation
                       |
                       v
              Severity Classification
                       |
                       v
                Report Generator
                       |
             +---------+---------+
             |         |         |
             v         v         v
            JSON      Events    Alerts
                     CSV        CSV
```

### Processing Components

**1. Authentication Log Parser**

Reuses the parser from Module 02 to normalize Linux authentication events.

**2. Detection Engine**

Correlates SSH authentication events using source IP addresses, usernames, timestamps, and configurable thresholds.

**3. Severity Classification**

Assigns alert severity according to the configured detection rules.

**4. Report Generator**

Exports analysis results into JSON and CSV formats.

**5. Command-Line Interface**

Connects the parser, detector, and reporter into one executable application.

## 5. Project Structure

```text
SOC-and-Log-Analysis/
|
|-- 03_SSH_Brute_Force_Detection/
|   |
|   |-- README.md
|   |
|   |-- sample_logs/
|   |   |-- ssh_brute_force.log
|   |
|   |-- reports/
|   |   |-- ssh_attack_report.json
|   |   |-- ssh_attack_events.csv
|   |   |-- security_alerts.csv
|   |
|   |-- src/
|       |-- __init__.py
|       |-- detector.py
|       |-- reporter.py
|       |-- main.py
|
|-- 02_Linux_Authentication_Log_Analysis/
|   |-- src/
|       |-- parser.py
|
|-- tests/
    |-- test_ssh_brute_force.py
```

### Important Files

| File | Purpose |
|---|---|
| `detector.py` | SSH brute-force detection and correlation logic |
| `reporter.py` | JSON and CSV report generation |
| `main.py` | Main application entry point |
| `parser.py` | Reused Linux authentication log parser from Module 02 |
| `ssh_brute_force.log` | Synthetic SSH authentication dataset |
| `test_ssh_brute_force.py` | Automated detection tests |

## 6. Detection Rules

The detection engine implements four primary detection rules.

### Rule 1: SSH Brute-Force Detection

**Rule ID:** `SSH_BRUTE_FORCE`

Identifies repeated failed SSH authentication attempts originating from the same source IP address within a configured time window.

Example:

```text
09:00:01 Failed password for shiva from 203.0.113.50
09:01:01 Failed password for shiva from 203.0.113.50
09:02:01 Failed password for shiva from 203.0.113.50
09:03:01 Failed password for shiva from 203.0.113.50
09:04:01 Failed password for shiva from 203.0.113.50
```

Detection condition:

- At least 5 failed authentication attempts.
- Attempts occur within a 5-minute window.
- Attempts originate from the same source IP.

Expected severity: MEDIUM.

### Rule 2: Multi-Account Brute-Force Detection

**Rule ID:** `SSH_MULTI_ACCOUNT_BRUTE_FORCE`

Identifies a source IP attempting authentication against multiple usernames.

Example:

```text
Failed password for admin from 198.51.100.25
Failed password for root from 198.51.100.25
Failed password for guest from 198.51.100.25
Failed password for test from 198.51.100.25
Failed password for oracle from 198.51.100.25
```

Detection condition:

- At least 5 failed attempts.
- At least 3 different usernames.
- Attempts originate from the same source IP within the configured window.

Expected severity: HIGH.

### Rule 3: Distributed Brute-Force Detection

**Rule ID:** `SSH_DISTRIBUTED_BRUTE_FORCE`

Identifies multiple source IP addresses attempting to authenticate against the same username.

Example:

```text
Failed password for deploy from 192.0.2.10
Failed password for deploy from 192.0.2.11
Failed password for deploy from 192.0.2.12
Failed password for deploy from 192.0.2.10
Failed password for deploy from 192.0.2.11
```

Detection condition:

- At least 5 failed attempts against the same username.
- At least 2 distinct source IP addresses.
- Attempts occur within the configured detection window.

Expected severity: HIGH.

### Rule 4: Successful Login After Brute-Force Activity

**Rule ID:** `SSH_SUCCESS_AFTER_BRUTE_FORCE`

Identifies a successful SSH authentication following repeated failures from the same source IP against the same username.

Example:

```text
Failed password for shiva from 203.0.113.50
Failed password for shiva from 203.0.113.50
Failed password for shiva from 203.0.113.50
Failed password for shiva from 203.0.113.50
Failed password for shiva from 203.0.113.50
Accepted password for shiva from 203.0.113.50
```

Detection condition:

- At least 5 failed attempts.
- A subsequent successful login.
- Same username and source IP.
- Activity occurs within the configured correlation window.

Expected severity: CRITICAL.

This alert indicates suspicious authentication activity and requires investigation. It does not independently confirm account compromise.

## 7. Severity Classification

The project uses four severity levels.

| Severity | Condition |
|---|---|
| LOW | 3–4 failed attempts |
| MEDIUM | 5–9 failed attempts |
| HIGH | 10–19 failed attempts or multi-account attack |
| CRITICAL | 20 or more failed attempts or successful login following a detected brute-force pattern |

Distributed brute-force alerts are currently assigned HIGH severity.

**Note:** These are project-specific classification rules, not universal security standards. Severity should be interpreted alongside the environment, account importance, and surrounding activity.

## 8. Technologies Used

| Technology | Purpose |
|---|---|
| Python | Application development |
| Regular Expressions | Authentication log parsing |
| CSV | Event and alert exports |
| JSON | Structured security reports |
| Pytest | Automated testing |
| PowerShell | Windows development environment |
| Linux Authentication Logs | Security event data source |

## 9. Requirements

- Python 3.9 or later.
- Pytest for automated testing.
- Windows, Linux, or macOS.
- Linux SSH authentication logs for real-world analysis.

The project was developed using Python 3.13.9.

## 10. Installation

Clone the repository:

```bash
git clone https://github.com/Vamshi273/SOC-and-Log-Analysis.git
```

Navigate to the repository:

```bash
cd SOC-and-Log-Analysis
```

Install Pytest in the project's virtual environment:

**Windows PowerShell:**

```powershell
.\.venv\Scripts\python.exe -m pip install pytest
```

**Linux/macOS:**

```bash
python -m pip install pytest
```

The project uses the parser from Module 02, so keep the repository's original directory structure intact.

## 11. Running the Application

From the repository root, execute:

**Windows PowerShell:**

```powershell
.\.venv\Scripts\python.exe .\03_SSH_Brute_Force_Detection\src\main.py --year 2026
```

**Linux/macOS:**

```bash
python 03_SSH_Brute_Force_Detection/src/main.py --year 2026
```

The application:

1. Loads the SSH authentication log.
2. Parses authentication events.
3. Detects suspicious SSH activity.
4. Calculates severity counts.
5. Generates JSON and CSV reports.

## 12. Command-Line Arguments

The application supports configurable input, output, and detection parameters.

| Argument | Description | Default |
|---|---|---|
| `--input` | Input authentication log | Included sample log |
| `--output` | Report output directory | Module 03 reports |
| `--year` | Year for syslog timestamps | 2026 |
| `--threshold` | Failed attempts required for detection | 5 |
| `--window` | Detection window in minutes | 5 |

### Custom Input File

```powershell
.\.venv\Scripts\python.exe .\03_SSH_Brute_Force_Detection\src\main.py --input ".\path\to\auth.log" --year 2026
```

### Custom Detection Threshold

```powershell
.\.venv\Scripts\python.exe .\03_SSH_Brute_Force_Detection\src\main.py --threshold 3 --window 5 --year 2026
```

### Custom Report Directory

```powershell
.\.venv\Scripts\python.exe .\03_SSH_Brute_Force_Detection\src\main.py --output ".\custom_reports" --year 2026
```

## 13. Generated Reports

The application generates three report files.

### 1. ssh_attack_report.json

Contains:

- Report metadata.
- Total authentication events.
- Failed authentication count.
- Successful authentication count.
- Total security alerts.
- Severity distribution.
- Detected attack details.
- Parsed authentication events.

### 2. ssh_attack_events.csv

Contains normalized authentication events.

Example columns:

| Column | Description |
|---|---|
| timestamp | Authentication event timestamp |
| hostname | Linux host |
| event_type | Authentication event classification |
| status | Authentication status, when available |
| username | Targeted username |
| source_ip | Source IP address |
| method | Authentication method |
| details | Additional event information |

### 3. security_alerts.csv

Contains detected security alerts.

Example columns:

| Column | Description |
|---|---|
| rule | Detection rule |
| severity | Alert severity |
| timestamp | Alert timestamp |
| source_ips | Associated source IP addresses |
| targeted_usernames | Targeted usernames |
| failed_attempts | Number of failed attempts |
| successful_logins | Number of successful logins |
| description | Alert explanation |

Reports are generated inside:

```text
03_SSH_Brute_Force_Detection/reports/
```

## 14. Sample Detection Results

The included synthetic dataset contains scenarios representing:

- Repeated SSH login failures.
- Multi-account brute-force activity.
- Distributed brute-force activity.
- Successful login after repeated failures.

Expected dataset summary:

| Metric | Expected Value |
|---|---:|
| Parsed events | 16 |
| Invalid lines | 0 |
| Failed attempts | 15 |
| Successful logins | 1 |
| Detected attack patterns | 4 |

These figures describe the included sample dataset and should be verified against the actual execution output.

## 15. Automated Testing

The project includes automated tests for its detection engine.

Test file:

```text
tests/test_ssh_brute_force.py
```

The tests cover:

| Test | Purpose |
|---|---|
| Repeated SSH Failures | Verifies brute-force detection |
| Multi-Account Attack | Verifies multiple username detection |
| Distributed Attack | Verifies multiple source IP detection |
| Successful Login Correlation | Verifies suspicious success detection |
| Below Threshold | Verifies that low activity does not trigger an alert |
| Custom Threshold | Verifies configurable detection thresholds |
| Invalid Threshold | Verifies input validation |

### Run Module 03 Tests

```powershell
.\.venv\Scripts\python.exe -m pytest .\tests\test_ssh_brute_force.py -v
```

### Run All Repository Tests

```powershell
.\.venv\Scripts\python.exe -m pytest .\tests -v
```

## 16. Sample Dataset

The project includes a synthetic SSH authentication log:

```text
sample_logs/ssh_brute_force.log
```

The sample dataset is designed to demonstrate different authentication attack patterns.

It uses documentation-only IP address ranges:

- `192.0.2.0/24`
- `198.51.100.0/24`
- `203.0.113.0/24`

These addresses are reserved for documentation and examples.

The dataset does not represent real attackers, production systems, or actual security incidents.

## 17. Security Analysis Workflow

A SOC analyst can use this module as part of an authentication investigation workflow.

**Step 1 — Collect Logs**

Obtain Linux SSH authentication logs from the target system.

**Step 2 — Parse Events**

Normalize authentication records into structured events.

**Step 3 — Identify Suspicious Activity**

Analyze failed and successful authentication attempts.

**Step 4 — Correlate Events**

Group events using source IP addresses, usernames, and timestamps.

**Step 5 — Generate Alerts**

Apply detection rules and assign severity levels.

**Step 6 — Review Reports**

Examine JSON and CSV reports to investigate suspicious activity.

**Step 7 — Investigate Further**

Validate the alerts against system context, user activity, and other security evidence before deciding whether an incident has occurred.

## 18. MITRE ATT&CK Mapping

The detection scenarios relate to the following MITRE ATT&CK techniques:

| Technique ID | Technique | Relevance |
|---|---|---|
| T1110 | Brute Force | Repeated authentication failures |
| T1110.001 | Password Guessing | Repeated password attempts |
| T1110.003 | Password Spraying | Attempts against multiple accounts using a limited set of passwords |

Reference: [MITRE ATT&CK — Brute Force](https://attack.mitre.org/techniques/T1110/)

These mappings describe related attack behaviors. The log patterns alone do not establish which exact technique was used by an attacker.

## 19. Limitations

- Detection depends on the quality and completeness of authentication logs.
- The implementation focuses on Linux SSH authentication events.
- The current detection engine uses configurable thresholds rather than machine learning.
- Successful-login correlation requires the same username and source IP.
- Distributed attack detection depends on the observed source IP addresses and configured thresholds.
- The implementation does not perform live network monitoring.
- No external IP reputation or threat intelligence enrichment is currently implemented.
- Detection alerts require analyst validation.
- The tool does not automatically block IP addresses or disable accounts.

## 20. Future Improvements

Potential improvements include:

- Real-time SSH log monitoring.
- Threat intelligence integration.
- GeoIP enrichment.
- IP reputation analysis.
- Advanced attack correlation.
- Alert notification integration.
- SIEM integration.
- Interactive security dashboards.
- Automated incident response workflows.
- Detection of additional SSH authentication anomalies.

## 21. Learning Outcomes

This project demonstrates practical cybersecurity and SOC analysis concepts:

- Linux authentication log analysis.
- SSH security monitoring.
- Authentication failure correlation.
- Brute-force attack detection.
- Multi-account attack identification.
- Distributed attack pattern analysis.
- Time-window-based event correlation.
- Security alert classification.
- JSON and CSV reporting.
- Python-based security automation.
- Automated testing with Pytest.

## 22. Disclaimer

This project is intended for educational purposes, cybersecurity learning, and authorized security analysis.

The included dataset is synthetic and uses documentation-only IP addresses.

Detection results are indicators of suspicious activity, not proof of a successful attack or account compromise.

Always obtain appropriate authorization before collecting or analyzing authentication logs from systems you do not own or administer.

---

**Developed as part of the SOC and Log Analysis project series.**