08 - Suspicious Process Detection
Overview
Suspicious Process Detection is a Python-based SOC analysis tool designed to identify potentially malicious Windows process activity from CSV-based process telemetry.

The tool analyzes process names, command-line arguments, parent-child process relationships, and executable paths to identify suspicious execution patterns.

It assigns risk scores, classifies alerts, and generates JSON and CSV investigation reports.
Features
- Windows process telemetry parsing
- Configurable JSON detection rules
- Suspicious executable detection
- Encoded PowerShell command detection
- LOLBins detection
- Parent-child process relationship analysis
- Suspicious executable path detection
- Risk scoring and severity classification
- JSON and CSV report generation
- Unit testing with pytest
Detection Capabilities
Detection	Example
Suspicious processes	mshta.exe, certutil.exe, rundll32.exe
Encoded commands	PowerShell -EncodedCommand
Suspicious process chains	winword.exe → cmd.exe
Temporary directory execution	AppData\Local\Temp
Public directory execution	C:\Users\Public


Risk Classification
Score	Severity
0–24	LOW
25–49	MEDIUM
50–74	HIGH
75–100	CRITICAL


Risk scores are capped at 100.
Project Structure
08_Suspicious_Process_Detection/
|
+-- config/
|   +-- detection_rules.json
|
+-- datasets/
|   +-- sample_process_logs.csv
|
+-- reports/
|
+-- src/
|   +-- __init__.py
|   +-- parser.py
|   +-- detector.py
|   +-- analyzer.py
|   +-- reporter.py
|   +-- main.py
|
+-- tests/
|   +-- conftest.py
|   +-- test_parser.py
|   +-- test_detector.py
|   +-- test_analyzer.py
|   +-- test_reporter.py
|
+-- README.md

Technologies Used
- Python 3
- CSV and JSON
- Pytest
- Windows process telemetry concepts
- PowerShell security analysis concepts
Installation
Clone the repository:
git clone https://github.com/Vamshi273/SOC-and-Log-Analysis.git

Navigate to the project:
cd SOC-and-Log-Analysis/08_Suspicious_Process_Detection

Install pytest:
pip install pytest

Usage
Run the analyzer from the project directory:
python -m src.main

Specify a custom input file:
python -m src.main --input datasets/sample_process_logs.csv

The analyzer processes the records, evaluates detection rules, calculates risk scores, and generates reports.
Running Tests
Run the project tests:
python -m pytest tests/ -v

Test result: 12 passed
Sample Analysis Results
The included sample dataset contains 14 simulated process records.
Metric	Result
Total records	14
Invalid records	0
Normal records	6
Alerts	8
LOW	6
MEDIUM	8
HIGH	0
CRITICAL	0


Example Detection Findings
Process	Detection	Risk Score
powershell.exe	Encoded command argument	30
mshta.exe	Suspicious executable	25
cmd.exe	Suspicious parent-child relationship	35
invoice.exe	Execution from temporary directory	25
certutil.exe	Suspicious executable	25
rundll32.exe	Suspicious executable	25
wscript.exe	Suspicious parent-child relationship	35
update.exe	Execution from public directory	25


These findings are investigation leads, not proof of malicious activity.
Generated Reports
The analyzer generates two report formats.
JSON Report
Contains:
- Analysis summary
- Process records
- Detection findings
- Risk scores
- Severity classifications
CSV Alert Report
Contains alert records suitable for:
- SOC investigation
- Spreadsheet analysis
- Incident review
- Security reporting
Reports are saved in the reports/ directory.
SOC Analyst Use Case
A SOC analyst can use this tool to:
1. Analyze collected Windows process telemetry.
2. Identify suspicious executable names.
3. Investigate encoded PowerShell commands.
4. Review unusual parent-child process relationships.
5. Detect execution from suspicious directories.
6. Prioritize findings using risk scores.
7. Export alerts for further investigation.
Limitations
- Uses CSV-based process telemetry rather than live endpoint monitoring.
- Detection depends on configured rules.
- Legitimate administrative tools may trigger alerts.
- Does not automatically block or terminate processes.
- Findings require manual investigation and validation.
Disclaimer
This project is intended for educational and defensive cybersecurity purposes.

The included dataset contains simulated process activity. Detection results should not be interpreted as confirmation of a real security incident.