\# Windows Event Log Analysis



A Python-based defensive security tool for analyzing Windows Security Event Logs, identifying suspicious authentication activity, and generating security reports.



\## Features



\- Windows Security Event Log analysis.

\- Successful and failed login monitoring.

\- Brute-force attack detection.

\- Successful login after repeated failures detection.

\- Explicit credential usage monitoring.

\- Special privilege assignment monitoring.

\- Timestamp validation and UTC normalization.

\- CSV and JSON report generation.

\- PowerShell-based Windows event collection.



\## Project Structure



```text

01\_Windows\_Event\_Log\_Analysis/

├── README.md

├── src/

│   ├── main.py

│   └── collect\_windows\_logs.ps1

├── sample\_logs/

│   └── sample\_security\_logs.csv

└── reports/

```



\## Technologies



\- Python

\- PowerShell

\- CSV and JSON

\- pytest



\## Windows Event IDs



| Event ID | Description |

|---|---|

| 4624 | Successful logon |

| 4625 | Failed logon |

| 4634 | Logoff |

| 4648 | Explicit credential usage |

| 4672 | Special privileges assigned |



\## Detection Capabilities



\### 1. Brute-force Detection



Detects five or more failed login attempts from the same IP address within ten minutes.



MITRE ATT\&CK: T1110 – Brute Force.



\### 2. Successful Login After Repeated Failures



Identifies successful logins following repeated failed login attempts from the same IP address.



MITRE ATT\&CK: T1078 – Valid Accounts.



\### 3. Explicit Credential Usage



Reports Event ID 4648 for further investigation.



\### 4. Special Privileges



Reports Event ID 4672 as informational security context.



These events are not automatically malicious.



\## Installation



From the main repository directory:



```powershell

pip install -r requirements.txt

```



\## Usage



Analyze the synthetic sample dataset:



```powershell

python .\\01\_Windows\_Event\_Log\_Analysis\\src\\main.py --input .\\01\_Windows\_Event\_Log\_Analysis\\sample\_logs\\sample\_security\_logs.csv

```



Display available options:



```powershell

python .\\01\_Windows\_Event\_Log\_Analysis\\src\\main.py --help

```



\## Windows Event Collection



Run PowerShell as Administrator:



```powershell

powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\\01\_Windows\_Event\_Log\_Analysis\\src\\collect\_windows\_logs.ps1 -Days 7

```



Appropriate permissions are required to access Windows Security logs.



\## Generated Reports



The analyzer generates:



\- `security\_report.csv`

\- `security\_report.json`



Reports are saved in the module's `reports/` directory.



\## Testing



Run the automated test suite from the repository root:



```powershell

python -m pytest .\\tests\\test\_windows\_event\_analyzer.py -v

```



\## Limitations



\- Analysis depends on the fields available in the input CSV.

\- Missing IP addresses can limit correlation.

\- Explicit credential usage and special privilege events require contextual investigation.

\- No detected alerts does not guarantee that a system is secure.

\- This project is not a replacement for an enterprise SIEM.



\## Security Notice



Use this tool only on systems and logs that you own or are authorized to analyze.



Do not publish personal Windows Security logs or reports containing private system information.



\## Project Status



Core implementation completed.



Automated tests: 10 passing.
