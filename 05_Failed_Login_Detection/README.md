\# 05 – Failed Login Detection \& Investigation



A cross-platform Python security log analysis tool that investigates failed authentication attempts from Windows Security Event Logs and Linux authentication logs.



The project identifies failure reasons, affected user accounts, source IP addresses, and authentication patterns. It generates structured JSON and CSV investigation reports.



\## Features



\- Windows Security Event ID 4625 analysis.

\- Linux SSH authentication failure analysis.

\- Linux invalid username detection.

\- PAM authentication failure detection.

\- Windows status and substatus code interpretation.

\- Failed-login classification.

\- Affected account analysis.

\- Source IP address analysis.

\- Chronological authentication failure timeline.

\- JSON and CSV report generation.

\- Support for Windows and Linux logs individually or together.

\- Automated unit tests using pytest.



\## Project Structure



```text

05\_Failed\_Login\_Detection/

│

├── README.md

│

├── sample\_logs/

│   ├── windows\_failed\_logins.csv

│   └── linux\_auth.log

│

├── reports/

│   ├── failed\_login\_report.json

│   └── failed\_login\_events.csv

│

├── src/

│   ├── \_\_init\_\_.py

│   ├── windows\_parser.py

│   ├── linux\_parser.py

│   ├── classifier.py

│   ├── analyzer.py

│   ├── reporter.py

│   └── main.py

│

└── tests/

&#x20;   ├── test\_windows\_parser.py

&#x20;   ├── test\_linux\_parser.py

&#x20;   ├── test\_classifier.py

&#x20;   ├── test\_analyzer.py

&#x20;   ├── test\_reporter.py

&#x20;   └── test\_cli.py

```



\## Technologies Used



\- Python 3

\- Windows Security Event Logs

\- Linux Authentication Logs

\- CSV

\- JSON

\- Regular Expressions

\- pathlib

\- argparse

\- pytest



The application uses Python standard-library modules for runtime execution. Pytest is required for running the test suite.



\## Detection and Investigation Capabilities



\### 1. Windows Failed Login Analysis



Analyzes Windows Security Event ID 4625.



Extracts:

\- Username

\- Domain

\- Source IP address

\- Workstation

\- Logon type

\- Status code

\- Substatus code

\- Authentication package

\- Logon process



\### 2. Windows Failure Classification



Interprets available Windows status and substatus codes.



| Status Code | Classification |

|---|---|

| 0xC0000064 | Unknown Username |

| 0xC000006A | Incorrect Password |

| 0xC000006D | Invalid Credentials |

| 0xC000006E | Account Restriction |

| 0xC000006F | Logon Hours Restriction |

| 0xC0000070 | Workstation Restriction |

| 0xC0000071 | Password Expired |

| 0xC0000072 | Account Disabled |

| 0xC000015B | Logon Type Not Granted |

| 0xC0000234 | Account Locked |



The classifier checks the substatus before the main status because the substatus can provide a more specific explanation.



\### 3. Linux Authentication Failure Analysis



Analyzes Linux authentication logs and identifies:



\- Failed SSH password attempts.

\- Invalid SSH usernames.

\- PAM authentication failures.

\- Associated usernames and source IP addresses when available.



The parser supports standard syslog-style timestamps.



\### 4. Failure Classification



Classifies authentication failures into categories:



\- INCORRECT\_PASSWORD

\- UNKNOWN\_USERNAME

\- INVALID\_CREDENTIALS

\- ACCOUNT\_RESTRICTION

\- LOGON\_HOURS\_RESTRICTION

\- WORKSTATION\_RESTRICTION

\- PASSWORD\_EXPIRED

\- ACCOUNT\_DISABLED

\- LOGON\_TYPE\_NOT\_GRANTED

\- ACCOUNT\_LOCKED

\- PAM\_AUTHENTICATION\_FAILURE

\- UNKNOWN



Unknown causes are retained as unknown instead of being incorrectly identified.



\### 5. Account Investigation



Provides:

\- Total failures per username.

\- Most affected accounts.

\- Unique affected account count.



\### 6. Source IP Investigation



Provides:

\- Total failures per source IP.

\- Most frequently observed source addresses.

\- Unique source IP count.



\### 7. Authentication Timeline



Creates a chronological timeline containing:

\- Timestamp

\- Platform

\- Username

\- Source IP

\- Failure category



\## Installation



Clone the repository:



```powershell

git clone https://github.com/Vamshi273/SOC-and-Log-Analysis.git

```



Navigate to the project:



```powershell

cd SOC-and-Log-Analysis

```



Create a virtual environment:



```powershell

python -m venv .venv

```



Activate it:



```powershell

.\\.venv\\Scripts\\Activate.ps1

```



Install pytest for testing:



```powershell

python -m pip install pytest

```



\## Usage



Run commands from the repository root directory.



\### Analyze Windows Logs



```powershell

python .\\05\_Failed\_Login\_Detection\\src\\main.py `

&#x20;   --windows ".\\05\_Failed\_Login\_Detection\\sample\_logs\\windows\_failed\_logins.csv"

```



\### Analyze Linux Logs



```powershell

python .\\05\_Failed\_Login\_Detection\\src\\main.py `

&#x20;   --linux ".\\05\_Failed\_Login\_Detection\\sample\_logs\\linux\_auth.log" `

&#x20;   --year 2026

```



\### Analyze Both Windows and Linux Logs



```powershell

python .\\05\_Failed\_Login\_Detection\\src\\main.py `

&#x20;   --windows ".\\05\_Failed\_Login\_Detection\\sample\_logs\\windows\_failed\_logins.csv" `

&#x20;   --linux ".\\05\_Failed\_Login\_Detection\\sample\_logs\\linux\_auth.log" `

&#x20;   --year 2026

```



\### Specify a Custom Report Directory



```powershell

python .\\05\_Failed\_Login\_Detection\\src\\main.py `

&#x20;   --windows ".\\05\_Failed\_Login\_Detection\\sample\_logs\\windows\_failed\_logins.csv" `

&#x20;   --linux ".\\05\_Failed\_Login\_Detection\\sample\_logs\\linux\_auth.log" `

&#x20;   --year 2026 `

&#x20;   --output ".\\05\_Failed\_Login\_Detection\\reports"

```



\## Generated Reports



The application generates two reports.



\### 1. JSON Investigation Report



`failed\_login\_report.json`



Contains:

\- Report generation timestamp.

\- Total failed logins.

\- Platform breakdown.

\- Failure category distribution.

\- Unique affected accounts.

\- Unique source IP addresses.

\- Top affected usernames.

\- Top source IP addresses.

\- Authentication timeline.

\- Classified event details.



\### 2. CSV Investigation Report



`failed\_login\_events.csv`



Contains structured event-level information:



\- Platform

\- Timestamp

\- Username

\- Source IP

\- Failure category

\- Failure description

\- Evidence code

\- Event ID

\- Windows status and substatus

\- Linux failure type

\- Additional details



\## Sample Execution Results



The project was tested using sample Windows and Linux authentication logs.



| Investigation Metric | Result |

|---|---:|

| Total Failed Logins | 8 |

| Windows Events | 4 |

| Linux Events | 4 |

| Incorrect Password | 4 |

| Unknown Username | 2 |

| Account Locked | 1 |

| PAM Authentication Failure | 1 |

| Unique Usernames | 4 |

| Unique Source IPs | 4 |



\### Top Affected Accounts



| Username | Failed Attempts |

|---|---:|

| admin | 4 |

| hacker | 2 |

| guest | 1 |

| root | 1 |



\### Top Source IP Addresses



| Source IP | Failed Attempts |

|---|---:|

| 192.168.1.50 | 3 |

| 192.168.1.60 | 2 |

| 192.168.1.70 | 2 |

| 192.168.1.80 | 1 |



These results are from the included sample dataset, not a live production environment.



\## Testing



Run the complete test suite:



```powershell

python -m pytest ".\\05\_Failed\_Login\_Detection\\tests" -v

```



Compile the source files:



```powershell

python -m compileall -q ".\\05\_Failed\_Login\_Detection\\src"

```



\### Test Results



\*\*47 tests passed.\*\*



Test coverage includes:

\- Windows event parsing.

\- Linux authentication log parsing.

\- Failure classification.

\- Investigation analysis.

\- JSON report generation.

\- CSV report generation.

\- Command-line execution.

\- Missing and invalid input handling.



\## Limitations



\- Windows analysis requires CSV input containing relevant Security Event fields.

\- Accurate Windows failure classification depends on the availability of status or substatus codes.

\- The existing Windows collector must export these fields for complete real-world failure-reason analysis.

\- Linux parsing currently supports selected syslog-style authentication messages.

\- Linux syslog timestamps do not include a year, so the `--year` argument should be supplied when analyzing historical logs.

\- PAM failures may not provide enough evidence to identify the exact authentication problem.

\- This project investigates failed authentication events; it is not a complete SIEM or real-time monitoring platform.



\## Security Notice



Use this project only for authorized security monitoring, defensive analysis, and educational purposes.



Authentication logs and generated reports may contain usernames, internal IP addresses, and other sensitive security information.



Do not publish real organizational logs, credentials, or confidential investigation data on public repositories.



The included sample logs use demonstration data.



\## Project Status



\*\*Status: Completed – Version 1.0\*\*



Module 05 adds cross-platform failed-login investigation capabilities to the SOC and Log Analysis project.



Future improvements may include additional authentication sources, richer event correlation, and integration with SIEM platforms.

