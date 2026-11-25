# Module 06 - Privilege Escalation Detection



A Python-based security log analysis tool that identifies and classifies privilege-related activities in Windows Security Event logs and Linux authentication logs.



The project helps security analysts investigate privileged account activity, administrative group membership changes, sudo usage, root sessions and account modifications.



## Project Overview



Privilege escalation occurs when an account or process obtains permissions beyond its intended authorization level. Monitoring privileged activity is an important part of security operations and incident investigation.



This tool analyzes Windows and Linux logs, extracts supported privilege-related events, assigns investigation risk levels and generates structured reports in JSON and CSV formats.



## Key Features



\- Cross-platform Windows and Linux log analysis.

\- Windows Security Event ID parsing.

\- Linux sudo and su activity detection.

\- Privileged account and group modification detection.

\- Risk classification: LOW, MEDIUM and HIGH.

\- Event chronology and platform statistics.

\- Actor and target account summaries where information is available.

\- Privileged group membership change tracking.

\- JSON and CSV report generation.

\- Invalid or unsupported record tracking.

\- Command-line interface.

\- Automated unit tests using pytest.



## Technologies Used



| Technology | Purpose |

|---|---|

| Python | Log parsing and analysis |

| CSV | Windows event input and structured reports |

| JSON | Machine-readable analysis reports |

| Regular Expressions | Linux log parsing |

| Argparse | Command-line interface |

| Pytest | Automated testing |



The application uses Python standard-library modules for its core functionality. Pytest is required for running the test suite.



## Supported Windows Events



| Event ID | Activity | Description |

|---|---|---|

| 4672 | Special privileges assigned | Special privileges assigned to a new logon |

| 4720 | User account created | Creation of a new user account |

| 4728 | Global group member added | Addition of a member to a security-enabled global group |

| 4732 | Local group member added | Addition of a member to a security-enabled local group |

| 4738 | User account changed | Modification of an existing user account |

| 4756 | Universal group member added | Addition of a member to a security-enabled universal group |



## Supported Linux Activities



The Linux parser identifies supported privilege-related activity, including:



\- Sudo command execution.

\- Sudo root session creation.

\- Su root session creation.

\- Privileged account modifications.

\- User account management commands.

\- Group management commands.



Examples of monitored commands include:



\- `sudo`

\- `su`

\- `useradd`

\- `usermod`

\- `groupadd`

\- `groupmod`

\- `gpasswd`



## Risk Classification



Events are assigned risk levels to help prioritize investigation.



| Risk Level | Meaning |

|---|---|

| LOW | Lower-priority or unclassified activity |

| MEDIUM | Privilege-related activity requiring review |

| HIGH | Sensitive administrative or privileged activity requiring investigation |



\*\*Important:\*\* A HIGH-risk classification indicates investigation priority. It does not automatically mean that an event is malicious or confirms a successful privilege escalation.



## Project Structure



```text

06\_Privilege\_Escalation\_Detection/

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

├── tests/

│   ├── \_\_init\_\_.py

│   ├── test\_windows\_parser.py

│   ├── test\_linux\_parser.py

│   ├── test\_classifier.py

│   ├── test\_analyzer.py

│   └── test\_reporter.py

│

├── sample\_logs/

│   ├── windows\_privilege\_events.csv

│   └── linux\_privilege.log

│

├── reports/

│   ├── privilege\_analysis\_report.json

│   └── privilege\_events\_report.csv

│

├── \_\_init\_\_.py

└── README.md

```



## Requirements



\- Python 3.10 or later.

\- Windows or Linux environment.

\- Pytest for automated testing.



## Installation



Clone the repository:



```bash

git clone https://github.com/Vamshi273/SOC-and-Log-Analysis.git

```



Navigate to the repository:



```bash

cd SOC-and-Log-Analysis

```



Create a virtual environment:



```bash

python -m venv .venv

```



Activate it on Windows:



```powershell

.venv\\Scripts\\Activate.ps1

```



Install pytest:



```bash

python -m pip install pytest

```



## Usage



Run the commands from the repository root directory.



### Analyze Windows and Linux logs together



```powershell

python -m 06\_Privilege\_Escalation\_Detection.src.main `

&#x20;   --windows ".\\06\_Privilege\_Escalation\_Detection\\sample\_logs\\windows\_privilege\_events.csv" `

&#x20;   --linux ".\\06\_Privilege\_Escalation\_Detection\\sample\_logs\\linux\_privilege.log" `

&#x20;   --year 2026 `

&#x20;   --output ".\\06\_Privilege\_Escalation\_Detection\\reports"

```



### Analyze Windows logs only



```powershell

python -m 06\_Privilege\_Escalation\_Detection.src.main `

&#x20;   --windows ".\\06\_Privilege\_Escalation\_Detection\\sample\_logs\\windows\_privilege\_events.csv"

```



### Analyze Linux logs only



```powershell

python -m 06\_Privilege\_Escalation\_Detection.src.main `

&#x20;   --linux ".\\06\_Privilege\_Escalation\_Detection\\sample\_logs\\linux\_privilege.log" `

&#x20;   --year 2026

```



### View command-line options



```powershell

python -m 06\_Privilege\_Escalation\_Detection.src.main --help

```



## Sample Analysis Results



The included sample logs produced the following results during testing:



| Metric | Result |

|---|---:|

| Total parsed events | 13 |

| Windows events | 6 |

| Linux events | 7 |

| MEDIUM-risk events | 5 |

| HIGH-risk events | 8 |

| Privileged group changes | 3 |

| Skipped Windows rows | 1 |

| Skipped Linux lines | 2 |



These results are based on the included sample data and may vary when analyzing other logs.



## Generated Reports



The tool generates two reports.



### 1. JSON Report



`privilege\_analysis\_report.json`



Contains:

\- Analysis summary.

\- Total event count.

\- Platform breakdown.

\- Event type statistics.

\- Risk distribution.

\- Top actors and target accounts where available.

\- Detailed analyzed events.



### 2. CSV Report



`privilege\_events\_report.csv`



Contains structured event information, including:



\- Platform.

\- Timestamp.

\- Hostname.

\- Event ID.

\- Event type.

\- Risk level.

\- Classification.

\- Actor and target account.

\- Group name.

\- Command.

\- Source IP.

\- Description and details.



## Running Automated Tests



Run all Module 06 tests:



```powershell

python -m pytest `

&#x20;   ".\\06\_Privilege\_Escalation\_Detection\\tests" `

&#x20;   --import-mode=importlib -v

```



### Test Results



\*\*38 tests passed.\*\*



The test suite covers:



\- Windows event parsing.

\- Linux privilege activity parsing.

\- Risk classification.

\- Cross-platform analysis.

\- Event statistics.

\- JSON report generation.

\- CSV report generation.

\- Missing and invalid input handling.



## Security and Investigation Considerations



\- Risk classifications are intended to support investigation, not replace analyst judgment.

\- Privileged activity can be legitimate administrative behavior.

\- Missing actor information should not be treated as proof of malicious activity.

\- Production deployment should use properly configured audit policies and reliable log collection.

\- Sample logs are demonstration data, not evidence of real security incidents.



## Learning Outcomes



This project demonstrates practical knowledge of:



\- Windows Security Event analysis.

\- Linux authentication log analysis.

\- Privileged account monitoring.

\- Security event classification.

\- Python-based security automation.

\- Structured security reporting.

\- Automated testing and validation.






