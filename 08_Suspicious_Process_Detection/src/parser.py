import csv
from pathlib import Path

REQUIRED_FIELDS = {
    "ProcessId",
    "ParentProcessId",
    "ProcessName",
    "ParentProcessName",
    "CommandLine",
    "ExecutablePath",
    "Username",
    "Timestamp",
}


def parse_process_logs(file_path):
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Process log file not found: {path}")

    records = []
    invalid_records = []

    with path.open("r", encoding="utf-8-sig", newline="") as file:
        reader = csv.DictReader(file)

        if not reader.fieldnames:
            raise ValueError("CSV file is empty or has no header.")

        missing_fields = REQUIRED_FIELDS - set(reader.fieldnames)

        if missing_fields:
            raise ValueError(
                f"Missing required CSV columns: {', '.join(sorted(missing_fields))}"
            )

        for row_number, row in enumerate(reader, start=2):
            try:
                record = {
                    key: (value or "").strip()
                    for key, value in row.items()
                    if key is not None
                }

                required_values = [
                    "ProcessId",
                    "ParentProcessId",
                    "ProcessName",
                    "ParentProcessName",
                    "CommandLine",
                    "ExecutablePath",
                    "Username",
                    "Timestamp",
                ]

                if any(not record.get(field) for field in required_values):
                    raise ValueError("One or more required values are empty.")

                record["ProcessId"] = int(record["ProcessId"])
                record["ParentProcessId"] = int(record["ParentProcessId"])
                record["ProcessName"] = record["ProcessName"].lower()
                record["ParentProcessName"] = record["ParentProcessName"].lower()
                record["ExecutablePath"] = record["ExecutablePath"].replace("/", "\\")
                record["CommandLine"] = record["CommandLine"].strip()

                records.append(record)

            except (ValueError, TypeError) as error:
                invalid_records.append({
                    "row": row_number,
                    "reason": str(error),
                })

    return records, invalid_records
