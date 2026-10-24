# Investigation Evidence

This folder contains screenshots documenting the Windows logon event investigation performed using Splunk Cloud.

## Evidence Index

| Screenshot | Description |
|---|---|
| `01-event-counts.png` | Counts of successful and failed logon events |
| `02-failed-logon-analysis.png` | Failed logon details, including account and failure status |
| `03-successful-logons.png` | Successful logon events and associated process details |
| `04-windows-logon-timeline.png` | Chronological reconstruction using the original event timestamps |
| `05-linked-logon-sessions.png` | Linked logon IDs and elevated-token analysis |

Screenshots are intended to support the investigation findings documented in `report/incident_report.md`. The event sample is limited and does not independently establish malicious activity.
