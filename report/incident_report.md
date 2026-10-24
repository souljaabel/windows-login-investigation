# Windows Logon Event Investigation

## 1. Overview

**Investigation Type:** Windows Security Event Log Analysis  
**Tools:** PowerShell, Splunk Cloud  
**Data Source:** `CA_4624_4625_LogonType2_LogonProc_chrome.evtx`  
**Host:** `MSEDGEWIN10`  
**Event Date:** September 9, 2020

### Objective

Analyze Windows Security Event IDs 4624 and 4625 to investigate a failed logon, review subsequent successful logons, and reconstruct the available event timeline.

## 2. Key Findings

- Identified **one failed logon event (Event ID 4625)** involving the `IEUser` account.
- The failure reason indicated an unknown username or incorrect password. The substatus `0xC000006A` indicated an incorrect password.
- Identified **three successful logon events (Event ID 4624)**.
- Two successful interactive logon events involved `IEUser` and were associated with `chrome.exe`.
- The two interactive sessions contained reciprocal linked logon IDs, consistent with related standard and elevated sessions.
- A separate successful logon used Logon Type 5 and `services.exe`, consistent with a Windows service logon.
- No source IP address was present in the analyzed failed-logon event.

## 3. Timeline

| Time (local event time) | Event ID | Event | Details |
|---|---:|---|---|
| 06:18:23.627 | 4625 | Failed logon | `IEUser`; incorrect password |
| 06:18:25.377 | 4624 | Successful logon | `SYSTEM` service logon; `services.exe` |
| 06:18:27.714 | 4624 | Successful logon | `IEUser`; Chrome-associated interactive session; elevated token |
| 06:18:27.714 | 4624 | Successful logon | `IEUser`; Chrome-associated interactive session; non-elevated token |

## 4. Technical Analysis

### Failed Logon — Event ID 4625

- **Account:** `IEUser`
- **Domain:** `MSEDGEWIN10`
- **Logon Type:** 2 — Interactive
- **Failure substatus:** `0xC000006A` — Incorrect password
- **Process:** `C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`
- **Process ID:** `0x1358`
- **Workstation:** `MSEDGEWIN10`
- **Source IP:** Not populated in the analyzed event

The event documents an unsuccessful interactive logon. By itself, it does not establish whether the failure was caused by user error, automated activity, or malicious behavior.

### Successful Logons — Event ID 4624

The dataset contained three successful logons. One was a Logon Type 5 service logon associated with `services.exe`. The other two were Logon Type 2 interactive sessions for `IEUser` associated with Chrome.

The interactive events included elevated and non-elevated tokens, along with linked logon IDs that suggest the sessions were related. These fields provide context but do not independently prove privilege abuse or malicious execution.

## 5. Limitations

- The sample contains only four events, limiting the scope of the investigation.
- The available events do not provide a source IP for the failed logon.
- No surrounding authentication, process-creation, network, or persistence telemetry was included in this sample.
- The event sequence alone cannot establish that the failed logon caused or was directly related to the subsequent successful logons.
- Splunk's indexed event time did not preserve the original event chronology, so the investigation used the original `TimeCreated` field for timeline reconstruction.

## 6. Conclusion

The analysis identified one failed interactive logon followed by three successful logon events. The successful events included a Windows service logon and two related-looking interactive sessions associated with Chrome.

**Assessment:** The available evidence is insufficient to classify this activity as malicious or confirm a compromise. Additional endpoint and authentication telemetry would be needed to determine whether the sequence represents normal activity or suspicious behavior.

## 7. Recommended Follow-Up

- Correlate with other Windows Security events from the same host and time period.
- Review process-creation telemetry, such as Event ID 4688, if available.
- Investigate additional failed logons and successful logons for the same account.
- Check available endpoint telemetry for unexpected Chrome child processes or suspicious activity.
- Preserve the original event logs and document any additional findings.
