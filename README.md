# EventLogMonitor (Windows Security Event GUI)

EventLogMonitor is a Python/Tkinter GUI tool for **hunting and monitoring critical Windows Security Event Log IDs**.  
It allows defenders to quickly query logs like **4625 (failed logons)**, **4672 (privilege logons)**, **4720 (account creation)**, and more — without memorizing Event IDs.

🚨 Designed for **SOC analysts, incident responders, and security engineers** who need fast visibility into Windows authentication and persistence events.

---

## ✨ Features

- **Searchable dropdown** of high-value Event IDs (with descriptions).
- **Multi-select list** so you can query multiple IDs at once.
- **Flexible lookback window** (hours).
- **Help window** (`?` button) with detailed explanations of each Event ID and why it matters.
- **Results in real time** inside the GUI.
- **Structured JSONL output** written to disk for SIEM ingestion:

- ## 🔑 Supported Event IDs

Some highlights:

| Event ID | Name | Why it matters |
|----------|------|----------------|
| 4624 | Successful logon | Detect abnormal login times or remote logons. |
| 4625 | Failed logon | Brute force & password spray detection. |
| 4648 | Logon with explicit credentials | Possible Pass-the-Hash/Ticket. |
| 4672 | Special privileges assigned | Admin logon alerting. |
| 4698 | Scheduled task created | Persistence indicator. |
| 4719 | Audit policy changed | Defense evasion. |
| 4720 | User account created | Persistence via backdoor accounts. |
| 4732 | Member added to privileged group | Privilege escalation. |
| 4740 | User account locked out | Brute-force side effect. |
| 4776 | Credential validation (NTLM) | Lateral movement or relay. |
| 1102 | Audit log cleared | Covering tracks. |

The **Help window** in the app lists all included Event IDs with detailed reasoning.

---

## 🖥️ Screenshots

*(Add screenshots here once you run the GUI — e.g., the main window with dropdown and results.)*

---

## 🚀 Usage

### Option 1 (Not necessary with EXE version): Run with Python
1. Install requirements:
 ```powershell
 py -3.13 -m pip install pywin32
