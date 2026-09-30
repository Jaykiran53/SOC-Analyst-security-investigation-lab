# SIEM Alert Triage

## Objective

Investigate and triage security alerts generated in a controlled Wazuh SOC lab environment.

The investigation follows the SOC workflow:

Activity → Log → Event → Rule → Alert → Investigation → Verdict → Response

## Lab Environment

- Wazuh SIEM
- Ubuntu Server
- Windows 11
- Sysmon
- Kali Linux
- VMware

## Alert 1 — User Account Enabled

### Activity

A Windows user account was enabled in the Windows 11 endpoint.

### Windows Event

- Event ID: 4722
- Channel: Security
- Event: User account was enabled
- Target account: testuser123

### Wazuh Detection

- Rule ID: 60109
- Rule description: User account enabled or created
- Rule level: 8
- MITRE ATT&CK: T1098 — Account Manipulation
- Tactic: Persistence

### Investigation

The event was reviewed in Wazuh to identify the affected account, user context, event ID, timestamp, and MITRE mapping.

### Verdict

Potentially suspicious account activity requiring investigation and validation of whether the account change was authorized.

---

## Alert 2 — New Windows Service Created

### Activity

A test Windows service named `TestSOCService` was created in the Windows 11 lab endpoint.

### Command Used

```cmd
sc create TestSOCService binPath= "C:\Windows\System32\cmd.exe"
---

## Alert 3 — Firewall Rule Modification

### Activity

A Windows firewall rule was added using `netsh`.

### Command Used

```cmd
netsh advfirewall firewall add rule name="SOC-Test-Block" dir=in action=block protocol=TCP localport=4444

### Sysmon Evidence

The firewall modification was intentionally generated in the controlled lab. In a real SOC environment, unexpected firewall changes should be investigated because attackers may modify firewall settings to weaken host defenses or facilitate malicious activity.

- Sysmon Event ID: 1 — Process Create
- Process: `C:\Windows\System32\netsh.exe`
- Parent process: `cmd.exe`
- User: `jay\kiran`

### Wazuh Detection

- Rule description: Netsh used to add firewall rule
- Rule ID: 92043
- Rule level: 10
- MITRE ATT&CK: T1562.004 — Disable or Modify System Firewall
- Tactic: Defense Evasion

### Investigation

The Wazuh alert was correlated with Sysmon process creation telemetry.

The command line, executable path, parent process, user, process ID and timestamp were reviewed.

### Verdict

The activity was intentionally generated in the controlled lab environment to simulate a firewall modification event.

Verdict: Benign / Authorized Lab Activity

In a real SOC environment, unexpected firewall rule changes should be investigated because attackers may modify firewall settings to weaken host defenses or facilitate malicious activity.

### Response

No containment action was required because the activity was intentionally generated for the lab.

In a real SOC environment, the analyst should validate the change with the system owner and investigate any unauthorized firewall modification.
