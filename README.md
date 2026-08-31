# MITRE ATT&CK Technique Mapping

## 🎯 Objective
Go beyond tagging an incident with a list of technique IDs at the end of a report. For a real investigated incident, map **every step of the attack chain** to a specific MITRE ATT&CK tactic and technique (with sub-technique where one applies), tie each mapping back to the exact evidence line that supports it, note which data source would detect it, and suggest a concrete detection or mitigation. Where the evidence doesn't cleanly point to one technique, say so — a mapping that overstates its own certainty is worse than one that shows its reasoning.

## 🤔 Why this matters for SOC L1
ATT&CK is the common vocabulary SOC, CTI (threat intel), and detection engineering teams actually use to talk to each other — "this alert fired on T1110" means something specific and shared, "brute force stuff" doesn't. Being able to take a messy set of logs and cleanly place each step onto the ATT&CK matrix — and explain *why* it belongs there, not just cite the ID — is a skill that shows up constantly in real SOC work: writing detection rules, briefing a shift lead, doing coverage analysis, or reading a threat intel report and knowing what to hunt for.

## 🛠️ Methodology
1. Start from a real, already-investigated incident (evidence, not a hypothetical).
2. For each distinct action in the attack chain, ask: what tactic (the *why*) does this serve, and what specific technique (the *how*) is this an instance of?
3. Cite the exact log line or artifact that supports the mapping. If a technique choice is a judgment call rather than a clear-cut match, say that explicitly instead of presenting it as certain.
4. Note the data source that surfaced the evidence (this matters operationally — see the Lessons Learnt in [project 1](https://github.com/zaimmzulhazziq/soc-log-analysis-siem), where the key evidence was only in Terminal History, not the network logs).
5. Suggest a detection idea or mitigation per technique — a mapping is more useful when it points forward to "how would I catch this next time," not just backward to "what happened."
6. Build an [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) layer file so the mapping can be visualized on the actual matrix, not just read as a table.

## 🔍 Worked example: SOC335 (CVE-2024-49138 privilege escalation)
Full technique-by-technique breakdown: [`technique-breakdown.md`](technique-breakdown.md)

Navigator layer file (load it at [mitre-attack.github.io/attack-navigator](https://mitre-attack.github.io/attack-navigator/) via "Open Existing Layer" → "Upload from local"): [`navigator/soc335-layer.json`](navigator/soc335-layer.json)

### Technique summary

| Step | Evidence | Tactic | Technique |
|---|---|---|---|
| 14 failed RDP logons against `admin`/`guest` | EventID 4625 ×14, Log Management | Credential Access | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) Brute Force: Password Guessing |
| Successful RDP logon as `Victor` from external IP | EventID 4624, Logon Type 10, Log Management | Initial Access | [T1133](https://attack.mitre.org/techniques/T1133/) External Remote Services |
| `whoami`, `whoami /priv` | Terminal History | Discovery | [T1033](https://attack.mitre.org/techniques/T1033/) System Owner/User Discovery |
| PowerShell downloads payload from S3 URL | Terminal History | Execution | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) Command and Scripting Interpreter: PowerShell |
| Same download, as a file-transfer action | Terminal History | Command and Control | [T1105](https://attack.mitre.org/techniques/T1105/) Ingress Tool Transfer |
| Archive extracted with hardcoded 7-Zip password | Terminal History | Defense Evasion | [T1027.013](https://attack.mitre.org/techniques/T1027/013/) Obfuscated Files or Information: Encrypted/Encoded File |
| Payload named `svohost.exe` to mimic `svchost.exe` | Process log, Terminal History | Defense Evasion | [T1036.005](https://attack.mitre.org/techniques/T1036/005/) Masquerading: Match Legitimate Name or Location |
| Execution exploits CVE-2024-49138 | Process log (`Device Action: Allowed`) | Privilege Escalation | [T1068](https://attack.mitre.org/techniques/T1068/) Exploitation for Privilege Escalation |

Full reasoning, data sources, and detection/mitigation notes for every row are in [`technique-breakdown.md`](technique-breakdown.md).

## 🔁 Difference from project 1's mapping
[Project 1's README](https://github.com/zaimmzulhazziq/soc-log-analysis-siem) tagged this same incident with a short technique list at the bottom of the report (T1110, T1059.001, T1105, T1036, T1068, T1548) — accurate, but flat. This project takes the same incident and does the deeper version of the same job: correct sub-techniques where one applies, the specific tactic each technique sits under, the evidence trail for each, and — honestly — a couple of places where the mapping is a judgment call rather than a clean fact (see the note on the RDP access technique in the breakdown). That gap between "tag it" and "map it properly" is exactly the skill this project is meant to demonstrate.

## 📚 Lessons learnt
- A technique ID alone doesn't communicate much — the tactic (why) and the specific evidence (how do I know) are what make a mapping actually useful to someone else reading it.
- Not every step maps cleanly to one technique. The RDP access step could reasonably be argued as T1133 (External Remote Services) or T1078 (Valid Accounts) depending on whether the successful logon used brute-forced or already-valid credentials — the evidence doesn't fully resolve which, and forcing a single confident answer would be less honest than noting the ambiguity (see `technique-breakdown.md`).
- Building the Navigator layer file by hand (rather than eyeballing the matrix) forces you to get the tactic-technique pairing exactly right, since Navigator will silently misplace a technique if it's assigned to a tactic it doesn't actually belong to.

## 🔗 Related
- [Project 1 — SOC Alert Triage & Log Analysis](https://github.com/zaimmzulhazziq/soc-log-analysis-siem) (the source investigation)
- [Project 2 — AI-Assisted Incident Triage](https://github.com/zaimmzulhazziq/ai-assisted-incident-triage) (same incident, different angle: reviewing AI-drafted reports)
