# Detection Engineering as Code

A personal detection engineering lab project mapping MITRE ATT&CK techniques 
to Sigma detection rules, validated against real telemetry in an isolated lab environment.

## Lab Architecture
- **Victim**: Windows 11 Enterprise Evaluation + Sysmon (SwiftOnSecurity config)
- **Detection**: Ubuntu VM running Elasticsearch + Kibana
- **Log shipping**: Winlogbeat (Windows → Elasticsearch)
- **Hypervisor**: VMware Workstation, host-only isolated networking

## Repository Structure
- `rules/` — Hand-written Sigma detection rules, one per ATT&CK technique
- `scripts/` — Automation scripts (simulate → detect → report pipeline)
- `results/` — Pass/fail detection reports per technique

## Techniques Covered
| Technique | Name | Tactic | Rule |
|---|---|---|---|
| T1547.001 | Registry Run Key Persistence | Persistence | rules/T1547.001.yml |
| T1059.001 | PowerShell Encoded Command | Execution | rules/T1059.001.yml |
| T1057 | Process Discovery | Discovery | rules/T1057.yml |
| T1055.001 | DLL Injection via mavinject | Defense Evasion | rules/T1055.001.yml |
| T1053.005 | Scheduled Task | Persistence | rules/T1053.005.yml |

## Pipeline
Simulate (Atomic Red Team) → Ship logs (Winlogbeat) → Convert rule (pySigma) 
→ Query Elasticsearch → Pass/Fail report
