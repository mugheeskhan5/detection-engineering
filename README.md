# Detection Engineering as Code

A personal lab project that simulates real MITRE ATT&CK techniques, validates hand-written Sigma detection rules against the resulting logs, and automates the entire loop — trigger → detect → report → visualize — into a version-controlled, CI/CD-driven pipeline.

**Status: Complete.** All six planned phases are done: lab build, manual technique hunting, Sigma rule authoring, pipeline automation, remote triggering, and ATT&CK Navigator coverage visualization.

---

## 1. What this project actually does

1. Simulates a MITRE ATT&CK technique on an isolated Windows VM (via [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)-style commands, triggered remotely).
2. Ships the resulting Sysmon/Windows Event Log telemetry to Elasticsearch via Winlogbeat.
3. Lints and validates a hand-written Sigma rule for that technique.
4. Converts the Sigma rule into a real Elasticsearch query (with correct ECS field mapping).
5. Queries Elasticsearch, scoped to a recent time window, to check whether the technique was actually detected.
6. Writes a structured PASS/FAIL report per technique.
7. Generates a live ATT&CK Navigator heatmap from the most recent verdict per technique.
8. Runs all of the above automatically via GitHub Actions whenever a rule changes.

---

## 2. Architecture

```
Host: Windows laptop, 16GB RAM, VMware Workstation
├── Windows 11 VM (victim/sensor)      — 192.168.86.128 (host-only, isolated)
│   ├── Sysmon (SwiftOnSecurity config)
│   ├── Winlogbeat — persistent Windows service, auto-starts on boot
│   ├── WinRM listener (HTTP, Basic auth) — remote command execution
│   └── No internet access, by design
└── Ubuntu VM (detection stack)        — 192.168.86.130 (host-only) + NAT (internet)
    ├── Elasticsearch + Kibana
    ├── Python pipeline (pySigma, sigma-cli, elasticsearch client, pywinrm)
    ├── git repo: ~/detection-engineering/
    └── GitHub Actions self-hosted runner (systemd service)
```

**Why host-only + isolated Windows VM:** prevents outbound internet noise from polluting Sysmon logs during atomic testing, and forces a clean, deliberate telemetry signal.

**Why Ubuntu is dual-homed:** it needs internet (package installs, GitHub) *and* a private channel to the isolated Windows VM. It's also the only machine that can reach both Windows (WinRM) and Elasticsearch, which is why it — not GitHub's cloud — has to run the CI/CD jobs.

---

## 3. Techniques covered

| Technique | Rule file | Detection logic | Level | Automated trigger |
|---|---|---|---|---|
| T1547.001 — Registry Run Key Persistence | `rules/T1547.001.yml` | `TargetObject\|contains: '\CurrentVersion\Run\'` | medium | ✅ WinRM (`reg add`) |
| T1059.001 — PowerShell Encoded Command | `rules/T1059.001.yml` | `CommandLine\|contains\|all` + parent-process filter | medium | ✅ WinRM (`powershell.exe -e`) |
| T1057 — Process Discovery (tasklist) | `rules/T1057.yml` | `Image\|endswith: '\tasklist.exe'` + parent-process filter | low | ✅ WinRM (`tasklist`) |
| T1053.005 — Scheduled Task Creation | `rules/T1053.005.yml` | `CommandLine\|contains\|all` (schtasks, `/ru system`, `/tr`, `cmd.exe`) | high | ✅ WinRM (`schtasks /create`) |
| T1055.001 — DLL Injection (mavinject) | `rules/T1055.001.yml` | `Image\|endswith: '\mavinject.exe'` | high | ❌ Manual only — see [Known limitations](#7-known-limitations--honest-gaps) |

T1057 is intentionally rated `low` — a single-event tasklist execution is indistinguishable from legitimate admin activity without behavioral correlation, which this pipeline doesn't attempt.

---

## 4. Repo structure

```
detection-engineering/
├── rules/                      # Sigma rules, one per technique
│   ├── T1547.001.yml
│   ├── T1059.001.yml
│   ├── T1057.yml
│   ├── T1053.005.yml
│   └── T1055.001.yml
├── scripts/
│   └── pipeline.py             # lint → validate → convert → trigger → query → report → heatmap
├── results/                    # per-run JSON reports (gitignored — regenerated every run)
├── heatmap_layer.json          # ATT&CK Navigator layer, regenerated from latest verdicts (tracked)
├── .github/workflows/
│   └── detection-pipeline.yml  # CI/CD workflow
├── .gitignore
└── README.md
```

---

## 5. The pipeline (`scripts/pipeline.py`)

### Stages

| Function | Purpose |
|---|---|
| `trigger_atomic(session, command, args)` | Executes the real attack technique remotely on Windows via WinRM |
| `lint_rule(rule_path)` | Runs `sigma check` via subprocess; validates YAML/Sigma syntax |
| `validate_rule(rule_path)` | Confirms required fields (`logsource`, `detection`, `id`) are present |
| `convert_rule(rule_path)` | Converts Sigma → Lucene query via pySigma, using the `ecs_windows` field-mapping pipeline |
| `query_rule(lucene_query, minutes=10)` | Queries Elasticsearch, scoped to a rolling time window, returns hit count |
| `write_report(...)` | Writes a timestamped PASS/FAIL JSON report to `results/` |
| `build_heatmap()` | Reads the *most recent* result per technique and generates a Navigator-compatible heatmap |

### Why the ECS pipeline matters

Sigma rules are written against raw Sysmon field names (`TargetObject`, `CommandLine`, `Image`, `ParentImage`). This Winlogbeat/Elasticsearch setup stores events under ECS-normalized field names instead (`registry.path`, `process.command_line`, `process.executable`, `process.parent.executable`). Converting without the `ecs_windows` pipeline produces syntactically valid queries that silently match zero documents, every time — a real false-negative trap. This was verified directly: the same rule set was queried both with and without the pipeline, confirming zero hits pre-mapping and correct hits post-mapping.

### Why the time window matters

Without a bounded `@timestamp` range, `query_rule` would search the *entire* historical index — meaning a rule could "pass" against an event logged weeks ago, telling you nothing about whether the technique you just triggered was actually detected right now. `query_rule` defaults to a 10-minute rolling window.

### Report format

```json
{
  "technique_id": "T1547.001",
  "query": "registry.path:*\\CurrentVersion\\Run\\*",
  "lint_result": true,
  "validate_result": true,
  "hit_count": 1,
  "verdict": "PASS"
}
```

`verdict` is `"PASS"` only if lint passed **and** validate passed **and** hit_count > 0. A rule that fails lint but somehow returns a stale hit is still correctly reported as `FAIL`.

---

## 6. Remote triggering (WinRM)

Windows VM is configured for HTTP + Basic auth WinRM (port 5985) — deliberately the "blunt shortcut" over HTTPS + certs, justified by the fact that this network is genuinely host-only and non-routable, with no machine positioned to intercept traffic. The same reasoning already applied to Elasticsearch's TLS verification mode.

```powershell
Enable-PSRemoting -Force
Set-Item WSMan:\localhost\Service\Auth\Basic -Value $true
Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $true
New-NetFirewallRule -Name "WinRM-HTTP-In" -DisplayName "WinRM HTTP In" -Enabled True -Direction Inbound -Protocol TCP -LocalPort 5985 -Action Allow
```

**Known quirk:** `pywinrm`'s `run_cmd(command, args_list)` reassembles the argument list into a single command-line string before transmission, but does **not** automatically re-quote multi-word arguments. A value like `Atomic Red Team` must be passed with literal embedded quotes: `'"Atomic Red Team"'` — otherwise it arrives on the Windows side as three separate broken tokens, producing `ERROR: Invalid syntax` from the target command.

**Known quirk 2:** `schtasks /create` will hang indefinitely over a non-interactive WinRM session if the task name already exists (it's waiting for a Y/N overwrite confirmation that can never arrive). Fixed by using a unique task name / `/F` force flag.

---

## 7. Known limitations & honest gaps

- **T1055.001 (DLL injection) is not automated.** Automating it requires discovering a live process PID and using `run_ps` instead of `run_cmd` — meaningfully more complex for a technique whose *detection* is already known-weak (see below). Deliberately deferred rather than forced.
- **T1055.001's rule only detects execution of `mavinject.exe`, not actual injection.** Sysmon Event ID 8 (CreateRemoteThread) was never captured during testing despite successful injection, root cause unresolved (suspected kernel driver timing issue). The rule still "passes" by its own definition (mavinject ran), but this is a weaker signal than it appears.
- **Sysmon Event ID 7 (Image Load) is fully disabled** in the SwiftOnSecurity config used here. Any future rule relying on DLL load visibility needs a custom Sysmon config.
- **T1057's zero-hit results are filter behavior, not a bug** — but this was a *hypothesis*, subsequently verified by checking `process.parent.executable` on the raw tasklist events directly in Kibana, confirming the exclusion filter was correctly removing them.
- **`results/` is not version-controlled.** Every pipeline run generates fresh, uniquely-timestamped per-technique reports; committing them would make the repo grow unboundedly. `heatmap_layer.json` (which overwrites in place, reflecting only current state) is tracked instead.
- **The CI/CD workflow reruns all techniques on any `rules/**` change**, not just the changed rule. Acceptable for this project's scale; a known, deliberate simplification.
- **No branch protection blocks a failing pipeline from landing on `main`.** GitHub's "require status checks" only blocks PR merges, not direct pushes — and a PR-per-change workflow was deemed unnecessary friction for a solo project. The Actions tab's pass/fail signal is relied on directly instead.

---

## 8. CI/CD

A GitHub Actions **self-hosted runner** runs as a `systemd` service on the Ubuntu VM (not GitHub's cloud runners — they have no network path to this isolated lab). On every push that touches `rules/**`, the workflow checks out the repo and runs the full pipeline — real WinRM trigger, real Elasticsearch query, real report — with zero manual VM interaction.

```yaml
name: Detection Engineering Pipeline
on:
  push:
    paths:
      - rules/**
jobs:
  test:
    runs-on:
      - self-hosted
      - linux
    env:
      WINRM_PASSWORD: ${{ secrets.WINRM_PASSWORD }}
    steps:
      - uses: actions/checkout@v4
      - name: Run pipeline
        run: python3 scripts/pipeline.py
```

Secrets (`WINRM_PASSWORD`) are stored in GitHub Actions repository secrets, never in the workflow file or `pipeline.py` itself.

---

## 9. Credential handling

- **`WINRM_PASSWORD`** — read via `os.environ["WINRM_PASSWORD"]`, set locally via `~/.bashrc` and via GitHub Actions repository secrets for CI. Treated seriously because it's a real Windows account login, subject to password-reuse risk.
- **Elasticsearch password** — left hardcoded in `pipeline.py` by deliberate choice: it's a randomly-generated, lab-only service credential with no reuse risk and no value outside this isolated environment.

---

## 10. Setup (from scratch)

**Windows VM:**
1. Install Sysmon (SwiftOnSecurity config) and Winlogbeat.
2. Install Winlogbeat as a persistent service: `install-service-winlogbeat.ps1`, then `Set-Service -Name winlogbeat -StartupType Automatic`.
3. Enable WinRM per Section 6 above.
4. Confirm network adapter is set to **Private**, not Public (required for `Enable-PSRemoting`).

**Ubuntu VM:**
```bash
git clone https://github.com/mugheeskhan5/detection-engineering
cd detection-engineering
pip3 install pysigma pysigma-backend-elasticsearch elasticsearch sigma-cli pywinrm --break-system-packages
echo 'export WINRM_PASSWORD="<your-windows-password>"' >> ~/.bashrc
source ~/.bashrc
```

**GitHub Actions runner (Ubuntu VM):**
1. `Settings → Actions → Runners → New self-hosted runner` on GitHub, follow the generated commands.
2. `sudo ./svc.sh install && sudo ./svc.sh start` — installs as a persistent service.
3. Add `WINRM_PASSWORD` under `Settings → Secrets and variables → Actions`.

**Run manually:**
```bash
python3 scripts/pipeline.py
```

**View coverage:**
Upload `heatmap_layer.json` at [mitre-attack.github.io/attack-navigator](https://mitre-attack.github.io/attack-navigator/) → Open Existing Layer.

---

## 11. Lessons worth remembering

- **Sigma field names ≠ your actual log schema.** Always verify real field names against a live document before trusting a rule's field references — don't assume ECS conventions without checking.
- **Exit codes, not string-matching, for programmatic pass/fail.** Parsing a CLI tool's printed text is fragile; wording changes silently break it. `returncode` doesn't.
- **Unbounded time-range queries lie about "recent" detection.** A query with no time filter can't distinguish "detected just now" from "detected three weeks ago."
- **`git add .` is fine day-to-day, but explicit file staging is worth it when verifying a specific mechanism** — it removes ambiguity about what actually caused an observed effect.
- **"No errors" ≠ "did what I expected."** Several real bugs this project only surfaced by checking actual state (registry keys, service status, file existence) rather than trusting a clean exit code.
- **Isolate variables before debugging distributed systems.** Ping → port → protocol; local execution → remote execution. Splitting a failure into layers turns a vague error into an obvious one.
