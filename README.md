# NetTruder

Version 1.1.0. The console was called NetWatch before 1.1.0.

A defensive network operations console for Windows, styled after Armitage /
Cobalt Strike but built to do the opposite of an attack framework.

NetTruder discovers hosts on your own network, audits the local machine, watches
the local connection table for intrusion indicators, can temporarily block a
remote address with the Windows firewall, and lists local processes with the
same quick response actions as Task Manager. It also contains a real `cmd`
terminal and a defensible coverage lab that scores whether documented
living-off-the-land primitives would be detected on this host. Version 1.1.0
adds a read-only process/data-flow map, a passive web-risk check, a static code
audit, a read-only threat investigation, a local alert triage board, an endpoint
block register and read-only data classification with an opt-in purge preview.

Nothing in this tool is offensive: there is no C2, no listener, no payload, no
lateral movement, no credential access and no persistence.

For a module-by-module explanation from SWEEP to PS LOGGING, including the
request/event architecture, the defensive review model and the manual browser
handoff, see `HOW-IT-WORKS.md`. Licensing and third-party provenance are in
`LICENSE` and `THIRD-PARTY-NOTICES.md`.

---

## Read this first

- **Read-only by default.** Scanning, the posture probe, the IDS and the 1.1.0
  analysis views (flow, web, code, threats, triage, exposure and data check)
  never change the system.
- **It never weakens security.** It does not touch Defender, the firewall
  profile, Windows Update, services, drivers, scheduled tasks or existing rules.
  It makes no service startup changes, no telemetry reduction, no page-file or
  network-stack tweaks and no personal-file deletion. There is no AV bypass and
  no payload, C2, persistence, credential access, obfuscation, hidden window or
  evasion primitive anywhere in the folder.
- **The IPS only creates its own rules**, named `NetTruder-IPS-<ip>-in` and
  `NetTruder-IPS-<ip>-out`. Every rule has an expiry and is removed automatically.
- **Blocking requires administrator.** Without elevation the IPS refuses and
  creates nothing.
- **Process termination is opt-in and confirmed.** Every kill needs an explicit
  dialog, is written to the audit log, and refuses core system or security
  processes. The process view itself is read-only until you press KILL.
- **Every security-relevant action is appended to an audit log.**
- **Nothing auto-elevates.** NetTruder never disables UAC and never turns a
  security control off. The elevated-shell action copies a script for review
  and paste; it never runs it for you.

If any of that is not what you want, do not run the IPS module.

For the security practices NetTruder follows and the practices an operator
should use, see `BEST-PRACTICES.md` at the root of this folder.

---

## Requirements

| Item | Detail |
|---|---|
| Version | 1.1.0 (engine, HTA footer and console state all agree) |
| OS | Windows 10 or Windows 11 |
| PowerShell | 5.1 (built in) |
| UI host | `mshta.exe` (built in) |
| Script host | `wscript.exe` (built in) |
| Admin | only for IPS block / unblock / release |

No install, no service, no driver, no build step. It is a folder of text files.
The console skin is static: the old animated scanline sweep is gone, and only
small status LEDs animate.

---

## Launch

**Standard user (scan, IDS, posture, terminal):**

```
Launch.cmd
```

**Administrator (adds IPS):**

```
Launch-Elevated.cmd
```

`Launch-Elevated.cmd` shows a UAC prompt and re-launches itself. The window badge
in the top-right reads `USER` or `ADMIN` so you always know which mode you are in.
The launcher is `NetTruder.hta`, the engine is `engine\NetTruder.ps1`, and the
lab script is `research\Test-NetTruderPosture.ps1`.

NetTruder sizes and centres its window once at launch, then never resizes it
again. The module list scrolls inside the left rail; the scope/response block,
version footer and status bar stay pinned on screen. Maximise or restore the
window with the title-bar buttons at any time - the console will not fight you.

### Why there is a `shim.vbs`

The console is an HTA. On machines with an endpoint agent (McAfee, in testing),
a direct HTA-to-PowerShell launch is refused with `0x800700E1`. NetTruder routes
the launch through `engine\shim.vbs`, which WSH runs, which starts the hidden
PowerShell worker. That is a normal parent/child chain and needs no policy
change. **Do not disable or whitelist your antivirus to make this run.** If the
shim is blocked too, the console says so in the CONSOLE pane and refuses to
pretend it worked.

### If the launch chain is blocked

Windows Script Host may be disabled, `.hta` may be blocked or unassociated, or a
product may refuse the `mshta -> wscript -> PowerShell` chain. NetTruder may
then not open. That is a valid control result, not a project failure. Record the
product, event id, parent/child pair and exact message, then stop. Do not
re-enable WSH, change `.hta` associations, add an exclusion, or switch to a
direct PowerShell call just to get the window open. See `BEST-PRACTICES.md`
section 13 for the five valid next paths and `research/BLOCKED-TESTS.md`
section 10 for the evidence template. The hardening and telemetry guidance in
`RESEARCH.md` and `research\README.md` still matters: prevention and detection
answer different questions.

### Optional browser extension

`browser-extension\` contains a read-only Chromium/Edge MV3 extension called
**NetTruder Site Posture** (v1.4.0). It shows page-level defensive posture:
HTTPS state, redacted mixed-content references, form and password-field context,
visible cookie names, optional security headers, and passive login indicators.
The login view can use a local, session-only list of exact trusted IdP hostnames
and review lookalike hosts, cross-origin login form actions, main-frame redirect
hosts and session cookie flag names. It uses an active-tab model, has no host
access by default, never reads browser history, form values, cookie values or
tokens, and sends no data anywhere. See `browser-extension\README.md` for
install, permission and limits.

The extension's **COPY REPORT** text can be pasted manually into **WEB RISK >
EXTENSION REPORT IMPORT** in this console. There is no automatic bridge: no
native messaging, listener, file drop, profile read or network request. The
import is in-memory only and treats all evidence as indicators, never as proof
of AiTM, MFA bypass, token replay or compromise. If enterprise policy blocks
unpacked extensions, record the block as a control success and stop; do not
weaken the policy to load it. See `research\BROWSER-EXTENSION-ABUSE.md` for the
malicious-extension threat model and
`research\AITM-PHISHING-SESSION-HIJACK.md` for the corrected ATT&CK mapping,
passive indicator limits and hardening checklist.

### Research lab

`research\` is a separate defensive lab for documented LOLBAS, worm-like and
Linux/Unix GTFOBins execution primitives. It inventories which system binaries
are present, checks whether the host has the telemetry and execution policy that
would record or block them, and can run four inert marker probes to validate that
logging fires end to end. It is read-only by default and never applies a
hardening change.

```
research\Invoke-Lab.cmd
```

See `research\README.md` for the catalogs, safety boundary, coverage-gap method
and the observed-block register. The same lab is also wired into the console as
module **14 - RESEARCH**; standalone runs and console runs share the catalogs and
write reports to the same folder.

### HEVD source study lab

A trimmed, **source-only** copy of HackSysExtremeVulnerableDriver lives in
`research\hevd-source\`. It is a static Code Audit target, not a driver to build
or load. The upstream exploit, builder, tools, signing certificate and `.git`
metadata were removed. A local Python 3 venv in that folder runs a standard-
library helper that prints beginner/advanced guides and summarizes bridged
findings; it installs no packages and executes no source.

In **CODE AUDIT**, press **HEVD SOURCE** for a read-only scan, **HEVD REVIEW** for
the layered beginner and advanced explanation, **HEVD GUIDE** for the safety
boundary, **INT WRAP** for a plain-language explanation of wrapped size
arithmetic, and **SEND TO RESEARCH** after a scan to copy masked findings into
module 14. Each finding shows static evidence, reach, preconditions, a state
label and an authorised-lab verification checklist; **EVIDENCE / VERIFY** opens
the same material with the documented fix. The bridge writes
`%LOCALAPPDATA%\NetTruder\hevd-source-findings.json`. Eight `Source Review`
catalog entries appear in RESEARCH under group `Kernel Source Review` and are
always `NOT EVALUATED` because no host binary is probed.

NetTruder never builds, signs, loads, installs or executes this driver, sends no
IOCTL, and carries no exploit code. Defender, firewall, VBS, HVCI and code
integrity stay as they are. See `research\HEVD-RESEARCH.md` for the full guide.

---

## Onboarding

On first run a welcome survey asks for your role and experience level, then a
10-step product tour walks the modules. After that, each view shows a short
in-app hint the first time you open it. Press **GUIDE** in the top bar at any
time to reopen onboarding.

The answers are stored locally in
`%LOCALAPPDATA%\NetTruder\state\onboarding.json` as `{seen, role, level, at}`.
Nothing is sent anywhere.

---

## Modules

### 01 - SWEEP

Discovers hosts and services on a network you are authorised to test.

- **Targets** accepts `192.168.1.0/24`, `192.168.1.10-200`,
  `192.168.1.10-192.168.1.80`, a single IP, or a hostname.
- **LOCAL SUBNET** fills in your own RFC1918 subnet.
- **GATEWAY** fills in the default gateway.
- **Port profile** picks the port set: `common` (28 ports), `web`, `remote`,
  `db`, `mail`.
- **Timeout** controls connect and ICMP patience.

Results are one row per live host: MAC (from the ARP/neighbour table), reverse
name, latency, open ports with service labels, and a rolled-up risk level. Click
a row for a detail strip. **ABORT** writes the run's stop file and the engine
stops at the next host boundary.

Guards:

- Sweeps are capped at `/22` (512 hosts).
- Non-private addresses are dropped unless the engine is called with
  `-AllowPublic`. The UI never sets that flag.

### 02 - PROCESS FLOW

A read-only process tree and data-flow map in an n8n-style graph. Boxes are
processes and remote endpoints; lines are parent links and TCP connections.
Filter by pid, process or path, and click a box to read its command line.

- Collected from the process table and the live TCP table; no process is
  started, changed or ended here.
- **FINDINGS** flags unusual parent/child shapes and many concurrent flows as
  triage context, never as proof of compromise.
- Smoke: 512 events, 260 nodes, 242 edges, 5 findings.

### 03 - WEB RISK

A passive web posture check. It uses GET and OPTIONS only: response headers,
TLS, cookies, forms, HTML comments and unauthenticated exposure paths. There is
no exploitation, fuzzing, auth bypass or payload.

- Enter a loopback or private URL. Public hosts require an explicit opt-in:
  tick **ALLOW PUBLIC HOST** in the UI, or pass `-AllowPublic` on the CLI. Nothing
  public is scanned without that step.
- OWASP ZAP commands are shown as copyable recipes. NetTruder never launches
  ZAP or any other scanner for you.
- The SITE DATA FLOW graph grows with the observed response, and every node
  opens evidence, why it matters and related findings. Target cards list link
  and script results; click one to inspect masked metadata or an inline body.
  Nothing is followed or executed.
- Findings carry an OWASP/CWE reference and a fix. The recipes are suggestions
  for a separate, authorised test.

**Honest no-response behaviour.** An unreachable target emits only `NT-WEB-000`
(`Web target did not answer`) with grade `n/a` and `answered=False`. Missing
headers on a target that did not respond are recorded as `NOT EVALUATED`, not as
missing-header findings; a silent host is not a clean host and not a dirty one.
Smoke results: a live loopback target returned HTTP 200 with 12 findings and
grade `F`; a refused target returned 1 finding and grade `n/a`.

**EXTENSION REPORT IMPORT** is a manual paste area in this view. Paste the
redacted text from the browser extension's **COPY REPORT** button and press
**IMPORT REPORT**. The console parses it in memory only, rejects secret-like
text without displaying it, and renders each row with state and remediation.
It does not open a browser profile, read a file, call the network, start a
listener or write the pasted report. The import adds separate `NOT EVALUATED`
rows for FIDO2 / WebAuthn, CAE and Conditional Access device compliance. These
are identity-plane controls and cannot be proven from page data.

### 04 - CODE AUDIT

A static review of a local source folder. Files are read as text and never
executed. NetTruder is review-only by default; secret values in findings are
masked, so the report shows the pattern and location without republishing the
secret.

- Findings explain the risk and the fix; checks cover risky APIs, command
  construction, weak crypto and embedded credentials.
- The toolbar filters by severity or text, sorts by severity/file/rule/line,
  exports a text report and opens the selected file in an external editor.
  The editor handoff never writes from NetTruder itself.
- The file inspector opens any file with hits in one fixed editor surface:
  line-numbered masked source, severity-coloured hit rows and gutter markers,
  current-line/status feedback, GO LINE, and click/copy/keyboard navigation.
  The same surface is reused for raw editing, so the layout does not change when
  write mode is enabled. Hit tabs, per-file severity counts and a function index
  jump to the matching line. COPY SNIPPET, COPY FILE, COPY FUNCTION and the
  report export are review-only handoff tools. The editor/detail area takes most
  of the window height; masked source is captured for up to 4,000 lines per
  file, so the scrollbar reaches the reported hit rather than stopping at an
  early truncation point.
- **WRITE MODE OFF** is the default. It resets on every audit and on restart.
  **WRITE MODE ON** requires explicit confirmation; raw source is then fetched
  with another confirmation and is not masked. SAVE requires a third
  confirmation, writes through a path guard, preserves the source encoding and
  line endings, and backs up the original under
  `%LOCALAPPDATA%\NetTruder\state\code-edits\` before saving. REVERT, COPY RAW
  and INSERT FIX TEMPLATE are available in the raw editor. No fix is applied
  automatically. Raw content for an edit session is carried in that run's event
  file under `%LOCALAPPDATA%\NetTruder\runs\`, so treat that run as sensitive.
- Smoke: 15 files, 167 findings.

### 05 - THREATS

A read-only socket, DNS and listener investigation. It groups live peers,
flows, listening ports and DNS-cache hints into one view for triage.

- No connection is opened and no remote host is probed from this view.
- **TASK MANAGER** and **FIREWALL** open the built-in Windows tools for the
  follow-up action; NetTruder does not change a rule.
- Smoke: 26 peers, 2 findings.

### 06 - TRIAGE

A local alert board built from an exported JSON or NDJSON alert file. Alerts are
normalised, deduplicated and prioritised, then routed to the relevant research
view for context.

- Decisions (acknowledge, suppress, resolve, reopen) are stored only in
  `state\triage-decisions.json`; routing opens the related view and does not
  change the upstream alert.
- Nothing is pushed upstream: the source alert system is never changed by a
  decision made here.

### 07 - EXPOSURE

The endpoint block evidence and control-success register. It records what an
endpoint product blocked, the product and signal, and what could not be
evaluated.

- A block is a positive defensive result. It is never a coverage pass and
  never upgrades a research gap to `OK`.
- NetTruder never re-runs a blocked action and never attempts a bypass or
  obfuscation to get around a control.
- Smoke: 91 events, 2 products, 1 gap.

### 08 - DATA

Read-only classification plus an opt-in cleanup.

- **DATA CHECK** classifies files under the NetTruder data root and reports
  secret/PII pattern hits and retention findings. Smoke: 356 files, 1 finding.
- **PURGE OLD DATA** is a preview by default. It needs both `-Yes` and
  `-AckRisk` to delete anything, and is limited to NetTruder-owned runs,
  snapshots and (optionally) audit files older than `RetentionDays`. Personal
  files are never in scope. Smoke preview: 0 files, 0 bytes, nothing deleted.

### 09 - IDS / IPS

**ARM IDS** starts a host-based monitor. It polls the local TCP table every two
seconds and raises alerts for:

1. A high-risk service listening (RDP, SMB, Telnet, FTP, VNC, Redis, MongoDB,
   Elasticsearch, Memcached, WinRM, database ports).
2. An established outbound session to a flagged port (4444, 4445, 31337, 1337,
   6667, 6666, 1080, 9050, 5938), naming the owning process.
3. **Beacon cadence** - six or more new sessions to one address inside 150
   seconds, mean interval 8-200 seconds, jitter (sigma/mean) of 0.30 or less.
   Reported as a possible C2 trait, never as proof.
4. **Fan-out** - one process opening sessions to many distinct hosts inside 60
   seconds. Browser processes (`msedge`, `chrome`, `firefox`, `brave`, `opera`,
   `vivaldi`, `iexplore`) are expected to fan out to CDNs and telemetry
   endpoints, so they raise a low-severity `FANOUT` at 30 hosts; other processes
   raise it at 25. A separate high-severity `LATERAL_FANOUT` fires when one
   process reaches 4 or more distinct hosts on sensitive ports (135, 139, 445,
   3389, 5985, 5986, 22), which is the shape that matters. The low browser alert
   is triage context, not a C2 verdict; the sensitive-port alert is the one to
   action.
5. **Admin-tool egress** - 19 process-keyed rules for tools that should not
   initiate transfers: `certutil`, `bitsadmin`, `mshta`, `regsvr32`, `wscript`,
   `cscript`, `rundll32`, `msiexec`, `installutil`, `msbuild`, `forfiles`,
   `pcalua`, `cmstp`, `odbcconf`, `verclsid`, `xwizard`, `hh`, `control` and
   `wmic`. The rule carries the ports that matter (usually 80/443; RPC range for
   `wmic`) and a severity. The alert is named `EGRESS_<PROC>` and uses a 600 s
   cooldown. When it fires, the engine reads the live command line with
   `Get-CimInstance Win32_Process` and appends it to the alert, so the operator
   sees `certutil -urlcache -split -f ...` rather than only a flow. If the
   command line is unreadable the alert says so instead of guessing.
   `bitsadmin` is the exception in practice: the transfer runs inside
   `svchost.exe` (BITS), so watch the `bitsadmin` command line and the
   BITS-Client operational log; do not expect the flow to carry the
   `bitsadmin.exe` name.

Alerts deduplicate on `(rule, address, process)` with cooldowns.

Each alert carries response actions: **REMEDY** opens a modal with the observed
detail, peer/port context and remediation steps, **BLOCK** the remote address,
**PROCESS** jump to the owning process in the PROCESSES view, **KILL** the owning
process (with confirmation), and **TASKMGR** open Windows Task Manager. KILL only
appears when the monitor could attribute a PID to the connection. High, medium
and low alerts also appear as dismissible toasts in the lower-right corner with
the same REMEDY / PROCESS / DISMISS actions. The modal's buttons are copy,
elevated-shell, and native-UI only; it never offers to disable a control.

**BLOCK** on an alert, or the response list, creates a temporary pair of firewall
rules. **RELEASE ALL** removes every NetTruder rule. **DISARM** stops the monitor
cleanly. **FIREWALL** opens `wf.msc` for inspection; NetTruder never changes other
firewall rules.

**AUTO-BLOCK HIGH** is off by default. When on, only HIGH severity alerts with a
public remote address are blocked, for 10 minutes.

The IPS refuses, in code:

- the local machine, the default gateway, and configured DNS servers
- loopback, multicast, broadcast, reserved and `0.x` addresses
- private/LAN peers unless the operator explicitly confirms (the UI shows a
  confirmation dialog and passes `-Yes`)
- more than 30 simultaneous blocks

TTL is clamped to 1-240 minutes. Expiry runs at engine start, on every status
call, and on a 60-second UI timer, so a crashed console cannot leave a permanent
block behind.

### 10 - TERMINAL

A real local shell. Every command runs as `cmd.exe /d /s /c` in your user
context, with the working directory shown in the prompt.

Built-ins (handled by the console, not cmd):

| Command | Effect |
|---|---|
| `cls` / `clear` | clear the pane |
| `help` | show built-ins |
| `cd <path>` / `cd /d <path>` | change the shell working directory |

Convenience buttons run `ipconfig /all`, `arp -a`, `netstat -ano`,
`tasklist /v`, `tasklist /svc`, `route print`, `whoami /all`, `systeminfo`,
`net share`, `net use`.

**KILL** terminates the running command tree. Commands have a 900 second cap.
Every command line is written to the audit log before it runs.

Above the pane is a toggle bar for long write-outs:

| Toggle | Default | Effect |
|---|---|---|
| **WRAP** | on | wrap long lines inside the pane; off gives a horizontal scrollbar |
| **FOLLOW** | on | keep the newest output in view; scrolling up turns it off and holds the view |
| **PAUSE** | off | queue new output and leave the current screen still; resuming flushes the queue |
| **COMPACT** | off | tighter line spacing and smaller text for dense output |
| **CLEAR** | - | empty the pane |

The right of the bar shows `LIVE` when following, `HOLD` when follow is off, and
`PAUSED <n>` with the queued line count, plus a running line counter. Pausing
never stops the command; it only changes what the pane renders.

The terminal is local only. There is no remote shell and no inbound listener.

Each command runs in its own `cmd.exe`. Environment changes (`set`, `path`) do not
persist between commands, but `cd` does because the console tracks the working
directory and passes it to the engine. Closing the console stops any running
command and disarms the IDS.

### 11 - POSTURE

Read-only local checks:

| Check | Source |
|---|---|
| Defender real-time protection | `Get-MpComputerStatus` |
| Signature age | `Get-MpComputerStatus` |
| Firewall profiles | `Get-NetFirewallProfile` |
| SMBv1 | `Get-SmbServerConfiguration` |
| RDP inbound | `Terminal Server\fDenyTSConnections` |
| BitLocker (OS volume) | `Get-BitLockerVolume` |
| Windows Update service state | `Get-Service wuauserv` |
| High-risk services on all interfaces | `Get-NetTCPConnection` |
| Active NetTruder blocks | IPS journal |

It reports, it does not remediate. A stopped `wuauserv` is reported as `info`, not
as a failure, because the service is demand-started by design on modern Windows.

Where a check has a matching Windows tool, the row carries an **OPEN** button:
SECURITY (Defender), FIREWALL (`wf.msc`), FEATURES (`optionalfeatures.exe`, for
SMBv1), REMOTE (`SystemPropertiesRemote.exe`), BITLOCKER, UPDATE
(`ms-settings:windowsupdate`), or PROCESSES for listeners bound to all
interfaces. These buttons only open the relevant Windows UI; NetTruder does not
apply the change for you.

### 12 - PROCESSES

A Task Manager-style, read-only inventory of the local machine:

- PID, process name, owning user, CPU percentage, working set, listening ports,
  parent PID, executable path and command line.
- **CPU** is measured from two process samples 600 ms apart across all logical
  processors.
- **LISTENING** shows the ports held by that PID and sorts listeners first.
- **REFRESH** collects a new snapshot (top 90 by listeners, CPU and memory).
- **TASK MANAGER**, **RESOURCE MONITOR**, **SERVICES** and **FIREWALL** open the
  built-in Windows tools.
- **FILTER** matches PID, name, owner, port, path or command line.
- **KILL** terminates the process after a confirmation dialog and an audit entry.
  **LOCATE** opens Explorer with the executable selected.

KILL is deliberately limited: PID 4 and below, the engine's own process, and
core system processes (`smss`, `csrss`, `wininit`, `winlogon`, `services`,
`lsass`, `svchost`, `MsMpEng`, `SecurityHealthService`, etc.) are refused. It is
a containment control for a suspicious user-mode process, not a system
management tool.

### 13 - AUDIT

One NDJSON file per day under `%LOCALAPPDATA%\NetTruder\audit`. The view lists
files, loads the newest 1,500 entries newest-first, and can open the folder.

Logged events: monitor start/stop, every alert, every block/release/expiry, every
scan summary, every posture probe, every process inventory, every termination,
every coverage inventory, and every terminal command line.

### 14 - RESEARCH

The coverage lab from `research\` wired into the console. It answers one
question: if a documented living-off-the-land primitive ran here, would this host
record it?

Three catalogs load side by side: 24 Windows LOLBAS entries, 6 Windows
worm-like propagation entries, and 30 Linux/Unix GTFOBins entries - 60
techniques in total. The table shows ID, host, group plus a `WIN`/`LNX` badge,
presence, gap and active controls. **GROUP** and **PLATFORM** filters narrow the
list. Entries are grouped by `group` and `method`, and Windows and Linux/Unix
are kept separate.

- **TECHNIQUE COVERAGE** carries presence as a tri-state: `YES`, `NO` or `N/E`
  (not evaluated). A Linux entry whose WSL filesystem is unreadable is `N/E`,
  never a clean result; NetTruder does not execute a Linux binary to check it.
  The gap score is `OK`, `CONTENT GAP`, `NETWORK GAP`, `LINUX GAP`, `BLIND` or
  `NOT EVALUATED`. Each row shows a `BASIS` line with the exact policy readings
  behind the label, so the score can be audited rather than trusted.
- **CONTROL PLANE** shows the read-only inventory: command-line auditing, Sysmon,
  script block logging, module logging, transcription, AMSI, AppLocker, WDAC, ASR
  and Windows Script Host state. Every control row is clickable and opens the
  same remediation modal as a finding. A control that is safer when **off**
  (for example, an unneeded legacy feature) is labelled `safer when off`; the
  modal shows review steps and still never turns it off for you.
- **FINDINGS** ranks the gaps that matter, highest first, and adds proof cards
  for 4688, Sysmon 1 and 4104. Every finding is clickable and opens remediation
  steps, the enable/harden script, the native UI, and copy/elevated-shell
  actions. The elevated-shell action copies a script for review and paste; it
  never auto-runs it, and no action turns a control off.
- **CLICK A ROW** to open the detail panel. It shows the event chain as a
  four-step tree: stage, MITRE technique, process path, what happens, which log
  records it, and a detection sample. The right column adds DETECT command-line
  patterns, the ASR rule GUIDs that map to the host, NETWORK monitoring ports and
  text, observed blocks, and REMEDIATE fixes. Both columns scroll and wrap, with
  a visible vertical scrollbar and enlarged tree/detection text, so long
  detection text and paths stay readable.
- **RUN INVENTORY** is read-only. **MARKER PROBES** additionally runs four inert
  marker scripts after a confirmation dialog; each writes one line to
  `markers.log` and exits. No payload, no network, no persistence.
- **BLOCKS** opens the observed-block register from `research\blocks.json`.
  A block is a positive control result on this host - evidence that a control
  did its job - not a coverage pass and not an upgrade of a gap to `OK`. The
  register records what was attempted, the error/product/signal, and what it
  teaches; no bypass was attempted.
- **REPORTS** opens `%LOCALAPPDATA%\NetTruder\lab` with the JSON and Markdown
  reports. **LAB FOLDER** opens the catalog and probe sources.

The view never changes a security setting. The catalogs are read directly from
`research\techniques.json`, `research\worm.json` and `research\gtfobins.json`,
so they render even before an inventory run.

**What "provable" means here.** A gap label is configuration-derived unless the
probe window could measure the signal. After MARKER PROBES, each row's `BASIS`
gains `measured[4688=on|off|n/a sysmon=on|off|n/a 4104=on|off|n/a]`, and the
proof cards report the same. The probe does not use broad event counts: 4688
proof counts only events whose new-process image is one of the four probe hosts,
Sysmon 1 is parsed by named XML field as a fallback, and 4104 proof counts only
events whose text contains the marker script token. That stops this tool's own
PowerShell activity, or an unrelated AMSI-triggered 4104, from flipping the
verdict.

The proof cards state the real error and the real session context, not a blanket
"requires elevation". The elevation card separates three different facts:

- **token elevated**: is this process running with an elevated token?
- **admin group**: is the account a member of Administrators, including the
  deny-only SID that UAC leaves in a filtered token?
- **Security log readable**: did the direct channel read succeed, and if not,
  what was the exact error?

It also shows the integrity level (`medium`, `high`, ...), the UAC elevation
type (`limited`, `full`, `default`), whether `SeSecurityPrivilege` is present
and enabled, the in-process enable result (`enabled`, `not-assigned:1300`,
`failed:<code>`), the Security and Sysmon errors, and the `auditpol` result.
That explains the common case where the session looks like an "administrator"
but the token is filtered: `adminGroup=yes`, `tokenElevated=no`,
`integrity=medium`, and the Security log read returns "Attempted to perform an
unauthorized operation." The card names that cause and links to the elevation
remediation; it does not claim that being in Administrators is enough.

If the Security log is unreadable, 4688 is reported as not accessible with the
error text and the label stays configuration-derived. The authoritative check
is a direct `Get-WinEvent -LogName Security -MaxEvents 1`; a filtered query that
returns zero rows is never allowed to upgrade an unreadable channel to a clean
result. `PSLOG` on the summary strip is the **PowerShell event channel**, not
the script-block policy; the policy has its own control row and finding.

Research stays defensive: the catalogs describe documented behaviour, detections
and hardening. There are no payloads, C2, persistence, credential access,
obfuscation, hidden windows or evasion. A blocked test is a positive result and
is recorded in `research\BLOCKED-TESTS.md`; no bypass is attempted.

### 15 - NETWORK

A read-only inventory of traffic to and from this host. The view is four equal
boxes: **NETWORK GRAPH**, **BROWSER NETWORK GRAPH**, **BROWSER WEB FLOWS** and
**BACKGROUND FLOWS**. It answers which sockets exist, which process owns each
one, how a packet would leave or arrive, and which destinations are used by the
browser versus background applications.

- **RUN INVENTORY** takes one snapshot. **LIVE 30s** is a toggle: it repeats a
  read-only 30s TCP connection sample until you press it again or press **STOP**.
  Each cycle samples every two seconds and replaces the view when it finishes;
  the button, status and summary highlight while live mode is on. **STOP** also
  ends an in-progress sample early. The window never captures packets, payloads
  or credentials. Names normally
  come from the local DNS cache, so a blank name is a visibility gap, not proof
  of a direct-IP connection. The optional history opt-in adds a bounded set of
  read-only A-record lookups as described below.
- **NETWORK GRAPH** is `THIS HOST -> owning process -> URL / remote endpoint`.
  Browser nodes are blue, background applications orange, system services green
  and remote endpoints purple. Click a node for its flow detail, or `THIS HOST`
  to open adapters and routes.
- **BROWSER NETWORK GRAPH** is a separate class beside the main graph:
  `BROWSER WEB -> browser process -> URL`. It only contains browser sockets, so
  browser traffic stays visually separate from background and system traffic.
- **BROWSER WEB FLOWS** and **BACKGROUND FLOWS** are separate, clickable tables
  with their own counts. The filter narrows either table and both graphs. Click
  a row to open the detail card with direction, local and remote endpoints, URL
  source, cached hostname, process path and masked command line, socket state,
  first/last seen, sample count, and a plain-language explanation of how the
  traffic is sent or arrives.
- **URL SOURCES**: every browser flow always gets a host-only endpoint such as
  `https://cached-host/` or `https://IP:port/`, labelled `HOST ONLY`. This is
  inferred from the socket and DNS cache and never claims a full visited path.
  The **READ BROWSER HISTORY** checkbox is an explicit per-run opt-in; when it
  is checked, local Edge/Chrome/Brave/Vivaldi/Firefox history databases are
  opened read-only and a matching host can supply a full URL and title, labelled
  `HISTORY`. Because a browser may use DNS-over-HTTPS and leave the Windows DNS
  cache empty, the same opt-in also permits up to 24 read-only A-record lookups
  for recent history hosts; if one resolves to the socket IP, the full URL is
  shown together with the IP endpoint. No profile file is copied, changed or
  deleted, and no DNS setting is modified.
- **FINDINGS** and **DETAIL** are modal buttons, not a permanent side panel.
  Findings are review triggers with state and remediation: broad listeners, RDP
  exposure, handler-style egress, unusual background egress, direct-IP traffic
  with no cached name, private peers on management ports, and sockets whose
  owner the current token cannot read. Each finding opens a click-through card.
  NetTruder never changes a firewall rule, DNS setting or security control.
- **PATHS / ROUTES** lists interface IPv4 addresses, gateways, DNS servers, MAC
  addresses and the IPv4 route table. That is where the `how sent / arriving`
  answer comes from; nothing in the routing table is changed.
- **PKTMON RECIPE** is a copyable, manual recipe for an administrator. NetTruder
  never launches pktmon, installs a driver, or reads an ETL itself. Use it only
  on networks you are authorised to observe.

UDP endpoints are shown as local binds only because UDP has no connection state.
Process attribution uses `Get-NetTCPConnection`, `Get-NetUDPEndpoint`,
`Get-OwnerMap` and `Win32_Process`; a filtered token may leave an owner
unreadable, and that is reported as a visibility gap. Browser flows are
attributed from the process name, browser install path and a bounded parent
chain so Edge network children and WebView2 hosts are included.

---

### 16 - PS LOGGING

A read-only PowerShell telemetry readout. **READ PS LOG** checks the documented
policy keys for `EnableScriptBlockLogging=1` and samples Event ID 4104 from the
`Microsoft-Windows-PowerShell/Operational` log for the last seven days. Each
masked sample shows the `WHO`, `WHAT` and `WHERE` fields present in the event:
account/SID where recorded, script-block ID and message part, plus host, process,
thread and path. Click a sample for the full verbose event detail.

The same run also queries explicit block or prevention events involving
PowerShell from the local AppLocker, WDAC/Code Integrity and Defender
operational channels. These are shown in a separate **BLOCKED / PREVENTED
POWERSHELL** pane with their own attribution and detail modal. The summary shows
how many block sources were readable; an unreadable or unconfigured channel is
reported as NOT EVALUATED, not as a clean result. Windows has no single generic
"blocked PowerShell" channel, so NetTruder reports only explicit control events
it can read and does not infer a block from Event ID 4104.

NetTruder never enables, disables or clears a log, never changes a policy key,
never re-runs a blocked command, and never executes a captured script block. If
logging is off, inaccessible or empty, that is shown with the Group Policy path
and forwarding advice. Attribution is limited to what the source recorded;
`NOT RECORDED` is shown when a field is absent. A captured line or block event is
defensive evidence, not a verdict about intent.

---

## Data locations

```
%LOCALAPPDATA%\NetTruder\
  runs\      <id>.request.json  <id>.events.ndjson  <id>.stop  <id>.pid
  state\     ips-journal.json  onboarding.json  triage-decisions.json
  audit\     audit-YYYYMMDD.ndjson
  lab\       lolbas-posture-YYYYMMDD-HHmmss.json / .md  markers.log
```

- `<id>.request.json` is written by the console, then deleted by the engine.
- `<id>.events.ndjson` is the live event stream (one JSON object per line).
- `<id>.stop` asks a running engine to stop.
- `state\ips-journal.json` is the authoritative list of active blocks.
- `state\onboarding.json` holds `{seen, role, level, at}` from the first-run
  survey; the GUIDE button reopens onboarding.
- `state\triage-decisions.json` holds local alert-board decisions only.
- `lab\` holds the research lab reports and the marker log (only written when
  MARKER PROBES are confirmed). The lab exports `NETTRUDER_LAB_DIR` to point the
  markers at that folder.
- The engine escapes everything to ASCII in the event stream, so the console can
  read it with a plain ASCII file read.
- Before 1.1.0 the root was `%LOCALAPPDATA%\NetWatch`. On first 1.1.0 start,
  state, audit and lab files are copied forward **only when the destination
  file is missing**. The old root is never deleted or moved, so rollback stays
  possible. Smoke migration: 41 files copied.

To remove all traces: release all blocks, then delete
`%LOCALAPPDATA%\NetTruder`.

---

## Command-line use

The engine works without the UI. Write a request file and pass it to the shim or
the cmd launcher:

```bat
rem request.json
rem {"action":"scan","runId":"cli1","targets":"192.168.1.0/24","profile":"common","timeoutMs":700}

engine\invoke.cmd request.json
```

Direct parameters also work:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\engine\NetTruder.ps1 -Action status -RunId t1
powershell -NoProfile -ExecutionPolicy Bypass -File .\engine\NetTruder.ps1 -Action probe  -RunId t2
powershell -NoProfile -ExecutionPolicy Bypass -File .\engine\NetTruder.ps1 -Action rules  -RunId t3
powershell -NoProfile -ExecutionPolicy Bypass -File .\engine\NetTruder.ps1 -Action scan   -RunId t4 -Targets 192.168.1.0/24
powershell -NoProfile -ExecutionPolicy Bypass -File .\engine\NetTruder.ps1 -Action watch  -RunId t5 -IntervalSec 2
powershell -NoProfile -ExecutionPolicy Bypass -File .\engine\NetTruder.ps1 -Action block  -RunId t6 -RemoteIp 203.0.113.9 -DurationMin 10
powershell -NoProfile -ExecutionPolicy Bypass -File .\engine\NetTruder.ps1 -Action release -RunId t7
powershell -NoProfile -ExecutionPolicy Bypass -File .\engine\NetTruder.ps1 -Action shell  -RunId t8 -CmdLine "netstat -ano" -MaxSeconds 30
powershell -NoProfile -ExecutionPolicy Bypass -File .\engine\NetTruder.ps1 -Action processes -RunId t9
powershell -NoProfile -ExecutionPolicy Bypass -File .\engine\NetTruder.ps1 -Action kill  -RunId t10 -ProcId 1234 -Yes
powershell -NoProfile -ExecutionPolicy Bypass -File .\engine\NetTruder.ps1 -Action research -RunId t11
powershell -NoProfile -ExecutionPolicy Bypass -File .\engine\NetTruder.ps1 -Action research -RunId t12 -Probes -Yes -LabDir C:\Temp\ntlab
powershell -NoProfile -ExecutionPolicy Bypass -File .\engine\NetTruder.ps1 -Action webscan -RunId t13 -Url http://127.0.0.1:8080
powershell -NoProfile -ExecutionPolicy Bypass -File .\engine\NetTruder.ps1 -Action flow -RunId t14
powershell -NoProfile -ExecutionPolicy Bypass -File .\engine\NetTruder.ps1 -Action netinv -RunId t15
powershell -NoProfile -ExecutionPolicy Bypass -File .\engine\NetTruder.ps1 -Action netinv -RunId t16 -SampleSec 30 -IntervalSec 2
powershell -NoProfile -ExecutionPolicy Bypass -File .\engine\NetTruder.ps1 -Action datapurge -RunId t17
```

Actions: `status`, `probe`, `rules`, `scan`, `watch`, `block`, `unblock`,
`release`, `expire`, `shell`, `processes`, `kill`, `research`, `webscan`,
`codeaudit`, `flow`, `investigate`, `netinv`, `triage`, `av`, `datacheck`,
`datapurge`, `pslog`.

Useful switches: `-AllowPublic`, `-AutoBlock`, `-Yes` (LAN block confirmation,
process termination, marker-probe consent and purge), `-AckRisk` (required with
`-Yes` for purge), `-RetentionDays 30`, `-ProcId`, `-Url`, `-Path`,
`-Ports "22,80,443,8000-8100"`, `-TimeoutMs 400`, `-Probes`, `-LabDir <path>`,
`-SampleSec`, `-IntervalSec`, `-MaxFlows`.
`datapurge` previews with no switches; it only deletes with `-Yes -AckRisk`.

Read the stream from PowerShell:

```powershell
Get-Content "$env:LOCALAPPDATA\NetTruder\runs\t4.events.ndjson" |
  ForEach-Object { $_ | ConvertFrom-Json } |
  Where-Object { $_.k -in 'host','port','done' }
```

Stop a long run: `New-Item "$env:LOCALAPPDATA\NetTruder\runs\t5.stop"`.

---

## Detection rule set

`engine\rules.json` holds the listener, remote-port and admin-tool egress rules
plus the beacon and fan-out thresholds. Edit it and restart the monitor; there is
no recompile step.

```json
{
  "version": "2026.11.2",
  "listenPorts": [ { "port": 3389, "service": "rdp", "sev": "high", "why": "..." } ],
  "remotePorts": [ { "port": 4444, "sev": "high", "why": "..." } ],
  "egressWatch": [
    { "process": "certutil.exe", "ports": "80,443,8080,8443", "sev": "high", "why": "..." },
    { "process": "bitsadmin.exe", "ports": "80,443", "sev": "high", "why": "..." }
  ],
  "beacon": { "minConnections": 6, "windowSec": 150, "maxJitter": 0.30,
              "minMeanSec": 8, "maxMeanSec": 200, "sev": "high" },
  "fanout": { "distinctHosts": 25, "windowSec": 60, "sev": "high",
              "browserProcs": ["msedge","chrome","firefox","brave","opera","vivaldi","iexplore"],
              "browserSev": "low", "browserHosts": 30,
              "lateralHosts": 4, "lateralSev": "high",
              "lateralPorts": "135,139,445,3389,5985,5986,22" }
}
```

`egressWatch` matches the owning process name with the extension stripped, so a
rule for `certutil.exe` matches `certutil`. The optional `ports` string accepts
single ports and ranges (`80,443,49152-65535`). The rule set ships with 19
admin-tool entries.

If the file is missing or malformed the engine falls back to empty port lists and
the default thresholds, so a bad edit degrades the monitor instead of crashing it.

---

## 1.1.0 validation smoke

Run on the test host after the rename and the new modules landed:

| Check | Result |
|---|---|
| Status | `migrated:41`, `adminGroup:true`, `tokenElevated:false` |
| Code audit | 15 files, 167 findings |
| Flow | 512 events, 260 nodes, 242 edges, 5 findings |
| Investigate | 26 peers, 2 findings |
| Exposure register | 91 events, 2 products, 1 gap |
| Data check | 356 files, 1 finding |
| Data purge preview | 0 files, 0 bytes, nothing deleted |
| Web - live loopback | 9 findings, grade D, HTTP 200 |
| Web - refused target | 1 finding (`NT-WEB-000`), grade n/a |
| Engine/UI event kinds | 52 handled, 0 unhandled |
| Console script | JS parse OK, CSS braces balanced, sources ASCII |

Validation artifacts: `nw-jsparse.js` under a local test harness folder and the
pre-rename backup `netwatch-pre-nettruder.zip`, both kept outside the repository.
See `RESEARCH.md` section 12 for the full read-out.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `Engine launch blocked: ... [code -2147024671]` | Endpoint agent refused the shim launch | Run `Launch.cmd` from the folder; if it persists, ask IT to review the script-launch policy. Do not disable protection. |
| `No response from the engine after 20s` | Engine never started, or the folder is incomplete | Confirm `engine\NetTruder.ps1` and `engine\shim.vbs` exist. Run `-Action status` by hand. |
| `IPS needs an elevated session` | Console started without admin | Close it and run `Launch-Elevated.cmd`. |
| Session says `admin account / filtered token` but proof says Security log unreadable | The account is in Administrators but UAC gave this process a filtered token (`tokenElevated=no`, `integrity=medium`) | This is UAC working as designed. Close NetTruder and run `Launch-Elevated.cmd` as administrator, then re-run the inventory. Click the ELEVATION card in proof for the exact remediation. Never disable UAC. |
| `SeSecurityPrivilege ... not-assigned:1300` | The privilege is not in this token, so the in-process enable cannot add it | Relaunch elevated. If it persists while elevated, review `secpol.msc` - Manage auditing and security log. |
| `Refused: ... is on a private range` | LAN block guard | Confirm the dialog in the UI, or pass `-Yes` on the CLI. |
| Scan finds nothing | Hosts block ICMP, or the range is wrong | Try a single known IP with `web` or `remote` profile. |
| Empty IDS stream | No listener or session matched the rules | Check the CONSOLE pane; `-Action rules` prints the active set. |
| Console feels sluggish on a huge sweep | Banner grabs and DNS lookups are serial per host | Narrow the target set or raise the timeout only on fast links. |

---

## Limits

- The port scan is a **connect scan**. It is not stealthy and cannot be, because
  it uses the normal socket API and needs no driver.
- The IDS samples the local TCP table every two seconds. Cadences faster than a
  few seconds cannot be resolved, and jitter is quantised by the poll interval.
- No packet capture, no inline IPS, no IPv6 blocking, no remote agents.
- The IPS blocks addresses, not applications. Use it as containment, not as a
  substitute for patching.
- The process view shows the top 90 processes by listeners, CPU and memory, not
  every process on a busy host. Owner names are blank where the token cannot be
  read without elevation.
- KILL cannot terminate a process you do not have rights to end; run
  `Launch-Elevated.cmd` if that is intended.
- Only IPv4 targets can be blocked.
- The research lab scores **telemetry coverage**, not exploitability. A `BLIND`
  row means this host has no process-creation logging to match the technique
  against; it is not a claim that an attacker is present. On a host without
  command-line auditing or Sysmon, every Windows catalog entry is expected to
  read `BLIND` until the audit policy changes. `LINUX GAP` and `NOT EVALUATED`
  mean the Windows host cannot see the Linux side, not that the technique is
  absent or safe.
- A recorded block (`research\blocks.json`) is host-specific evidence that one
  control stopped one documented test. It does not clear the catalog row, does
  not cover variants, and no bypass is attempted to "confirm" it.
- Web risk is passive. A target that does not answer is `NT-WEB-000` at grade
  `n/a`, never a set of clean headers; ZAP recipes are for a separate,
  authorised test and are never launched by NetTruder.
- Code audit, flow, threats, triage and data check read files and live state;
  they do not execute source, open sockets, change processes or write back to
  an alert source. Purge touches only NetTruder-owned data older than
  `RetentionDays` and needs both `-Yes` and `-AckRisk`.
- Browser fan-out is expected. `FANOUT` from a browser is low severity and is
  triage context; use `LATERAL_FANOUT` (sensitive ports) as the actionable
  signal.

See `RESEARCH.md` for the test matrix, the launch-chain investigation, and the
research notes.
