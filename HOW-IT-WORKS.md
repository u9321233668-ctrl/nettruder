# NetTruder - How It Works

This document explains what NetTruder does, module by module from `01 SWEEP` to
`16 PS LOGGING`, and how the pieces fit together. `README.md` is the launch and
quick-reference guide; `BEST-PRACTICES.md` is the operator guide. This document
is the architecture and behaviour reference.

NetTruder is a defensive Windows evidence console with a read-only browser
extension. It makes local state visible: hosts, connections, processes, source
code, control settings, alert state and telemetry. It does not make an attack
possible, and it does not trade away an existing protection to keep working.

---

## 1. The trust model in one page

Five rules govern every module.

1. **Read-only by default.** Scanning, inventory, flow maps, web checks, source
   review and telemetry readouts do not change the host. Actions that do change
   state are opt-in and named.
2. **Never weaken a control.** NetTruder does not disable or reconfigure
   Defender, firewall profiles, Windows Update, services, drivers, scheduled
   tasks, WSH, AppLocker, WDAC, ASR or logging. It never offers a button that
   turns a protection off.
3. **A block is a result.** If an endpoint product, policy or guardrail refuses
   an action, NetTruder records the product, signal, message and context, then
   stops. It does not retry, re-enable, whitelist, obfuscate or bypass.
4. **Honest labels.** Missing visibility is `NOT EVALUATED` or `NOT RECORDED`,
   never a clean result. A static source hit is `STATIC LEAD / NOT RUNTIME
   VERIFIED`, never proof of exploitability. A blocked test is positive control
   evidence, never a coverage pass.
5. **State plus remediation.** Findings and popup alerts show what was observed
   and what to do next. Suggestions are copyable commands, native Windows UI or
   an elevated shell handoff for review. NetTruder does not auto-run a fix.

### What is opt-in

| Capability | Default | Boundary |
|---|---|---|
| Sweep, inventory, read-only views | On demand | Private targets only in the UI; `-AllowPublic` is CLI-only and never set by the console |
| IDS monitor | Off | `ARM IDS` polls the local TCP table; no packets captured |
| Temporary firewall block | Off | Explicit `BLOCK`; 10-minute default TTL; destination and count guards; `RELEASE ALL` removes NetTruder rules only |
| Local shell | On demand | `cmd.exe /d /s /c`, 900-second cap, every command line audit-logged |
| Process termination | Off | Confirmation dialog, audit entry and a refusal list for core processes |
| Code Audit raw write | Off | Three confirmations, path guard, backup before save; resets every audit and restart |
| Data purge | Preview only | Deletes only with `-Yes -AckRisk`, only NetTruder-owned files, never personal files |
| Browser history enrichment | Off | Explicit per-run checkbox, read-only databases, bounded A-record lookups |
| Marker probes | Off | Confirmation dialog; four inert scripts write one line each and exit |
| Live network mode | Off | `LIVE 30s` toggles to `LIVE ON`; manual `RUN INVENTORY` stops live mode |

---

## 2. Architecture and message flow

### Components

| Component | Role |
|---|---|
| `Launch.cmd`, `Launch-Elevated.cmd` | Start the console as a standard user or through a UAC prompt. The window badge reads `USER` or `ADMIN`. |
| `NetTruder.hta` | The UI shell. Authored for IE11 document mode 11 and ES5 JScript: no CSS variables, grid, `:is()` or `:where()`. |
| `ui/app.js`, `ui/style.css` | Console logic, event dispatch, views and modals. |
| `engine/shim.vbs` | WSH shim that starts one hidden, short-lived PowerShell worker for one request. |
| `engine/invoke.cmd` | Command-line launcher that starts the same worker with a request file. |
| `engine/NetTruder.ps1` | The engine. Reads a request, performs one action, writes events to an NDJSON file. |
| `engine/rules.json` | Listener, remote-port and admin-tool egress rules used by IDS/IPS. |
| `research/` | Defensive catalogs, reports, the source-only HEVD study lab and its helper. |
| `browser-extension/` | Read-only MV3 browser extension. No network code and no automatic bridge. |
| `%LOCALAPPDATA%\NetTruder\` | Runtime data: request files, event streams, stop files, state, audit and lab reports. |

### The UI path

1. The operator clicks a control in the HTA. `ui/app.js` writes a small JSON
   request file under `%LOCALAPPDATA%\NetTruder\runs\<id>.request.json`.
   Keeping arguments in a file avoids cmd quoting problems for target lists and
   terminal commands, and keeps the launcher command line short and constant.
2. The HTA calls `engine\shim.vbs`. WSH runs the shim, which starts one hidden
   PowerShell worker:
   `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File NetTruder.ps1 -RequestFile <file>`.
   The shim exists because a direct HTA-to-PowerShell launch was refused on a
   hardened host in testing. It is a normal parent/child chain and needs no
   policy change.
3. The engine reads the request, deletes the request file, and performs one
   action. It writes ASCII-escaped NDJSON events to
   `%LOCALAPPDATA%\NetTruder\runs\<id>.events.ndjson`: one JSON object per line.
4. The HTA polls that file and dispatches on the `k` field, for example `host`,
   `port`, `alert`, `finding`, `done`. Every emitted kind has a handler; the
   validation harness checks this coverage.
5. `ABORT` or `STOP` writes `<id>.stop`. The engine checks it at safe boundaries
   and ends the run. Expiry of temporary blocks is also checked at engine start,
   on every status call and on a 60-second UI timer, so a crashed console cannot
   leave a permanent block behind.
6. State changes that must outlive a run go to `state\` (IPS journal, onboarding
   answers, triage decisions). A dated NDJSON file under `audit\` records monitor
   start/stop, alerts, blocks, releases, expiries, scan summaries, posture
   probes, process inventories, terminations, coverage inventories and every
   terminal command line.

### If the launch chain is blocked

Windows Script Host may be disabled, `.hta` may be blocked or unassociated, or a
product may refuse the `mshta -> wscript -> PowerShell` chain. The console says
so and does not pretend the engine started. That is a valid control result.
The operator records the exact message, product and event ID and stops. NetTruder
does not re-enable WSH, change `.hta` associations, add an exclusion or switch
to a direct PowerShell call to get a window open.

### The CLI path

The engine works without the UI. Either write a request file and call
`engine\invoke.cmd request.json`, or call `NetTruder.ps1` directly with
parameters such as `-Action status`, `-Action scan -Targets 192.168.1.0/24`,
`-Action codeaudit -Path <folder>`, `-Action research`, `-Action webscan -Url
<loopback URL>`, `-Action pslog` or `-Action datapurge`. The action list is in
`README.md`. The event stream can be read with `Get-Content ... |
ConvertFrom-Json`, and a run can be stopped by creating its `.stop` file. The
CLI is how the engine is validated without relying on a WSH-launched window.

---

## 3. How defensive review and suggestions work

### The review shape

Every finding, control row, popup alert and modal follows the same shape:

- **State:** what was observed, including `YES`, `NO`, `N/E`, `ON`, `OFF`,
  `UNREADABLE`, `NOT EVALUATED` or `NOT RECORDED` where appropriate.
- **Source of truth:** the API, registry key, log channel, file or event that
  produced the state. Research rows include a `BASIS` line with the exact
  policy readings behind the label.
- **Meaning:** why the state matters, in plain language.
- **Remediation:** what to review or enable, with copyable text where useful.
- **Limit:** what the observation cannot prove.

This is why a silent host is not reported as missing headers, an unreadable log
is not reported as disabled logging, and a regex hit in source is not reported
as a proven bug.

### The suggestion shape

Suggestions are guidance, not automation:

- A **REMEDY** modal shows observed detail and review steps.
- **Copy** puts a command or script on the clipboard for the operator to read.
- **Elevated shell** copies a command for pasting into an administrator shell;
  it does not run it.
- **OPEN** or native-UI buttons launch the relevant Windows tool, such as
  `wf.msc`, Security, Remote settings or BitLocker. NetTruder does not apply the
  change.
- A control that is safer when off is labelled `safer when off`. The modal still
  explains review steps and never turns it off.

Rows about FIDO2 / WebAuthn, Continuous Access Evaluation and Conditional
Access device compliance stay `NOT EVALUATED` unless verified in identity
telemetry. Page-level browser data cannot prove an identity-plane control.

### Blocked actions

If a control blocks a test, the block is recorded with the product, signal and
exact message, and the action stops. Blocks are stored in the endpoint block
register and in `research/BLOCKED-TESTS.md`. No bypass, retry, token capture,
header change, IP change or User-Agent change is attempted.

---

## 4. Module reference

### 01 - SWEEP

Host and service discovery on a network you are authorised to test. Targets can
be `192.168.1.0/24`, a range, a start-end pair, a single IP or a hostname.
`LOCAL SUBNET` and `GATEWAY` fill from the host. Port profiles are `common`
(28 ports), `web`, `remote`, `db` and `mail`; timeout controls connect and ICMP
patience.

Each live host becomes one row with MAC from the ARP/neighbour table, reverse
name, latency, labelled open ports and a rolled-up risk level. A detail strip
opens on click. `ABORT` writes the run's stop file and the engine stops at the
next host boundary.

Guards: sweeps are capped at `/22` (512 hosts), and non-private addresses are
dropped unless the engine is called with `-AllowPublic`. The UI never sets that
flag.

### 02 - PROCESS FLOW

A read-only n8n-style graph of the process tree and TCP flows. Boxes are
processes and remote endpoints; lines are parent links and connections. Filter
by pid, process or path and click a box for its command line. Data comes from
the process and live TCP tables; nothing is started, changed or ended here.
`FINDINGS` flags unusual parent/child shapes and many concurrent flows as
triage context, never as proof of compromise.

### 03 - WEB RISK

A passive web posture check using GET and OPTIONS only: response headers, TLS,
cookies, forms, HTML comments and unauthenticated exposure paths. No fuzzing,
exploitation, auth bypass or payload. Loopback and private URLs are the normal
targets; a public host needs `ALLOW PUBLIC HOST` in the UI or `-AllowPublic` on
the CLI.

OWASP ZAP commands are shown as copyable recipes; NetTruder never launches ZAP.
The site data-flow graph grows from the observed response, and target cards
expose masked metadata or inline bodies without following links or executing
scripts. Findings carry an OWASP/CWE reference and a fix.

An unreachable target emits only `NT-WEB-000`, grade `n/a`, `answered=False`.
Missing headers on a target that did not answer become `NOT EVALUATED`, not
findings. A silent host is neither clean nor dirty.

`EXTENSION REPORT IMPORT` is a manual paste area. It parses the redacted report
from the extension in memory only, rejects secret-like text without displaying
it, writes no file and calls no network. Identity controls added to the report
remain `NOT EVALUATED`.

### 04 - CODE AUDIT

Static review of a local source folder. Files are read as text and never
executed. Findings carry a rule ID, severity, location, risk explanation, CWE
or OWASP reference and a fix. Secret-like values in findings are masked by
default.

The toolbar filters by severity or text, sorts by severity/file/rule/line,
exports a text report and opens the selected file in an external editor. The
file inspector shows line-numbered masked source, coloured hit rows, gutter
markers, GO LINE, hit tabs, per-file severity counts and a function index.
Copy actions are review-only handoff tools.

`WRITE MODE OFF` is the default and resets on every audit and restart. Turning
it on requires confirmation; fetching raw source requires another confirmation;
SAVE requires a third. Saves pass a path guard, preserve encoding and line
endings, and back up the original under `%LOCALAPPDATA%\NetTruder\state\code-edits\`.
Raw content for an edit session lives in that run's event file, so that run
should be treated as sensitive. No fix is applied automatically.

The HEVD area adds `HEVD SOURCE` (read-only scan), `HEVD REVIEW` (layered
beginner and advanced explanation), `HEVD GUIDE` (safety boundary), `INT WRAP`
(wrapped arithmetic explainer) and `SEND TO RESEARCH` (masked findings into the
research view). See section 6.

### 05 - THREATS

A read-only socket, DNS and listener investigation. It groups live peers,
flows, listening ports and DNS-cache hints for triage. No connection is opened
and no remote host is probed from this view. `TASK MANAGER` and `FIREWALL` open
built-in Windows tools for follow-up; NetTruder does not change a rule.

### 06 - TRIAGE

A local alert board built from an exported JSON or NDJSON alert file. Alerts
are normalised, deduplicated and prioritised, then routed to the relevant
research view for context. Acknowledge, suppress, resolve and reopen decisions
are stored only in `state\triage-decisions.json`. Nothing is pushed upstream
and the source alert system is never changed.

### 07 - EXPOSURE

The endpoint block evidence and control-success register. It records what an
endpoint product blocked, the product and signal, and what could not be
evaluated. A block is a positive defensive result, never a coverage pass and
never an upgrade of a research gap. NetTruder never re-runs a blocked action or
attempts a bypass.

### 08 - DATA

Read-only classification plus an opt-in cleanup. `DATA CHECK` classifies files
under the NetTruder data root and reports secret/PII pattern hits and retention
findings. `PURGE OLD DATA` is a preview by default; it needs both `-Yes` and
`-AckRisk` and is limited to NetTruder-owned runs, snapshots and optionally old
audit files. Personal files are never in scope.

### 09 - IDS / IPS

`ARM IDS` starts a host-based monitor that polls the local TCP table every two
seconds. It raises alerts for high-risk listeners, established sessions to
flagged ports, beacon-like cadence, fan-out and admin-tool egress. Beacon and
fan-out findings are triage context, not proof of C2; browsers have a higher
fan-out threshold because CDN traffic is expected. Admin-tool egress rules are
process-keyed and, when they fire, the engine reads the live command line so the
operator sees context rather than only a socket.

Alerts deduplicate on rule, address and process with cooldowns. Each alert can
open a remediation modal, create a temporary block, jump to the owning process,
kill the owning process with confirmation, or open Task Manager. High, medium
and low alerts also appear as dismissible toasts with the same evidence-led
actions. The modal never offers to disable a control.

`BLOCK` creates a temporary pair of firewall rules only. `RELEASE ALL` removes
every NetTruder rule; other firewall rules are untouched. `DISARM` stops the
monitor. `AUTO-BLOCK HIGH` is off by default and, when enabled, blocks only
high-severity public peers for 10 minutes.

The IPS refuses local machine, gateway, DNS servers, loopback, multicast,
broadcast, reserved and `0.x` addresses, private peers without explicit
confirmation, and more than 30 simultaneous blocks. TTL is clamped to 1-240
minutes.

### 10 - TERMINAL

A real local shell. Every command runs as `cmd.exe /d /s /c` in the user
context, with the visible working directory passed to the engine. Built-ins
handle `cls`, `help` and `cd`; convenience buttons run common read-only Windows
diagnostics such as `ipconfig /all`, `arp -a`, `netstat -ano`, `tasklist`,
`route print`, `whoami /all`, `systeminfo` and share listings.

`KILL` terminates the running command tree; commands have a 900-second cap and
every command line is audit-logged before it runs. `WRAP`, `FOLLOW`, `PAUSE`,
`COMPACT` and `CLEAR` control rendering only, not execution. The terminal is
local only: no remote shell and no inbound listener. Each command runs in its
own `cmd.exe`, so environment changes do not persist; `cd` does because the
console tracks it.

### 11 - POSTURE

Read-only local checks: Defender real-time status and signature age, firewall
profiles, SMBv1, RDP inbound setting, BitLocker on the OS volume, Windows Update
service state, high-risk services on all interfaces and active NetTruder
blocks. It reports, it does not remediate. A stopped `wuauserv` is `info`
because the service is demand-started by design.

Where a check has a matching Windows tool, the row opens that UI only:
Security, firewall, optional features, Remote settings, BitLocker, Update or
Processes. NetTruder does not apply the change.

### 12 - PROCESSES

A Task Manager-style, read-only inventory: PID, name, owner, CPU percentage,
working set, listening ports, parent PID, executable path and command line. CPU
is measured from two samples 600 ms apart. `LISTENING` sorts listeners first,
`REFRESH` takes a new snapshot, `FILTER` matches several fields, and native
buttons open Task Manager, Resource Monitor, Services and the firewall.

`KILL` requires confirmation and an audit entry. PID 4 and below, the engine's
own process and core system processes such as `smss`, `csrss`, `wininit`,
`winlogon`, `services`, `lsass`, `svchost`, `MsMpEng` and
`SecurityHealthService` are refused. `LOCATE` opens Explorer with the executable
selected. This is containment for a suspicious user-mode process, not a system
management tool.

### 13 - AUDIT

One NDJSON file per day under `%LOCALAPPDATA%\NetTruder\audit`. The view lists
files, loads the newest 1,500 entries newest-first and can open the folder.
Logged events include monitor start/stop, alerts, blocks, releases, expiries,
scan summaries, posture probes, process inventories, terminations, coverage
inventories and terminal command lines. This is a local accountability record,
not telemetry forwarding.

### 14 - RESEARCH

The coverage lab. It loads four catalogs: Windows LOLBAS, Windows worm-like
propagation, Linux/Unix GTFOBins and HEVD source-study entries. Platform and
group filters keep Windows separate from Linux/Unix and source study separate
from host binaries.

Presence is tri-state: `YES`, `NO` or `N/E`. A Linux entry whose WSL filesystem
is unreadable is `N/E`, never a clean result; NetTruder does not execute a Linux
binary to check it. Gap labels include `OK`, `CONTENT GAP`, `NETWORK GAP`,
`LINUX GAP`, `BLIND` and `NOT EVALUATED`, and each row carries a `BASIS` line
with the readings behind it.

`CONTROL PLANE` inventories command-line auditing, Sysmon, script block
logging, module logging, transcription, AMSI, AppLocker, WDAC, ASR and WSH
state. Every row opens the same remediation modal as a finding. `FINDINGS`
ranks gaps and adds proof cards for 4688, Sysmon 1 and 4104. Clicking a row
opens a four-step event chain: stage, technique, process path, what happens,
which log records it, and a detection sample, plus detection text, ASR
guidance, network ports, observed blocks and remediation.

`RUN INVENTORY` is read-only. `MARKER PROBES` additionally runs four inert
scripts after confirmation; each writes one line to `markers.log` and exits.
Proof counts only events that name one of the four probe hosts or contain the
marker token, so NetTruder's own PowerShell activity or an unrelated 4104 cannot
flip a verdict. The elevation card separates token elevation, Administrators
group membership and Security log readability, including integrity level, UAC
elevation type and `SeSecurityPrivilege`; a filtered token is not misreported as
a log failure or a clean result.

`BLOCKS` opens the observed-block register. `REPORTS` opens the JSON and
Markdown lab reports. The view never changes a security setting.

### 15 - NETWORK

A read-only inventory of traffic to and from this host, split into four boxes:
`NETWORK GRAPH`, `BROWSER NETWORK GRAPH`, `BROWSER WEB FLOWS` and `BACKGROUND
FLOWS`. Browser and background traffic stay in separate tables and separate
graph classes.

`RUN INVENTORY` takes one snapshot. `LIVE 30s` repeats a read-only 30-second
TCP sample until toggled off or stopped; a manual `RUN INVENTORY` also ends
live mode. Each cycle samples every two seconds and replaces the view. The
window never captures packets, payloads or credentials. Names normally come
from the local DNS cache, so a blank name is a visibility gap, not proof of a
direct-IP connection.

The main graph is `THIS HOST -> owning process -> URL / remote endpoint`; the
browser graph is `BROWSER WEB -> browser process -> URL`. Every browser flow
also gets a host-only endpoint labelled `HOST ONLY`; it is inferred from the
socket and DNS cache and never claims a full visited path. `READ BROWSER
HISTORY` is an explicit per-run opt-in that opens local history databases
read-only and may supply a full URL labelled `HISTORY`, with up to 24 bounded
A-record lookups when DNS-over-HTTPS leaves the Windows cache empty. No profile
file is copied, changed or deleted and no DNS setting is modified.

Findings and detail are modal buttons with state and remediation: broad
listeners, RDP exposure, handler-style egress, unusual background egress,
direct-IP traffic without a cached name, private peers on management ports and
sockets whose owner the token cannot read. `PATHS / ROUTES` lists interfaces,
gateways, DNS servers, MAC addresses and the IPv4 route table. `PKTMON RECIPE`
is copyable guidance for an administrator; NetTruder never launches pktmon or
reads an ETL. UDP endpoints appear as local binds because UDP has no connection
state.

### 16 - PS LOGGING

A read-only PowerShell telemetry readout. `READ PS LOG` checks the documented
policy key for `EnableScriptBlockLogging=1` and samples Event ID 4104 from the
`Microsoft-Windows-PowerShell/Operational` log for the last seven days. Each
masked sample shows the `WHO`, `WHAT` and `WHERE` fields present in the event:
account or SID where recorded, script-block ID and message part, plus host,
process, thread and path. Absent fields are `NOT RECORDED`.

The same run queries explicit block or prevention events involving PowerShell
from AppLocker, WDAC/Code Integrity and Defender operational channels. They
appear in a separate `BLOCKED / PREVENTED POWERSHELL` pane with attribution and
detail. The summary reports how many block sources were readable; an unreadable
or unconfigured channel is `NOT EVALUATED`. Windows has no single generic
"blocked PowerShell" channel, so NetTruder reports only explicit control events
it can read and does not infer a block from 4104.

NetTruder never enables, disables or clears a log, never changes a policy key,
never re-runs a blocked command and never executes a captured script block. If
logging is off, inaccessible or empty, the UI shows the Group Policy path and
forwarding advice. A captured line or block event is defensive evidence, not a
verdict about intent.

---

## 5. Browser extension and manual handoff

`browser-extension/` contains **NetTruder Site Posture** v1.4.0, a read-only
MV3 extension for Chromium-based browsers. It uses `activeTab`, `scripting`,
`storage`, `webRequest` and optional per-origin host permission. It has no
network code, no history or bookmarks access, no cookie values, no form values
and no tabs scraping. URLs in findings and reports have query strings and
fragments removed.

The popup reports HTTPS state, mixed-content references, form and password
field context, visible cookie names, passive login indicators and, after an
explicit per-origin grant and reload, security headers and redirect hosts.
Headers are observed, never rewritten, and requests are never blocked. Without
the grant, header rows stay `NOT EVALUATED`. Browser internal pages,
`view-source:`, extension pages and `file:` pages are also `NOT EVALUATED`.

A CAPTCHA or bot check is a site-side control result. The operator selects the
type and outcome and records the encounter; NetTruder does not solve it, pick
images, capture tokens, retry, change headers, IP or User-Agent. The extension
is a passive indicator tool, not an AiTM or exploit detector.

There is no automatic bridge. `COPY REPORT` places a redacted report on the
clipboard; the operator pastes it into `WEB RISK > EXTENSION REPORT IMPORT`.
There is no native messaging, localhost listener, fixed-folder file drop,
hidden pipe or WSH re-enable. If a browser policy blocks the extension, that is
a valid control result and the operator follows the software approval process.

---

## 6. Static kernel source study (HEVD)

`research/hevd-source/` is a trimmed, source-only copy of HEVD with its original
GPL-3.0 license and attribution. It is study material, not an installation
kit. NetTruder does not build, sign, install, load or run the driver, and does
not provide a device request, size value, payload or bypass.

`CODE AUDIT` can scan that folder read-only. Rules such as `NT-C-INIT` and
`NT-C-INT-WRAP` produce masked findings with an evidence line, a plain-language
reason, a fix, reach context and a five-step authorised-lab verification
checklist. `NT-C-INT-WRAP` flags size arithmetic inside a bound comparison:
the addition itself can wrap a fixed-width value, so the comparison reads a
small number while the real requirement is large. The `INT WRAP` modal explains
that mechanism without supplying a trigger.

Every such finding stays `STATIC LEAD / NOT RUNTIME VERIFIED`. That is both a
boundary and a capability statement: the engine is a regex-based reader, so it
cannot prove reachability or exploitability, and even a compiler would not make
a source pattern a runtime proof. The tool highlights the bug class and stops
short of proof, triggering or enabling it.

`HEVD-RESEARCH.md` documents the rules and the safety boundary;
`hevd-catalog.json` carries detection and hardening guidance;
`hevd-scenarios.json` holds beginner and advanced source-review exercises,
including `B7 - Read a wrapped-size finding`. The helper in
`research/hevd-source/tools/hevd_lab.py` only reads local JSON and text.

---

## 7. Data locations and privacy

```
%LOCALAPPDATA%\NetTruder\
  runs\   <id>.request.json  <id>.events.ndjson  <id>.stop  <id>.pid
  state\  ips-journal.json  onboarding.json  triage-decisions.json
  audit\  audit-YYYYMMDD.ndjson
  lab\    lolbas-posture-*.json / .md  markers.log
```

The request file is written by the console and deleted by the engine. The event
stream is ASCII-escaped so it can be read with a plain ASCII file read. Before
version 1.1.0 the root was `%LOCALAPPDATA%\NetWatch`; state, audit and lab files
are copied forward only when the destination file is missing, and the old root
is never deleted.

NetTruder never reads browser profiles by default, never sends data anywhere,
and never reads form or cookie values. Raw source for an enabled code-edit
session and captured PowerShell text are sensitive local artifacts; handle the
corresponding run files accordingly. To remove all traces, release all blocks
and delete `%LOCALAPPDATA%\NetTruder`. Personal files, Downloads, Documents and
browser profiles are never deleted by this tool.

---

## 8. Validation and known limits

The local validation harness checks PowerShell AST parse, CSS brace balance and
absence of modern CSS constructs, ASCII-only sources, and engine/UI event kind
coverage. Catalog JSON is parsed and the HEVD helper's `check` action verifies
its entries and scenarios. Browser-side JavaScript is parse-checked in an
in-app browser harness because Node is not installed. The engine can also be
exercised through its CLI without the HTA.

Known limits:

- The HTA/WSH launch may be blocked on a hardened host; that is a recorded
  control result, not a defect, and no bypass is attempted.
- The static engine matches text patterns. It has no compiler, type analysis or
  data-flow engine and cannot prove exploitability.
- NetTruder sees local Windows sources only. It cannot see EDR telemetry, SIEM
  forwarding or network sensors, so `BLIND` does not mean undetected.
- Real unpacked browser loading and live browser permission scenarios have not
  been performed in this environment.
- The catalogs are a starting point, not a complete inventory of every public
  technique.

---

## 9. Repository notes

NetTruder code is MIT licensed; see `LICENSE`. Attribution for the trimmed HEVD
source copy, public catalog references and research citations is in
`THIRD-PARTY-NOTICES.md`. Runtime data and the local Python environment are
excluded by `.gitignore`; the copy-only mirror workflow never uses `robocopy
/MIR`.

NetTruder is authored and maintained by the repository owner. Development and
documentation assistance was provided by OpenCode AI (Big Pickle model); it is
a contributor, not the owner or author of record.
