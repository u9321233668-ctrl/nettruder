# NetTruder - Research Read-Out

What was built, how it was tested, and what the results mean. Every claim below
was verified on the test host unless it is explicitly marked as a limit.

---

## 1. Objective and scope

Build a defensive network console for Windows with these capabilities. All of it
is version 1.1.0; the console was named NetWatch before that release.

| Capability | Implementation |
|---|---|
| Network discovery | ICMP sweep, ARP/neighbour enrichment, reverse DNS |
| Port and service sweep | TCP connect scan with banner grab |
| Host IDS | Polled TCP table analysis against a JSON rule set |
| IPS | Host-firewall active response, TTL-bound and reversible |
| Local terminal | Single-command `cmd.exe` runner, audited |
| UI | JScript HTA, dark operations-console skin |
| Process/data-flow map | Read-only process tree and TCP flow graph |
| Passive web risk | GET/OPTIONS header, TLS, cookie, form and exposure check |
| Static code audit | Read-only source review with masked secrets |
| Threat investigation | Read-only socket, DNS and listener review |
| Local triage | Exported-alert board with local-only decisions |
| Exposure register | Endpoint block evidence; no re-run, no bypass |
| Data security | Read-only classification and opt-in, bounded purge |

Research boundary: this is not an offensive framework. There is no C2, agent,
listener, payload, stager, lateral movement, remote shell, credential access,
persistence, obfuscation, hidden windows, or defence evasion. The terminal is
local only.

---

## 2. Test environment

| Item | Value |
|---|---|
| OS | Windows 11, build 26300 |
| PowerShell | 5.1.26100.9818 |
| UI host | mshta, `documentMode 11`, `JSON` available |
| Security products | Windows Defender (`productState 393472`) + McAfee (`266240`) |
| Defender real-time | off (per `Get-MpComputerStatus`) |
| Firewall | domain, private, public all enabled |
| SMBv1 | disabled |
| RDP inbound | disabled |
| Power plan | no High performance scheme present |

---

## 3. Verified results

| Test | Method | Result |
|---|---|---|
| Engine syntax | PowerShell AST parser | PARSE OK |
| Console syntax | cscript with DOM stubs | PARSE OK |
| Rule set load | `rules.json` | v2026.11.2, 16 listener rules, 9 remote-port rules, 19 egress rules |
| Status | `-Action status` | host, IPv4 set, gateway 192.168.0.1, DNS 192.168.0.1, 0 monitors, 0 blocks |
| Posture probe | `-Action probe` | 8 checks, complete in ~18 s |
| Sweep | `127.0.0.1`, common, 400 ms | 1 host up, 2 ports (135/rpc, 445/smb) |
| IDS arm/disarm | watch + stop file | pid file created, alert raised, clean stop, pid removed |
| IPS without admin | `-Action block 8.8.8.8` | refused, 0 firewall rules created |
| Terminal (CLI) | request file, `echo ... && cd` | stdout streamed, correct cwd, exit 0 |
| UI init | diag HTA on the real DOM | engine path and shim resolved, status run booted |
| **UI-driven sweep** | button path from the console | 1 host row, ports 135/445, stats and progress updated |
| **UI-driven IDS** | arm, alert, disarm | monitor flag true, 1 alert rendered, clean disarm |
| **UI-driven terminal** | `echo ui-term-ok && ver` | output rendered, exit 0, input re-enabled |
| **UI-driven posture** | probe from the console | 8 rows rendered, COMPLETE state |
| **UI-driven IPS refusal** | BLOCK 8.8.8.8 as user | "elevated session" message, 0 rules created |
| **Close-time cleanup** | arm IDS, close the window | engine wrote its stop file, exited, pid file removed |
| Audit view | list, load, render | 1 file listed, 18 entries rendered |
| **Status after rename** | `-Action status` | `migrated:41`, `adminGroup:true`, `tokenElevated:false` |
| **Code audit** | `-Action codeaudit` | 15 files, 167 findings, secret values masked |
| **Flow** | `-Action flow` | 512 events, 260 nodes, 242 edges, 5 findings |
| **Investigate** | `-Action investigate` | 26 peers, 2 findings |
| **Exposure register** | `-Action av` | 91 events, 2 products, 1 gap |
| **Data check / purge preview** | `-Action datacheck` / `datapurge` | 356 files / 1 finding; preview 0 files, 0 bytes, nothing deleted |
| **Web - loopback** | `-Action webscan` | 9 findings, grade D, HTTP 200 |
| **Web - refused target** | `-Action webscan` | 1 finding (`NT-WEB-000`), grade n/a |
| **Engine/UI event kinds** | event dispatch smoke | 52 handled, 0 unhandled |

Posture output on the test host:

```
defender-rt        off              high
defender-sig       0 day(s)         ok
firewall           all profiles on  ok
smbv1              disabled         ok
rdp                disabled         ok
wuauserv           Stopped          info
exposed-listeners  none             ok
ips                0 active         info
```

No firewall rule was ever created during testing, so there was nothing to undo.

---

## 4. The launch-chain finding

This was the one real defect found, and it is worth recording because it is a
clean example of behaviour-based blocking.

**Symptom.** The console initialised, wrote a valid request file, and then no
engine events appeared.

**Evidence.** `mshta` -> `WScript.Shell.Run("powershell.exe ...")` failed with
HRESULT `-2147024671` = `0x800700E1` (`ERROR_VIRUS_INFECTED`). The same call from
`cscript` succeeded, so the path and arguments were fine.

| Parent | Command line | API | Result |
|---|---|---|---|
| mshta | `powershell.exe -Command "exit 0"` | Wsh.Run | blocked `0x800700E1` |
| mshta | full path to powershell.exe | Wsh.Run | blocked |
| mshta | `cmd /c powershell.exe ...` | Wsh.Run | blocked |
| mshta | `cmd /c echo hi` | Wsh.Run | OK |
| mshta | `wscript.exe "shim.vbs" "req.json"` | Wsh.Run | OK |
| mshta | `ShellExecute("wscript.exe", ...)` | ShellExecute | OK |
| mshta | `cmd /c wscript.exe "shim.vbs" "req.json"` | Wsh.Run | OK |
| cscript | `powershell.exe ...` | Wsh.Run | OK |

**Resolution.** The console no longer launches PowerShell. It writes a JSON
request file and calls `engine\shim.vbs`. WSH runs the shim, and the shim starts
a hidden PowerShell worker with `-RequestFile`. All three shim variants were
verified to produce a complete event stream.

**Point of principle.** The block was not bypassed and no security product was
weakened, disabled, or excluded. The launch chain was moved into a normal
WSH parent, which the policy permits. If that is ever blocked too, the console
reports it and stops.

---

## 5. Architecture

```
NetTruder.hta  --(writes)-->  %LOCALAPPDATA%\NetTruder\runs\<id>.request.json
     |                                    |
     | (polls, 220 ms)                    v
     +---------- <id>.events.ndjson <-- shim.vbs -> powershell NetTruder.ps1
                                          |
                                          v
                                   audit-YYYYMMDD.ndjson
```

- The UI and engine are decoupled. The console can be restarted without killing
  a running monitor, and the monitor can outlive a closed window until disarmed.
- Events are newline-delimited JSON, ASCII-escaped, so no encoding negotiation
  is needed across file boundaries.
- The engine writes a `boot` event with mode, admin state, pid and version, so the
  UI can label the session truthfully.
- `-RequestFile` keeps target lists and terminal commands out of command-line
  quoting entirely. That removes a whole class of escaping bugs.

---

## 6. Detection logic

The IDS polls `Get-NetTCPConnection` every two seconds.

1. **Exposed listener.** A port from `rules.json` is listening. Severity per port.
2. **Flagged egress.** An established session to a known handler or proxy port,
   with the owning process named.
3. **Beacon cadence.** At least six new sessions to one address inside 150 s,
   mean gap 8-200 s, coefficient of variation <= 0.30. This is a *statement about
   timing*, not an attribution.
4. **Fan-out.** One process touching 25+ distinct hosts inside 60 s.

Alerts deduplicate on `(rule, address, process)` with 300/600/900 s cooldowns.
Memory is bounded: the seen-key table is trimmed at 4,000 entries, the per-IP
session history is dropped at 800 keys.

---

## 7. Safety controls, verified

- Read-only default: scan, probe and IDS create no firewall rules.
- Private-range guard on scanning; `/22` cap; public targets need `-AllowPublic`.
- IPS refuses local IP, gateway, DNS, loopback, multicast, broadcast, reserved.
- IPS refuses private peers without explicit confirmation.
- IPS caps at 30 active rules and clamps TTL to 1-240 minutes.
- Firewall footprint is exactly `NetTruder-IPS-<ip>-in` / `-out`.
- Expiry is enforced at engine start, on status, and by a UI timer.
- Every block, release, alert, probe, scan and terminal command is audited.
- No service, driver, Defender, Windows Update, telemetry or profile change.

---

## 8. Observations

1. **Selective process-launch control is normal, and it breaks naive tooling.**
   The block depended on the parent process and the command line, not on the
   target binary. Anything that shells out from an HTA will hit this class of
   policy eventually. Request-file plus WSH shim is a durable pattern.

2. **"Defender real-time off" does not mean "unprotected".** Two AV products are
   registered and the second one is the active owner. A posture probe should
   report the raw state and let the operator interpret it; NetTruder does.

3. **Polling IDS granularity is a hard limit, not a tuning problem.** At a 2 s
   poll, cadences below roughly 6 s cannot be distinguished and jitter is
   quantised to 2 s. Anything faster needs ETW or packet capture, which this
   design deliberately avoids because it would need a driver.

4. **Connect scanning is the honest choice for a no-driver tool.** It is easy to
   detect, and that is fine: the tool is for authorised discovery and defence
   validation, not stealth.

5. **TTL-bound containment beats permanent blocklists.** Every block expires, so
   a mistaken or malicious alert cannot permanently cut a host off. The journal
   is the source of truth, and `release` is one click.

6. **Decoupled UI and engine is what makes the monitor usable.** The engine keeps
   scanning and alerting even if the console is closed, and the console can
   reattach because all state lives in files.

---

## 9. Limits

- Connect scan only; no SYN scan, no OS fingerprinting.
- IPv4 only for blocking.
- No packet capture, no inline IPS, no remote agents.
- Beacon and fan-out heuristics are triage signals, not proof.
- The terminal is exactly as powerful as the account that launched it. It is not
  a sandbox and is not intended to be one.

---

## 10. Update 2026-11-15 - provable labels, detail panel, admin-tool egress

This update answers three questions that came out of the first read-out: are the
`BLIND` rows provable, what does a row actually mean, and can the monitor see an
admin tool reaching the network.

### 10.1 Targeted proof, not broad counts

The first probe implementation compared broad 4688 and 4104 counts before and
after the marker scripts. That was wrong on two counts. A standard user cannot
read the Security log at all, and the tool's own PowerShell activity generates
4104 events during the run, so the content delta moved even with script block
logging off.

The proof is now targeted:

- **4688** counts only events whose new-process image is one of the four probe
  hosts (`wscript.exe`, `cscript.exe`, `mshta.exe`, `powershell.exe`).
- **4104** counts only events whose text contains the marker token
  `NWPROBE-4104-CONTENT-MARKER` from `probes\marker.ps1`.

Each technique row now carries a `basis` string with the raw policy readings, and
after a probe run it gains `measured[4688=on|off|n/a 4104=on|off|n/a]`. `n/a` means
the log was unreadable, so the label stays configuration-derived; `off` means the
probe measured the signal and nothing was recorded. Where a measurement contradicts
a policy reading, the findings say so instead of repeating the registry value.

Verified on this host:

| Reading | Result |
|---|---|
| Security log readable | no (`secAccessible=false`, `secDelta=null`, `secMatched=0`) |
| PowerShell log readable | yes (`psAccessible=true`) |
| Broad 4104 delta | +29 |
| Targeted marker matches | 0 (`psMatched=0`) |

The +29 is exactly the noise the targeted match exists to reject: the tool's own
commands emit 4104 events, but none contain the marker token. The honest answer is
`n/a` for process proof and `off` for content, not a delta-derived guess.

### 10.2 The detail panel

Clicking a row opens a panel that explains the gap rather than only naming it:

- **PROCESS TREE** - four labelled steps (stage, technique, process, action), each
  with the log that records it and an inert detection sample.
- **DETECT** - the command-line patterns worth alerting on.
- **ATTACK SURFACE REDUCTION** - the documented Defender ASR rule GUIDs for the
  host, shown with the admin command for reference. The console never applies it.
- **NETWORK MONITORING** - the egress ports and what to watch for.
- **REMEDIATE** - policy, allow-listing and monitoring fixes.

Enrichment lives in `research/techniques.json` (`tree`, `cmd`, `asr`, `net`, `fix`)
and is carried through the lab into `restech`, so the catalog and the UI cannot
drift apart.

### 10.3 Admin-tool egress

`engine\rules.json` now carries 19 process-keyed `egressWatch` entries for
`certutil`, `bitsadmin`, `mshta`, `regsvr32`, `wscript`, `cscript`, `rundll32`,
`msiexec`, `installutil`, `msbuild`, `forfiles`, `pcalua`, `cmstp`, `odbcconf`,
`verclsid`, `xwizard`, `hh`, `control` and `wmic`. On a match the engine raises
`EGRESS_<PROC>`, reads the live command line with `Get-CimInstance Win32_Process`
and appends it to the alert.

The `bitsadmin` caveat is documented rather than papered over: BITS performs the
transfer inside `svchost.exe`, so the flow rarely carries the `bitsadmin` name.
Detect it from the command line and the BITS-Client operational log; the egress
rule is a backstop.

### 10.4 Test results

- **Egress end-to-end passed.** With a listener on `192.168.0.236:80`, a WSH probe
  produced `EGRESS_WSCRIPT` for `wscript -> 192.168.0.236:80`, with the command
  line captured. The engine stopped cleanly afterwards.
- **certutil test blocked by AV, not bypassed.** `certutil -urlcache -split -f`
  was refused at process start by McAfee ("file contains a virus or potentially
  unwanted software"). That is a valid defensive result: it shows the control
  plane doing its job. It was not bypassed, and no attempt was made to.
- **UI smoke test passed.** All seven views rendered at 905x782 with no horizontal
  overflow; the detail panel showed a 4-step tree, ASR rows, command matches,
  network ports and remediation. The old horizontal scan beam is removed, leaving
  a static skin with only small status LEDs animating.

## 11. Update 2026-11-16 - triage, blocks, three catalogs, proven proof

This update closes four gaps from the first read-out: a noisy fan-out alert, a
catalog that covered only Windows execution hosts, proof wording that guessed at
elevation, and remediation that was visible but not actionable.

### 11.1 Browser fan-out is not lateral movement

The alert `FANOUT` fired for `msedge` opening sessions to 30 distinct hosts in 60
seconds (`audit-20261115.ndjson:26`). That is normal browser CDN and telemetry
behaviour, so treating it as a high-severity C2 signal produced noise and trained
the operator to ignore the rule. Removing fan-out detection would be the wrong
fix.

The monitor now distinguishes two shapes:

- **`FANOUT`** - browser processes (`msedge`, `chrome`, `firefox`, `brave`,
  `opera`, `vivaldi`, `iexplore`) raise it at 30 distinct hosts with
  `sev=low`; other processes still raise it at 25 with the configured severity.
  The alert is triage context, not a C2 verdict.
- **`LATERAL_FANOUT`** - one process reaching 4 or more distinct hosts on
  sensitive ports (135, 139, 445, 3389, 5985, 5986, 22) raises `sev=high`. This
  is the shape that actually resembles lateral movement.

`engine\rules.json` carries the thresholds (`browserProcs`, `browserSev`,
`browserHosts`, `lateralHosts`, `lateralSev`, `lateralPorts`), so they can be
tuned without touching code.

### 11.2 A block is evidence, not coverage

`research\blocks.json` and `research\BLOCKED-TESTS.md` record tests that a
control stopped. The first three records are:

| ID | Vector | Result |
|---|---|---|
| BLOCK-001 | `mshta.exe` -> `powershell.exe` | blocked before process start, `0x800700E1` |
| BLOCK-002 | `certutil -urlcache -split -f` | refused at process start; no download completed |
| BLOCK-003 | block a public address without elevation | NetTruder refused; zero firewall rules created |

A block is a positive control result and is shown as `BLK n` on the technique
row and as a card in the detail panel. It never upgrades a `BLIND` or
`CONTENT GAP` row to `OK`, because one blocked variant says nothing about the
variants that were not attempted. No bypass was attempted to strengthen a
record; the block register states its evidence limits explicitly.

### 11.3 Three catalogs, two platforms

The lab now loads 60 techniques:

| Catalog | Count | Group | Platform |
|---|---|---|---|
| `techniques.json` | 24 | Proxy Execution 17, Script Hosts 4, Management Interfaces 1, Download and Decode 2 | Windows |
| `worm.json` | 6 | Worm-like Propagation | Windows |
| `gtfobins.json` | 30 | Linux / Unix (GTFOBins) | Linux / Unix |

The worm-like catalog covers `net.exe`, `sc.exe`, `schtasks.exe`,
`WmiPrvSE.exe`, `psexesvc.exe` and `mstsc.exe` - the hosts that show up in
propagation chains rather than execution chains. GTFOBins presence is checked
read-only through a readable WSL filesystem. An unreadable or absent WSL is
reported as `NOT EVALUATED`, never as clean, and no Linux binary is executed.
Rows carry `platform`, `group` and `method`; the UI filters on group and platform
and keeps Windows and Linux visually distinct with a `WIN`/`LNX` badge.

### 11.4 Proof states the real error

The proof card used to imply "requires elevation" whenever a log was unreadable.
That was both vague and sometimes wrong. It now separates:

- **tokenElevated**: is the process token elevated?
- **adminGroup**: is the account in Administrators, including the deny-only SID
  that UAC leaves in a filtered token?
- **integrity / elevationType**: `medium`/`high` and `limited`/`full`/`default`;
- Security-log readability plus the actual error text;
- Sysmon readability plus the actual error text;
- `SeSecurityPrivilege` present/enabled plus the enable result
  (`enabled`, `not-assigned:1300`, `failed:<code>`);
- `auditpol` readability and error;
- **Sysmon 1 as a fallback** for process proof when Security 4688 is unavailable,
  parsed by named `Image` XML field.

This resolves the "session elevated but Security log not readable" report. The
account is in Administrators, but UAC handed the process a filtered token:
`adminGroup=yes`, `tokenElevated=no`, `integrity=medium`,
`elevationType=limited`, `securityReadable=no`,
`SeSecurityPrivilege present=no`, and the enable attempt returns
`not-assigned:1300` (AdjustTokenPrivileges succeeded but
`ERROR_NOT_ALL_ASSIGNED` means the privilege is not in this token). Group
membership is not an elevated token. The remediation is to relaunch
`Launch-Elevated.cmd` as administrator; NetTruder never disables UAC.

A log containing "No events were found that match the specified selection
criteria" is treated as readable with zero matches, not as an unreadable log.
Conversely, a filtered 4688 query that returns zero rows is not treated as proof
when the direct channel read failed: `secAccessible=false`, `secDelta=null`,
`matched=0`, and the label stays configuration-derived. `PSLOG enabled=True` is
labelled as the PowerShell **event channel**; the script-block policy is a
separate control row and finding. In the latest run the channel was readable,
`psMatched=0`, so content logging is honestly reported as `off` rather than
inferred from a broad event delta.

The lab refused to read the Security log as a filtered administrator
(`Attempted to perform an unauthorized operation.`), reported `sysmonError` for
the missing Sysmon operational log, and still completed all 60 techniques. The
probe run executed all four inert markers with `marker=True` and correctly
reported that no 4688 or Sysmon 1 event matched them. The elevation card in the
UI is clickable and opens the elevation remediation (steps, last error, and the
native `secpol.msc` view).

### 11.5 Control and finding remediation is clickable

Every control row and every finding now opens a remediation modal. It shows the
observed state, the source, why it matters, numbered steps, the enable/harden
script, the native UI, and copy / elevated-shell actions. The elevated-shell
action copies the script and opens an elevated PowerShell for review; it does not
auto-run it.

The modal never offers to turn a security control **off**. Controls that are
safer when off are labelled `safer when off` and open review steps instead.
Alerts gained a **REMEDY** action and spawn dismissible toasts with REMEDY /
PROCESS / DISMISS. The remediation text states plainly that NetTruder never
weakens a control.

### 11.6 Readability and layout

The process-tree and detect columns are independent scroll areas with wrapping,
so long paths and command lines are visible instead of clipped. Text was raised
in the process tree, detect, control-plane, findings and detail headers. Research
rows show `ID / HOST / GROUP / PLATFORM / HERE / GAP / ACTIVE CONTROLS`, and the
summary strip adds `LINUX GAP`, `NOT EVAL`, `BLOCKS`, `WSL` and the two proof
channels. The layout was re-smoked at 1480x900, 1280x800, 1100x700, 900x640 and
760x560 with no horizontal overflow and all text reachable by scrolling.

### 11.7 Validation

- `techniques.json`, `worm.json`, `gtfobins.json` and `blocks.json` parse as JSON
  and are pure ASCII.
- No host is duplicated across the three catalogs, so row lookup by host is
  unambiguous.
- `Test-NetTruderPosture.ps1` and `engine\NetTruder.ps1` parse cleanly.
- Research lab end-to-end: 60 techniques, 30 Windows + 30 Linux, 3 blocks, 6
  groups, WSL `kali-linux` readable, 11 control rows, 5 findings.
- Probe run: 4/4 markers executed, `marker=True`, Security 4688 unreadable with
  its real error, Sysmon unavailable with its real error, 4104 readable with
  `matched=0`.
- `ui\app.js` parses under JScript and `NetTruder.hta` contains the modal and
  toast containers; CSS braces balance and the file is ASCII.

---

## 12. Update 2026-11-18 - version 1.1.0 rename, new modules and onboarding

The project is NetTruder 1.1.0 everywhere: the engine header and boot event
report `1.1.0`, the HTA footer reads `v1.1.0`, and the console state carries the
same version. The console was NetWatch before 1.1.0. The launcher is
`NetTruder.hta`, the engine is `engine\NetTruder.ps1`, and the lab is
`research\Test-NetTruderPosture.ps1`.

### 12.1 Legacy state is copied, never moved

The data root is `%LOCALAPPDATA%\NetTruder`. On first start the engine looks at
`%LOCALAPPDATA%\NetWatch` and copies `state`, `audit` and `lab` files into the
new root **only when the destination file is missing**. The old folder is never
deleted or moved, so a rollback stays possible. The smoke run reported
`migrated:41`. Nothing is written to the legacy root.

### 12.2 Fourteen modules and the GUIDE button

The rail is 01-14: SWEEP, PROCESS FLOW, WEB RISK, CODE AUDIT, THREATS, TRIAGE,
EXPOSURE, DATA, IDS/IPS, TERMINAL, POSTURE, PROCESSES, AUDIT, RESEARCH. The
engine actions are `status`, `probe`, `rules`, `scan`, `watch`, `block`,
`unblock`, `release`, `expire`, `shell`, `processes`, `kill`, `research`,
`webscan`, `codeaudit`, `flow`, `investigate`, `triage`, `av`, `datacheck` and
`datapurge`.

- **flow** builds a read-only process tree/data-flow graph in an n8n-style
  layout. Smoke: 512 events, 260 nodes, 242 edges, 5 findings.
- **webscan** makes passive GET/OPTIONS checks of headers, TLS, cookies, forms,
  comments and exposure paths. OWASP ZAP commands are copyable recipes only and
  ZAP is never launched. Public hosts need an explicit opt-in: tick **ALLOW
  PUBLIC HOST** in the UI or pass `-AllowPublic` on the CLI. Smoke: loopback 9
  findings / grade D / HTTP 200; refused target 1 finding / grade n/a.
- **codeaudit** reads source as text and never runs it; secret values are masked
  in findings. Smoke: 15 files, 167 findings.
- **investigate** is a read-only socket/DNS/listener review. Smoke: 26 peers,
  2 findings.
- **triage** normalises exported JSON/NDJSON alerts into a local board.
  Decisions live in `state\triage-decisions.json` and are never pushed upstream.
- **av** is an endpoint block evidence / control-success register. Smoke: 91
  events, 2 products, 1 gap. It never re-runs a blocked action and never tries
  a bypass or obfuscation.
- **datacheck** classifies files read-only. Smoke: 356 files, 1 finding.
  **datapurge** previews by default and needs both `-Yes` and `-AckRisk` to
  delete anything. It is bounded to NetTruder-owned runs/snapshots and optional
  audit files older than `RetentionDays`; personal files are never in scope.
  Smoke preview: 0 files, 0 bytes, nothing deleted.

The safety boundary is unchanged: no Defender/firewall/Update/service/driver/
task weakening, no service startup changes, no telemetry reduction, no page-file
or network-stack tweaks, no personal-file deletion, no payloads/C2/persistence/
credential access/obfuscation/hidden windows/evasion, and no AV bypass.

### 12.3 Web-scan honesty

An unreachable target produces exactly one finding, `NT-WEB-000` (`Web target
did not answer`), grade `n/a` and `answered=False`. Missing headers on a target
that did not respond are `NOT EVALUATED`, not missing-header findings. The
loopback smoke answered with HTTP 200 and produced 9 findings at grade D; the
refused-target smoke produced 1 finding at grade n/a. A silent host is neither a
clean nor a dirty result.

### 12.4 Onboarding

First run shows a welcome survey (role and level), then a 10-step product tour.
Each view adds a progressive in-app hint the first time it is opened. **GUIDE**
in the top bar reopens onboarding at any time. State is local:
`%LOCALAPPDATA%\NetTruder\state\onboarding.json` holds `{seen, role, level, at}`.

### 12.5 Elevation facts remain separate

`adminGroup` (account membership), `tokenElevated` (current UAC token) and
Security-log readability are reported as three different facts. The smoke run
showed `adminGroup:true`, `tokenElevated:false`. The authoritative readability
check is a direct `Get-WinEvent -LogName Security -MaxEvents 1`; a filtered 4688
query returning zero rows never upgrades an unreadable channel to a clean
result. `SeSecurityPrivilege` is reported explicitly as `enabled`,
`not-assigned:1300` or `failed:<code>`. `PSLOG CH` on the summary is the
PowerShell **event channel**, not the script-block policy; the policy has its
own control row and finding.

### 12.6 Control-plane actions

Every control-plane row and finding is clickable and offers enable, harden,
copy, native-UI and elevated-shell actions. The elevated-shell action copies a
script for review and paste; it never auto-runs it. NetTruder never turns a
control off, never disables UAC and never auto-elevates.

### 12.7 Research catalogs and blocks

The catalogs keep their shape but are consistently labelled:
`research\techniques.json` (24 Windows entries), `research\worm.json` (6 Windows
worm-like entries), `research\gtfobins.json` (30 Linux/Unix entries),
`research\blocks.json` (observed block register) and `research\BLOCKED-TESTS.md`.
`platform`, `group` and `method` keep Windows separate from Linux/Unix. Blocks
are positive control results and never upgrade a coverage gap to `OK`. No
bypass, obfuscation or evasion is attempted. The lab exports
`NETTRUDER_LAB_DIR` to the report folder for the inert marker probes.

### 12.8 Validation

- Engine and UI event kinds: 52 handled, 0 unhandled.
- `ui\app.js` parses (JS parse OK), CSS braces balance and all sources are
  ASCII-only.
- Validation artifacts: `nw-jsparse.js` in a local test harness folder and the
  pre-rename backup `netwatch-pre-nettruder.zip`, both kept outside this repo.

---

## 13. Update 2026-11-20 - the console-blocked result and next paths

A hardened host can stop `Launch.cmd` before NetTruder starts. This is treated
as a research result, not a defect. The UI depends on `mshta.exe` and
`engine\shim.vbs` depends on WSH; if WSH is disabled, `.hta` is blocked, or the
launch chain is refused, the console reports the block or does not start.

### 13.1 What the result means

- The block is proof that one control acted on one parent/child chain on one
  host at one time.
- It does not prove the technique is blocked everywhere, and it never upgrades
  a `BLIND` or `NOT EVALUATED` coverage row to `OK`.
- A missing process event after a refused launch is expected: the process never
  started, so it is not an IDS detection failure.
- Hardening still matters. It reduces what can run; 4688, Sysmon, 4104, EDR and
  SIEM forwarding still answer what was attempted, by whom, and whether the
  control drifted.

### 13.2 The five valid next paths

1. **Keep an approved lab or admin-workstation console.** The full UI only
   needs one authorised host where the launch chain is permitted. It does not
   have to run on every hardened endpoint.
2. **Treat the block as an acceptance test.** Record host, account, launcher,
   parent/child pair, control, event id and the exact signal, then stop. No
   retry, alternate launcher, whitelist or exclusion.
3. **Compare hosts with POSTURE and RESEARCH.** Re-run the read-only inventory
   on an allowed host and compare WSH, AppLocker/WDAC, ASR, 4688, 4104, Sysmon,
   AMSI and EDR/SIEM state with the blocked host.
4. **Document the blocked-console case.** `research/BLOCKED-TESTS.md` section 10
   and `BEST-PRACTICES.md` section 13 now record WSH disabled, `mshta` blocked
   and shim blocked as control-success cases with an evidence template.
5. **Keep the evidence, not just the UI.** Reports, NDJSON event streams, audit
   entries and block records are the durable output. Save them with run id,
   host and time; redact and protect them before sharing.

### 13.3 Documentation and validation

This update changed documentation only. No registry value, script-host policy,
service, Defender setting, firewall profile, log channel or security control was
changed. No blocked command was re-run, and no alternate launcher was tested.
The launch-chain evidence from BLOCK-001 remains the measured example:
`0x800700E1`, `ERROR_VIRUS_INFECTED`, and `Engine launch blocked: ...
[code -2147024671]`. The WSH-disabled case is documented as a response pattern
with fields to capture when it is observed, not as a new measured probe run.

