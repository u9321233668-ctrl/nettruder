# NetTruder // LOLBAS, Worm-like and GTFOBins Research Lab

A defensive research harness for living-off-the-land binaries and scripts
(LOLBAS), worm-like propagation behaviour and Linux/Unix GTFOBins, plus the
telemetry that should catch them.

This is NetTruder 1.1.0. The lab script is `Test-NetTruderPosture.ps1`, and the
marker probes read `NETTRUDER_LAB_DIR` for the report folder.

The lab runs standalone (`Invoke-Lab.cmd`) and is also invoked by the console as
module **14 - RESEARCH**, which re-emits the same report as console events.
Nothing here changes a security setting, and nothing here is an attack tool.

---

## Safety boundary

**This is a detection lab, not a loader kit.**

- Read-only inventory. The only writes are the JSON report, the Markdown report
  and `markers.log` under `%LOCALAPPDATA%\NetTruder\lab`.
- No payloads, no shellcode, no download cradle, no C2, no listener, no
  persistence, no credential access, no privilege escalation.
- No obfuscation, no encoded arguments, no hidden windows and no process
  injection in the probes.
- Marker probes only append a line to a log and exit. They require both
  `-RunMarkerProbes` and `-Yes`.
- The tool never disables Defender, the firewall, Windows Update, services,
  drivers or scheduled tasks. It makes no service startup changes, no telemetry
  reduction, no page-file or network-stack tweaks and no personal-file deletion.
- A blocked test is recorded as a positive control result in `blocks.json` and
  `BLOCKED-TESTS.md`. No bypass, obfuscation or evasion is attempted, and a block
  is never treated as a coverage pass. There is no AV bypass workflow.

If you want to test a technique that is not covered here, add it to
`techniques.json` with an **inert** probe and document the expected telemetry
first. Do not add a payload to this folder.

## Why there are no extra shim-style launchers

`engine\shim.vbs` exists for one reason: on hosts with an endpoint agent, the
HTA-to-PowerShell launch is refused, so NetTruder routes it through WSH. That is
production plumbing.

Adding more hidden or encoded launcher variants would be indistinguishable from
malware, would weaken the trust story of a defensive tool, and would not teach
you anything that the documented LOLBAS catalog does not already cover. The
useful research question is not "can I build another chain?" but "does this host
record the chains that already exist?". That is what this lab measures.

The same rule applies when Windows Script Host is disabled. The console may not
open on that host, and that is a valid control result. Record it, compare the
host with POSTURE / RESEARCH on an approved host, and use the five next paths in
`BEST-PRACTICES.md` section 13. Do not re-enable WSH, change `.hta`
associations, or call the engine directly just to get around the refusal. See
`BLOCKED-TESTS.md` section 10 for the evidence template.

## Files

| File | Purpose |
|---|---|
| `techniques.json` | Catalog of 24 publicly documented Windows execution primitives with ATT&CK IDs, expected telemetry, detection logic, hardening notes, a four-step event chain, command-line match patterns, ASR rule mappings, egress ports and remediation. Entries carry `platform`, `group` and `method`. |
| `worm.json` | Catalog of 6 Windows worm-like propagation primitives (`net.exe`, `sc.exe`, `schtasks.exe`, `WmiPrvSE.exe`, `psexesvc.exe`, `mstsc.exe`) under the `Worm-like Propagation` group. Same entry shape, read-only. |
| `gtfobins.json` | Catalog of 30 Linux/Unix GTFOBins entries under `Linux / Unix (GTFOBins)`. Presence is checked read-only through a readable WSL filesystem; no Linux binary is executed. |
| `hevd-catalog.json` | Eight `Source Review` entries under `Kernel Source Review`. Static HEVD study subjects, not host binaries, so gap is always `NOT EVALUATED`. |
| `hevd-scenarios.json` | Six beginner and six advanced source-review exercises with objectives, steps, evidence to record and defensive takeaways. |
| `HEVD-RESEARCH.md` | Full source-only lab guide: safety boundary, Code Audit bridge, kernel source rules, static WinDbg guide, tracks and evidence limits. |
| `hevd-source\` | Trimmed upstream HEVD source copy plus a local, standard-library-only Python venv and helper. Code Audit target only; never built or loaded. |
| `blocks.json` | Host-specific observed-block register. A block is a positive control result with the product, signal, scope and what it teaches - not a coverage pass. |
| `BLOCKED-TESTS.md` | Human-readable block register with the allow/deny matrix, evidence limits and safe-reproduction rules. |
| `BROWSER-EXTENSION-ABUSE.md` | Defensive threat model for malicious extension abuse: ATT&CK mapping, permission limits, review questions and block handling. No install or bypass detail. |
| `AITM-PHISHING-SESSION-HIJACK.md` | Corrected ATT&CK mapping for proxy phishing, conceptual interception architecture, passive browser indicators, identity-plane detection needs, redacted evidence template and FIDO2 / CAE / device-compliance hardening. Not exploit or detection proof. |
| `Test-NetTruderPosture.ps1` | Read-only control-plane inventory, three-catalog technique coverage scoring, WSL presence checks, optional marker probes with targeted 4688/Sysmon 1/4104 matching, JSON and Markdown reports. |
| `Invoke-Lab.cmd` | Runs the inventory and pauses at the end. |
| `probes\marker.vbs` | Inert WSH VBScript marker. Appends one line to `markers.log`. |
| `probes\marker.js` | Inert WSH JScript marker. |
| `probes\marker.hta` | Inert HTA marker with a visible window; closes itself. |
| `probes\marker.ps1` | Inert PowerShell marker. |

All paths resolve under the 1.1.0 data root `%LOCALAPPDATA%\NetTruder`; the lab
exports `NETTRUDER_LAB_DIR` to the report folder so the markers write
`markers.log` there. Legacy NetWatch state is copied forward only when the
destination file is missing; the old root is never deleted or moved.

## HEVD source study lab

`hevd-source\` is a source-only copy of a deliberately vulnerable driver. It is
included so Code Audit has realistic kernel C code to read and classify. NetTruder
never builds, signs, loads or installs it, sends no device request, and retains
no exploit or payload code. The `Exploit\`, `Builder\` and `Tools\` folders, the
test certificate and `.git` metadata were removed from the local copy.

The local venv helper uses only the Python standard library:

```
research\hevd-source\.venv\Scripts\python.exe tools\hevd_lab.py check
research\hevd-source\.venv\Scripts\python.exe tools\hevd_lab.py review
research\hevd-source\.venv\Scripts\python.exe tools\hevd_lab.py guide --level beginner
research\hevd-source\.venv\Scripts\python.exe tools\hevd_lab.py guide --level advanced
research\hevd-source\.venv\Scripts\python.exe tools\hevd_lab.py findings
```

In the console, **CODE AUDIT > HEVD SOURCE** runs the read-only scan, **HEVD
REVIEW** opens the layered explanation, and **SEND TO RESEARCH** copies masked
findings into module 14. The bridge carries the static evidence, reach,
preconditions, verification checklist and state label as well as the masked
snippet and fix. The bridge file is
`%LOCALAPPDATA%\NetTruder\hevd-source-findings.json`. A source finding is a review
lead with a documented fix, never proof of exploitability. See
`HEVD-RESEARCH.md` for the full boundary, added rules and study tracks.

## Run

Inventory only, the default:

```
research\Invoke-Lab.cmd
```

From PowerShell directly:

```
powershell -NoProfile -ExecutionPolicy Bypass -File .\research\Test-NetTruderPosture.ps1
```

Create a report in a custom folder:

```
powershell -NoProfile -ExecutionPolicy Bypass -File .\research\Test-NetTruderPosture.ps1 -OutDir <lab output folder>
```

The lab sets `NETTRUDER_LAB_DIR` to that output folder for the marker probes.

Run the inert marker probes as well:

```
powershell -NoProfile -ExecutionPolicy Bypass -File .\research\Test-NetTruderPosture.ps1 -RunMarkerProbes -Yes
```

The probes open normally, write one line each and exit. Watch Event Viewer or
your EDR while they run.

From the console, open **14 - RESEARCH** and press **RUN INVENTORY** for the
read-only pass, or **MARKER PROBES** for the confirmed probe run. The console
calls this script with `-OutDir %LOCALAPPDATA%\NetTruder\lab` and re-emits the
report as events, so both entry points produce the same JSON and Markdown files.
**GROUP** and **PLATFORM** filters narrow the table without re-running anything,
and **BLOCKS** opens the observed-block register.

## What the inventory checks

| Area | Source |
|---|---|
| Command line process auditing | `ProcessCreationIncludeCmdLine_Enabled` |
| Sysmon | `Sysmon` / `Sysmon64` service state |
| PowerShell script block logging | `EnableScriptBlockLogging` |
| PowerShell module logging | `EnableModuleLogging` |
| PowerShell transcription | `EnableTranscripting` |
| AMSI providers | `HKLM\SOFTWARE\Microsoft\AMSI\Providers` |
| AppLocker rules | `HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2\*` |
| WDAC policies | `System32\CodeIntegrity\CiPolicies\Active\*.cip` |
| Defender ASR rules | `Get-MpPreference` |
| Windows Script Host | `WSH\Settings\Enabled`, `Remote`, `TrustPolicy` |
| Event logs | PowerShell Operational, Sysmon Operational |
| Each catalog binary | presence, path, version, Authenticode status and signer |

No value is written. Missing registry values are reported as defaults, not
changed.

## The technique catalogs

Three catalogs load together: 24 Windows LOLBAS entries, 6 Windows worm-like
propagation entries and 30 Linux/Unix GTFOBins entries - 60 techniques in total.
Windows and Linux/Unix stay separate through the `platform` field, and entries
are grouped by `group` plus `method`.

`techniques.json` covers documented primitives such as:

- `mshta.exe`, `wscript.exe`, `cscript.exe`
- `rundll32.exe`, `regsvr32.exe`, `msiexec.exe`
- `installutil.exe`, `MSBuild.exe`, `regasm.exe`, `regsvcs.exe`
- `wmic.exe`, `cmstp.exe`, `odbcconf.exe`, `mmc.exe`, `xwizard.exe`
- `forfiles.exe`, `pcalua.exe`, `control.exe`, `verclsid.exe`
- `certutil.exe`, `bitsadmin.exe`, `hh.exe`, `mavinject.exe`
- `powershell.exe`, `cmd.exe`

`worm.json` adds the propagation-shaped hosts that matter on Windows:
`net.exe`, `sc.exe`, `schtasks.exe`, `WmiPrvSE.exe`, `psexesvc.exe` and
`mstsc.exe`, under `Worm-like Propagation`.

`gtfobins.json` adds 30 Linux/Unix entries under `Linux / Unix (GTFOBins)`.
Presence is checked through the WSL filesystem only. If WSL is absent or
unreadable, the entry is `NOT EVALUATED`; the lab never executes a Linux binary
and never reports an unreadable distro as clean.

Every entry has:

```json
{
  "id": "T1105",
  "name": "Certutil",
  "host": "certutil.exe",
  "platform": "windows",
  "group": "Download and Decode",
  "method": "Certificate utility",
  "abuse": "what the primitive can do",
  "telemetry": ["event IDs that should record it"],
  "detection": "high-signal child/parent chains and arguments",
  "hardening": ["policy or allow-listing options"],
  "needs": ["process", "content", "network"],
  "controls": ["cmdline", "sysmon", "amsi", "applocker", "wdac", "asr"],
  "tree": [
    { "s": "stage", "t": "T1105", "p": "certutil.exe", "a": "what happens",
      "d": "which log records it", "c": "detection sample, never a live payload" }
  ],
  "cmd": { "m": ["regex to match in a command line"], "w": "why the pattern matters" },
  "asr": [ { "g": "ASR rule GUID", "n": "ASR rule name" } ],
  "net": { "w": "what to watch on the wire", "ports": "80,443" },
  "fix": ["operational remediation, not applied by the lab"]
}
```

`tree` is the event chain the console renders when you click a row. `cmd` is the
command-line detection set, `asr` maps the host to documented Defender ASR rules,
`net` describes the egress rule, and `fix` is the operational remediation. Sites
in samples use `example.com` and `203.0.113.0/24` and are labelled detection
samples; they are not payloads or live infrastructure.

The catalog is a starting point. The canonical list is the LOLBAS project and
MITRE ATT&CK; add entries with a source link and an inert probe.

## Reading the coverage column

| Gap | Meaning |
|---|---|
| `OK` | A process or content signal that applies to the technique is enabled. |
| `CONTENT GAP` | Process creation is logged, but script content is not (no AMSI or script block logging). |
| `NETWORK GAP` | Process creation is logged, but there is no network telemetry (no Sysmon) for download-capable primitives. |
| `BLIND` | No process creation telemetry is enabled. Policy presence does not change this result. |
| `LINUX GAP` | A Linux/Unix entry is visible through a readable WSL filesystem, but this Windows host has no Linux telemetry for it. |
| `NOT EVALUATED` | Presence could not be checked (for example, WSL is absent or unreadable). This is never a clean result. |

The `Active controls` column lists applicable controls that are on, including
AppLocker, WDAC and ASR. Those three are execution or blocking policy, not
telemetry. A host can have a WDAC policy file and still record nothing, so the
gap column never treats policy presence as detection.

`OK` is not a guarantee. A signal can be enabled and still be unread, under-sized
or not forwarded. The marker probes exist to test that end-to-end path.

A row can move from `BLIND` to `OK` between runs because the label is recalculated
from the current host readings. For Windows rows this happens when the
command-line auditing policy reads on or a Sysmon service is running; a probe run
can also promote the row when a readable 4688 or Sysmon 1 log matches the inert
marker processes. The inventory itself never enables auditing, installs Sysmon or
executes a LOLBAS technique. Network-dependent rows stay `NETWORK GAP` while
Sysmon is absent, and `Source Review` rows stay `NOT EVALUATED`.

Each row also carries a `basis` string, for example:

```
process[4688 cmdline=off sysmon=off] content[4104=off amsi=on] network[sysmon-flow=off]
```

That is the raw reading behind the label, so a reviewer can see why the row says
`BLIND` instead of taking it on faith. After a probe run the string gains
`measured[4688=n/a sysmon=n/a 4104=off]`. `n/a` means the log was unreadable and
the label stays configuration-derived; `off` means the probe measured the signal
and it recorded nothing.

## Reading a row

Click any row to open the detail panel. It is the part that explains the gap
instead of only labelling it.

- **PROCESS TREE** - a four-step event chain: stage, ATT&CK technique, the
  process path, what happens at that step, which log records it, and the
  detection sample. The samples are inert text, not payloads.
- **DETECT** - command-line patterns worth alerting on, with a short note on why
  each pattern matters.
- **ATTACK SURFACE REDUCTION** - the documented Defender ASR rule GUIDs that map
  to this host. The panel shows the `Add-MpPreference` command for reference and
  never runs it.
- **NETWORK MONITORING** - the egress ports and what to watch on the wire. This
  is the same rule set the IDS uses, named `EGRESS_<PROC>`.
- **REMEDIATE** - operational fixes: policy, allow-listing, log forwarding and
  monitoring. None of them are applied by the lab.
- **OBSERVED BLOCKS** - if this host has a recorded block for the technique, the
  detail panel shows the block card. It is evidence that a control worked once,
  not a coverage pass.

Every **CONTROL PLANE** row and every **FINDINGS** card is clickable. Both open
the same remediation modal: the observed state, why it matters, numbered steps,
the enable/harden script, the native UI, and copy / elevated-shell actions. The
elevated-shell action copies a script for review and paste; it never auto-runs
it. The modal never offers to turn a security control **off**. Controls that are
safer when off are labelled `safer when off` and open review steps instead.
NetTruder never disables UAC and never auto-elevates.

The process-tree and detect columns scroll independently and wrap long paths and
command lines, so no text is clipped. Alerts also appear as dismissible toasts
with REMEDY / PROCESS / DISMISS actions.

A row is a prompt for a conversation about the host, not a verdict about the
binary. The binary being signed and present is expected; the question is whether
this host records what it does.

## Marker probes and telemetry validation

Run the four probes, then check each source:

| Probe | Host | Expected local evidence |
|---|---|---|
| `wsh-vbs` | `wscript.exe` | 4688 / Sysmon 1 with `wscript.exe` and the script path; AMSI content event if the AV product integrates AMSI. |
| `wsh-js` | `cscript.exe` | 4688 / Sysmon 1 with `cscript.exe` and `//nologo`; AMSI content event. |
| `hta` | `mshta.exe` | 4688 / Sysmon 1 with `mshta.exe` and the `.hta` path; AMSI content event; window creation if you record it. |
| `powershell` | `powershell.exe` | 4688 / Sysmon 1; 4104 script block with the marker script; transcription file if enabled. |

If a probe writes its marker but no event appears, you have found a real coverage
gap. That is the useful result. It is not a 0-day; it is a logging or forwarding
problem you can fix.

### Targeted proof, not broad counts

The probe window compares event counts before and after the four marker scripts
run, but the verdict does not use the broad delta. Broad counts move for reasons
that have nothing to do with the probes, including this tool's own PowerShell
activity and unrelated AMSI-triggered 4104 events.

Instead:

- **4688 proof** counts only Security events whose new-process image is one of the
  four probe hosts (`wscript.exe`, `cscript.exe`, `mshta.exe`,
  `powershell.exe`).
- **Sysmon 1 proof** is the fallback when the Security log is unavailable. It
  parses the named `Image` XML field and counts only the four probe hosts.
- **4104 proof** counts only PowerShell events whose text contains the marker
  token `NWPROBE-4104-CONTENT-MARKER` from `probes\marker.ps1`.

So `matched=0` with an unreadable log means "not measured", while `matched=0` on a
readable log means "measured and absent". The JSON report keeps the broad
`before`/`after`/`delta` numbers for context and adds `matched` for the verdict.

The proof card states the real error and the real session context instead of a
blanket "requires elevation". The elevation card separates token elevation from
Administrators group membership:

| Field | Meaning |
|---|---|
| `tokenElevated` | the process token is elevated |
| `adminGroup` | the account is in Administrators, including the deny-only SID in a UAC-filtered token |
| `integrity` / `elevationType` | token integrity (`medium`, `high`, ...) and UAC type (`limited`, `full`, `default`) |
| `securityReadable` | the direct Security channel read succeeded |
| `privilegePresent` / `privilegeEnabled` | `SeSecurityPrivilege` is in the token and enabled |
| `privilegeAttemptResult` | `enabled`, `not-assigned:1300` (privilege is not in this token) or `failed:<code>` |

The card also shows the Security error, Sysmon error and `auditpol` result.
"No events were found that match the specified selection criteria" is treated as
a readable log with zero matches, not as an unreadable log. The authoritative
readiness check is a direct `Get-WinEvent -LogName Security -MaxEvents 1`. A
filtered 4688 query that returns zero rows is not treated as proof when that
direct channel read failed; the channel read is authoritative.

On an administrator account with a filtered token the usual result is
`adminGroup=yes`, `tokenElevated=no`, `integrity=medium`, Security read denied,
and `SeSecurityPrivilege` not assigned. That is UAC working as designed, not a
NetTruder bug. Right-click `Launch-Elevated.cmd` and choose Run as administrator,
then re-run the inventory. NetTruder never disables UAC and never auto-elevates.

On a standard user account the Security log is normally unreadable, so 4688 proof
comes back unavailable with the actual error and the label stays
configuration-derived. The content side does not need elevation. `PSLOG
enabled=True` in the summary means the PowerShell **event channel** is enabled;
it does not mean the script-block policy is on. Those are separate control rows.

## Observed blocks

`blocks.json` is host-specific evidence, separate from the catalogs and from the
coverage score. Each record carries the technique, host, product, vector, command
shape, result, signal, scope, what it teaches and what to detect. A block is a
positive control result: the control did its job.

A block never upgrades a coverage gap to `OK`, because it says nothing about the
variants that were not attempted. The lab records blocks, comments on them with
`observed-block`, and does not retry with a bypass. `BLOCKED-TESTS.md` holds the
long-form register, the allow/deny matrix and the evidence limits.

## Network watch for admin tools

The IDS rule set includes 19 process-keyed egress rules for binaries that should
not normally make outbound connections: `certutil`, `bitsadmin`, `mshta`,
`regsvr32`, `wscript`, `cscript`, `rundll32`, `msiexec`, `installutil`,
`msbuild`, `forfiles`, `pcalua`, `cmstp`, `odbcconf`, `verclsid`, `xwizard`,
`hh`, `control` and `wmic`.

- The alert is named `EGRESS_<PROC>`, for example `EGRESS_CERTUTIL`.
- Rules are keyed by process name with the extension stripped, and matched
  against an outbound port spec such as `80,443,8080,8443`.
- When a rule fires, the engine reads the live command line with
  `Get-CimInstance Win32_Process` and appends it to the alert, so you see
  `certutil -urlcache -split -f ...` rather than only a flow.
- Alerts use a 600 s cooldown per `(rule, address, process)`.

`bitsadmin` is the documented exception: it hands the transfer to BITS, which runs
inside `svchost.exe`. The outbound flow will usually carry the `svchost` name, not
`bitsadmin`. Detect it from the `bitsadmin` command line and the
`Microsoft-Windows-Bits-Client/Operational` log; treat the egress rule as a
backstop, not the primary signal.

The console and the lab only display and monitor. They never add a firewall rule,
change a policy value or touch Defender. If you test with a real admin tool, point
it at a host you control and expect endpoint AV to block it - a block is a valid
defensive result, not a failure of the test.

## Looking for gaps instead of 0-days

Cataloging known primitives will not produce a 0-day. What it can produce is a
short list of things your host would not notice. A repeatable loop:

1. **Pick one primitive.** Start with `mshta`, `wscript` or `rundll32`.
2. **Write the expected chain.** For example `winword.exe -> mshta.exe ->
   powershell.exe`, or `explorer.exe -> wscript.exe -> cmd.exe`.
3. **State the expected evidence.** Process creation with command line, script
   content, network connection, child process, file write.
4. **Run the inert probe or a harmless equivalent.** `mshta about:blank` is
   enough to test process visibility; the marker scripts test content and
   ancestry.
5. **Check each source independently.** Event Viewer, Sysmon, EDR, SIEM. Do not
   assume forwarding works because the local log has the event.
6. **Record the gap.** Which source was missing, why, and what would have caught
   it.
7. **Fix the source, then re-run the same probe.** A technique is only covered
   when the fix is validated, not when the policy is enabled.
8. **Add the result to `techniques.json`.** Include the parent/child chain,
   arguments and the detection that fired.

New malware techniques usually come from reverse engineering a sample or from
structured adversary emulation, not from re-running the same signed binaries.
If you go that route, keep it inside a lab VM, use samples you are authorised to
handle, and write the detection before you write the tooling.

## Event map

| Event | Source | Use |
|---|---|---|
| 4688 | Security | Process creation; needs command line auditing for arguments. |
| 4104 | PowerShell Operational | Script block content. |
| 4103 | PowerShell Operational | Module and pipeline execution. |
| 400 / 403 | PowerShell Operational | Session start and stop. |
| 1 | Sysmon | Process creation with hashes and parent. |
| 3 / 22 | Sysmon | Network connection and DNS query. |
| 7 | Sysmon | Image load; catches DLL side-loading. |
| 8 | Sysmon | Create remote thread; injection signal. |
| 11 | Sysmon | File create. |
| 19 / 20 / 21 | Sysmon | WMI filter, consumer and activity. |
| 1116 / 1117 | Defender Operational | Malware and action taken. |

## Hardening checklist

Recommendations only. Nothing here is applied by the lab.

- Enable **Audit Process Creation** and the **Include command line** policy.
- Deploy **Sysmon** with a maintained configuration (SwiftOnSecurity or Olaf
  Hartong are common starting points) and forward the operational log.
- Enable **PowerShell script block logging**, **module logging** and
  **transcription** for high-risk users at minimum.
- Start **Defender ASR** in audit mode, then move high-value rules to block:
  Office child processes, script downloads, executable content from email,
  credential stealing from LSASS.
- Use **WDAC** or **AppLocker** to allow-list execution paths. Block
  `mshta.exe`, `wscript.exe`, `cscript.exe`, `regsvr32.exe`, `rundll32.exe` and
  `mavinject.exe` only after confirming no business application depends on them.
- If VBScript and JScript are not needed, set the **Windows Script Host
  Enabled** policy to `0` and remove `.hta` file associations for users who do
  not need them.
- Disable **remote WSH** unless it is required.
- Apply egress filtering so signed system binaries cannot freely reach the
  internet.
- Keep Defender cloud protection, tamper protection and sample submission on
  where policy allows.

Every one of these changes the host. Test on a pilot ring, document the rollback
and never disable a security control to make a tool run.

## Version and validation notes

The catalogs are labelled by version 1.1.0: `techniques.json` has 24 Windows
entries, `worm.json` 6 Windows worm-like entries, `gtfobins.json` 30 Linux/Unix
entries, `blocks.json` is the observed block register and `BLOCKED-TESTS.md` is
its long-form log. `platform`, `group` and `method` keep Windows separate from
Linux/Unix; a recorded block is positive control evidence and never upgrades a
coverage gap to `OK`.

Supporting smoke results: status `migrated:41`, `adminGroup:true`,
`tokenElevated:false`; 52 engine/UI event kinds handled and 0 unhandled; JS
parse OK; CSS braces balanced; all sources ASCII-only. Validation artifacts are
`nw-jsparse.js` and the pre-rename backup `netwatch-pre-nettruder.zip`, both
kept in a local test harness folder outside this repository.

## Limitations

- The catalogs are not exhaustive and do not include every LOLBAS, worm-like or
  GTFOBins entry.
- The script cannot see EDR telemetry, SIEM forwarding or network sensors. It
  reports local Windows sources only. A third-party EDR can still record what
  this report marks `BLIND`, but the lab does not claim to see it.
- `AppLocker` and `WDAC` presence is not proof that these specific binaries are
  blocked. Read the effective policy before claiming coverage.
- `BLIND` means no local source was detected. It does not prove a technique
  would succeed.
- `LINUX GAP` and `NOT EVALUATED` mean the Windows host cannot see the Linux
  side. WSL presence checks are read-only and no Linux binary is executed, so
  the lab cannot say whether a Linux detection rule fires.
- Process proof (`4688`) needs a readable Security log, which a standard user
  normally does not have. Without elevation it is reported as `n/a` with the
  actual error, not `off`. Sysmon 1 is used as a fallback when it is installed.
- Signature status is informational. A valid Microsoft signature is expected for
  these binaries; it is not a trust decision.
- Marker probes are intentionally simple. They test the visibility of the host
  process and script content, not every argument pattern.
- The egress rules are a heuristic keyed on process name. A renamed binary, a
  copy invoked through another host, or a transfer done inside `svchost.exe`
  (BITS) will not match the expected name. Pair them with command-line auditing
  and proxy logs.
- A recorded block is one observation on one host. It does not cover variants,
  other builds, other policy states or other endpoints, and no bypass is
  attempted to strengthen it.

## References

- LOLBAS Project: https://lolbas-project.github.io/
- GTFOBins: https://gtfobins.github.io/
- MITRE ATT&CK: https://attack.mitre.org/
- Microsoft Defender ASR rules: https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-reference
- Sysmon: https://learn.microsoft.com/sysinternals/downloads/sysmon
- SwiftOnSecurity Sysmon config: https://github.com/SwiftOnSecurity/sysmon-config
- Olaf Hartong Sysmon config: https://github.com/olafhartong/sysmon-modular
- PowerShell logging: https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_logging_windows
