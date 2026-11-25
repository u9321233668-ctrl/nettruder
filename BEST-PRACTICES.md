# NetTruder - Best Cybersecurity Practices

Version 1.1.0. This guide describes the security practices NetTruder is built on
and the practices an operator should follow when using it. It is a defensive
document: it explains how to reduce risk and interpret evidence honestly. It
contains no payloads, no exploitation steps, no control bypass and no advice to
weaken a security product.

NetTruder is a defensive network operations console for Windows. It discovers
hosts, audits the local machine, watches the connection table, can temporarily
block a remote address, and provides read-only analysis views. It is not an
attack framework: there is no C2, listener, payload, lateral movement,
credential access or persistence anywhere in the folder.

---

## Read this first

- **Read-only by default.** Scanning, the posture probe, the IDS and all
  analysis views never change the system.
- **It never weakens security.** It does not touch Defender, the firewall
  profile, Windows Update, services, drivers, scheduled tasks or existing rules.
  There is no payload and no machine-wide policy change. Per-process
  `-ExecutionPolicy Bypass` and hidden launchers are disclosed in `README.md`;
  no AV exclusion is added and no control is disabled.
- **State changes need consent.** Blocking, process termination and data purge
  each require an explicit, logged, opt-in action.
- **Actions are bounded and reversible.** Blocks expire; code edits are backed
  up; purge is limited to NetTruder-owned data.
- **Evidence is stated honestly.** `BLIND`, `CONTENT GAP`, `NETWORK GAP`,
  `LINUX GAP` and `NOT EVALUATED` are real limits, not clean results.
- **A block is a positive defensive result.** Never re-run or try to bypass a
  command an endpoint control refused.

If any of that is not what you want, do not run the IPS module.

---

## 1. Principles NetTruder follows

These are the design rules the tool enforces in code. They are the baseline for
everything an operator does with it.

| Principle | What it means in NetTruder |
|---|---|
| Least privilege | Standard user for everything except IPS block/unblock. Admin only when needed. |
| Read-only default | Observation and analysis first; change only on explicit consent. |
| Do no harm to controls | Defender, firewall, VBS, HVCI, code integrity, Update and logs stay as they are. |
| Bounded action | `/22` scan cap, 30-block cap, 1-240 minute TTL, 90-process view, 30-second live sample. |
| Reversibility | `RELEASE ALL` removes NetTruder rules; code edits are backed up; legacy state is copied, never moved. |
| Auditability | Every security-relevant action is appended to an NDJSON audit log. |
| Honest evidence | A gap label describes missing visibility, not a clean host or a compromised one. |
| Honest launch chain | The hidden per-process worker and WSH shim are documented. A blocked test is a control success; no exclusion, policy change or re-enabling is attempted. |
| Means, not dependency | The healthiest outcome for a security tool is being unnecessary on a well-configured machine. A control that stops NetTruder **because it removes the class of behaviour the tool depends on** is a success; a rule aimed at the tool itself, leaving the technique available, is lost visibility. |
| Local-only | No remote agent, no inbound listener, no data sent anywhere. |
| Source-only review | Code, driver source and crash-dump commands are read or copied, never executed by NetTruder. |

---

## 2. Before you run: operator checklist

1. **Confirm authorisation.** Sweep, web risk and packet-mon tasks only on
   networks you own or are explicitly authorised to test. NetTruder drops
   non-private targets unless `-AllowPublic` is passed, and the UI never sets
   that flag; an explicit opt-in is still your responsibility.
2. **Use the right launcher.** `Launch.cmd` for standard work;
   `Launch-Elevated.cmd` only when you intend to use IPS. The badge reads `USER`
   or `ADMIN` so you always know the mode.
3. **Run from a trusted, complete folder.** Keep `NetTruder.hta`,
   `engine\NetTruder.ps1`, `engine\shim.vbs` and the `research\` catalogs
   together. Treat unexpected edits as a change to review, not a given.
4. **Leave endpoint protection on.** If the launch chain is blocked, do not
   disable, whitelist or exclude anything. The shim exists because a normal
   WSH parent chain is permitted; if that is blocked too, the console reports
   it and stops. Section 13 gives the five valid next paths.
5. **Protect the data root.** `%LOCALAPPDATA%\NetTruder\runs\` can contain raw
   source for an edit session and other sensitive evidence. Keep it local and
   controlled; see section 7.
6. **Know the baseline.** Run POSTURE and a coverage inventory before making
   changes so you have something to compare against.

---

## 3. Safe practice by module

| Module | Practice |
|---|---|
| 01 SWEEP | Only authorised ranges. Prefer a single known IP first. A connect scan is visible by design; do not expect stealth. |
| 02 PROCESS FLOW | Read-only. Use findings as triage context, never as proof of compromise. |
| 03 WEB RISK | Loopback/private by default; tick **ALLOW PUBLIC HOST** only with authorisation. GET/OPTIONS only; ZAP stays a copyable recipe. The extension report import is a manual, in-memory paste; it reads no profile, file or network and rejects secret-like text. |
| 04 CODE AUDIT | Read-only default. Keep **WRITE MODE OFF**; enable it only with intent, review the backup, and treat raw run files as sensitive. |
| 05 THREATS | Read-only. Open Task Manager and the firewall console for follow-up; NetTruder changes nothing here. |
| 06 TRIAGE | Decisions stay local; never expect the upstream alert system to be changed. |
| 07 EXPOSURE | Record blocks as evidence. Do not re-run a blocked action or try to get around it. |
| 08 DATA | Review the classification first. Purge previews; it deletes only with `-Yes -AckRisk` and only NetTruder-owned data. |
| 09 IDS / IPS | Arm the IDS for detection. Use BLOCK only for a real containment need; it is TTL-bound. Leave **AUTO-BLOCK HIGH** off unless you accept its behaviour. |
| 10 TERMINAL | Treat it as a normal shell with your account's full power. Every command is audited. It is not a sandbox. |
| 11 POSTURE | Report, do not remediate. Open the native Windows tool for any change and apply it through your change process. |
| 12 PROCESSES | Read-only until KILL. KILL is containment for a suspicious user-mode process, with confirmation and audit. |
| 13 AUDIT | Review the log regularly. It is the record of what NetTruder actually did. |
| 14 RESEARCH | Read the `BASIS` line, not just the label. Marker probes are inert and opt-in; run them only with consent. |
| 15 NETWORK | Read-only. Browser history is an explicit per-run opt-in and read-only. Keep browser and background flows separate. |
| 16 PS LOGGING | Read-only. 4104 attribution and control-block events are displayed with event-sourced WHO / WHAT / WHERE. NetTruder never enables, disables or clears a log, and never re-runs a blocked command. Use the Group Policy path shown to remediate elsewhere. |

---

## 4. Identity, privilege and elevation

- The `USER` / `ADMIN` badge is authoritative for the console's own mode.
- `adminGroup`, `tokenElevated` and log readability are three different facts.
  Membership in Administrators does not mean the current token is elevated;
  UAC commonly leaves `tokenElevated=no`, `integrity=medium`. Relaunch
  `Launch-Elevated.cmd` rather than disabling UAC.
- Every remediation or enable script is **copy-only**. NetTruder opens an
  elevated shell for you to review and paste; it never runs the script for you.
- Native-UI buttons only open the relevant Windows tool (`wf.msc`,
  `secpol.msc`, Security settings, and so on). The change is still yours.

---

## 5. Interpreting evidence honestly

A core practice is to read a label together with its basis.

| Label | Honest meaning |
|---|---|
| `OK` | The process signal is present and the technique's telemetry needs are satisfied or measured. It is not proof that abuse occurred. |
| `BLIND` | No native process-creation telemetry to match the technique against. It is not a claim that an attacker is present; third-party EDR or a proxy may still record activity. |
| `CONTENT GAP` / `NETWORK GAP` | Script-block content or egress visibility is missing; the technique may still be partly visible. |
| `LINUX GAP` / `NOT EVALUATED` | The Windows host cannot see the Linux/Unix side, or the source subject is not a host binary (for example, the HEVD `Source Review` entries). Not a clean result. |
| `STATIC LEAD / NOT RUNTIME VERIFIED` | A code or kernel-source finding is a review lead with a checklist, not proof of exploitability. |

Other evidence rules worth keeping:

- A silent web target is `NT-WEB-000` at grade `n/a`, never a set of clean
  headers. Missing headers on a target that did not answer are `NOT EVALUATED`.
- Marker proof uses targeted matches, not broad event counts. `matched=0` on an
  unreadable log means "not measured"; on a readable log it means "measured and
  absent".
- Beacon, fan-out and flow findings are triage signals. Browser fan-out is
  expected; `LATERAL_FANOUT` on sensitive ports is the actionable shape.
- A captured script-block line is defensive evidence, not a verdict about
  intent.

**Decision discipline — how not to make a blind call:**

- Separate three things before you act: what was observed, what it suggests and
  what you decide to do. Report the first, label the second, and only make the
  third when the basis is stated.
- Never promote `BLIND`, `NOT EVALUATED`, `CONTENT GAP`, a filtered token or a
  refusal into a clean result. They mean "not seen here", not "not there", and
  not "compromised".
- Do not treat a configuration reading as a measured event, or a single event
  as a configuration fact. POSTURE reads policy; RESEARCH tries to prove that
  policy produced telemetry. When they disagree, say so and investigate scope.
- Prefer two independent signals before an irreversible action. A finding plus
  a corroborating event is stronger than either alone; one triage signal is a
  reason to look, not to block or terminate.
- State the source and time of every claim. "The policy reads on" and "a 4104
  event was observed" are different sentences with different confidence.
- Ask what would falsify the conclusion. If nothing could, it is a belief, not
  evidence. Record the alternative explanation you ruled out.
- Do not let silence become a verdict. An unreadable log, a blocked probe or an
  unavailable host produces absence of evidence, not evidence of absence.
- Escalate instead of guessing. If the basis is missing, write `NOT EVALUATED`
  and go and get the missing signal.

---

## 6. Change control and remediation

- NetTruder does not remediate automatically. It shows state, why it matters,
  numbered steps, a copyable script and the native UI.
- Apply hardening through your normal change process, then re-run POSTURE and
  the coverage inventory to verify the change took effect.
- Code Audit **WRITE MODE** resets on every audit and on restart. Raw content
  needs a second confirmation, and SAVE needs a third; the original is backed
  up under `%LOCALAPPDATA%\NetTruder\state\code-edits\` before writing. No fix
  is applied automatically.
- Before a purge, read the preview. Deletion requires both `-Yes` and
  `-AckRisk` and is limited to NetTruder-owned runs, snapshots and optionally
  old audit files. Personal files are never in scope.
- To remove all traces: `RELEASE ALL`, then delete `%LOCALAPPDATA%\NetTruder`.

A sound remediation follows the same order every time:

1. **Preserve the evidence first.** Save the report, run id, event stream and
   audit entries with a hash before changing anything. Remediation destroys the
   state you just measured.
2. **Name the exact gap and the exact target.** "Enable script block logging on
   host X through GPO Y" is actionable; "improve security" is not.
3. **Check the blast radius.** Inventory dependencies, affected users and legacy
   workflows. Section 15 shows why a control that looks purely beneficial can
   also stop a legitimate tool.
4. **Test in audit or monitor mode first.** AppLocker, WDAC and Defender ASR
   should observe before they enforce. Review the events, then move to block
   mode. That applies to preventive policy; the IPS is explicit, temporary
   containment, not a preventive policy change.
5. **Use the native management path.** Group Policy, Intune, `secpol.msc` or the
   product console. NetTruder copies steps to the clipboard; reading, pasting
   and running them are yours. Never paste an unreviewed string.
6. **Make it reversible.** Record the previous value, the owner, the change id
   and the rollback. Temporary blocks keep an expiry. Prefer a narrow, logged
   exception over a global change; never disable a control to make a tool work.
7. **Verify with a different signal.** Re-run POSTURE for state and RESEARCH for
   telemetry. If the policy reads on but no event appears, the change is not
   verified.
8. **Close the loop.** Attach before/after evidence to the change record, note
   what stayed `BLIND`, and review after the next policy cycle.

What not to do:

- Do not remediate from a single finding, a severity colour or a score. Those
  rank review order, not certainty.
- Do not equate "the block fired" with "the remediation worked". A block is a
  control result; the underlying weakness may still be present.
- Do not weaken a control to remove a finding, add a global AV exclusion, or
  re-enable a disabled script host just to keep a tool running.
- Do not run a copyable script without reading every line, including paths,
  account scope and any `reg add` or `Add-MpPreference` values.
- Do not treat one tool's output as authoritative for another product's state.
  Correlate with EDR, SIEM and the native console.

---

## 7. Data protection and privacy

- Findings mask secret values; the report shows the pattern and location,
  not the republished secret.
- The event stream is ASCII-escaped. `%LOCALAPPDATA%\NetTruder\runs\` may still
  hold raw source for an edit session, so handle those files as sensitive.
- Browser history is opt-in per run and read-only. No profile file is copied,
  changed or deleted, and no DNS setting is modified. History adds a full URL
  and title only for a host that matches a socket.
- Crash dumps can contain user paths, tokens or other sensitive data. Work on
  a copy, record its hash and source host, and redact before sharing.
- Keep retention short: use DATA CHECK and the purge preview, and clear old
  NetTruder data when it is no longer needed.

---

## 8. Hardening posture to aim for

NetTruder reports the following; it does not change them. Set them through
Group Policy, your management tooling or the native Windows UI.

| Area | Target state | Why it matters |
|---|---|---|
| Command-line auditing (4688) | Include command line | Gives RESEARCH a process signal to match techniques against. |
| Sysmon | Installed with a reviewed config | Adds process, network and image telemetry with named fields. |
| Script Block Logging (4104) | Enabled via Group Policy | Records script content for the coverage lab and PS LOGGING view. |
| Module logging / transcription | Enabled where appropriate | Adds complementary PowerShell visibility. |
| AMSI, AppLocker / WDAC, ASR | Enabled per policy | Prevents or blocks malicious execution and script abuse. |
| Defender real-time and signatures | On and current | Two AV products may be registered; report raw state and interpret it. |
| Firewall profiles | On | NetTruder creates only its own expiring IPS rules. |
| SMBv1 | Disabled | Removes a legacy lateral-movement path. |
| RDP inbound | Restricted / disabled unless needed | Reduces exposed management surface. |
| BitLocker and Windows Update | On / current | Protects data at rest and closes known vulnerabilities. |
| Windows Script Host | Disabled where `.vbs`/`.js`/`.hta` are not needed | Removes a common script-execution path; inventory dependencies first. |
| `mshta.exe` / `.hta` | Blocked with AppLocker or WDAC where not needed | Disabling WSH alone does **not** stop HTA scripts. |

Controls that are safer when off are labelled that way in the UI and open
review steps; NetTruder never turns a control off for you. For the scope and
limits of WSH/HTA policy, including the fact that NetTruder's own console
depends on that chain, see section 15.

---

## 9. Mapping to established frameworks

NetTruder supports security outcomes; it does not claim compliance with any
framework. A light mapping helps place the tool in a programme.

| Framework outcome | How NetTruder supports it |
|---|---|
| NIST CSF - Identify | SWEEP, NETWORK, AUDIT and the research catalogs inventory hosts, flows, owners and coverage gaps. |
| NIST CSF - Protect | POSTURE reporting, hardening guidance, read-only defaults and least privilege support safe configuration. |
| NIST CSF - Detect | IDS alerts, web-risk findings, code-audit findings and research coverage gaps surface issues. |
| NIST CSF - Respond | TTL-bound IPS containment, process KILL, triage decisions and exposure records support response. |
| NIST CSF - Recover | Reversible blocks, backed-up edits and clear audit records help restore a known state. |
| CIS Controls - Inventory | Asset and software inventories via sweep, process and network views. |
| CIS Controls - Protective controls | Guidance for command-line auditing, script logging, ASR, application control and firewall posture. |
| CIS Controls - Logging and monitoring | NDJSON audit log, IDS, PS LOGGING readout and evidence-based findings. |
| CIS Controls - Incident response | Local triage, containment actions and the observed-block register. |

Treat this as orientation, not an attestation.

---

## 10. A sensible operating cadence

1. **Baseline:** POSTURE, then RESEARCH coverage inventory. Record the report.
2. **Discover:** SWEEP authorised ranges; review PROCESS FLOW and NETWORK.
3. **Watch:** ARM IDS during a change window or incident watch; review alerts
   with REMEDY rather than reflexively blocking.
4. **Assess:** PASSIVE WEB RISK on your own services; CODE AUDIT on local
   source; KERNEL REVIEW and the static KERNEL DBG guide for source-only
   kernel study.
5. **Triage:** Import exported alerts and route them in TRIAGE; keep decisions
   local.
6. **Verify:** Re-run POSTURE and the coverage inventory after any hardening
   change; review the AUDIT log.
7. **Clean up:** RELEASE ALL blocks, review retention, and remove stale
   NetTruder data you no longer need.

---

## 11. Practices to avoid

- Disabling or whitelisting Defender, the firewall, Windows Update, VBS, HVCI,
  code integrity, services, drivers or scheduled tasks to make a tool run.
- Re-running a blocked command or attempting a bypass, obfuscation or evasion.
- Treating `BLIND`, `NOT EVALUATED` or a web `n/a` as a clean result.
- Treating a finding, alert or static lead as proof of compromise or
  exploitability without corroboration.
- Deleting personal files, Downloads, Documents or browser profiles. NetTruder
  never does this; neither should a cleanup script you run alongside it.
- Building, signing, installing or loading the HEVD study driver, sending an
  IOCTL, or enabling live kernel debugging for a source-only review.
- Leaving elevated IPS blocks in place; TTL and `RELEASE ALL` exist for a
  reason.
- Running the terminal as a sandbox. It has the full power of the launching
  account.

---

## 12. Quick checklist

**Before:** authorised scope; correct launcher; endpoint controls on; baseline
captured; data root understood.

**During:** read-only first; explicit consent for any change; leave security
controls on; interpret labels with their basis; do not re-run blocked actions.

**After:** verify the change; review the audit log; release temporary blocks;
retain only what you need; redact and protect shared evidence.

---

## 13. When the console is blocked - five valid next paths

A hardened host may refuse `Launch.cmd` before NetTruder starts. That can
happen when Windows Script Host is disabled, `.hta` is blocked or unassociated,
or the `mshta -> wscript -> PowerShell` chain is refused. This is a control
success and a research result, not a broken program. The UI is unavailable on
that host; the project is not.

The ideal end state is that this host no longer needs NetTruder at all. The tool
teaches the questions — what policy says, what telemetry proves, what a refusal
looks like — so the operator can answer them natively and finish without it. A
block is a *control* success, but not a *measurement* success: record what could
not be observed as `NOT EVALUATED` and get that evidence from native logs, EDR
or an approved host where the chain is permitted. Never let "the control worked"
become "we know everything is fine".

A control counts only when you would want it independently of the tool. Turning
off WSH or denying `mshta` by policy is hardening; writing a rule that blocks
NetTruder while leaving script hosts available is not. The second case removes
the witness, not the weakness, and should be recorded as a coverage gap.

Do not change `WSH Settings\Enabled`, `DisableWindowsScriptHost`, AppLocker,
WDAC, Defender ASR, `.hta` associations, endpoint exclusions or firewall
profiles just to make the window open. Do not switch to a direct PowerShell
call if the reason for stopping was a blocked script-host policy. A narrow,
logged, time-limited exception for one approved admin account is a change
decision, not a bypass; a global control change is not.

### Path 1 - Keep an approved lab or admin-workstation console

Run the full console on one authorised lab or admin workstation where the
launch chain is already permitted. It does not need to run on every hardened
endpoint. Keep the folder complete (`NetTruder.hta`, `engine\NetTruder.ps1`,
`engine\shim.vbs`, `research\` catalogs), use `Launch.cmd` for normal work and
`Launch-Elevated.cmd` only when IPS is intended. The value is the repeatable
inventory and evidence this one host produces.

### Path 2 - Treat the block as an acceptance test

When a control stops the launch, the acceptance criterion has been met. Record:

- host, date/time, account and whether the session was elevated;
- exact launcher and parent/child pair (`mshta`, `wscript`, `powershell`);
- control or product, product event id and log source if available;
- message or code, for example `0x800700E1`, `ERROR_VIRUS_INFECTED`, or
  `Engine launch blocked: ... [code -2147024671]`;
- telemetry that did record the attempt: 4688, Sysmon 1, 4104, EDR or SIEM;
- explicit statement that no retry, alternate launcher, whitelist or exclusion
  was attempted.

Then stop. A refusal is the result. See `research/BLOCKED-TESTS.md` section 10
for the evidence template.

### Path 3 - Compare hosts with POSTURE and RESEARCH

On hosts where the console is allowed, run POSTURE and the RESEARCH inventory,
then compare the readings with the blocked host. The useful comparison is:
WSH state, AppLocker/WDAC presence, Defender ASR, 4688 with command line,
PowerShell 4104, Sysmon, AMSI, and EDR/SIEM forwarding. A block never upgrades
`BLIND` or `NOT EVALUATED` to `OK`; it only says one vector was refused once.
Hardening reduces what can run; detection and logging still answer what was
attempted, who did it and whether the control drifted.

### Path 4 - Document the blocked-console case

Keep a short note beside the block register: WSH disabled, `mshta` blocked, or
shim blocked; what launched; what refused it; what was recorded; and what was
not attempted. `research/BLOCKED-TESTS.md` section 10 is the place for this.
This turns "the tool would not open" into a repeatable control-validation
case rather than a limitation.

### Path 5 - Keep the evidence, not just the UI

The durable output is the JSON and Markdown reports, NDJSON event streams,
audit entries and the block register, not the window itself. Save the report
folder with its run id, note the host and time, and record hashes of files you
share. Redact paths, accounts and script text before moving evidence off the
host. Retain only what the change record needs, and review it after any policy
change. The launcher is one way to produce evidence; the evidence is the
programme output.

---

## 14. Optional browser extension

`browser-extension\` is an optional read-only Chromium/Edge MV3 companion.
**NetTruder Site Posture** reports page-level defensive state: HTTPS, redacted
mixed-content references, form and password-field context, visible cookie
names, script counts and optional security headers.

- It uses an active-tab model. No site access is granted at install.
- Header read is opt-in per origin and can be revoked with the same button.
- It reads no browser history, no form values and no cookie values.
- Every finding shows a state and a remediation; `NOT EVALUATED` is never a
  clean result.
- It makes no request changes, runs no test payload and sends no data anywhere.
- If enterprise policy blocks unpacked extensions, record the block and stop.
  Do not disable policy or developer-mode controls just to load it.

Version 1.4.0 adds passive login indicators: an exact trusted IdP host list held
only in browser session storage, lookalike hostname features, cross-origin
password form actions, main-frame redirect hosts after header grant, and session
cookie flag names without values. These are review states, not proof of AiTM,
MFA bypass, token replay or post-compromise state.

The extension's redacted **COPY REPORT** text can be pasted into **WEB RISK >
EXTENSION REPORT IMPORT** in the WSH/HTA console. The handoff is manual and
in-memory only. The console does not read a browser profile, open a file, make a
network request, start a listener or write the report to disk. A paste with
secret-like text is rejected without showing the value. Hardening controls such
as FIDO2 / WebAuthn, Continuous Access Evaluation and Conditional Access device
compliance stay `NOT EVALUATED` until verified in the identity control plane.

See `browser-extension\README.md` for the install steps, permission table and
limits. The extension does not replace the console; it adds a small,
low-privilege read-out for ordinary browsing work. For the threat model of
malicious extension abuse after another execution control has blocked a script
chain, see `research/BROWSER-EXTENSION-ABUSE.md`. For AiTM mapping, evidence
limits and the hardening checklist, see
`research/AITM-PHISHING-SESSION-HIJACK.md`. Both notes are defensive only: they
map techniques, state what an extension can and cannot imply, and give review
questions without install or bypass detail.

---

## 15. Windows Script Host and HTA as machine policy

Disabling WSH is a legitimate hardening control (CISA **CM0078**, MITRE ATT&CK
**T1059.007**). Set `Enabled = 0` under
`HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings`, and the per-user and
Wow6432Node keys where applicable, or enforce it with AppLocker or WDAC. The
expected refusal is `Windows Script Host access is disabled on this machine`.
It is appropriate on hosts that do not need `.vbs`, `.js`, `.wsf` or HTA
content.

**It is not complete on its own.** The `Enabled` value stops `wscript.exe` and
`cscript.exe`; it does not stop `mshta.exe`, which hosts HTA documents and can
still run VBScript/JScript. Treat them as separate controls (CISA **CM0005**,
MITRE **T1218.005**): deny `mshta.exe` with AppLocker or WDAC, block `.hta` at
the mail gateway, change the `.hta` association if it is not needed, and monitor
process creation and command lines for attempts. A block is the result, not a
coverage pass.

Rollout order:

1. Inventory actual use of `.vbs`, `.js`, `.hta`, logon scripts and internal
   tools. CISA notes that some update and recovery flows may depend on WSH.
2. Run AppLocker/WDAC in audit mode and review the events first.
3. Enforce through Group Policy or management tooling with a change record.
4. Keep 4688 / Sysmon 1 monitoring; a policy is not evidence that nothing was
   attempted.

**NetTruder dependency.** Its UI chain is
`mshta -> wscript -> shim.vbs -> powershell.exe`. Disabling WSH or blocking
`mshta` will stop the console from opening. That is a valid control result. Do
not re-enable WSH, change `.hta` associations or add an exclusion to make the
window appear. Use the CLI path, or an approved host where the chain is already
permitted. A tool availability problem is not a reason to weaken the host.

Reference guidance: CISA CM0078 and CM0005, MITRE ATT&CK T1059.007 and
T1218.005, and Microsoft's *Understand App Control script enforcement*.

---

## Limits

- Connect scan only; no SYN scan, no OS fingerprinting, no packet capture.
- IPv4 only for blocking; no inline IPS and no remote agents.
- IDS polls the TCP table every two seconds; fast cadences cannot be resolved.
- Beacon, fan-out and flow findings are triage signals, not proof.
- Research scores telemetry coverage, not exploitability.
- Code, kernel-source and WinDbg material is static; NetTruder does not execute
  source, load a driver, attach to a kernel or run debugger commands.
- The terminal is exactly as powerful as the account that launched it.

See `README.md` for module details and `RESEARCH.md` for the test read-out.
