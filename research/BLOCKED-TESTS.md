# Blocked test commands - register and analysis

Every test command in this file was **refused by a running control** and was
**not bypassed**. A block is a valid defensive result: it is evidence that a
control plane did its job. It is not evidence that a technique is covered in
general, and it does not upgrade a `BLIND` coverage row to `OK`.

This register exists because the first read-out recorded two blocks in prose and
the research module could not express them. The lab now carries a
machine-readable block register (`research/blocks.json`) into the report and the
console detail panel. Section 10 is the documented response pattern for the
console being blocked itself. It is a procedure and evidence template, not a new
measured probe run.

- Register version: `2026.11.3`
- Host: Windows 11 build 26300, standard user unless stated
- Products registered on the host: Windows Defender and McAfee
- Related docs: `RESEARCH.md` section 4 and section 10.4, `research/README.md`

---

## 1. Summary

| ID | Vector | Control that acted | Result | Evidence quality |
|---|---|---|---|---|
| BLOCK-001 | `mshta` starts PowerShell directly | McAfee endpoint | `0x800700E1` at launch | Matrix recorded in `RESEARCH.md` |
| BLOCK-002 | `certutil -urlcache -split -f` download | McAfee endpoint | refused at process start | Prose record; argv not logged |
| BLOCK-003 | IPS block as a standard user | NetTruder privilege guard | refused, 0 firewall rules | Recorded in verified results |

Three classes of block should not be mixed up:

| Class | Who refuses | What it proves | Example here |
|---|---|---|---|
| Endpoint AV | McAfee or Defender | The product's process or content policy matched | BLOCK-001, BLOCK-002 |
| OS / enterprise policy | AppLocker, WDAC, ASR, script-host policy | The host policy matched, independent of AV | not observed in the original run; console-blocked case in section 10 |
| Self-guardrail | NetTruder | Its own safety rule worked | BLOCK-003 |

A blocked test says something about **one vector on one host at one time**. It
does not say the technique is blocked in general. Variants that were not tried
may still work, and a different product version or policy set may behave
differently.

---

## 2. Method and evidence rules

- The command was composed as a defensive test vector, not as an attack payload.
- The result was read from the process launch API, the product notification, or
  the console message. It was not inferred from a missing log entry alone.
- Where a control vector was available, it was run. `cmd /c echo hi` is the
  control for BLOCK-001: it proves the harness itself works, so a refusal is
  attributable to the policy rather than to a broken test.
- The tests were not retried with encoding, renaming, alternate parents,
  whitelisting, or exclusion. No attempt was made to evade any product.
- A missing telemetry event after a blocked process is expected. It must not be
  scored as an IDS detection failure when the process never started.

Evidence quality matters. BLOCK-001 has a full allow/deny matrix. BLOCK-002 has a
clear product message but the exact URL and temp path were not written to a
machine log, so it is a documented vector, not a byte-for-byte replay. BLOCK-003
has a verified result and a firewall-rule count of zero.

---

## 3. BLOCK-001 - mshta starts PowerShell directly

### What was attempted

The console is an HTA running in `mshta.exe`. The first engine launcher called
`WScript.Shell.Run` with a PowerShell command line. The HTA initialised, wrote a
valid request file, and then no engine events appeared.

### Observed result

`WScript.Shell.Run("powershell.exe ...")` failed with:

```
HRESULT -2147024671  =  0x800700E1  =  ERROR_VIRUS_INFECTED
```

The same call from `cscript.exe` succeeded, so the executable path, quoting and
arguments were valid. The control was sensitive to the parent process and the
child command line, not to `powershell.exe` in isolation.

### Allow / deny matrix

| Parent | Command line | API | Result |
|---|---|---|---|
| mshta | `powershell.exe -Command "exit 0"` | Wsh.Run | blocked `0x800700E1` |
| mshta | full path to `powershell.exe` | Wsh.Run | blocked |
| mshta | `cmd /c powershell.exe ...` | Wsh.Run | blocked |
| mshta | `cmd /c echo hi` | Wsh.Run | OK (control) |
| mshta | `wscript.exe "shim.vbs" "request.json"` | Wsh.Run | OK |
| mshta | `ShellExecute("wscript.exe", ...)` | ShellExecute | OK |
| mshta | `cmd /c wscript.exe "shim.vbs" "request.json"` | Wsh.Run | OK |
| cscript | `powershell.exe ...` | Wsh.Run | OK |

### Why this is a valid defensive result

The technique being tested is "a script host starts a shell". The product
refused exactly that behaviour. The useful signal is the parent/child pair, and
the refusal shows the pair was evaluated.

The control row also proves the test was sound. A block that cannot be
distinguished from a broken harness is not evidence. Here the harness ran the
allowed control, the allowed replacement chain, and the blocked chain on the
same host in the same session.

### What it does not prove

- It does not prove that `mshta.exe` cannot be abused. A different child, a
  different invocation API, or a different policy version may behave differently.
- It does not prove that process-creation telemetry is on. The block happened
  before a process existed, so 4688 would have nothing to record.
- It does not prove that the content or network layers are covered. A blocked
  launch leaves nothing to inspect at those layers.

### Detection lesson

Alert on the chain, not only the image:

- 4688 or Sysmon 1 where `ParentImage` ends in `mshta.exe` and `Image` ends in
  `powershell.exe` or `cmd.exe`.
- Command lines containing `-EncodedCommand`, `-WindowStyle Hidden`, `IEX`,
  `DownloadString` or `FromBase64String` when the parent is a script host.
- EDR script-host rules that key on `mshta.exe` spawning a shell, which is
  precisely the behaviour McAfee refused here.

### Resolution and research follow-up

The console now writes a JSON request file and calls `engine\shim.vbs`; WSH runs
the shim, which starts the hidden PowerShell worker. This is a normal
parent/child chain and needed no policy change. The block was not bypassed and
no product was weakened.

Follow-up:

1. Keep BLOCK-001 as a regression vector for the launch chain. If the shim is
   ever blocked the same way, the console must report it and stop.
2. Add parent-image chain rules to the IDS/egress guidance, not just command-line
   pattern lists.
3. When testing a new endpoint product, re-run the full matrix so the result is
   attributable to the current policy set.

---

## 4. BLOCK-002 - certutil URL cache download

### What was attempted

A signed Windows binary was asked to fetch a file with its documented download
arguments, as a download-control test:

```
certutil.exe -urlcache -split -f http://<lab-listener>/sample.txt %TEMP%\nw-sample.txt
```

The test was intended to exercise the IDS egress rule `EGRESS_CERTUTIL` and the
command-line enrichment path.

### Observed result

McAfee refused the process at start with a notification that the file contains a
virus or potentially unwanted software. The download did not complete and no
`EGRESS_CERTUTIL` alert was raised, because the process never reached the
network.

Caveat: the exact URL, listener port and temp destination were not captured in a
machine log. The command shape above is the documented test vector, not a
byte-for-byte replay of the original argv. That limitation is recorded rather
than hidden.

### Why this is a valid defensive result

A download-control test asks one question: can the signed binary be used to pull
content past the network control? The endpoint product answered "no" before the
network control was reached. That is the control working, one layer earlier than
the test expected.

The absence of `EGRESS_CERTUTIL` is therefore **not** an IDS gap. The IDS cannot
see a process that was never created. Scoring it as a miss would be a false
negative in the report, not a false negative in the product.

### What it does not prove

- It does not prove that `certutil` egress is covered on a host without that
  endpoint product.
- It does not prove that other download arguments, other binaries, or BITS are
  covered. BITS is the important exception: the transfer runs inside
  `svchost.exe`, so the process name rarely carries `bitsadmin`.
- It does not prove that the endpoint product would block a different payload.
  The refusal is specific to the tested command and content.

### Detection lesson

- Command line: `certutil` with `-urlcache`, `-split`, `-verifyctl`, `-decode`,
  `-encode` or a URL.
- Network: `certutil.exe` opening 80/443/8080/8443 to an address that is not a
  known certificate or update endpoint.
- Endpoint: Defender operational 1116/1117 or the McAfee event log, correlated
  with the test timestamp.
- BITS: alert on `bitsadmin /transfer`, `/AddFile`, `/SetNotifyCmdLine` and
  BITS-Client operational events. The process-name egress rule is only a
  backstop.

### Safe reproduction guidance

Only re-run this test when all of the following are true:

1. The listener is on a lab host you control and serves an inert text file.
2. The endpoint product's log is being captured before the run.
3. The command, exit code, product event id and firewall/IDS state are recorded
   in the same note.
4. The test is not retried with an alternate argument set after a block. A block
   is the result; retrying with variations turns a control test into an evasion
   attempt.

A useful non-triggering companion test is `certutil -hashfile <local-file>
SHA256`, which exercises the binary without the download arguments. It is not a
substitute for the blocked test and should be labelled as normal use.

---

## 5. BLOCK-003 - NetTruder refuses its own IPS action

### What was attempted

A standard user asked the console to block a public address, first from the CLI
and then from the UI:

```
NetTruder.ps1 -Action block 8.8.8.8
UI: BLOCK 8.8.8.8
```

### Observed result

The action was refused with an "elevated session required" message. Zero
firewall rules were created. The same code also refuses local addresses,
gateways, DNS servers, loopback, multicast, broadcast and reserved ranges, and
requires explicit confirmation before a private peer is blocked.

### Why this is a valid defensive result

A containment tool that can silently cut off its own management path, its
gateway or a public service is more dangerous than the threat it is responding
to. The refusal is the safety property working. The verification is not just the
message: the `NetTruder-IPS-*` rule count stayed at zero.

### Research follow-up

Add an assertion to every IPS test: after a refused block, the firewall must
contain no `NetTruder-IPS-*` rules, and the audit log must contain the refused
attempt. This separates "the UI said no" from "nothing changed".

---

## 6. What was not attempted

The boundary is part of the result:

- No attempt to disable, exclude, whitelist or tamper with Defender or McAfee.
- No encoded command, obfuscation, packing or alternate interpreter to get
  around BLOCK-001 or BLOCK-002.
- No C2, listener, payload, stager, persistence, credential access, lateral
  movement or defence evasion.
- No attempt to alter the firewall, services, drivers, Windows Update, telemetry
  or browser profiles.
- No attempt to re-enable Windows Script Host, restore `.hta` associations, add
  an exclusion or change launchers after a refusal.
- No retry loop against a blocked command. A refusal ends the test.

If a future test is blocked, the correct next step is to record the block and
review the control, not to vary the command until something executes.

---

## 7. How the register is wired into the research module

The register is intentionally separate from `techniques.json` because it is
host-specific observation data, not generic technique knowledge.

| File | Role |
|---|---|
| `research/blocks.json` | Machine-readable register. One entry per observed block, keyed by technique id. |
| `research/Test-NetTruderPosture.ps1` | Loads the register, attaches matching blocks to each technique, adds a `blocks` array to the report and a "Defensive blocks" section to the Markdown report. |
| `engine/NetTruder.ps1` | Carries each technique's blocks into the `restech` event and adds a block count to `resmeta` and `done`. |
| `ui/app.js` | Shows a `BLOCKS n` chip in the research summary and a "DEFENSIVE BLOCK OBSERVED" section in the detail panel. |
| `research/README.md` | Documents the schema and the rule that a block is not a coverage pass. |

Each register entry has these fields:

| Field | Meaning |
|---|---|
| `id` | Stable register id, `BLOCK-nnn`. |
| `tech` | Technique id, or `GUARD-*` for a NetTruder guardrail. |
| `kind` | `endpoint-av`, `policy` or `guardrail`. |
| `product` | The control that acted, with enough detail to interpret the result. |
| `cmd` | The test vector. Placeholders are used where the original value was not retained. |
| `result` | What happened, in one sentence. |
| `signal` | Error code, product message or console message. |
| `scope` | What made the result specific to this host or parent. |
| `valid` | Why the block is a positive control result. |
| `teaches` | The general lesson for detection engineering. |
| `detect` | The telemetry that would record the attempt if it were not blocked. |
| `followup` | The next safe step. |
| `variants` | Allow/deny rows for the same vector, including controls. |
| `evidence` | Where the observation is recorded and how strong it is. |

The console shows the block next to the technique, for example under Mshta and
Certutil. Guardrail entries appear in the report and the summary count, but they
do not attach to a technique row because they are not technique tests.

---

## 8. Research backlog

Priority order, highest value first:

1. **Capture the block event id.** For every blocked test, record the endpoint
   product's event id and timestamp, not only the message. This turns "McAfee
   said no" into a correlatable artifact.
2. **Separate the three verdicts in the report.** A technique can be `BLOCKED`,
   `OBSERVED` or `NOT OBSERVED`. Today the gap label describes telemetry, while
   the block register describes execution control. Keep both and never let one
   overwrite the other.
3. **Add a live block probe, consent-gated.** A small set of inert vectors could
   be run only with `-RunMarkerProbes -Yes`, and the result recorded as
   `blocked-by` or `allowed`. This must never retry a blocked vector with
   variations.
4. **Add parent-image chain rules.** The mshta result shows that a command-line
   list alone would have missed the most important signal. Add at least:
   script host -> shell, Office -> shell, and shell -> download tool.
5. **Correlate endpoint and IDS timelines.** If a process is blocked, IDS should
   stay quiet by design. If a process executes and IDS stays quiet, that is a
   real coverage finding. The report should say which case occurred.
6. **Test the same matrix on a host without McAfee.** The comparison shows what
   the native Windows controls cover and what the third-party product adds.
7. **Document BITS separately.** A `bitsadmin` block says little about the
   transfer, because BITS runs in `svchost.exe`. Test the command line, the
   BITS-Client log and the outbound flow together.
8. **Keep the register append-only.** When a policy changes, add a new dated
   observation instead of editing the old one. The history is the useful part.

---

## 9. Evidence index

| Source | What it contains |
|---|---|
| `RESEARCH.md` section 4 | Launch-chain finding, full allow/deny matrix, HRESULT. |
| `RESEARCH.md` section 10.4 | certutil block note and egress test result. |
| `RESEARCH.md` section 3 | IPS refusal as a standard user, zero rules created. |
| `research/blocks.json` | The same observations in machine-readable form. |
| `README.md` - "Why there is a shim.vbs" | The supported launch chain and the instruction not to disable AV. |
| Section 10 of this file | Documented console-blocked response pattern: WSH disabled, `mshta` blocked or shim blocked; record and stop, no bypass. |

No machine log in `%LOCALAPPDATA%\NetTruder` contains the blocked argv. The
register records that limitation instead of presenting the prose note as a
captured event. Adding endpoint event capture is backlog item 1.

---

## 10. When the console itself is blocked (WSH, mshta or shim)

This section is a response pattern, not a new measured test in the original
register. NetTruder's UI needs `mshta.exe` and JScript; `engine\shim.vbs` needs
WSH. If Windows Script Host is disabled, `.hta` is blocked or unassociated, or
the `mshta -> wscript -> PowerShell` chain is refused, `Launch.cmd` may stop
before any engine event file is created. That is the same class of result as
BLOCK-001: a control acted on the launch chain.

### What to record

| Field | What to write |
|---|---|
| When and where | Host name, date/time, account, elevated or standard session. |
| Launch attempt | `Launch.cmd` or `Launch-Elevated.cmd`, UI path and exact error text. |
| Refusing control | Product or policy, plus the event id and log name if available. |
| Signal | HRESULT, product message or console message. Do not guess one. |
| Parent / child | The pair that was evaluated, for example `mshta -> wscript` or `mshta -> powershell`. |
| Telemetry | 4688, Sysmon 1, 4104, EDR or SIEM evidence that recorded the attempt, with `not measured` where unreadable. |
| NetTruder state | Whether the UI opened, whether an event file exists, and whether any engine action ran. |
| Boundary | Explicit note that no retry, alternate launcher, whitelist or exclusion was attempted. |

Known signal shapes from the launch-chain work:

- `HRESULT -2147024671 = 0x800700E1 = ERROR_VIRUS_INFECTED` from the direct
  `mshta -> powershell` launch in BLOCK-001.
- `Engine launch blocked: ... [code -2147024671]` when the console reports a
  failed engine start and stops.
- WSH disabled: no launch at all, because `wscript.exe` cannot run the shim and
  an HTA may be blocked before script execution. Record the POSTURE reading and
  any product event; do not invent a signal that was not captured.

### What not to do

- Do not set `WSH Settings\Enabled` to `1` or clear `DisableWindowsScriptHost`.
- Do not change AppLocker, WDAC, Defender ASR, `.hta` associations or endpoint
  exclusions to make the console open.
- Do not re-run with a different parent, an encoded argument or a direct
  PowerShell call after a refusal.
- Do not treat a missing process event as an IDS detection failure. The process
  never started.
- Do not score the technique as `OK`. A block says nothing about telemetry
  coverage or about variants that were not attempted.

### Acceptance-test checklist

1. Capture the launch attempt and exact error before closing the window.
2. Identify the control from the product console or log; record event id, log
   name and timestamp.
3. Compare with POSTURE / RESEARCH readings taken on an approved host where the
   console is allowed.
4. Confirm that no retry, alternate launcher, whitelist or exclusion was used.
5. Attach the event extract and report to the change record, then stop.

### Follow-up

Use an approved lab or admin-workstation console as described in
`BEST-PRACTICES.md` section 13, Path 1. If a genuine business need requires the
console on a locked-down host, request a narrow, logged, time-limited exception
for a named account and path through change control. That is a documented
decision with logging and expiry; disabling the control globally is not.
