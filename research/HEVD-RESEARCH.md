# HEVD Source Study Lab

Version 1.1.0. This is a **source-only defensive study lab** for the trimmed
local copy of HackSysExtremeVulnerableDriver (HEVD).

HEVD is a deliberately vulnerable driver used for security education. This lab
uses it only as a static Code Audit target. NetTruder never builds, signs,
loads, installs or executes it. No IOCTL is sent, no payload is produced, and
no exploit code is retained in this folder.

---

## Safety boundary

- No driver build, load, install, service or startup change.
- No exploit source, payload, bypass, persistence or credential material.
- No device request from the console or helper.
- No security-control change. Keep Defender, firewall, VBS, HVCI and code
  integrity as they are.
- Application Control blocks are valid results; never bypass them.
- A source finding is a review lead, not proof of exploitability.

The upstream `Exploit/`, `Builder/` and `Tools/` folders, the test `.pfx`, and
the `.git` metadata were removed from `research/hevd-source/`. See
`research/hevd-source/SOURCE-ONLY.txt` for the retained-file list.

---

## Folder layout

| Path | Purpose |
|---|---|
| `research/hevd-source/` | Trimmed upstream source copy. Code Audit target. |
| `research/hevd-source/.venv/` | Local Python 3 virtual environment for the helper. |
| `research/hevd-source/tools/hevd_lab.py` | Standard-library helper for checks, guides and finding summaries. |
| `research/hevd-source/requirements.txt` | Notes on the venv. No package is required. |
| `research/hevd-catalog.json` | Defensive RESEARCH catalog of eight kernel source-study entries. |
| `research/hevd-scenarios.json` | Beginner and advanced source-review exercises. |
| `research/HEVD-RESEARCH.md` | This document. |

The venv and helper do not install packages or touch the system Python. To use
them, run commands from `research/hevd-source/`:

```
.venv\Scripts\python.exe tools\hevd_lab.py check
.venv\Scripts\python.exe tools\hevd_lab.py review
.venv\Scripts\python.exe tools\hevd_lab.py guide --level beginner
.venv\Scripts\python.exe tools\hevd_lab.py guide --level advanced
.venv\Scripts\python.exe tools\hevd_lab.py paths
```

---

## Code Audit integration

In the CODE AUDIT module:

1. Press **HEVD SOURCE** to fill the path and start a read-only scan.
2. Review FILES WITH HITS and FINDINGS. Source is masked by default.
3. Click a file or finding to inspect numbered, highlighted source.
4. Press **KERNEL REVIEW** for the layered beginner and advanced explanation.
5. Press **KERNEL DBG** for a static WinDbg guide with copyable commands only.
6. Press **HEVD GUIDE** for the safety boundary and command prompts.
7. Press **SEND TO RESEARCH** to copy masked findings into RESEARCH.
8. Open RESEARCH and filter group `Kernel Source Review` for the catalog.

The bridge writes `%LOCALAPPDATA%\NetTruder\hevd-source-findings.json`. The
helper can summarize it:

```
.venv\Scripts\python.exe tools\hevd_lab.py findings
```

To save a Markdown report:

```
.venv\Scripts\python.exe tools\hevd_lab.py findings --out study-findings.md
```

Only masked `why`, `fix`, `file`, `line`, `cwe`, `snippet`, `evidence`, `reach`,
`preconditions`, `check` and `verdict` values are bridged. Raw source is never
sent.

---

## Added Code Audit rules

The engine includes C/C++ source extensions and defensive kernel rules:

| Rule | Focus |
|---|---|
| `NT-C-DANGEROUS-COPY` | Unbounded copy or format APIs; confirm destination capacity. |
| `NT-C-POOL-ALLOC` | Kernel pool allocation; check size arithmetic and initialisation. |
| `NT-C-IOCTL-DISPATCH` | Device-control entry point; review length and access validation. |
| `NT-C-USER-POINTER` | User-pointer probe and copy boundary. |
| `NT-C-INIT` | Buffer initialisation before use. |
| `NT-C-INT-WRAP` | Size arithmetic inside a bound check; confirm checked arithmetic before comparison. |
| `NT-C-CUSTOM` | Placeholder for a locally authored defensive rule. |

These rules flag review subjects, not vulnerabilities. Confirm each one by
reading the surrounding source before recording a finding.

---

## Integer wrap review

A fixed-width integer has a maximum. Addition or multiplication past that
maximum drops the high digits, so the result becomes small. If a bound check
compares that wrapped result, it can accept a request whose real size is larger
than the destination. The check passed because it read the wrong number, not
because the request was safe.

In the local source copy, `Driver/HEVD/Windows/IntegerOverflow.c` line 117
places addition inside a bound comparison. `NT-C-INT-WRAP` flags that pattern.
It is a review lead only: the engine does not compile the source, does not know
the input range, and does not claim the wrap can be reached.

Read the finding with `HEVD-INT` in RESEARCH. Record the input type, the maximum
possible value, where the result is used as a size, and the checked-arithmetic
fix. Keep `STATIC LEAD / NOT RUNTIME VERIFIED`. No size value, trigger step,
driver load or device request is part of this lab.

---

## Kernel DBG guide

**KERNEL DBG** is a static debugger guide, not a debugging session. It presents
a lawful crash-dump workflow and copyable WinDbg commands. NetTruder does not
attach to a kernel, read live memory, change boot debug settings, load a driver
or execute the displayed commands. The **COPY DETAIL** button copies the
command list for an administrator to review in their own tool.

Use the guide only for dumps you are authorised to read. Confirm the image and
symbol versions match the source tree before mapping a stack frame to a local
file:line. Treat the result as `STATIC LEAD / NOT RUNTIME VERIFIED`. Dumps can
contain user paths, tokens or other sensitive data, so redact before sharing.
Keep Defender, firewall, VBS, HVCI and code integrity enabled.

---

## Beginner track

1. Read `SOURCE-ONLY.txt` and the upstream README.
2. Run **HEVD SOURCE** in Code Audit.
3. Open one `NT-C-DANGEROUS-COPY` finding and read the masked source.
4. Press **SEND TO RESEARCH** and open the transferred finding.
5. Filter RESEARCH to `Kernel Source Review` and read HEVD-COPY.
6. Run the helper `check` and `guide --level beginner` commands.

The goal is to explain a bug class and its safe replacement in plain language.

---

## Advanced track

1. Trace a length value from the device-control entry to the copy site.
2. Audit allocation arithmetic and record the maximum possible size.
3. Map allocation, reference, free and pointer-clear lines for one object.
4. Document the probe/copy/validate order for a user buffer.
5. Draft a narrow `NT-C-CUSTOM` rule and verify its masked output.
6. Produce a research note with evidence, controls and explicit limits.

The goal is a review artifact, not a working exploit. Do not add payload code,
IOCTL senders, bypasses or dynamic trigger steps to this lab.

---

## RESEARCH catalog entries

| ID | Subject |
|---|---|
| `HEVD-IOCTL` | Device-control boundary and buffer validation. |
| `HEVD-COPY` | Fixed-size copy review. |
| `HEVD-POOL` | Pool allocation, sizing and lifetime. |
| `HEVD-UAF` | Object lifetime and ownership. |
| `HEVD-INT` | Integer arithmetic that feeds sizes and lengths. |
| `HEVD-UNINIT` | Initialisation before read. |
| `HEVD-PTR` | User-pointer boundary and single-snapshot copy. |
| `HEVD-MITIGATIONS` | Mapping bug classes to platform controls and evidence limits. |

All entries use `method = Source Review`, `platform = windows`, and
`gap = NOT EVALUATED` after an inventory run. That is intentional: they are
source subjects, not host binaries to probe.

---

## Layered kernel source review

The same source is explained at two levels so beginners and advanced reviewers
can work from one artifact:

| Layer | What it answers | Where to read it |
|---|---|---|
| Beginner | What is the bug class, in plain language, and what should safe code do? | **HEVD REVIEW** modal, `tools/hevd_lab.py review`, beginner scenarios. |
| Advanced | Where is the boundary, how does data flow, and what evidence limits apply? | **EVIDENCE / VERIFY** on a finding, advanced scenarios, catalog detection and hardening rows. |

The beginner layer uses a box-and-parcel analogy for buffer sizing. The
advanced layer names the dispatch boundary, traces length and size values,
checks capacity and lifetime, and records file:line evidence. Both layers end
at the same boundary: static review only, no runtime claim.

## Static evidence and verification checklist

A Code Audit finding now carries `evidence`, `reach`, `preconditions`, `check`
and `verdict`. In the UI these appear under **STATIC EVIDENCE / VERIFY
CHECKLIST**, and the **EVIDENCE / VERIFY** button opens the same material with
the documented fix and the explicit state `STATIC LEAD / NOT RUNTIME
VERIFIED`.

The checklist asks a reviewer to trace the call chain, verify bounds and
pointer handling in source, and confirm the driver was not built, signed,
installed or loaded. It contains no trigger step, payload, IOCTL or bypass. An
authorised lab may extend the checklist under its own change control; this tool
never does.

## Evidence limits

- A Code Audit hit is a pattern match, not a confirmed bug.
- A catalog entry is a study guide, not an observation about this host.
- `NOT EVALUATED` means no host binary or runtime behaviour was tested.
- Mitigation state should be read from RESEARCH control rows, not inferred
  from source code.
- If a control blocks an action, record the block as a positive result.
