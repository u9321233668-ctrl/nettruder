# Browser extension abuse - defensive threat model

This is a defensive research note. It explains how a compromised host could use
a browser extension as an access path after another execution control, such as
Windows Script Host, has blocked a script-launching chain. It does **not**
provide a malicious extension, install method, persistence recipe, evasion
guidance, native bridge, or any instruction for bypassing a control.

- Scope: threat model, ATT&CK mapping, defensive review questions, remediation
- Safety rule: a browser policy block is a valid control result; record it and stop
- Related docs: `BEST-PRACTICES.md` section 13 and section 14,
  `research/BLOCKED-TESTS.md` section 10, `browser-extension/README.md`
- ATT&CK source: T1176.001 Browser Extensions, MITRE ATT&CK, accessed 2026-11-21

---

## 1. The hypothesis, stated carefully

Assume a host foothold already exists and an administrator has disabled Windows
Script Host. That blocks the `cscript`, `wscript`, and related HTA launch paths.
It does **not** block JavaScript running inside Chromium or Edge, because an
extension runs in the browser's own extension runtime, not in WSH.

That does not mean an extension simply bypasses the admin. Installation and
enablement still cross a separate trust boundary: enterprise policy, developer
mode, store installation, user consent, or prior write access to browser
configuration. If any of those are weak, an attacker may prefer a browser
extension because it gives a durable, user-context view of web sessions.

The accurate framing is:

- Not a WSH bypass
- Not automatic Windows admin elevation
- A different persistence and browser-session access path
- Application-level broadening: authenticated web apps, cookies, headers,
  page content, and user identity, depending on granted permissions

A disabled script host remains a valid control success for the channel it
actually governs. It should not be re-enabled to test or compare behavior.

---

## 2. Technique names

| Mapping | Name | Why it matters here |
|---|---|---|
| T1176 / T1176.001 | Software Extensions / Browser Extensions | Adversaries may abuse browser extensions for persistent access. This is the primary mapping. |
| T1185 | Browser Session Hijacking | A malicious extension can act inside the user's authenticated browser context. Often called man-in-the-browser behavior at a high level. |
| T1555.003 | Credentials from Web Browsers | Browser-stored credentials are a common target class, subject to browser protections and user consent. |
| T1539 | Steal Web Session Cookie | Session material is more useful than a password when MFA is already satisfied. NetTruder never reads or reports cookie values. |
| M1047 | Audit | Confirm installed extensions are the intended ones. |
| M1038 | Execution Prevention | Browser extension allow or deny lists are a valid control. |
| M1033 | Limit Software Installation | Restrict installation sources and require sufficient permission. |
| M1051 | Update Software | Keep browser and endpoint controls current. |
| M1017 | User Training | Close browser sessions when finished and report unexpected permission prompts. |

MITRE lists real-world examples such as Grandoreiro, Lumma Stealer, Kimsuky,
Mispadu, and TRANSLATEXT using malicious extensions for data theft, cookie
theft, or persistence. These are cited as evidence that the pattern is real, not
as a source of implementation detail.

---

## 3. What a malicious extension can and cannot imply

A browser extension is powerful inside its granted permission scope, but the
scope is still bounded.

| Capability area | Defensive interpretation | Honest limit |
|---|---|---|
| Active tab and DOM reads | Can observe page structure and text in pages it is allowed to read. | Modern browsers isolate extensions; a normal extension cannot simply read every other extension. |
| Authenticated web sessions | Can act with the user's already-authenticated browser identity if granted access. | This is web-app access, not Windows administrator access. |
| Cookies, headers, downloads | Sensitive APIs require explicit permissions and are detectable in a permission review. | NetTruder does not request cookies, downloads, history, or native messaging. |
| Request observation or modification | Some extension APIs can observe or change web traffic when permitted. | NetTruder uses `webRequest` only to observe headers after per-origin grant; no blocking, rewriting, or redirecting. |
| Native bridge | A browser-to-native bridge requires a separately registered native host. | An extension cannot simply conjure OS command execution from nothing. Any such bridge is an additional artifact to find. |
| OS elevation | Not provided by the extension model itself. | Requires a separate local component, vulnerable service, or policy/profile weakness. |

The key defensive point is that permission state matters more than the mere
presence of an extension. A low-privilege read-only helper and a data-stealing
extension are not equivalent.

---

## 4. NetTruder-specific posture

The current `browser-extension\` project is deliberately constrained:

- Manifest V3 with `activeTab`, `scripting`, `storage`, and `webRequest`
- optional `<all_urls>` host access is requested only per origin by user action
- no `fetch`, XHR, beacon, history API, cookies API, downloads API, or
  native messaging
- no form values, cookie values, query strings, fragments, or payload text
- no request modification, blocking, redirect, or test payload
- all findings carry a state and a remediation; `NOT EVALUATED` is never clean

Therefore the current NetTruder extension is not an example of the abuse pattern
described above. It is a deliberately low-privilege read-out. The hypothetical
only applies if an attacker replaced or extended it with invasive permissions and
network behavior, which would be a change from the reviewed design.

The WSH-disabled result on this host stays a control success. Nothing in this
note changes, retries, or bypasses it.

---

## 5. Defensive review questions

These are investigation prompts, not attack steps. Each one should produce
evidence and a remediation or a documented non-finding.

| Review question | Evidence to keep | Remediation or disposition |
|---|---|---|
| Is the extension expected and approved? | Name, ID, version, store or unpacked source | Remove or disable unexpected extensions through the approved process. Do not delete personal files or profiles. |
| Are permissions broader than the purpose? | Manifest permission and host-permission list | Remove unneeded permissions; prefer active-tab and per-origin grants. |
| Is developer mode or unpacked loading allowed? | Enterprise policy state and observed load event | Restrict where policy permits; record a policy block and stop. |
| Is there an unusual update source? | Update URL and distribution type from inventory | Verify against the approved distribution path. Do not contact an unknown update URL. |
| Is there a native messaging component? | Presence of a registered native host | Treat as a separate high-value artifact and review with endpoint telemetry. |
| Did browser egress change after install? | EDR, proxy, or browser-process telemetry | Investigate new untrusted destinations; preserve evidence before containment. |
| Did the user see an unexpected permission prompt? | User report and browser permission state | Revoke access and review the install source. Do not blame the user. |

A normal extension generally cannot enumerate other extensions in modern
Chromium. Detection of malicious extensions therefore belongs mainly in
enterprise policy, EDR, browser telemetry, and read-only profile inventory, not
in a second ordinary extension.

---

## 6. If a control blocks the extension

Record the same kind of evidence used for blocked console paths:

- product or policy that refused the load
- exact message, event id, or browser policy name
- browser, profile, extension name, ID, and version if known
- what was not attempted: no policy edit, no developer-mode change, no
  unpacked reload, no signature or path workaround, no retry
- disposition: valid control result, escalate through change control if the
  extension is genuinely required

See `research/BLOCKED-TESTS.md` section 10 for the shared evidence template.

---

## 7. Limits of this note

- It is a threat model, not a detection claim or an incident finding.
- A block on one host at one time does not prove general coverage.
- Absence of suspicious extension telemetry is not proof of absence.
- This note does not establish that NetTruder or its extension was malicious or
  modified. The reviewed code shows the opposite design intent.
- NetTruder does not detect browser exploits or post-compromise state from
  extension evidence.
- No host policy, browser policy, browser profile, WSH setting, or extension
  installation was changed to produce this note.
