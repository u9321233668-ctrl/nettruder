# NetTruder Site Posture - browser extension

Version 1.4.0. A read-only defensive browser extension for Chromium-based
browsers (Microsoft Edge and Google Chrome). It is a companion to the NetTruder
console, not an attack tool and not a replacement for the console.

It reads the current page and optionally its main-frame response headers. It
also reports passive login indicators using a local, session-only list of exact
trusted IdP hostnames. It never modifies a request, never runs a test payload,
never reads browser history, form values, cookie values, tokens or credential
values, and never sends data anywhere. There is no network code in the
extension.

---

## Safety boundary

- **Local only.** Results stay in the popup and in an optional clipboard copy.
- **Active-tab model.** No site access is granted just by installing the
  extension.
- **Read-only DOM.** `content.js` reads element names, attribute names and
  redacted URLs. It does not read input values, text content of scripts, or
  cookies' values.
- **Redacted URLs.** Query strings and fragments are removed from every URL in
  a finding or report.
- **Optional headers.** Response headers are captured only after the user
  grants read access for that exact origin. Headers are observed, never
  rewritten, and requests are never blocked.
- **No history, no bookmarks, no cookies API, no downloads, no tabs scraping.**
  The extension uses only `activeTab`, `scripting`, `storage`, `webRequest`,
  and per-origin optional host permission.
- **No bypass.** If a browser policy blocks the extension, that is a valid
  control result. Do not change enterprise policy, developer mode settings or
  endpoint controls just to make it load.
- **Manual control records only.** A CAPTCHA or bot check is recorded by you,
  never solved. NetTruder does not click images, analyse pictures, capture
  tokens, retry the challenge, or change headers, IP or User-Agent. Records
  live only in the popup until **COPY REPORT**; nothing is stored when it closes.
- **Passive indicators only.** CSP violation events, SRI/iframe/link attribute
  tokens and header values are observed. NetTruder does not create violations,
  run exploit code, read process memory, attach a debugger or inspect browser
  internals. A clean report is not proof that no exploit occurred.

---

## Install

1. Open `edge://extensions` or `chrome://extensions`.
2. Enable **Developer mode** only if your organisation permits local
   extensions.
3. Choose **Load unpacked** and select this `browser-extension` folder.
4. Pin **NetTruder Site Posture** to the toolbar if you want quick access.

No build step, no package manager, no remote script and no account is needed.
If policy disallows unpacked extensions, use the documented software approval
process. Do not disable a policy to load this extension.

---

## Use

1. Open an ordinary `http` or `https` page.
2. Click the extension icon.
3. Press **RUN READ-ONLY CHECK**.
4. Expand a finding to see its state, evidence and remediation.
5. Review **HEADER QUALITY** and **COOKIE FLAGS** for parsed values and weak
   settings. Cookie values are never shown.
6. Under **LOGIN / AITM INDICATORS**, add exact IdP hostnames and press **SAVE
   LOCAL HOST LIST**. The list is session-only; it stores hostnames, not values.
   Review host trust, lookalike features, form action origin, redirect summary
   and session cookie flags. None of these proves AiTM.
7. If you want security headers or redirect hosts, press **GRANT HEADER READ**
   for that origin, reload the tab, then run the check again. The same button
   revokes access.
8. If a site presents a CAPTCHA or bot check, choose the type and outcome in
   **CONTROL ENCOUNTER**, press **RECORD ENCOUNTER**, and stop. Do not try to
   pass the challenge.
9. Use **COPY REPORT** to place a redacted text report on the clipboard before
   closing the popup. You may paste it manually into the console's **WEB RISK >
   EXTENSION REPORT IMPORT** area. There is no automatic bridge. Control records
   are not stored after the popup closes.

NetTruder does not reload the tab for you. With only DOM access, header-related
rows stay `NOT EVALUATED`, not clean. Browser internal pages, `view-source:`,
extension pages and `file:` pages are also `NOT EVALUATED`.

---

## What it checks

| Check | Evidence source | Honest limit |
|---|---|---|
| HTTPS transport | `location.protocol` | Says nothing about certificate validity beyond what the browser already enforced. |
| Loaded mixed content | `src` plus `link` rels such as stylesheet, preload, icon and preconnect | Attribute references only; it does not inspect CSS `url()` or script-fetched resources. |
| Insecure navigation references | `a[href]`, `form[action]`, and `link[href]` without a loaded rel | Lower severity; not loaded mixed content. The `rel` value is shown. |
| Password fields on http | `input[type=password]` count | Count only; no value is read. |
| Form actions | `form[action]` | Redacted target only; no submission is made. |
| Login host trust | Exact local hostname list compared with `location.hostname` | Session-only hostname list. No match is a review state, not proof of phishing. |
| Lookalike host features | Sampled `location.hostname` features | Punycode, IP literal, numeric labels, many hyphens or long labels are context signals only. |
| Cross-origin login form action | Origin of `form[action]` for forms with a password field | Origin and redacted target only. No value is read and no submission is made. |
| Main-frame redirect hosts | Passive `webRequest` redirect host cache | Requires per-origin header grant and reload. Query strings and fragments are discarded. |
| Session cookie flag review | Names and flag names from optional `Set-Cookie` capture | Never reads or reports cookie values. Absence is not proof that no session cookie exists. |
| CSP meta tag | `meta[http-equiv]` | A meta tag is partial. The response header is the primary control. |
| Visible cookie names | `document.cookie` names | HttpOnly cookies and all flags are invisible to page JavaScript. |
| Inline handler sample | Sampled `on*` attributes | A sample, not a full CSP audit. |
| Script / frame surface | Counts of scripts and iframes | Counts only; no script text is read or executed. |
| Security headers | Optional `webRequest` observation | Requires per-origin permission and a reload after granting. |
| Header quality | Parsed CSP, HSTS, Referrer-Policy, Permissions-Policy and isolation headers | A header can be present and still weak; absence is context-dependent. |
| CSP violations | Browser-generated `securitypolicyviolation` events | Passive only; no violation is caused and absence is not proof of a strong CSP. |
| Cookie flags | `Set-Cookie` names and flags from the optional header capture | Never reads or reports cookie values. HttpOnly cookies remain invisible to page JS. |
| `javascript:` URL references | `javascript:` in sampled `src`, `href` or `action` attributes | High severity. Scheme, tag, attribute and context only; payload text is not read. |
| `data:` URL references | `data:` in sampled attributes | Review severity; context is shown. Payload text is not read. |
| `blob:` URL references | `blob:` in sampled attributes | Media/preview contexts are informational; other contexts need review. Payload text is not read. |
| SRI presence | Cross-origin script/stylesheet `integrity` attributes | Presence only; NetTruder does not verify the hash. |
| Iframe isolation | `sandbox` attribute tokens | Attribute tokens only; no frame content is read. |
| New-tab links | `target="_blank"` and `rel` tokens | Attribute tokens only; no click is performed. |
| Control encounters | Manual type/outcome selection in the popup | Evidence only; no detection, solving, clicking, image analysis, token capture or retry. |

Headers shown when available:

- Content-Security-Policy
- Strict-Transport-Security
- X-Content-Type-Options
- X-Frame-Options
- Referrer-Policy
- Permissions-Policy
- X-XSS-Protection (legacy, informational)
- Content-Type
- Cross-Origin-Opener-Policy
- Cross-Origin-Embedder-Policy
- Cross-Origin-Resource-Policy

Every row shows a state and a remediation. `NOT EVALUATED` means NetTruder did
not see the evidence; it is never a pass.

### Scheme and context remediation

| Scheme/context | State | What it means | Remediation |
|---|---|---|---|
| `javascript:` in any sampled attribute | `FOUND`, high | A script URL was referenced. NetTruder reports only the scheme, tag, attribute and context. | Remove the URL, sanitise untrusted input and constrain script sources with CSP. |
| `data:` in any sampled attribute | `REVIEW` | An inline data URL was referenced. Its safety depends on the element context. | Prefer HTTPS or trusted local assets. If required, confirm the context and constrain script or frame sources with CSP. |
| `blob:` in `video`, `audio`, `source` or `img` | `INFO` | Often a local preview or MediaRecorder object URL. It is not an exploit by itself. | Confirm it was created from trusted local data and revoked when done. Do not remove a working preview just to clear the row. |
| `blob:` in frames, scripts or navigation attributes | `REVIEW` | The scheme alone cannot establish safety in an executable or navigation context. | Confirm the blob origin, avoid it in executable attributes and constrain script or frame sources with CSP. |

NetTruder never reads or reports the text after the scheme. A report contains
only the scheme, tag, attribute and context.

---

## Login and AiTM indicators

Version 1.4.0 adds a passive login review section. It does not detect an
Adversary-in-the-Middle proxy, cookie theft, MFA bypass, token replay or
post-compromise state. The browser read cannot see those facts.

The section reports:

- **Login host trust** - password surface on a host that does not match the
  local exact-hostname list. With no list configured, the state is
  `NOT EVALUATED`, not clean.
- **Lookalike host features** - sampled hostname features such as punycode, IP
  literal, numeric labels, many hyphens and long labels. These are context
  signals only.
- **Login form action origin** - password forms whose action resolves to a
  different origin. Values are never read.
- **Main-frame redirect chain** - redacted host-to-host hops observed after the
  per-origin header grant. NetTruder never follows, blocks or changes a
  redirect.
- **Session cookie flags** - session-like `Set-Cookie` names and flags from the
  optional header capture. No cookie value is read.
- **AiTM detection limit** - an explicit row stating that TLS termination,
  cookie values, MFA bypass, token replay and post-compromise state are not
  visible to this check.

Hardening controls belong to the identity plane, not the browser read. FIDO2 /
WebAuthn origin-bound credentials, Continuous Access Evaluation and Conditional
Access device compliance are therefore `NOT EVALUATED` in the report. Verify
them with IdP administrators and sign-in logs. See
`research/AITM-PHISHING-SESSION-HIJACK.md` for the corrected ATT&CK mapping and
hardening checklist.

---

## Control encounters

The **CONTROL ENCOUNTER** panel turns a CAPTCHA, bot check, rate limit or access
denied page into clean evidence. Choose the control type and outcome, then press
**RECORD ENCOUNTER**. Each record shows:

- state: `CHALLENGE OBSERVED`, `BLOCKED`, `HUMAN PASSED` or `ABANDONED`
- type, host and redacted page URL
- observation time
- remediation: stop, preserve the notice, do not bypass it, use an authorised
  access path if needed, and review probe cadence separately

This is deliberately manual. NetTruder does **not** detect a challenge in order
to interact with it, does not select images, does not solve puzzles, does not
capture challenge tokens, and does not retry. A site-side control is a result to
record, not a target to pass. Records stay in the popup until **COPY REPORT**;
they are not written to storage or profile history.

---

## Passive indicators, not exploit detection

NetTruder does not claim to detect browser exploits. A web extension cannot see
renderer memory corruption, JIT exploitation, sandbox escape, process injection
or browser internals. Those need endpoint, browser or lab telemetry under proper
authorisation.

It does provide passive indicators that support browser security research:

- CSP violation events generated by the browser itself
- weak CSP, HSTS, referrer, permissions and cross-origin isolation headers
- cookie flags without cookie values
- scheme/context URL references (`javascript:`, `data:` and `blob:`)
- missing SRI on cross-origin scripts and stylesheets
- missing or broad iframe sandbox tokens
- new-tab links without `noopener` / `noreferrer`
- passive login host, lookalike host, cross-origin form action and redirect host
  indicators, explicitly not AiTM proof

Each indicator has a state and a remediation. `NOT EVALUATED`, `NONE SEEN` and
`N/A` are never clean passes. These checks help explain prerequisites and
control gaps; they do not prove that an exploit was attempted or succeeded.

---

## Permission model

| Permission | Why it is present | What it does not allow |
|---|---|---|
| `activeTab` | Read the page the user is currently looking at. | No background tab reading. |
| `scripting` | Inject the read-only DOM reader after a button press. | No page script execution beyond NetTruder's own reader. |
| `storage` | Keep the last header record for the active tab in session storage. | No profile history or long-term tracking. |
| `webRequest` | Observe main-frame response headers after permission is granted. | No blocking, no header modification, no redirect. |
| Optional `<all_urls>` host access | Lets the user grant one exact origin at a time through the browser prompt. | Access is not granted at install and can be revoked at any time. |

The browser shows its own permission prompt. NetTruder never silently grants
itself site access and never asks for `<all_urls>` as a permission at install.

---

## Files

| File | Purpose |
|---|---|
| `manifest.json` | MV3 manifest and permission declarations. |
| `background.js` | Read-only main-frame header observer, cookie-flag reducer and local session cache. |
| `content.js` | Injected DOM reader and passive CSP violation observer. Returns redacted structure and tokens only. |
| `popup.html` | Popup markup. |
| `popup.css` | Dark console styling with no external resources. |
| `popup.js` | Popup state, findings, remediation and clipboard report. |

---

## Limits

- This is not a vulnerability scanner. It does not probe other hosts.
- It cannot see HSTS preload state, EDR telemetry, SIEM forwarding or browser
  enterprise policy. Those stay outside the report.
- It cannot see HttpOnly cookies from page JavaScript. `Set-Cookie` names and
  flags are read only from the optional header capture; values are never shown.
- It cannot see CSS `url()` references or script-fetched resources.
- SRI presence is not hash verification. A bad hash is still a problem.
- CSP violation events are passive. No violation is caused by NetTruder and
  no event does not prove a strong CSP.
- It does not detect browser exploits or post-compromise state. That needs
  authorised endpoint, browser or lab telemetry.
- It cannot see TLS termination at a proxy, cookie or token values, MFA bypass,
  token replay or IdP policy state. Login rows are indicators only. FIDO2 /
  WebAuthn, CAE and Conditional Access device compliance stay `NOT EVALUATED`.
- A header can be present and still be badly configured. Read the value, not
  just the `PRESENT` state.
- A `NOT EVALUATED` row is missing evidence, not a clean result.
- Unpacked extensions may be blocked by policy. That block is a valid control
  result; record it and stop.
- A CAPTCHA or bot check is a site-side control result. It is recorded manually,
  never solved or bypassed.

Use `BEST-PRACTICES.md` and `research/BLOCKED-TESTS.md` for the wider NetTruder
rules on blocks, evidence and no bypass. For AiTM mapping, passive indicator
limits and the identity-plane hardening checklist, see
`research/AITM-PHISHING-SESSION-HIJACK.md`.
