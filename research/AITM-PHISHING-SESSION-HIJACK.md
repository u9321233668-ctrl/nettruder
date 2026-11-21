# Adversary-in-the-Middle (AiTM) Phishing and Session Hijacking

Defensive research note for NetTruder 1.1.0 and the optional
`NetTruder Site Posture` browser extension. This note explains how to interpret
passive indicator evidence. It is not an exploit guide, a proxy setup guide, a
credential-capture procedure or a claim that NetTruder can detect an AiTM
compromise.

---

## Safety boundary

- No reverse proxy, phishing page, relay, listener or replay tool is included.
- NetTruder does not read or report cookie values, session tokens, credentials,
  query strings, fragments, form values or payload text.
- The extension uses `activeTab`, read-only DOM inspection, optional per-origin
  response-header observation and passive main-frame redirect host observation.
- The WSH/HTA console accepts only a manual paste of the extension's redacted
  report. There is no native messaging host, localhost listener, fixed-folder
  drop, hidden pipe, profile read or automatic data path.
- Every indicator carries a state and remediation. `NOT EVALUATED`, `NONE SEEN`,
  `INDICATORS ONLY` and `N/A` are never clean passes.
- A blocked extension load, blocked script chain or CAPTCHA is a control result.
  Record it and stop. Do not change policy, WSH, `.hta` association, endpoint
  protection, headers, IP, User-Agent or browser controls to continue.

---

## MITRE ATT&CK mapping - corrected

The AiTM reverse-proxy phishing pattern is not `T1556.007`. That sub-technique is
**Modify Authentication Process: Hybrid Identity** and applies to modification
of hybrid identity infrastructure such as AD FS or Entra PTA agents. Use it only
when there is separate evidence of that infrastructure being modified.

| Technique | Name | Where it fits in this pattern | NetTruder claim |
|---|---|---|---|
| `T1566.002` | Phishing: Spearphishing Link | The lure that causes the victim to open an attacker-controlled sign-in page. | Passive host, redirect and page indicators only. |
| `T1539` | Steal Web Session Cookie | Session token capture and replay after a successful sign-in through the proxy. | Never asserted from page data. Requires IdP/session telemetry. |
| `T1071.001` | Application Layer Protocol: Web Protocols | HTTPS carries the proxy front-end traffic and later replay traffic. | Only redacted browser host/flow context; no payload or token read. |
| `T1556.006` | Modify Authentication Process: Multi-Factor Authentication | Outcome layer where conventional MFA approval can be relayed or bypassed. | Never asserted locally. Requires IdP sign-in and MFA logs. |
| `T1556.007` | Modify Authentication Process: Hybrid Identity | Separate case: backdooring AD FS, PTA or equivalent hybrid identity components. | Not evaluated by this extension or console. |

Use `T1556.007` in a report only with distinct administrative or identity-plane
evidence. Do not use it as a generic label for AiTM phishing.

---

## Attack lifecycle and interception architecture - conceptual only

This is the defensive model used to reason about evidence sources. It is a
diagram, not a deployment recipe. NetTruder does not build, emulate or test any
part of it.

```text
[ Victim Browser ] <--- TLS Session 1 ---> [ AiTM Reverse Proxy ] <--- TLS Session 2 ---> [ Legitimate IdP ]
                                                    |
                                                    +-- session material can be intercepted
                                                    +-- MFA prompts can be relayed

Observation point A: browser/DOM/redirect hosts (NetTruder extension)
Observation point B: IdP sign-in, MFA, session and token telemetry (not visible to extension)
Observation point C: EDR, proxy, DNS and SIEM telemetry (not visible to extension)
```

Important consequences:

1. The browser generally sees a valid TLS session to the host it actually
   connected to. A valid padlock does not prove the host is the intended IdP.
2. A reverse proxy can relay the legitimate IdP content, so page structure alone
   can look normal. Host spelling, exact origin, form action origin and redirect
   chain are more useful than page appearance.
3. Cookie and token values are secrets. NetTruder never reads them. Session risk
   must be established from IdP logs, session-replay telemetry and SIEM
   correlation.
4. MFA result, token replay and post-compromise state are control-plane or
   identity-plane conclusions. A browser read cannot prove or disprove them.

---

## What the extension can observe

These are passive indicators, not detections of exploitation:

- password surface on a host not in the local trusted IdP hostname list;
- sampled hostname features such as punycode, IP literal, numeric labels,
  unusual hyphenation or long labels;
- password form whose `action` resolves to a different origin;
- main-frame redirect host chain, only after per-origin header read is granted;
- session-like `Set-Cookie` names and flag names, never values;
- HTTP login transport and mixed-content references;
- expired, absent or weak security headers where header read is available.

Each row is a review trigger. A lookalike host with a password field is still
only a review state. It is not proof of AiTM, credential theft, MFA bypass or
session replay.

---

## What NetTruder will not claim

The extension and console cannot determine any of the following from a page read
or a local host inventory:

- that TLS was terminated at an attacker-controlled proxy;
- the value of a session cookie, bearer token, assertion or credential;
- whether an MFA prompt was bypassed, relayed or socially approved;
- whether a token was replayed from another IP, device or user agent;
- whether an account or host is post-compromise.

Any report that asserts those from extension evidence alone would be false. The
manual console import keeps those items as `NOT EVALUATED` with remediation.

---

## Detection opportunities by layer

### Browser / page layer - extension evidence

| Signal | State meaning | Remediation |
|---|---|---|
| Login host not in local exact-host list | `REVIEW` or `NOT EVALUATED` if no list is configured | Verify link source through a trusted channel; maintain an exact IdP host list for the browser session. |
| Lookalike hostname feature | `REVIEW`, context only | Check spelling, punycode and exact host; do not enter credentials until confirmed. |
| Cross-origin password form action | `REVIEW` | Confirm the action origin is an expected IdP or identity broker. |
| Unexpected main-frame redirect hosts | `REVIEW` | Correlate with IdP and proxy logs; absence of observed hops is not proof of no earlier redirect. |
| Session-like cookie flag weakness | `WEAK` from names/flags only | Set Secure, HttpOnly and explicit SameSite where appropriate; do not expose values. |

### Identity plane - required for confirmation

These sources are outside the extension and must be reviewed by an authorised
identity or SOC operator:

- IdP sign-in logs: new or unfamiliar IP, impossible travel, new device ID, new
  user agent, repeated near-simultaneous sign-ins, and rapid session reuse;
- MFA logs: prompt type, approval result, number matched, and whether a
  phishing-resistant method was used;
- session and token telemetry: token issuance, refresh, revocation and replay
  indicators from different addresses or devices;
- Conditional Access evaluation details: device compliance, managed-device
  state, named location and risky-sign-in decisions;
- CAE or equivalent continuous evaluation events where the platform supports
  them;
- administrative audit for hybrid identity infrastructure if `T1556.007` is
  being considered.

### Endpoint, proxy and network plane

- EDR process and command-line telemetry for the browser and any suspicious
  helper processes;
- secure web gateway or proxy logs for newly registered or low-reputation
  domains, unusual TLS destinations and referral chains from mail or chat;
- DNS logs for lookalike domains and first-seen hosts;
- SIEM correlation across mail delivery, URL clicks, IdP sign-in, proxy and EDR
  events.

NetTruder's NETWORK view can show redacted browser destinations from the local
socket and DNS cache. It does not capture packets, decrypt TLS, inspect payloads
or read browser history unless the operator explicitly opts in per run.

---

## Defensive hardening strategies

These controls reduce the value of AiTM phishing. NetTruder does not configure,
enable or verify them from the browser read. Record them as `NOT EVALUATED` in
the console import until an authorised identity administrator confirms state
from the IdP control plane.

### FIDO2 / WebAuthn hardware security keys

- Enforce origin-bound, phishing-resistant credentials where supported.
- The WebAuthn challenge is bound to the relying-party origin, so a proxied
  hostname should not satisfy the legitimate relying party's registration.
- Prefer hardware-backed keys or device-bound platform authenticators for
  privileged and high-risk accounts; retire weaker SMS, voice and reusable OTP
  methods where the IdP policy allows.
- Verify enforcement in IdP authentication-method policy and sign-in logs. A
  user having a key registered is not the same as a policy requiring it.
- State plus remediation: `NOT EVALUATED` -> require phishing-resistant methods
  in the IdP under change control; review exclusions and legacy app gaps.

### Continuous Access Evaluation (CAE)

- Enable supported CAE or equivalent real-time token evaluation so risk signals
  such as location or IP drift can trigger revocation.
- Coverage depends on IdP, application, token type and client support. An
  access token that does not participate in CAE is not covered by that control.
- Verify with sign-in, token and revocation telemetry. Do not infer CAE state
  from a successful browser session.
- State plus remediation: `NOT EVALUATED` -> confirm supported workloads, enable
  through the identity provider under change control, and validate revocation
  with authorised test telemetry or vendor-documented evidence.

### Conditional Access device compliance

- Require managed, compliant or hybrid-joined device attributes before access
  to cloud resources, with explicit review of guest, break-glass and legacy
  protocol exclusions.
- Device compliance is an authorization decision, not proof that the endpoint
  is clean at the moment of sign-in.
- Verify the effective policy scope, exclusions and evaluation details in IdP
  sign-in logs.
- State plus remediation: `NOT EVALUATED` -> require compliant devices for the
  relevant apps and users, restrict legacy authentication, and review
  exceptions through the normal governance process.

---

## Redacted evidence template

Copy only redacted text. Never include cookie values, tokens, credentials,
query strings, fragments, authorization headers or full form bodies.

```text
CASE: <local case id>
HOST / DOMAIN: <exact observed hostname>
TRUST LIST MATCH: yes / no / not evaluated
HOSTNAME FEATURES: <sampled features or none seen>
LOGIN FORM ACTION ORIGIN: <origin only or same document>
MAIN-FRAME REDIRECT HOSTS: <host -> host, redacted>
SECURITY HEADER STATE: <evaluated / not evaluated>
SESSION COOKIE FLAGS: <names and flags only, or not evaluated>
CONTROL ENCOUNTER: <state from manual record, or none>
IDP SIGN-IN REVIEW: <not evaluated / requested / reviewed>
MFA METHOD REVIEW: <not evaluated / phishing-resistant / other>
CAE / TOKEN REVOCATION REVIEW: <not evaluated / requested / reviewed>
DEVICE COMPLIANCE REVIEW: <not evaluated / requested / reviewed>
EDR / PROXY / SIEM CORRELATION: <not evaluated / requested / reviewed>
CONCLUSION: INDICATORS ONLY - NOT PROOF OF AITM, MFA BYPASS OR SESSION REPLAY
```

---

## Manual handoff to the WSH/HTA console

1. In the extension, press **COPY REPORT**.
2. In the console, open **WEB RISK** and find **EXTENSION REPORT IMPORT**.
3. Paste the redacted report into the text area.
4. Press **IMPORT REPORT**.

The console parses the pasted text in memory only. It does not open a browser
profile, read a file, make a network request, start a listener, write the report
to disk or push anything back to the extension. If the paste contains
secret-like text, the console rejects it without displaying the value. Every
rendered row includes state and remediation.

The import view always adds three separate hardening rows: FIDO2 / WebAuthn,
CAE and Conditional Access device compliance. Their state is `NOT EVALUATED`
because a browser report cannot prove IdP policy.

---

## "Proof of exploitability" and "proof of AiTM"

For this project, proof means static evidence plus an authorised-lab verification
checklist, or independent telemetry from the control plane that owns the claim.
Extension evidence plus a console import is not proof of AiTM, cookie theft,
MFA bypass, token replay or post-compromise state.

A defensible conclusion sounds like:

> The page showed a login host outside the local trust list and a cross-origin
> form action. IdP, EDR and proxy correlation is pending. No claim of AiTM or
> compromise is made.

It does not sound like:

> AiTM detected, MFA bypassed, session token stolen.

---

## References

- MITRE ATT&CK T1566.002: https://attack.mitre.org/techniques/T1566/002/
- MITRE ATT&CK T1539: https://attack.mitre.org/techniques/T1539/
- MITRE ATT&CK T1071.001: https://attack.mitre.org/techniques/T1071/001/
- MITRE ATT&CK T1556.006: https://attack.mitre.org/techniques/T1556/006/
- MITRE ATT&CK T1556.007: https://attack.mitre.org/techniques/T1556/007/
- Related note: `BROWSER-EXTENSION-ABUSE.md`
- Extension limits: `../browser-extension/README.md`
- Console evidence rules: `../BEST-PRACTICES.md`
