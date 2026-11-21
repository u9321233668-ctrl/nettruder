# Third-party notices and catalog provenance

NetTruder's console, engine, launchers, browser extension and project
documentation are licensed under the MIT License. See `LICENSE`,
Copyright (c) 2026 NetTruder Labs.

The repository also contains a trimmed source-study copy and references public
security taxonomies. Those materials are not relicensed by the MIT License.

## HEVD source study copy

`research/hevd-source/` is a trimmed copy of HackSys Extreme Vulnerable Driver
(HEVD), authored by HackSys Inc. and Payatu Software Labs LLP. It carries its
own `LICENSE` file, which is the GNU General Public License version 3, and its
source headers retain the original copyright and attribution. NetTruder does
not claim authorship of that code and does not relicense it.

The copy exists only so `CODE AUDIT` can read local source text and so the
source-only exercises in `research/HEVD-RESEARCH.md` can be followed. NetTruder
does not build, sign, install, load or execute the driver, and the repository
does not add exploit code, trigger steps, device requests or size values. The
Windows and Linux source trees are presented as reading material and as targets
for static review rules such as `NT-C-INT-WRAP`.

Original project: https://github.com/hacksysteam/HackSysExtremeVulnerableDriver

## Public catalog references

The defensive catalogs under `research/` are maintained in this repository as
reading aids. They list documented primitives together with telemetry,
detection context and hardening guidance. Technique identifiers and names
follow public taxonomies; the canonical projects are:

- LOLBAS Project: https://lolbas-project.github.io/
- GTFOBins: https://gtfobins.github.io/
- MITRE ATT&CK: https://attack.mitre.org/

`research/techniques.json` covers Windows living-off-the-land execution
primitives, `research/worm.json` covers Windows worm-like propagation shapes,
`research/gtfobins.json` covers Linux and Unix primitives, and
`research/hevd-catalog.json` covers source-study subjects. Their text is
defensive: it names what to record, how to harden and what cannot be concluded.
No catalog here contains exploitation syntax, payloads, credential values, C2
addresses or persistence recipes.

`research/blocks.json` records block messages observed during local testing.
Each entry names the product or policy signal and the lesson learned; no block
was bypassed and no blocked action was retried.

`research/AITM-PHISHING-SESSION-HIJACK.md` and
`research/BROWSER-EXTENSION-ABUSE.md` cite public MITRE ATT&CK technique pages.
Identity-plane controls that require verified telemetry, including FIDO2 /
WebAuthn, Continuous Access Evaluation and Conditional Access device
compliance, are recorded as `NOT EVALUATED` rather than inferred from page data.

## Browser extension

The extension in `browser-extension/` is part of NetTruder and is covered by the
same MIT License. It performs no network requests, reads no form or cookie
values and has no automatic data bridge to the console.
