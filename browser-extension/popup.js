'use strict';

/* NetTruder Site Posture - popup controller.
   All work is local. There is no fetch, no history read, and no active test. */

var S = {
  tab: null,
  dom: null,
  headers: null,
  redirects: null,
  permission: false,
  trustedHosts: [],
  err: '',
  reportText: '',
  encounters: []
};

var TRUST_KEY = 'nt-trusted-login-hosts';
var SESSION_COOKIE_RE = /(^|[-_])(session|sess|sid|auth|token|oauth|saml)([-_]|$)/i;
var ENCOUNTER_FIX = 'Stop and preserve the notice. Do not solve or bypass the challenge, and do not change headers, IP, User-Agent or browser controls. Use an authorised access path if legitimate access is needed. Review probe cadence separately.';
var AITM_FIX = 'These are passive indicators, not AiTM proof. Verify the link source, host spelling and IdP sign-in logs. Do not enter credentials until the destination is confirmed.';
var NL = String.fromCharCode(13, 10);

var HEADER_RULES = [
  {
    name: 'content-security-policy',
    label: 'Content-Security-Policy',
    fix: 'Set a restrictive CSP through the response header. Prefer it over a meta tag and review unsafe-inline carefully.'
  },
  {
    name: 'strict-transport-security',
    label: 'Strict-Transport-Security',
    fix: 'After validating HTTPS, set HSTS with a tested max-age and includeSubDomains only where correct.'
  },
  {
    name: 'x-content-type-options',
    label: 'X-Content-Type-Options',
    fix: 'Set nosniff so browsers do not guess a different MIME type.'
  },
  {
    name: 'x-frame-options',
    label: 'X-Frame-Options',
    fix: 'Use CSP frame-ancestors as the primary control; keep X-Frame-Options only as a legacy backstop.'
  },
  {
    name: 'referrer-policy',
    label: 'Referrer-Policy',
    fix: 'Set a documented policy such as strict-origin-when-cross-origin or no-referrer.'
  },
  {
    name: 'permissions-policy',
    label: 'Permissions-Policy',
    fix: 'Declare the browser features the site is allowed to use and deny the rest.'
  },
  {
    name: 'x-xss-protection',
    label: 'X-XSS-Protection (legacy)',
    fix: 'Usually set to 0 on modern sites. Use CSP instead; absence here is not automatically a defect.',
    optional: true
  },
  {
    name: 'content-type',
    label: 'Content-Type',
    fix: 'Set the correct MIME type and an explicit UTF-8 charset for HTML responses.'
  },
  {
    name: 'cross-origin-opener-policy',
    label: 'Cross-Origin-Opener-Policy',
    fix: 'Set a tested value such as same-origin when you need opener isolation.'
  },
  {
    name: 'cross-origin-embedder-policy',
    label: 'Cross-Origin-Embedder-Policy',
    fix: 'Set require-corp only after third-party resources are confirmed compatible.'
  },
  {
    name: 'cross-origin-resource-policy',
    label: 'Cross-Origin-Resource-Policy',
    fix: 'Set same-origin or same-site on resources that should not be embedded cross-origin.'
  }
];

function el(id) { return document.getElementById(id); }

function esc(value) {
  var s = String(value === null || value === undefined ? '' : value);
  return s.replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function clip(value, max) {
  var s = String(value === null || value === undefined ? '' : value);
  if (s.length > max) { return s.slice(0, max) + '...'; }
  return s;
}

function redactUrl(raw) {
  try {
    var u = new URL(String(raw || ''));
    var port = u.port ? ':' + u.port : '';
    return u.protocol + '//' + u.hostname + port + u.pathname;
  } catch (e) { return ''; }
}

function hostFromUrl(raw) {
  try {
    var u = new URL(String(raw || ''));
    return u.hostname || 'NO DATA';
  } catch (e) { return 'NO DATA'; }
}

function normaliseHostList(raw) {
  var out = [];
  var parts = String(raw || '').split(/[\s,;]+/);
  for (var i = 0; i < parts.length; i++) {
    var value = parts[i].trim().toLowerCase();
    if (!value) { continue; }
    if (value.indexOf('://') >= 0) {
      try { value = new URL(value).hostname; }
      catch (e) { continue; }
    }
    value = value.replace(/:\d+$/, '');
    if (!/^[a-z0-9.-]+$/.test(value)) { continue; }
    if (value.charAt(0) === '.' || value.charAt(value.length - 1) === '.') { continue; }
    if (out.indexOf(value) < 0) { out.push(value); }
  }
  return out;
}

function hostInList(host, list) {
  var h = String(host || '').toLowerCase();
  for (var i = 0; i < list.length; i++) {
    if (list[i] === h) { return true; }
  }
  return false;
}

function bindClick(id, fn) {
  var node = el(id);
  if (node) { node.addEventListener('click', fn); }
}

function setStatus(text) {
  var node = el('state');
  if (node) { node.textContent = String(text || ''); }
}

function chip(label, value, cls) {
  return '<span class="chip ' + esc(cls || '') + '"><b>' + esc(label) + '</b> '
    + esc(value === null || value === undefined ? '-' : value) + '</span>';
}

function findingHtml(f) {
  return '<details class="row ' + esc(f.sev || 'dim') + '">'
    + '<summary><span class="badge">' + esc(f.state || '-') + '</span>'
    + '<span class="title">' + esc(f.title || '') + '</span></summary>'
    + '<div class="rowbody">' + esc(f.detail || '')
    + '\r\n\r\nFIX: ' + esc(f.fix || 'No action needed.') + '</div></details>';
}

function appendFindingLines(lines, items) {
  for (var i = 0; i < items.length; i++) {
    lines.push('[' + items[i].state + '] ' + items[i].title);
    lines.push('  ' + items[i].detail);
    lines.push('  FIX: ' + items[i].fix);
  }
}

function dangerCount(dom, key, fallback) {
  if (dom.dangerousSummary && dom.dangerousSummary[key] !== undefined) {
    return dom.dangerousSummary[key];
  }
  return fallback;
}

function dangerExampleLines(items) {
  var lines = [];
  for (var i = 0; i < items.length; i++) {
    lines.push(items[i].scheme + ' ' + items[i].tag + '[' + items[i].attr
      + '] context=' + (items[i].context || 'attribute'));
  }
  if (!lines.length) { return 'No example in the first 12 rows.'; }
  return lines.join('\r\n');
}

function getActiveTab() {
  return new Promise(function (resolve) {
    chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
      resolve(tabs && tabs[0] ? tabs[0] : null);
    });
  });
}

function inspectable(url) {
  return !/^(chrome|edge|about|moz-extension|chrome-extension|devtools|view-source|file):/i.test(String(url || ''));
}

function getHeaders(tabId, url) {
  return new Promise(function (resolve) {
    try {
      chrome.runtime.sendMessage({ type: 'nt-get-headers', tabId: tabId, url: url }, function (record) {
        void chrome.runtime.lastError;
        resolve(record || null);
      });
    } catch (e) { resolve(null); }
  });
}

function getRedirects(tabId, url) {
  return new Promise(function (resolve) {
    try {
      chrome.runtime.sendMessage({ type: 'nt-get-redirects', tabId: tabId, url: url }, function (record) {
        void chrome.runtime.lastError;
        resolve(record || null);
      });
    } catch (e) { resolve(null); }
  });
}

function clearHeaders(tabId) {
  return new Promise(function (resolve) {
    try {
      chrome.runtime.sendMessage({ type: 'nt-clear-headers', tabId: tabId }, function (ok) {
        void chrome.runtime.lastError;
        resolve(!!ok);
      });
    } catch (e) { resolve(false); }
  });
}

function loadTrustedHosts() {
  try {
    chrome.storage.session.get(TRUST_KEY, function (data) {
      S.trustedHosts = normaliseHostList((data && data[TRUST_KEY]) || '');
      var box = el('trustedHosts');
      if (box) { box.value = S.trustedHosts.join('\r\n'); }
      renderTrustedHostState();
      renderLogin();
    });
  } catch (e) {
    S.trustedHosts = [];
    renderTrustedHostState();
  }
}

function saveTrustedHosts() {
  var box = el('trustedHosts');
  var raw = box ? box.value : '';
  var list = normaliseHostList(raw);
  S.trustedHosts = list;
  var payload = {};
  payload[TRUST_KEY] = list.join('\r\n');
  try {
    chrome.storage.session.set(payload, function () {
      void chrome.runtime.lastError;
      renderTrustedHostState();
      render();
      setStatus('LOCAL HOST LIST SAVED // NO DATA SENT');
    });
  } catch (e) {
    renderTrustedHostState();
    render();
    setStatus('LOCAL HOST LIST NOT SAVED');
  }
}

function renderTrustedHostState() {
  var node = el('trustedHostState');
  if (!node) { return; }
  node.textContent = S.trustedHosts.length
    ? ('LOCAL LIST: ' + S.trustedHosts.length + ' HOST(S) // SESSION ONLY')
    : 'NO LOCAL HOST LIST // HOST TRUST NOT EVALUATED';
}

function updateHeaderButton() {
  var btn = el('btnHeaders');
  if (btn) { btn.textContent = S.permission ? 'REVOKE HEADER READ' : 'GRANT HEADER READ'; }
}

function refreshPermission() {
  chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
    var tab = tabs && tabs[0];
    if (!tab || !tab.url || !/^https?:/i.test(tab.url)) {
      S.permission = false;
      updateHeaderButton();
      return;
    }
    try {
      var pattern = new URL(tab.url).origin + '/*';
      chrome.permissions.contains({ origins: [pattern] }, function (granted) {
        S.permission = !!granted;
        updateHeaderButton();
      });
    } catch (e) {
      S.permission = false;
      updateHeaderButton();
    }
  });
}

function runCheck() {
  setStatus('READING');
  S.dom = null;
  S.headers = null;
  S.redirects = null;
  S.err = '';
  S.reportText = '';

  getActiveTab().then(function (tab) {
    if (!tab || !tab.url) {
      S.err = 'No active page URL was available.';
      render();
      setStatus('NOT EVALUATED // NO ACTIVE TAB');
      return;
    }
    S.tab = tab;
    refreshPermission();

    if (!inspectable(tab.url)) {
      S.err = 'Browser internal, extension, view-source and file pages cannot be read by this extension.';
      render();
      setStatus('NOT EVALUATED // PAGE NOT READABLE');
      return;
    }

    chrome.scripting.executeScript({
      target: { tabId: tab.id },
      files: ['content.js']
    }, function (results) {
      if (chrome.runtime.lastError) {
        S.err = chrome.runtime.lastError.message || 'Injection was refused.';
        render();
        setStatus('NOT EVALUATED // INJECTION REFUSED');
        return;
      }
      S.dom = results && results[0] ? results[0].result : null;
      if (!S.dom) {
        S.err = 'The read-only DOM reader returned no result.';
        render();
        setStatus('NOT EVALUATED // NO DOM RESULT');
        return;
      }
      getHeaders(tab.id, tab.url).then(function (record) {
        S.headers = record;
        return getRedirects(tab.id, tab.url);
      }).then(function (record) {
        S.redirects = record;
        render();
        setStatus('OK // LOCAL READ // ' + (S.headers ? 'HEADERS CAPTURED' : 'HEADERS NOT EVALUATED'));
      });
    });
  });
}

function toggleHeaders() {
  chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
    var tab = tabs && tabs[0];
    if (!tab || !tab.url || !/^https?:/i.test(tab.url)) {
      setStatus('HEADER READ APPLIES TO HTTP(S) PAGES ONLY');
      return;
    }
    var pattern;
    try { pattern = new URL(tab.url).origin + '/*'; }
    catch (e) { setStatus('HEADER READ COULD NOT RESOLVE THIS ORIGIN'); return; }

    if (S.permission) {
      chrome.permissions.remove({ origins: [pattern] }, function () {
        S.permission = false;
        clearHeaders(tab.id);
        updateHeaderButton();
        render();
        setStatus('HEADER READ REVOKED // NO DATA SENT');
      });
      return;
    }

    chrome.permissions.request({ origins: [pattern] }, function (granted) {
      S.permission = !!granted;
      updateHeaderButton();
      if (S.permission) {
        clearHeaders(tab.id);
        setStatus('HEADER READ GRANTED // RELOAD TAB, THEN RUN CHECK');
      } else {
        setStatus('HEADER READ NOT GRANTED // CHECKS STAY READ-ONLY');
      }
      render();
    });
  });
}

function domFindings(dom) {
  var out = [];
  var h = (S.headers && S.headers.headers) || {};
  var known = !!S.headers;

  function add(sev, state, title, detail, fix) {
    out.push({ sev: sev, state: state, title: title, detail: detail, fix: fix || 'No action needed.' });
  }

  if (dom.secure) {
    add('good', 'OK', 'HTTPS transport', 'The page scheme is https.', 'Keep HTTPS and add HSTS only after validation.');
  } else {
    add('bad', 'EXPOSED', 'HTTP transport', 'The page scheme is http; there is no transport protection.', 'Serve the page over HTTPS and redirect http to https.');
  }

  if (!dom.secure) {
    add('dim', 'N/A', 'Loaded mixed content', 'Mixed-content grading applies to an https page. This page is http.', 'Check again after the site is served over HTTPS.');
  } else if (dom.mixedCount > 0) {
    var lines = [];
    for (var i = 0; i < dom.mixed.length; i++) {
      lines.push(dom.mixed[i].tag + '[' + dom.mixed[i].attr + '] ' + dom.mixed[i].target);
    }
    add('bad', 'FOUND', 'http loaded subresource references',
      dom.mixedCount + ' loaded http reference(s) on an https page. Redacted targets:\r\n' + lines.join('\r\n'),
      'Replace http subresources with https or host them locally.');
  } else {
    add('good', 'NONE SEEN', 'No http loaded subresource references',
      'No loaded http reference was found in the sampled subresource attributes.',
      'Keep loaded subresources on https and re-check after page changes.');
  }

  if (!dom.secure) {
    add('dim', 'N/A', 'Insecure navigation references', 'Navigation-reference grading applies to an https page. This page is http.', 'Check again after the site is served over HTTPS.');
  } else if ((dom.mixedNavCount || 0) > 0) {
    var navLines = [];
    for (var nv = 0; nv < dom.mixedNav.length; nv++) {
      var nav = dom.mixedNav[nv];
      navLines.push(nav.tag + '[' + nav.attr + ']'
        + (nav.rel ? ' rel=' + nav.rel : '') + ' ' + nav.target);
    }
    add('warn', 'FOUND', 'http navigation/metadata references',
      dom.mixedNavCount + ' http reference(s) on an https page. These are not loaded subresources. Redacted targets:\r\n' + navLines.join('\r\n'),
      'Change outbound and metadata links to https where supported. Confirm the rel value before treating this as mixed content.');
  } else {
    add('good', 'NONE SEEN', 'No insecure navigation references',
      'No http navigation or metadata reference was found in the sampled a, form and link attributes.',
      'Keep outbound links and metadata references on https where supported.');
  }

  var danger = dom.dangerous || [];
  var jsRefs = [];
  var dataRefs = [];
  var blobMediaRefs = [];
  var blobOtherRefs = [];
  for (var d = 0; d < danger.length; d++) {
    var ref = danger[d];
    var refContext = ref.context || 'attribute';
    if (ref.scheme === 'javascript:') {
      jsRefs.push(ref);
    } else if (ref.scheme === 'data:') {
      dataRefs.push(ref);
    } else if (ref.scheme === 'blob:' && refContext === 'media/preview') {
      blobMediaRefs.push(ref);
    } else if (ref.scheme === 'blob:') {
      blobOtherRefs.push(ref);
    }
  }
  var jsCount = dangerCount(dom, 'javascript', jsRefs.length);
  var dataCount = dangerCount(dom, 'data', dataRefs.length);
  var blobMediaCount = dangerCount(dom, 'blobMedia', blobMediaRefs.length);
  var blobOtherCount = dangerCount(dom, 'blobOther', blobOtherRefs.length);
  var totalDanger = jsCount + dataCount + blobMediaCount + blobOtherCount;

  if (!totalDanger) {
    add('good', 'NONE SEEN', 'No javascript:, data: or blob: URL references',
      'No sampled src, href or action attribute used one of these schemes. Scheme payload text is never read.',
      'Keep javascript: out of attributes, review data: by context and confirm blob: media URLs are expected.');
  } else {
    if (jsCount > 0) {
      add('bad', 'FOUND', 'javascript: URL references',
        jsCount + ' reference(s) in the sampled attributes. Scheme, tag, attribute and context only; payload text was not read.'
        + '\r\n' + dangerExampleLines(jsRefs),
        'Remove javascript: URLs from src, href and action attributes. Sanitise untrusted input and constrain script sources with CSP.');
    }
    if (dataCount > 0) {
      add('warn', 'REVIEW', 'data: URL references',
        dataCount + ' reference(s) in the sampled attributes. Review by context; payload text was not read.'
        + '\r\n' + dangerExampleLines(dataRefs),
        'Prefer https URLs or trusted local assets. If data: is required, confirm the context and constrain script or frame sources with CSP.');
    }
    if (blobMediaCount > 0) {
      add('dim', 'INFO', 'blob: media references',
        blobMediaCount + ' media/preview reference(s), such as video[src], audio[src] or source[src]. Scheme, tag, attribute and context only; payload text was not read.'
        + '\r\n' + dangerExampleLines(blobMediaRefs),
        'Usually legitimate for local previews or MediaRecorder output. Confirm the page created it from trusted local data and revokes object URLs when done. Do not remove a working preview just to clear this row.');
    }
    if (blobOtherCount > 0) {
      add('warn', 'REVIEW', 'blob: non-media references',
        blobOtherCount + ' non-media reference(s) in the sampled attributes. Review by context; payload text was not read.'
        + '\r\n' + dangerExampleLines(blobOtherRefs),
        'Confirm the blob was created from trusted local data. Avoid blob: in script, frame or navigation attributes and constrain script or frame sources with CSP.');
    }
  }

  if (dom.passwordFields > 0 && !dom.secure) {
    add('bad', 'EXPOSED', 'Password input on http',
      dom.passwordFields + ' password field(s) appear on an http page.',
      'Move the login form to HTTPS before any credential is entered.');
  } else if (dom.passwordFields > 0) {
    add('good', 'HTTPS', 'Password input on https',
      dom.passwordFields + ' password field(s) seen on an https page. Values were not read.',
      'Keep the login form on HTTPS and review autocomplete policy.');
  } else {
    add('dim', 'NONE', 'No password input seen', 'No password field was present in the DOM at read time.', 'No action needed.');
  }

  if (dom.badFormActions > 0) {
    add('warn', 'FOUND', 'Form action uses http on https',
      dom.badFormActions + ' form(s) submit to an http target from an https page.',
      'Change the form action to an https endpoint.');
  } else {
    add('good', 'NONE SEEN', 'No insecure form action seen',
      dom.formCount + ' form(s) checked; no http action was found on this https page.',
      'Keep form actions on https.');
  }

  if (h['content-security-policy']) {
    add('good', 'OK', 'CSP response header',
      'Captured: ' + clip(h['content-security-policy'], 220),
      'Review directives for unsafe-inline, unsafe-eval and overly broad sources.');
  } else if (known) {
    add('warn', 'MISSING', 'No CSP response header captured',
      'The captured main-frame response did not include Content-Security-Policy.',
      'Add a restrictive CSP response header with change control.');
  } else if (dom.cspMeta > 0) {
    add('warn', 'PARTIAL', 'CSP meta tag present',
      dom.cspMeta + ' CSP meta tag(s) found in the DOM. Header state is NOT EVALUATED until header read is granted and the tab is reloaded.',
      'Prefer a response header. A meta CSP is limited and cannot set frame-ancestors or report-only.');
  } else {
    add('dim', 'NOT EVALUATED', 'CSP not evaluated',
      'No CSP meta tag was found and no response header was captured.',
      'Grant header read for this origin, reload the tab, then run the check again.');
  }

  if (dom.cookieCount > 0) {
    add('dim', 'NAMES ONLY', 'Visible cookie names',
      'Names: ' + dom.cookieNames.join(', ') + '. Values and Secure, HttpOnly and SameSite flags are not visible to page JavaScript.',
      'Review cookie flags in DevTools or a header capture; do not expose cookie values in reports.');
  } else {
    add('dim', 'NONE VISIBLE', 'No non-HttpOnly cookie names visible',
      'HttpOnly cookies are deliberately invisible to page JavaScript. This is not proof that no cookies exist.',
      'Review Set-Cookie headers in DevTools when you need the full flag state.');
  }

  if (dom.inlineHandlers > 0) {
    add('warn', 'FOUND', 'Inline event handler attributes (sample)',
      dom.inlineHandlers + ' element(s) matched the sampled on* attribute set.',
      'Move handlers to external scripts and constrain them with CSP.');
  } else {
    add('good', 'NONE', 'No sampled inline handlers',
      'No element matched the sampled on* attributes.',
      'Keep new code free of inline handlers.');
  }

  add('dim', 'COUNT', 'Script and frame surface',
    'External scripts: ' + dom.externalScripts + '. Inline scripts: ' + dom.inlineScripts + '. Iframes: ' + dom.iframes + '. No script content was read.',
    'Review third-party scripts, consider SRI where appropriate, and constrain frames with CSP frame-ancestors.');

  var sriMissing = (dom.sriMissingScripts || 0) + (dom.sriMissingStyles || 0);
  var crossOrigin = (dom.crossOriginScripts || 0) + (dom.crossOriginStyles || 0);
  if (sriMissing > 0) {
    add('warn', 'FOUND', 'Cross-origin resources without SRI',
      sriMissing + ' of ' + crossOrigin + ' cross-origin script/style reference(s) had no integrity attribute.',
      'Add SRI hashes for pinned third-party assets and keep them updated with change control.');
  } else if (crossOrigin > 0) {
    add('good', 'OK', 'Cross-origin SRI present',
      crossOrigin + ' cross-origin script/style reference(s) checked; all had an integrity attribute.',
      'Keep SRI hashes updated and review third-party dependencies.');
  } else {
    add('dim', 'N/A', 'Cross-origin SRI not applicable',
      'No cross-origin script or stylesheet reference was found in this read.',
      'Recheck after third-party assets are added.');
  }

  if (!dom.iframes) {
    add('dim', 'N/A', 'Iframe isolation not applicable', 'No iframe was present in the DOM at read time.', 'No action needed.');
  } else if ((dom.framesWithoutSandbox || 0) > 0 || (dom.framesWithWeakSandbox || 0) > 0) {
    add('warn', 'FOUND', 'Iframe isolation gap',
      (dom.framesWithoutSandbox || 0) + ' iframe(s) without sandbox; '
      + (dom.framesWithWeakSandbox || 0) + ' iframe(s) with a broad or risky sandbox token set.',
      'Add sandbox with least privilege. Avoid allow-scripts plus allow-same-origin unless required, and set CSP frame-ancestors.');
  } else {
    add('good', 'OK', 'Iframe sandbox seen',
      dom.iframes + ' iframe(s) had a sandbox attribute without the sampled risky combinations.',
      'Keep sandbox least-privilege and set CSP frame-ancestors.');
  }

  if (!dom.blankLinks) {
    add('dim', 'N/A', 'Reverse tabnabbing not applicable', 'No target="_blank" link was found in this read.', 'No action needed.');
  } else if ((dom.blankWithoutRel || 0) > 0) {
    add('warn', 'FOUND', 'New-tab links without rel',
      (dom.blankWithoutRel || 0) + ' of ' + dom.blankLinks + ' target="_blank" link(s) lacked noopener or noreferrer.',
      'Add rel="noopener noreferrer" to every target="_blank" link.');
  } else {
    add('good', 'OK', 'New-tab links isolated',
      dom.blankLinks + ' target="_blank" link(s) included noopener and noreferrer.',
      'Keep rel tokens on new-tab links.');
  }

  if ((dom.cspViolationCount || 0) > 0) {
    var violationLines = [];
    for (var v = 0; v < dom.cspViolations.length; v++) {
      var cv = dom.cspViolations[v];
      violationLines.push(cv.directive + ' blocked=' + cv.blocked + ' source=' + cv.source + ' line=' + cv.line);
    }
    add('warn', 'FOUND', 'CSP violations observed',
      dom.cspViolationCount + ' browser-generated CSP violation event(s) seen passively. Redacted summary:'
      + '\r\n' + violationLines.join('\r\n'),
      'Fix the CSP directive or remove the blocked resource. NetTruder did not cause these violations.');
  } else {
    add('dim', 'NONE SEEN', 'No CSP violations observed',
      'No securitypolicyviolation event was seen during this read. This is not proof that CSP is strong.',
      'Review the CSP response header separately; absence of an event can mean no CSP or no violation.');
  }

  add('good', 'READ ONLY', 'No active test executed',
    'This check read DOM structure, passive browser events and optional response headers only. No request was modified, no page script text was run, and no block was attempted.',
    'No action needed.');

  return out;
}

function errorFinding(err) {
  return [{
    sev: 'warn',
    state: 'NOT EVALUATED',
    title: 'Page check unavailable',
    detail: err || 'The page could not be read.',
    fix: 'Open an ordinary http(s) page, grant only the read access you need, and run the check again. Do not change a security control to make the extension work.'
  }];
}

function headerStateText() {
  if (!S.tab || !S.tab.url || !/^https?:/i.test(S.tab.url)) { return 'NOT APPLICABLE'; }
  if (!S.permission) { return 'OPT IN REQUIRED'; }
  if (!S.headers) { return 'WAITING FOR RELOAD'; }
  return 'CAPTURED';
}

function renderSummary() {
  var box = el('summary');
  if (!box) { return; }
  var d = S.dom;
  var hs = headerStateText();
  var hsCls = hs === 'CAPTURED' ? 'good' : (hs === 'OPT IN REQUIRED' ? 'warn' : 'dim');
  box.innerHTML =
    chip('SITE', d ? d.host : (redactUrl(S.tab && S.tab.url) || 'NO DATA'), 'dim')
    + chip('SCHEME', d ? d.scheme.toUpperCase() : '-', d ? (d.secure ? 'good' : 'bad') : 'dim')
    + chip('MIXED', d ? d.mixedCount : '-', d && d.mixedCount ? 'bad' : 'dim')
    + chip('COOKIES', d ? d.cookieCount : '-', 'dim')
    + chip('HEADERS', hs, hsCls)
    + chip('MODE', 'READ ONLY', 'good');
}

function renderHeaders() {
  var box = el('headers');
  var label = el('headerState');
  if (!box) { return; }
  var text = headerStateText();
  if (label) { label.textContent = text; }

  if (text === 'NOT APPLICABLE') {
    box.innerHTML = findingHtml({
      sev: 'dim', state: text, title: 'Header read not applicable',
      detail: 'Header capture runs for http(s) pages only. Browser internal and file pages stay NOT EVALUATED.',
      fix: 'Open an http(s) page if you need a header review.'
    });
    return;
  }
  if (text === 'OPT IN REQUIRED') {
    box.innerHTML = findingHtml({
      sev: 'warn', state: text, title: 'Read-only header access not granted',
      detail: 'The extension has no host access by default. DOM checks still run; response headers stay NOT EVALUATED.',
      fix: 'Use GRANT HEADER READ for this origin, reload the tab, then run the check. You can revoke it with the same button.'
    });
    return;
  }
  if (text === 'WAITING FOR RELOAD') {
    box.innerHTML = findingHtml({
      sev: 'warn', state: text, title: 'Permission granted; no matching response captured',
      detail: 'NetTruder does not reload the tab for you. The last captured response does not match this URL.',
      fix: 'Reload this tab, then press RUN READ-ONLY CHECK. Nothing was sent or changed.'
    });
    return;
  }

  var html = [];
  var captured = S.headers.headers || {};
  for (var i = 0; i < HEADER_RULES.length; i++) {
    var rule = HEADER_RULES[i];
    var value = captured[rule.name];
    if (value !== undefined) {
      html.push(findingHtml({
        sev: 'good', state: 'PRESENT', title: rule.label,
        detail: clip(value, 240), fix: rule.fix
      }));
    } else if (rule.optional) {
      html.push(findingHtml({
        sev: 'dim', state: 'ABSENT', title: rule.label,
        detail: 'Legacy header not present. This is informational, not a defect by itself.', fix: rule.fix
      }));
    } else {
      html.push(findingHtml({
        sev: 'warn', state: 'MISSING', title: rule.label,
        detail: 'Not present in the captured main-frame response.', fix: rule.fix
      }));
    }
  }
  box.innerHTML = html.join('');
}

function headerVal(name) {
  var h = (S.headers && S.headers.headers) || {};
  return h[name];
}

function qualityFindings() {
  var out = [];
  function add(sev, state, title, detail, fix) {
    out.push({ sev: sev, state: state, title: title, detail: detail, fix: fix });
  }

  if (!S.headers) {
    add('dim', 'NOT EVALUATED', 'Header quality not evaluated',
      'No matching main-frame response was captured. Header values stay NOT EVALUATED, not clean.',
      'Grant header read for this origin, reload the tab, then run the check again.');
    return out;
  }

  var csp = headerVal('content-security-policy');
  if (!csp) {
    add('warn', 'MISSING', 'CSP response header',
      'No Content-Security-Policy header was captured.',
      'Add a restrictive CSP response header with change control.');
  } else {
    var lowerCsp = csp.toLowerCase();
    var cspIssues = [];
    if (lowerCsp.indexOf('unsafe-inline') >= 0) { cspIssues.push('unsafe-inline'); }
    if (lowerCsp.indexOf('unsafe-eval') >= 0) { cspIssues.push('unsafe-eval'); }
    if (lowerCsp.indexOf('object-src') < 0) { cspIssues.push('no object-src'); }
    if (lowerCsp.indexOf('frame-ancestors') < 0) { cspIssues.push('no frame-ancestors'); }
    if (lowerCsp.indexOf('base-uri') < 0) { cspIssues.push('no base-uri'); }
    if (cspIssues.length) {
      add('warn', 'WEAK', 'CSP response header',
        'Captured CSP has review points: ' + cspIssues.join(', ') + '.' + NL + clip(csp, 220),
        'Remove unsafe-inline and unsafe-eval, and add object-src, frame-ancestors and base-uri where appropriate.');
    } else {
      add('good', 'OK', 'CSP response header',
        'Captured CSP has no sampled unsafe tokens and includes key directives.' + NL + clip(csp, 220),
        'Keep the CSP under change control and review new third-party sources.');
    }
  }

  var hsts = headerVal('strict-transport-security');
  if (!hsts) {
    add('warn', 'MISSING', 'Strict-Transport-Security',
      'No HSTS header was captured.',
      'After validating HTTPS, set HSTS with a tested max-age and includeSubDomains only where correct.');
  } else {
    var m = /max-age\s*=\s*(\d+)/i.exec(hsts);
    var age = m ? Number(m[1]) : -1;
    var hstsIssues = [];
    if (age < 31536000) { hstsIssues.push('max-age below 31536000'); }
    if (hsts.toLowerCase().indexOf('includesubdomains') < 0) { hstsIssues.push('no includeSubDomains'); }
    if (hstsIssues.length) {
      add('warn', 'WEAK', 'Strict-Transport-Security',
        'HSTS review points: ' + hstsIssues.join(', ') + '.' + NL + clip(hsts, 220),
        'Use a tested max-age and add includeSubDomains only after subdomain review.');
    } else {
      add('good', 'OK', 'Strict-Transport-Security',
        'HSTS has a long max-age and includeSubDomains.' + NL + clip(hsts, 220),
        'Keep the HSTS policy under change control.');
    }
  }

  var ref = headerVal('referrer-policy');
  if (!ref) {
    add('warn', 'MISSING', 'Referrer-Policy',
      'No Referrer-Policy header was captured.',
      'Set strict-origin-when-cross-origin or no-referrer according to your data policy.');
  } else if (/unsafe-url|no-referrer-when-downgrade/i.test(ref)) {
    add('bad', 'WEAK', 'Referrer-Policy',
      'Captured policy can leak path or origin information.' + NL + clip(ref, 220),
      'Use strict-origin-when-cross-origin or no-referrer unless a weaker policy is documented.');
  } else {
    add('good', 'OK', 'Referrer-Policy', 'Captured: ' + clip(ref, 220), 'Keep the documented referrer policy.');
  }

  var perms = headerVal('permissions-policy');
  if (!perms) {
    add('warn', 'MISSING', 'Permissions-Policy',
      'No Permissions-Policy header was captured.',
      'Declare allowed browser features explicitly and deny the rest.');
  } else if (/\*\s*\)/.test(perms)) {
    add('warn', 'BROAD', 'Permissions-Policy',
      'Captured policy contains a wildcard for at least one feature.' + NL + clip(perms, 220),
      'Replace wildcards with an explicit allowlist of origins.');
  } else {
    add('good', 'OK', 'Permissions-Policy', 'Captured: ' + clip(perms, 220), 'Keep the feature allowlist minimal.');
  }

  var isolation = [
    ['cross-origin-opener-policy', 'Cross-Origin-Opener-Policy',
      'Set same-origin when opener isolation is required and tested.'],
    ['cross-origin-embedder-policy', 'Cross-Origin-Embedder-Policy',
      'Set require-corp only after third-party resources are confirmed compatible.'],
    ['cross-origin-resource-policy', 'Cross-Origin-Resource-Policy',
      'Set same-origin or same-site on resources that should not be embedded cross-origin.']
  ];
  for (var i = 0; i < isolation.length; i++) {
    var value = headerVal(isolation[i][0]);
    if (!value) {
      add('dim', 'NOT SET', isolation[i][1],
        'Header not present in the captured response. This is context-dependent, not automatically a defect.',
        isolation[i][2]);
    } else {
      add('good', 'PRESENT', isolation[i][1], 'Captured: ' + clip(value, 220), isolation[i][2]);
    }
  }

  return out;
}

function cookieFlagFindings() {
  var out = [];
  if (!S.headers) {
    out.push({
      sev: 'dim', state: 'NOT EVALUATED', title: 'Cookie flags not evaluated',
      detail: 'No matching response was captured. Header-based Set-Cookie flags stay NOT EVALUATED.',
      fix: 'Grant header read for this origin, reload the tab, then run the check again.'
    });
    return out;
  }

  var list = S.headers.headers['set-cookie-flags'] || [];
  if (!list.length) {
    out.push({
      sev: 'dim', state: 'NONE CAPTURED', title: 'No Set-Cookie flags captured',
      detail: 'No Set-Cookie header was present in the captured main-frame response. Cookie values are never read.',
      fix: 'Review Set-Cookie headers in DevTools when you need the full flag state.'
    });
    return out;
  }

  for (var i = 0; i < list.length; i++) {
    var summary = list[i];
    var lower = summary.toLowerCase();
    var missing = [];
    if (lower.indexOf('secure') < 0) { missing.push('Secure'); }
    if (lower.indexOf('httponly') < 0) { missing.push('HttpOnly'); }
    if (/^samesite=/i.test(summary)) {
      if (/samesite=none/i.test(summary) && lower.indexOf('secure') < 0) {
        missing.push('Secure for SameSite=None');
      }
    } else {
      missing.push('SameSite');
    }
    out.push({
      sev: missing.length ? 'warn' : 'good',
      state: missing.length ? 'WEAK' : 'OK',
      title: 'Cookie flag summary',
      detail: 'Names and flags only; no value was captured.' + NL + summary
        + NL + 'Review points: ' + (missing.length ? missing.join(', ') : 'none seen'),
      fix: 'Set Secure, HttpOnly and an explicit SameSite value where appropriate. Never include cookie values in reports.'
    });
  }
  return out;
}

function sessionCookieFindings() {
  var out = [];
  if (!S.headers) {
    out.push({
      sev: 'dim', state: 'NOT EVALUATED', title: 'Session cookie flags not evaluated',
      detail: 'No matching main-frame response was captured. Session cookie flags stay NOT EVALUATED.',
      fix: 'Grant header read for this origin, reload the tab, then run the check again.'
    });
    return out;
  }

  var list = S.headers.headers['set-cookie-flags'] || [];
  var sessions = [];
  for (var i = 0; i < list.length; i++) {
    var name = String(list[i]).split(';')[0].trim();
    if (SESSION_COOKIE_RE.test(name)) { sessions.push(list[i]); }
  }
  if (!sessions.length) {
    out.push({
      sev: 'dim', state: 'NONE SEEN', title: 'No session-like cookie flags captured',
      detail: 'No captured Set-Cookie name matched the local session-name sample. Cookie values are never read.',
      fix: 'Review IdP session telemetry; absence here is not proof that no session cookie exists.'
    });
    return out;
  }

  var weak = [];
  for (var s = 0; s < sessions.length; s++) {
    var summary = sessions[s];
    var lower = summary.toLowerCase();
    var missing = [];
    if (lower.indexOf('secure') < 0) { missing.push('Secure'); }
    if (lower.indexOf('httponly') < 0) { missing.push('HttpOnly'); }
    if (!/samesite=/i.test(summary)) { missing.push('SameSite'); }
    if (missing.length) { weak.push(String(summary).split(';')[0].trim() + ': ' + missing.join(', ')); }
  }
  if (weak.length) {
    out.push({
      sev: 'warn', state: 'WEAK', title: 'Session cookie flag review',
      detail: weak.length + ' session-like cookie(s) have review points. Names and flags only; no value was read.'
        + NL + weak.join(NL),
      fix: 'Set Secure, HttpOnly and an explicit SameSite value where appropriate. Correlate with IdP session logs; never expose cookie values.'
    });
  } else {
    out.push({
      sev: 'good', state: 'OK', title: 'Session cookie flags present',
      detail: sessions.length + ' session-like cookie(s) had Secure, HttpOnly and SameSite in the captured flags. No value was read.',
      fix: 'Keep the flags under change control and review IdP session lifetimes and replay telemetry.'
    });
  }
  return out;
}

function loginFindings() {
  var out = [];
  function add(sev, state, title, detail, fix) {
    out.push({ sev: sev, state: state, title: title, detail: detail, fix: fix || AITM_FIX });
  }

  var dom = S.dom;
  if (!dom) {
    add('dim', 'NOT EVALUATED', 'Login indicators not evaluated',
      'No page read is available. Login and AiTM indicators stay NOT EVALUATED.',
      'Open an ordinary http(s) page, then press RUN READ-ONLY CHECK.');
    return out;
  }

  var host = dom.hostname || 'NOT EVALUATED';
  var hasLogin = (dom.passwordFields || 0) > 0 || (dom.passwordFormCount || 0) > 0;

  if (!hasLogin) {
    add('dim', 'N/A', 'Login host trust not applicable',
      'No password field or password form was seen in this DOM read.',
      'No action needed. Recheck on the actual sign-in page.');
  } else if (!S.trustedHosts.length) {
    add('warn', 'NOT EVALUATED', 'Login host trust',
      'A login surface was seen on ' + host + ', but no trusted IdP hostnames are configured locally.',
      'Add exact IdP hostnames under TRUSTED LOGIN HOSTS. The list stays in this browser session.');
  } else if (hostInList(host, S.trustedHosts)) {
    add('good', 'TRUSTED', 'Login host trust',
      'Password surface seen on ' + host + '. This host matches the local trusted host list.',
      'Keep the local list reviewed and still verify IdP sign-in logs. A trusted host does not prove the session is clean.');
  } else {
    add('warn', 'REVIEW', 'Login host trust',
      'Password surface seen on ' + host + '. This host does not match the local trusted host list. No credential value was read.',
      AITM_FIX);
  }

  var flags = dom.hostFlags || [];
  if (!hasLogin || !flags.length) {
    add('dim', 'NONE SEEN', 'Lookalike host features',
      'No sampled lookalike hostname feature was reported on ' + host + '. This is not proof that the host is legitimate.',
      'Keep exact host allowlists and verify unexpected links through a trusted channel.');
  } else {
    add('warn', 'REVIEW', 'Lookalike host features',
      'Host ' + host + ' has sampled features: ' + flags.join(', ') + '. These are context signals only.',
      AITM_FIX);
  }

  if (!dom.passwordFormCount) {
    add('dim', 'N/A', 'Login form action origin',
      'No password form was associated with a form element in this read.',
      'Recheck on the actual sign-in page if needed.');
  } else if ((dom.crossOriginLoginFormCount || 0) > 0) {
    var actionLines = [];
    for (var a = 0; a < dom.crossOriginLoginForms.length; a++) {
      var fa = dom.crossOriginLoginForms[a];
      actionLines.push('action origin=' + fa.actionOrigin + ' target=' + fa.target);
    }
    add('warn', 'REVIEW', 'Login form action origin',
      dom.crossOriginLoginFormCount + ' password form(s) submit to a different origin. No value was read.'
      + NL + actionLines.join(NL),
      AITM_FIX);
  } else {
    add('good', 'SAME ORIGIN', 'Login form action origin',
      dom.passwordFormCount + ' password form(s) checked; no cross-origin action was found.',
      'Keep login actions on the expected IdP origin and verify IdP logs for anomalies.');
  }

  if (!S.permission) {
    add('dim', 'NOT EVALUATED', 'Main-frame redirect chain',
      'Redirect observation needs the same per-origin header grant. No redirect evidence was captured.',
      'Grant header read for this origin, reload the tab, then run the check again.');
  } else if (!S.headers) {
    add('dim', 'WAITING FOR RELOAD', 'Main-frame redirect chain',
      'Permission is granted, but no matching main-frame response was captured for this URL.',
      'Reload this tab, then press RUN READ-ONLY CHECK. NetTruder does not reload it for you.');
  } else {
    var hops = (S.redirects && S.redirects.hops) || [];
    if (!hops.length) {
      add('good', 'NONE SEEN', 'Main-frame redirect chain',
        'No main-frame redirect hop was observed in the captured navigation. Absence is not proof that no redirect occurred earlier.',
        'Correlate with IdP and proxy logs when investigating a suspicious login.');
    } else {
      var hopLines = [];
      for (var r = 0; r < hops.length; r++) {
        hopLines.push(hops[r].from + ' -> ' + hops[r].to);
      }
      add('warn', 'REVIEW', 'Main-frame redirect chain',
        hops.length + ' main-frame redirect hop(s) observed. Redacted hosts only:'
        + NL + hopLines.join(NL),
        AITM_FIX);
    }
  }

  var sessionItems = sessionCookieFindings();
  for (var c = 0; c < sessionItems.length; c++) {
    out.push(sessionItems[c]);
  }

  add('dim', 'INDICATORS ONLY', 'AiTM detection limit',
    'NetTruder cannot see TLS termination, cookie values, MFA bypass, token replay or post-compromise state from a page read.',
    'Confirm with IdP sign-in logs, EDR, proxy and SIEM telemetry. Do not treat this section as proof of compromise.');

  return out;
}

function renderLogin() {
  var box = el('loginIndicators');
  var label = el('loginState');
  if (!box) { return; }
  var items = loginFindings();
  var html = [];
  for (var i = 0; i < items.length; i++) { html.push(findingHtml(items[i])); }
  box.innerHTML = html.join('');
  if (label) { label.textContent = S.dom ? (items.length + ' INDICATORS') : 'NOT EVALUATED'; }
}

function renderQuality() {
  var box = el('quality');
  var label = el('qualityState');
  if (!box) { return; }
  var items = qualityFindings();
  var html = [];
  for (var i = 0; i < items.length; i++) { html.push(findingHtml(items[i])); }
  box.innerHTML = html.join('');
  if (label) { label.textContent = S.headers ? (items.length + ' CHECKS') : 'NOT EVALUATED'; }
}

function renderCookieFlags() {
  var box = el('cookieFlagList');
  var label = el('cookieFlagState');
  if (!box) { return; }
  var items = cookieFlagFindings();
  var html = [];
  for (var i = 0; i < items.length; i++) { html.push(findingHtml(items[i])); }
  box.innerHTML = html.join('');
  if (label) { label.textContent = S.headers ? (items.length + ' ROW(S)') : 'NOT EVALUATED'; }
}

function encounterFinding(rec) {
  var sev = rec.outcome === 'BLOCKED' ? 'bad'
    : (rec.outcome === 'CHALLENGE OBSERVED' ? 'warn' : 'dim');
  return {
    sev: sev,
    state: rec.outcome,
    title: rec.type,
    detail: 'Type: ' + rec.type
      + NL + 'Outcome: ' + rec.outcome
      + NL + 'Observed: ' + rec.at
      + NL + 'Host: ' + rec.host
      + NL + 'Page: ' + rec.page
      + NL + 'Source: website anti-abuse control. NetTruder did not solve, click, analyse images, capture tokens, retry, or change headers, IP or User-Agent.',
    fix: ENCOUNTER_FIX
  };
}

function renderEncounters() {
  var box = el('encounters');
  var count = el('encCount');
  var label = el('encounterState');
  if (!box) { return; }
  if (count) { count.textContent = String(S.encounters.length); }

  if (!S.encounters.length) {
    box.innerHTML = findingHtml({
      sev: 'dim',
      state: 'NONE',
      title: 'No control encounters recorded',
      detail: 'Records here are manual only. NetTruder never detects, selects, solves or retries a challenge on your behalf.',
      fix: 'If a site presents a challenge, record it here and stop. Do not weaken browser, network or endpoint controls to continue.'
    });
    if (label) { label.textContent = 'NO ENCOUNTERS // MANUAL ONLY'; }
    return;
  }

  var html = [];
  for (var i = 0; i < S.encounters.length; i++) {
    html.push(findingHtml(encounterFinding(S.encounters[i])));
  }
  box.innerHTML = html.join('');
  if (label) {
    label.textContent = S.encounters.length + ' MANUAL RECORD(S) // NO INTERACTION';
  }
}

function recordEncounter() {
  var typeNode = el('encType');
  var outcomeNode = el('encOutcome');
  var type = typeNode ? typeNode.value : 'Other observed control';
  var outcome = outcomeNode ? outcomeNode.value : 'CHALLENGE OBSERVED';

  getActiveTab().then(function (tab) {
    var url = tab && tab.url ? tab.url : '';
    S.encounters.push({
      at: new Date().toISOString(),
      type: type,
      outcome: outcome,
      host: hostFromUrl(url),
      page: redactUrl(url) || 'NO DATA'
    });
    renderEncounters();
    S.reportText = buildReportText();
    setStatus('CONTROL ENCOUNTER RECORDED // NO INTERACTION');
  });
}

function clearEncounters() {
  S.encounters = [];
  renderEncounters();
  S.reportText = buildReportText();
  setStatus('CONTROL ENCOUNTER RECORDS CLEARED // NO DATA SENT');
}

function buildReportText() {
  var lines = [];
  var findings = S.dom ? domFindings(S.dom) : errorFinding(S.err);
  lines.push('NETTRUDER SITE POSTURE REPORT');
  lines.push('Generated: ' + new Date().toISOString());
  lines.push('Page: ' + (S.dom ? S.dom.redactedUrl : (redactUrl(S.tab && S.tab.url) || 'NO DATA')));
  lines.push('Boundary: ' + (S.dom ? S.dom.boundary : 'No page data was read.'));
  lines.push('');
  lines.push('FINDINGS');
  appendFindingLines(lines, findings);
  lines.push('');
  lines.push('HEADER QUALITY / ' + (S.headers ? 'EVALUATED' : 'NOT EVALUATED'));
  appendFindingLines(lines, qualityFindings());
  lines.push('');
  lines.push('COOKIE FLAGS / ' + (S.headers ? 'EVALUATED' : 'NOT EVALUATED'));
  appendFindingLines(lines, cookieFlagFindings());
  lines.push('');
  lines.push('LOGIN / AITM INDICATORS / ' + (S.dom ? 'INDICATORS ONLY' : 'NOT EVALUATED'));
  lines.push('Trusted local hosts: ' + S.trustedHosts.length + ' (session only, hosts never values)');
  appendFindingLines(lines, loginFindings());
  lines.push('');
  lines.push('HEADERS / ' + headerStateText());
  for (var j = 0; j < HEADER_RULES.length; j++) {
    var r = HEADER_RULES[j];
    var v = S.headers ? S.headers.headers[r.name] : undefined;
    lines.push('[' + (v !== undefined ? 'PRESENT' : (S.headers ? 'MISSING' : 'NOT EVALUATED')) + '] ' + r.label
      + (v !== undefined ? ' = ' + clip(v, 240) : ''));
  }
  lines.push('');
  lines.push('CONTROL ENCOUNTERS / ' + S.encounters.length);
  if (!S.encounters.length) {
    lines.push('[NONE] No manual control encounter recorded.');
  } else {
    for (var k = 0; k < S.encounters.length; k++) {
      var ef = encounterFinding(S.encounters[k]);
      lines.push('[' + ef.state + '] ' + ef.title);
      lines.push('  ' + ef.detail);
      lines.push('  FIX: ' + ef.fix);
    }
  }
  lines.push('');
  lines.push('No browser history was read. No cookie, token or credential value was read. Control encounters are manual records only. No data was sent anywhere. No blocked command was retried.');
  return lines.join('\r\n');
}

function render() {
  var findings = S.dom ? domFindings(S.dom) : errorFinding(S.err);
  var findBox = el('findings');
  var count = el('findCount');
  if (findBox) {
    var html = [];
    for (var i = 0; i < findings.length; i++) { html.push(findingHtml(findings[i])); }
    findBox.innerHTML = html.join('');
  }
  if (count) { count.textContent = String(findings.length); }
  renderSummary();
  renderHeaders();
  renderQuality();
  renderCookieFlags();
  renderLogin();
  renderEncounters();
  S.reportText = buildReportText();
  var copy = el('btnCopy');
  if (copy) { copy.disabled = !S.dom && !S.headers && !S.encounters.length; }
}

function fallbackCopy() {
  var area = document.createElement('textarea');
  area.value = S.reportText;
  area.setAttribute('readonly', 'readonly');
  area.style.position = 'fixed';
  area.style.top = '-1000px';
  document.body.appendChild(area);
  area.select();
  var ok = false;
  try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
  document.body.removeChild(area);
  setStatus(ok ? 'REPORT COPIED' : 'COPY FAILED // SELECT TEXT MANUALLY');
}

function copyReport() {
  if (!S.reportText) { return; }
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(S.reportText).then(function () {
      setStatus('REPORT COPIED');
    }, function () {
      fallbackCopy();
    });
  } else {
    fallbackCopy();
  }
}

bindClick('btnRun', runCheck);
bindClick('btnHeaders', toggleHeaders);
bindClick('btnCopy', copyReport);
bindClick('btnSaveTrustedHosts', saveTrustedHosts);
bindClick('btnRecordEncounter', recordEncounter);
bindClick('btnClearEncounters', clearEncounters);

loadTrustedHosts();
refreshPermission();
render();
setStatus('READY // LOCAL ONLY // NO DATA SENT');
