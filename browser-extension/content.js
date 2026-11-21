(function () {
  'use strict';

  /* NetTruder Site Posture - injected read-only DOM reader.
     It reads structure and attribute names only. It does not read form values,
     does not execute page script text, and does not follow any link. */

  function clip(value, max) {
    var s = String(value === null || value === undefined ? '' : value);
    if (s.length > max) { return s.slice(0, max) + '...'; }
    return s;
  }

  function absolute(raw) {
    try { return new URL(String(raw || ''), location.href).href; }
    catch (e) { return ''; }
  }

  function redacted(raw) {
    try {
      var u = new URL(String(raw || ''), location.href);
      var port = u.port ? ':' + u.port : '';
      return u.protocol + '//' + u.hostname + port + u.pathname;
    } catch (e) { return ''; }
  }

  function originOf(raw) {
    var full = absolute(raw);
    if (!full) { return ''; }
    try { return new URL(full).origin; }
    catch (e) { return ''; }
  }

  function isHttp(raw) {
    return /^http:/i.test(String(raw || ''));
  }

  function schemeOf(raw) {
    var s = String(raw || '').replace(/^\s+/, '');
    var m = /^([a-z][a-z0-9+.-]*):/i.exec(s);
    return m ? m[1].toLowerCase() : '';
  }

  function safeTarget(raw) {
    var scheme = schemeOf(raw);
    if (scheme === 'javascript' || scheme === 'data' || scheme === 'blob') {
      return scheme + ':';
    }
    return clip(redacted(raw), 180);
  }

  /* Passive CSP violation observer. The browser generates these events;
     NetTruder only records a redacted summary and never causes a violation. */
  var CSP_KEY = '__ntCspViolations';
  if (!window[CSP_KEY]) {
    window[CSP_KEY] = [];
    window.addEventListener('securitypolicyviolation', function (e) {
      var list = window[CSP_KEY];
      list.push({
        at: new Date().toISOString(),
        directive: clip(e.violatedDirective || e.effectiveDirective || 'unknown', 80),
        blocked: safeTarget(e.blockedURI),
        source: e.sourceFile ? clip(redacted(e.sourceFile), 180) : 'NOT EVALUATED',
        line: Number(e.lineNumber || 0)
      });
      if (list.length > 20) { list.shift(); }
    }, true);
  }
  var cspEvents = window[CSP_KEY] || [];

  var doc = document;
  var page = location.href;
  var secure = /^https:/i.test(String(location.protocol || ''));
  var pageOrigin = '';
  try { pageOrigin = location.origin; } catch (e) { pageOrigin = ''; }
  var hostname = String(location.hostname || '');

  var pairs = [
    ['script', 'src'],
    ['img', 'src'],
    ['iframe', 'src'],
    ['link', 'href'],
    ['audio', 'src'],
    ['video', 'src'],
    ['source', 'src'],
    ['form', 'action'],
    ['a', 'href']
  ];

  var LOADED_LINK_RELS = [
    'stylesheet', 'preload', 'modulepreload', 'icon', 'shortcut',
    'apple-touch-icon', 'manifest', 'preconnect'
  ];

  function linkLoadsResource(node) {
    var rel = String(node.getAttribute('rel') || '').toLowerCase();
    var tokens = rel.split(/\s+/);
    for (var r = 0; r < tokens.length; r++) {
      if (LOADED_LINK_RELS.indexOf(tokens[r]) >= 0) { return true; }
    }
    return false;
  }

  function schemeContext(tag, attr) {
    if (tag === 'video' || tag === 'audio' || tag === 'source' || tag === 'img') {
      return 'media/preview';
    }
    if (tag === 'iframe' || tag === 'frame') { return 'frame'; }
    if (tag === 'script') { return 'script'; }
    if (tag === 'a') { return 'navigation'; }
    if (tag === 'form') { return 'form action'; }
    if (tag === 'link') { return 'link metadata/resource'; }
    return attr || 'attribute';
  }

  function hostFlags(host) {
    var out = [];
    var h = String(host || '').toLowerCase();
    function addFlag(name) { if (out.indexOf(name) < 0) { out.push(name); } }
    if (h.indexOf('xn--') >= 0) { addFlag('punycode'); }
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) { addFlag('ip-literal'); }
    var labels = h.split('.');
    for (var i = 0; i < labels.length; i++) {
      if (/^\d+$/.test(labels[i])) { addFlag('numeric-label'); }
      if ((labels[i].match(/-/g) || []).length >= 3) { addFlag('many-hyphens'); }
      if (labels[i].length > 30) { addFlag('long-label'); }
    }
    return out;
  }

  var mixed = [];
  var mixedNav = [];
  var dangerous = [];
  var dangerousSummary = {
    javascript: 0,
    data: 0,
    blobMedia: 0,
    blobOther: 0
  };
  var DANGEROUS = ['javascript', 'data', 'blob'];
  for (var p = 0; p < pairs.length; p++) {
    var selector = pairs[p][0] + '[' + pairs[p][1] + ']';
    var nodes = doc.querySelectorAll(selector);
    for (var n = 0; n < nodes.length; n++) {
      var raw = nodes[n].getAttribute(pairs[p][1]) || '';
      var full = absolute(raw);
      var scheme = schemeOf(raw);
      if (secure && isHttp(full)) {
        var entry = {
          tag: pairs[p][0],
          attr: pairs[p][1],
          target: clip(redacted(full), 180)
        };
        if (pairs[p][0] === 'link') {
          entry.rel = String(nodes[n].getAttribute('rel') || '') || 'NOT SET';
        }
        if (pairs[p][0] === 'a' || pairs[p][0] === 'form'
            || (pairs[p][0] === 'link' && !linkLoadsResource(nodes[n]))) {
          mixedNav.push(entry);
        } else {
          mixed.push(entry);
        }
      }
      if (DANGEROUS.indexOf(scheme) >= 0) {
        var context = schemeContext(pairs[p][0], pairs[p][1]);
        dangerous.push({
          tag: pairs[p][0],
          attr: pairs[p][1],
          scheme: scheme + ':',
          context: context
        });
        if (scheme === 'javascript') {
          dangerousSummary.javascript++;
        } else if (scheme === 'data') {
          dangerousSummary.data++;
        } else if (context === 'media/preview') {
          dangerousSummary.blobMedia++;
        } else {
          dangerousSummary.blobOther++;
        }
      }
    }
  }

  var forms = doc.forms ? Array.prototype.slice.call(doc.forms) : [];
  var badFormActions = 0;
  var passwordForms = [];
  var crossOriginLoginForms = [];
  for (var f = 0; f < forms.length; f++) {
    var action = forms[f].getAttribute('action');
    if (action && secure && isHttp(absolute(action))) { badFormActions++; }
    var pwd = forms[f].querySelectorAll
      ? forms[f].querySelectorAll('input[type="password"]') : [];
    if (pwd.length) {
      var actionAbs = action ? absolute(action) : '';
      var actionOrigin = action ? originOf(action) : '';
      var formEntry = {
        hasAction: !!action,
        target: actionAbs ? clip(redacted(actionAbs), 180) : 'SAME DOCUMENT',
        actionOrigin: actionOrigin || 'SAME DOCUMENT',
        sameOrigin: !actionOrigin || actionOrigin === pageOrigin
      };
      passwordForms.push(formEntry);
      if (actionOrigin && actionOrigin !== pageOrigin) {
        crossOriginLoginForms.push(formEntry);
      }
    }
  }

  var cspMeta = 0;
  var refMeta = 0;
  var metas = doc.querySelectorAll('meta[http-equiv]');
  for (var m = 0; m < metas.length; m++) {
    var eq = String(metas[m].getAttribute('http-equiv') || '').toLowerCase();
    if (eq === 'content-security-policy') { cspMeta++; }
    if (eq === 'referrer-policy') { refMeta++; }
  }

  var cookieNames = [];
  try {
    var parts = String(doc.cookie || '').split(';');
    for (var c = 0; c < parts.length; c++) {
      var name = parts[c].split('=')[0].trim();
      if (name && cookieNames.indexOf(name) < 0) { cookieNames.push(name); }
    }
  } catch (e) { }

  var scripts = doc.querySelectorAll('script[src]');
  var externalScripts = 0;
  var crossOriginScripts = 0;
  var sriMissingScripts = 0;
  for (var s = 0; s < scripts.length; s++) {
    var srcOrigin = originOf(scripts[s].getAttribute('src'));
    if (srcOrigin && srcOrigin !== pageOrigin) {
      externalScripts++;
      crossOriginScripts++;
      if (!scripts[s].hasAttribute('integrity')) { sriMissingScripts++; }
    }
  }

  var links = doc.querySelectorAll('link[href]');
  var crossOriginStyles = 0;
  var sriMissingStyles = 0;
  for (var l = 0; l < links.length; l++) {
    var rel = String(links[l].getAttribute('rel') || '').toLowerCase();
    if (rel.indexOf('stylesheet') < 0) { continue; }
    var hrefOrigin = originOf(links[l].getAttribute('href'));
    if (hrefOrigin && hrefOrigin !== pageOrigin) {
      crossOriginStyles++;
      if (!links[l].hasAttribute('integrity')) { sriMissingStyles++; }
    }
  }

  var frames = doc.querySelectorAll('iframe');
  var framesWithoutSandbox = 0;
  var framesWithWeakSandbox = 0;
  for (var fr = 0; fr < frames.length; fr++) {
    if (!frames[fr].hasAttribute('sandbox')) {
      framesWithoutSandbox++;
      continue;
    }
    var sandboxTokens = String(frames[fr].getAttribute('sandbox') || '')
      .toLowerCase().split(/\s+/);
    if (sandboxTokens.indexOf('allow-scripts') >= 0
        && sandboxTokens.indexOf('allow-same-origin') >= 0) {
      framesWithWeakSandbox++;
    }
    if (sandboxTokens.indexOf('allow-top-navigation') >= 0) {
      framesWithWeakSandbox++;
    }
  }

  var blankLinks = doc.querySelectorAll('a[target="_blank"],a[target=blank]');
  var blankWithoutRel = 0;
  for (var b = 0; b < blankLinks.length; b++) {
    var rel = String(blankLinks[b].getAttribute('rel') || '').toLowerCase();
    if (rel.indexOf('noopener') < 0 || rel.indexOf('noreferrer') < 0) {
      blankWithoutRel++;
    }
  }

  var inlineHandlerSample = doc.querySelectorAll(
    '[onclick],[onerror],[onload],[onmouseover],[onfocus],[onchange],[onsubmit]'
  ).length;

  var result = {
    at: new Date().toISOString(),
    scheme: String(location.protocol || '').replace(':', ''),
    host: location.host || 'NOT EVALUATED',
    hostname: hostname || 'NOT EVALUATED',
    hostFlags: hostFlags(hostname),
    redactedUrl: clip(redacted(page), 200),
    secure: secure,
    mixedCount: mixed.length,
    mixed: mixed.slice(0, 12),
    mixedNavCount: mixedNav.length,
    mixedNav: mixedNav.slice(0, 12),
    dangerousCount: dangerous.length,
    dangerous: dangerous.slice(0, 12),
    dangerousSummary: dangerousSummary,
    formCount: forms.length,
    badFormActions: badFormActions,
    passwordForms: passwordForms.slice(0, 12),
    passwordFormCount: passwordForms.length,
    crossOriginLoginFormCount: crossOriginLoginForms.length,
    crossOriginLoginForms: crossOriginLoginForms.slice(0, 12),
    passwordFields: doc.querySelectorAll('input[type="password"]').length,
    cspMeta: cspMeta,
    referrerMeta: refMeta,
    cookieCount: cookieNames.length,
    cookieNames: cookieNames.slice(0, 20),
    inlineHandlers: inlineHandlerSample,
    externalScripts: externalScripts,
    crossOriginScripts: crossOriginScripts,
    sriMissingScripts: sriMissingScripts,
    crossOriginStyles: crossOriginStyles,
    sriMissingStyles: sriMissingStyles,
    inlineScripts: doc.querySelectorAll('script:not([src])').length,
    iframes: frames.length,
    framesWithoutSandbox: framesWithoutSandbox,
    framesWithWeakSandbox: framesWithWeakSandbox,
    blankLinks: blankLinks.length,
    blankWithoutRel: blankWithoutRel,
    cspViolationCount: cspEvents.length,
    cspViolations: cspEvents.slice(-8),
    boundary: 'DOM structure, attribute names, URL schemes and contexts, hostname features, login form action origins, link rel tokens, SRI presence, iframe sandbox tokens and browser-generated CSP violation summaries only. Loaded http references are separated from navigation/metadata references. Scheme payload text is never read. No credential value, form value, cookie value, query string, fragment or script text is reported.'
  };

  return result;
}());
