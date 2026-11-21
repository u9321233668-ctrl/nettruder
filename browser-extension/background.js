'use strict';

/* NetTruder Site Posture - background observer.
   Read-only. It never blocks a request, never modifies a header, and never
   sends data anywhere. Header capture runs only for origins the user grants
   through the browser's own permission prompt. */

var CACHE_KEY = 'nt-header-cache';
var REDIRECT_KEY = 'nt-redirect-cache';

var WATCHED = [
  'content-security-policy',
  'strict-transport-security',
  'x-content-type-options',
  'x-frame-options',
  'referrer-policy',
  'permissions-policy',
  'x-xss-protection',
  'content-type',
  'cross-origin-opener-policy',
  'cross-origin-embedder-policy',
  'cross-origin-resource-policy'
];

/* Set-Cookie values are session secrets. This keeps the name and flag names
   only; the cookie value itself is never stored or sent to the popup. */
function cookieFlags(value) {
  var parts = String(value || '').split(';');
  var first = parts.shift() || '';
  var eq = first.indexOf('=');
  var name = eq > 0 ? first.slice(0, eq).trim() : '';
  if (!name) { return ''; }

  var flags = [];
  for (var i = 0; i < parts.length; i++) {
    var part = parts[i].trim();
    var lower = part.toLowerCase();
    if (lower === 'secure' || lower === 'httponly') {
      flags.push(lower === 'secure' ? 'Secure' : 'HttpOnly');
    } else if (/^samesite=/i.test(part)) {
      flags.push('SameSite=' + part.split('=')[1].slice(0, 20));
    } else if (/^path=/i.test(part)) {
      flags.push('Path=' + part.split('=')[1].slice(0, 80));
    } else if (/^max-age=/i.test(part)) {
      flags.push('Max-Age=' + part.split('=')[1].slice(0, 20));
    } else if (/^expires=/i.test(part)) {
      flags.push('Expires=set');
    }
  }
  return name + (flags.length ? '; ' + flags.join('; ') : '; NO FLAGS');
}

function saveCache(map) {
  var payload = {};
  payload[CACHE_KEY] = map;
  chrome.storage.session.set(payload, function () {
    void chrome.runtime.lastError;
  });
}

function readCache(callback) {
  chrome.storage.session.get(CACHE_KEY, function (data) {
    var map = (data && data[CACHE_KEY]) || {};
    callback(map);
  });
}

function hostOf(raw) {
  try { return new URL(String(raw || '')).hostname || 'NO DATA'; }
  catch (e) { return 'NO DATA'; }
}

function saveRedirects(map) {
  var payload = {};
  payload[REDIRECT_KEY] = map;
  chrome.storage.session.set(payload, function () {
    void chrome.runtime.lastError;
  });
}

function readRedirects(callback) {
  chrome.storage.session.get(REDIRECT_KEY, function (data) {
    var map = (data && data[REDIRECT_KEY]) || {};
    callback(map);
  });
}

chrome.runtime.onInstalled.addListener(function () {
  saveCache({});
  saveRedirects({});
});

/* Main-frame response headers only. A stale entry is ignored by the popup
   unless its URL still matches the active tab exactly. */
chrome.webRequest.onHeadersReceived.addListener(function (details) {
  if (details.type !== 'main_frame') { return; }
  var found = {};
  var list = details.responseHeaders || [];
  for (var i = 0; i < list.length; i++) {
    var name = String(list[i].name || '').toLowerCase();
    if (name === 'set-cookie') {
      var summary = cookieFlags(list[i].value);
      if (summary) {
        if (!found['set-cookie-flags']) { found['set-cookie-flags'] = []; }
        if (found['set-cookie-flags'].length < 12) {
          found['set-cookie-flags'].push(summary.slice(0, 240));
        }
      }
      continue;
    }
    if (WATCHED.indexOf(name) >= 0) {
      found[name] = String(list[i].value || '').slice(0, 600);
    }
  }
  readCache(function (map) {
    map[String(details.tabId)] = {
      url: details.url,
      at: Date.now(),
      headers: found
    };
    saveCache(map);
  });
  readRedirects(function (map) {
    var key = String(details.tabId);
    var rec = map[key] || { hops: [] };
    rec.finalUrl = details.url;
    rec.at = Date.now();
    map[key] = rec;
    saveRedirects(map);
  });
}, { urls: ['<all_urls>'] }, ['responseHeaders']);

/* Main-frame redirect hosts only. This is passive observation; no redirect is
   followed, blocked or changed by NetTruder. Query strings and fragments are
   discarded before storage. */
chrome.webRequest.onBeforeRedirect.addListener(function (details) {
  if (details.type !== 'main_frame') { return; }
  var from = hostOf(details.url);
  var to = hostOf(details.redirectUrl);
  if (!to || to === 'NO DATA') { return; }
  readRedirects(function (map) {
    var key = String(details.tabId);
    var rec = map[key] || { hops: [] };
    var last = rec.hops.length ? rec.hops[rec.hops.length - 1].to : '';
    if (last !== to) {
      rec.hops.push({ from: from, to: to, at: Date.now() });
      if (rec.hops.length > 12) { rec.hops.shift(); }
    }
    rec.url = details.url;
    rec.at = Date.now();
    map[key] = rec;
    saveRedirects(map);
  });
}, { urls: ['<all_urls>'] });

chrome.runtime.onMessage.addListener(function (msg, sender, sendResponse) {
  if (!msg || typeof msg.type !== 'string') { return false; }

  if (msg.type === 'nt-get-headers') {
    readCache(function (map) {
      var rec = map[String(msg.tabId)] || null;
      if (!rec || rec.url !== msg.url) { sendResponse(null); return; }
      sendResponse(rec);
    });
    return true;
  }

  if (msg.type === 'nt-get-redirects') {
    readRedirects(function (map) {
      var rec = map[String(msg.tabId)] || null;
      if (!rec || rec.finalUrl !== msg.url) { sendResponse(null); return; }
      sendResponse(rec);
    });
    return true;
  }

  if (msg.type === 'nt-clear-headers') {
    readCache(function (map) {
      delete map[String(msg.tabId)];
      saveCache(map);
    });
    readRedirects(function (map) {
      delete map[String(msg.tabId)];
      saveRedirects(map);
    });
    sendResponse(true);
    return true;
  }

  return false;
});
