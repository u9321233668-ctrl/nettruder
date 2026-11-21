/* ==========================================================================
   NETTRUDER // OPS CONSOLE - JScript (ES5) for Windows Script Host / mshta
   --------------------------------------------------------------------------
   Front end only. All scan, IDS, IPS and shell work happens in
   engine\NetTruder.ps1. This file launches the engine hidden, tails its
   NDJSON event stream, and renders the result.
   ========================================================================== */

/* ------------------------------- globals ------------------------------- */
var S = {
  version: '1.1.0',
  base: '',
  engine: '',
  shim: '',
  root: '',
  runs: '',
  audit: '',
  state: '',
  fso: null,
  sh: null,
  cwd: '',
  winLock: { w: 0, h: 0 },
  streams: {},
  hosts: {},
  hostOrder: [],
  selected: '',
  alerts: [],
  alertSeq: 0,
  toastSeq: 0,
  modal: null,
  blocked: [],
  posture: [],
  procs: [],
  procDirty: false,
  procSelected: 0,
  procFilter: '',
  procStamp: 0,
  ruleset: '-',
  stats: { hosts: 0, ports: 0, alerts: 0 },
  monitor: false,
  admin: false,
  adminGroup: false,
  adminKnown: false,
  targets: '',
  profile: 'common',
  hostDirty: false,
  postureDirty: false,
  termBusy: false,
  termHistory: [],
  termIdx: -1,
  termWrap: true,
  termFollow: true,
  termPaused: false,
  termCompact: false,
  termPending: [],
  termCount: 0,
  lastCmd: '',
  research: {
    catalogVersion: '',
    catalogVersions: '',
    catalogs: [],
    catalog: [],
    blocks: [],
    blockCount: 0,
    filters: { group: '', platform: '' },
    loaded: false,
    meta: null,
    controls: [],
    findings: [],
    probes: [],
    proof: null,
    selected: '',
    detailKey: '',
    bridged: [],
    dirty: false,
    running: false
  },
  flow: { meta: null, nodes: [], edges: [], findings: [], selected: '', dirty: false },
  web: { meta: null, zap: null, pages: [], trees: {}, flows: [], findings: [], selected: '', flowNode: '', dirty: false },
  site: { state: 'NO DATA', meta: [], findings: [], hardening: [], imported: false, rejected: false, dirty: false },
  code: {
    meta: null, files: [], findings: [], selected: -1, fileSelected: '', fileFilter: '',
    sevFilter: '', search: '', sort: 'sev', functions: [], funcPath: '', selectedFunction: -1,
    activeLine: 0,
    raw: null, rawMode: false, rawDirty: false, writeEnabled: false, writeBusy: false,
    lastWrite: '', hevd: false, dirty: false
  },
  inv: { meta: null, conns: [], dns: [], listen: [], findings: [], dirty: false },
  net: {
    meta: null, nodes: [], edges: [], browserNodes: [], browserEdges: [], flows: [], samples: [],
    adapters: [], routes: [], dns: [], findings: [], historyMeta: null, selected: '', dirty: false,
    live: false, liveCycle: 0, liveLastStart: 0, pendingSnapshot: false
  },
  pslog: { meta: null, events: [], blocks: [], findings: [], dirty: false },
  triage: { meta: null, items: [], svcs: [], plan: [], dirty: false },
  av: { meta: null, products: [], events: [], findings: [], dirty: false },
  data: { meta: null, cats: [], files: [], purge: [], findings: [], armed: false, dirty: false },
  onboard: { seen: false, role: '', level: '', step: 0, tour: false, path: '' }
};

var RANK = { info: 0, low: 1, med: 2, high: 3 };

/* ------------------------------- helpers ------------------------------- */
function el(id) { return document.getElementById(id); }

/* Walk up to the nearest element carrying an attribute. Text nodes and the
   document object do not implement getAttribute in IE11, so stop at nodeType 1. */
function closestAttr(node, name) {
  var cur = node;
  while (cur && cur.nodeType === 1) {
    if (cur.getAttribute && cur.getAttribute(name) !== null) { return cur; }
    cur = cur.parentNode;
  }
  return null;
}
function closestAnyAttr(node, names) {
  var cur = node, i;
  while (cur && cur.nodeType === 1) {
    if (cur.getAttribute) {
      for (i = 0; i < names.length; i++) {
        if (cur.getAttribute(names[i]) !== null) { return cur; }
      }
    }
    cur = cur.parentNode;
  }
  return null;
}

function esc(s) {
  if (s === null || s === undefined) { return ''; }
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function rep(ch, n) {
  var s = '';
  for (var i = 0; i < n; i++) { s += ch; }
  return s;
}

/* Quote a value for the Windows command line (CommandLineToArgvW rules). */
function q(value) {
  var s = String(value);
  var out = '"', bs = 0;
  for (var i = 0; i < s.length; i++) {
    var c = s.charAt(i);
    if (c === '\\') { out += '\\'; bs++; continue; }
    if (c === '"') { out += rep('\\', bs + 1) + '"'; bs = 0; continue; }
    out += c; bs = 0;
  }
  out += rep('\\', bs) + '"';
  return out;
}

function pad2(n) { return (n < 10 ? '0' : '') + n; }
function hhmmss() {
  var d = new Date();
  return pad2(d.getHours()) + ':' + pad2(d.getMinutes()) + ':' + pad2(d.getSeconds());
}
function runId() {
  var s = '', i;
  for (i = 0; i < 4; i++) { s += Math.floor(Math.random() * 0x10000).toString(16); }
  return s + '-' + new Date().getTime().toString(16);
}
function rank(sev) { return RANK[sev] === undefined ? 0 : RANK[sev]; }
function maxSev(a, b) { return rank(a) >= rank(b) ? a : b; }

function isPrivate(ip) {
  var o = String(ip).split('.');
  if (o.length !== 4) { return true; }
  var a = parseInt(o[0], 10), b = parseInt(o[1], 10);
  if (a === 10 || a === 127 || a === 0) { return true; }
  if (a === 172 && b >= 16 && b <= 31) { return true; }
  if (a === 192 && b === 168) { return true; }
  if (a === 169 && b === 254) { return true; }
  if (a === 100 && b >= 64 && b <= 127) { return true; }
  return false;
}

function plural(n, word) { return n + ' ' + word + (n === 1 ? '' : 's'); }

/* ------------------------------- paths -------------------------------- */
function baseDir() {
  var u = decodeURI(location.href);
  var p = u.replace(/^file:\/{1,3}/i, '');
  p = p.replace(/\//g, '\\');
  if (!/^[A-Za-z]:/.test(p) && p.charAt(0) !== '\\') { p = '\\\\' + p; }
  var i = p.lastIndexOf('\\');
  return p.substring(0, i);
}

function ensureDir(path) {
  if (!S.fso.FolderExists(path)) { S.fso.CreateFolder(path); }
}

function readAll(path) {
  var f = S.fso.OpenTextFile(path, 1, false, 0);
  try { return f.ReadAll(); } finally { f.Close(); }
}

function writeText(path, text) {
  var f = S.fso.CreateTextFile(path, true, false);
  try { f.Write(text); } finally { f.Close(); }
}

/* The engine reads opt-in source content as UTF-16LE. FSO's third argument
   selects Unicode, which keeps editor content intact on its way to the shim. */
function writeUnicodeText(path, text) {
  var f = S.fso.CreateTextFile(path, true, true);
  try { f.Write(text); } finally { f.Close(); }
}

/* ------------------------------- console ------------------------------- */
function pushConsole(level, msg, src) {
  var c = el('console');
  if (!c) { return; }
  var line = document.createElement('div');
  line.className = 'ln ' + (level || 'info');

  var ts = document.createElement('span');
  ts.className = 'ts';
  ts.appendChild(document.createTextNode(hhmmss()));
  line.appendChild(ts);

  var lv = document.createElement('span');
  lv.className = 'lv ' + (level || 'info');
  lv.appendChild(document.createTextNode((level || 'info').toUpperCase()));
  line.appendChild(lv);

  if (src) {
    var sc = document.createElement('span');
    sc.className = 'src';
    sc.appendChild(document.createTextNode('[' + src + ']'));
    line.appendChild(sc);
  }

  var m = document.createElement('span');
  m.className = 'msg';
  m.appendChild(document.createTextNode(msg === undefined || msg === null ? '' : String(msg)));
  line.appendChild(m);

  c.appendChild(line);
  while (c.childNodes.length > 700) { c.removeChild(c.firstChild); }
  c.scrollTop = c.scrollHeight;
}

/* ------------------------------- engine -------------------------------- */
function jsonStr(value) {
  var s = String(value);
  var out = '"';
  for (var i = 0; i < s.length; i++) {
    var c = s.charAt(i);
    var code = s.charCodeAt(i);
    if (c === '"') { out += '\\"'; }
    else if (c === '\\') { out += '\\\\'; }
    else if (c === '\n') { out += '\\n'; }
    else if (c === '\r') { out += '\\r'; }
    else if (c === '\t') { out += '\\t'; }
    else if (code < 32 || code > 126) { out += '\\u' + ('0000' + code.toString(16)).slice(-4); }
    else { out += c; }
  }
  return out + '"';
}

function writeRequest(id, action, args) {
  var parts = ['"action":' + jsonStr(action), '"runId":' + jsonStr(id)];
  for (var k in args) {
    if (!args.hasOwnProperty(k)) { continue; }
    var v = args[k];
    if (v === null || v === undefined) { continue; }
    if (typeof v === 'boolean') { parts.push(jsonStr(k) + ':' + (v ? 'true' : 'false')); }
    else if (typeof v === 'number') { parts.push(jsonStr(k) + ':' + String(v)); }
    else { parts.push(jsonStr(k) + ':' + jsonStr(v)); }
  }
  var path = S.runs + '\\' + id + '.request.json';
  writeText(path, '{' + parts.join(',') + '}');
  return path;
}

function startStream(key, action, args) {
  var id = runId();
  var st = {
    key: key, id: id, pos: 0, buf: '', done: false, action: action,
    started: new Date().getTime(), sawBoot: false
  };
  st.path = S.runs + '\\' + id + '.events.ndjson';
  S.streams[key] = st;

  var reqPath = '';
  var cmd = '';
  try {
    reqPath = writeRequest(id, action, args || {});
    cmd = 'wscript.exe "' + S.shim + '" "' + reqPath + '"';
  } catch (e0) {
    pushConsole('err', 'Could not write the engine request: ' + e0.message, key);
    st.done = true;
    return st;
  }
  S.lastCmd = cmd;
  if (!S.fso.FileExists(S.shim)) {
    pushConsole('err', 'Engine shim missing: ' + S.shim, key);
    pushConsole('dim', 'The nettruder folder is incomplete. Re-extract it and run Launch.cmd.', key);
    st.done = true;
    return st;
  }
  try {
    S.sh.Run(cmd, 0, false);
  } catch (e) {
    pushConsole('err', 'Engine launch blocked: ' + e.message + ' [code ' + e.number + ']', key);
    pushConsole('dim', 'An endpoint agent may be blocking script-to-PowerShell launches. Have its policy reviewed; do not disable protection just to run this tool.', key);
    st.done = true;
    return st;
  }
  el('sbRun').innerHTML = 'RUN ' + id;
  refreshChips();
  return st;
}

function pump(st) {
  if (!st || st.done) { return; }
  var text;
  try { text = readAll(st.path); } catch (e) { return; }
  if (!text || text.length <= st.pos) { return; }
  var chunk = text.substring(st.pos);
  st.pos = text.length;
  var lines = (st.buf + chunk).split('\n');
  st.buf = lines.pop();
  for (var i = 0; i < lines.length; i++) {
    if (lines[i].length) { handleLine(st, lines[i]); }
  }
}

function pumpAll() {
  var now = new Date().getTime();
  for (var k in S.streams) {
    if (!S.streams.hasOwnProperty(k)) { continue; }
    var st = S.streams[k];
    pump(st);
    if (!st.done && !st.sawBoot && (now - st.started) > 20000) {
      st.done = true;
      pushConsole('err', 'No response from the engine after 20s (' + st.action + ').', k);
      pushConsole('dim', 'Check that the nettruder folder is intact and that no security policy blocks script launches.', k);
      if (st.action === 'watch') { S.monitor = false; }
      if (st.action === 'probe') {
        if (el('postureState')) { el('postureState').innerHTML = 'FAILED'; }
        if (el('btnProbe')) { el('btnProbe').disabled = false; }
      }
      if (st.action === 'processes') {
        if (el('procState')) { el('procState').innerHTML = 'FAILED'; }
        if (el('btnProcRefresh')) { el('btnProcRefresh').disabled = false; }
      }
      if (st.action === 'research') {
        if (el('researchState')) { el('researchState').innerHTML = 'FAILED'; }
        setResearchBusy(false);
      }
      if (st.action === 'pslog') {
        if (el('pslogState')) { el('pslogState').innerHTML = 'FAILED'; }
        if (el('btnPsLogRun')) { el('btnPsLogRun').disabled = false; }
      }
      if (k === 'term') {
        S.termBusy = false;
        if (el('termInput')) { el('termInput').disabled = false; el('termInput').focus(); }
        if (el('btnTermRun')) { el('btnTermRun').disabled = false; }
      }
      refreshChips();
    }
  }
  netLiveWatchdog();
}

/* Closing the console disarms the monitor and stops running commands. */
function stopAllStreams() {
  for (var k in S.streams) {
    if (!S.streams.hasOwnProperty(k)) { continue; }
    var st = S.streams[k];
    if (!st.done) {
      try { writeText(S.runs + '\\' + st.id + '.stop', '1'); } catch (e) { }
    }
  }
}

function busy() {
  var keys = ['sweep', 'posture', 'ctl', 'term', 'procs', 'kill', 'research',
    'flow', 'web', 'code', 'inv', 'triage', 'av', 'data', 'pslog'];
  for (var i = 0; i < keys.length; i++) {
    var st = S.streams[keys[i]];
    if (st && !st.done) { return true; }
  }
  return false;
}

function setChip(which, cls, text) {
  var c = el('chip' + which);
  if (!c) { return; }
  c.className = 'chip' + (cls ? ' ' + cls : '');
  el('chip' + which + 'Txt').innerHTML = text;
}

function refreshChips() {
  if (busy()) { setChip('Engine', 'on', 'RUNNING'); }
  else { setChip('Engine', '', 'IDLE'); }

  if (S.monitor) { setChip('Monitor', 'on', 'ARMED'); }
  else { setChip('Monitor', '', 'STANDBY'); }

  if (S.blocked.length > 0) { setChip('Ips', 'warn', S.blocked.length + ' ACTIVE'); }
  else { setChip('Ips', '', 'DISARMED'); }
}

/* ------------------------------- events -------------------------------- */
function handleLine(st, raw) {
  var line = raw.replace(/\r$/, '');
  if (!line) { return; }
  var e;
  try { e = JSON.parse(line); } catch (err) { return; }

  switch (e.k) {
    case 'boot': onBoot(st, e); break;
    case 'log': pushConsole(e.lvl || 'info', e.m, st.key); break;
    case 'host': onHost(e.d); break;
    case 'hostmeta': onHostMeta(e.d); break;
    case 'port': onPort(e.d); break;
    case 'alert': onAlert(e.d); break;
    case 'posture': onPosture(e.d); break;
    case 'stat': onStat(e.d); break;
    case 'blocklist': onBlockList(e.d); break;
    case 'ruleset': onRuleset(e.d); break;
    case 'term': onTerm(e.d, e.m); break;
    case 'termexit': onTermExit(e.d); break;
    case 'proc': onProc(e.d); break;
    case 'procdone': onProcDone(e.d); break;
    case 'resmeta': onResMeta(e.d); break;
    case 'rescontrol': onResControl(e.d); break;
    case 'restech': onResTech(e.d); break;
    case 'resfind': onResFind(e.d); break;
    case 'resproof': onResProof(e.d); break;
    case 'resprobe': onResProbe(e.d); break;
    case 'flowmeta': S.flow.meta = e.d; S.flow.nodes = []; S.flow.edges = []; S.flow.findings = []; S.flow.dirty = true; break;
    case 'flownode': if (e.d) { S.flow.nodes.push(e.d); S.flow.dirty = true; } break;
    case 'flowedge': if (e.d) { S.flow.edges.push(e.d); S.flow.dirty = true; } break;
    case 'flowfinding': if (e.d) { S.flow.findings.push(e.d); S.flow.dirty = true; } break;
    case 'webmeta': S.web.meta = e.d; if (e.d && e.d.zap) { S.web.zap = e.d.zap; } S.web.pages = []; S.web.findings = []; S.web.trees = {}; S.web.flows = {}; S.web.selected = ''; S.web.flowNode = ''; S.web.dirty = true; break;
    case 'webpage': if (e.d) { S.web.pages.push(e.d); S.web.dirty = true; } break;
    case 'webtree': if (e.d) { S.web.trees[e.d.url] = e.d; S.web.dirty = true; } break;
    case 'webflow': if (e.d) { S.web.flows[e.d.url] = e.d; S.web.dirty = true; } break;
    case 'webfinding': if (e.d) { S.web.findings.push(e.d); S.web.dirty = true; } break;
    case 'zap': if (e.d && !S.web.zap) { S.web.zap = e.d; S.web.dirty = true; } break;
    case 'codemeta': S.code.meta = e.d; S.code.files = []; S.code.findings = []; S.code.viewMap = []; S.code.selected = -1; S.code.fileSelected = ''; S.code.fileFilter = ''; S.code.sevFilter = ''; S.code.search = ''; S.code.functions = []; S.code.funcPath = ''; S.code.selectedFunction = -1; S.code.activeLine = 0; S.code.raw = null; S.code.rawMode = false; S.code.rawDirty = false; S.code.writeEnabled = false; S.code.writeBusy = false; S.code.lastWrite = ''; S.code.dirty = true; break;
    case 'codefile': if (e.d) { S.code.files.push(e.d); S.code.dirty = true; } break;
    case 'codefinding': if (e.d) { S.code.findings.push(e.d); S.code.dirty = true; } break;
    case 'coderaw': onCodeRaw(e.d); break;
    case 'codewrite': onCodeWrite(e.d); break;
    case 'invmeta': S.inv.meta = e.d; S.inv.dirty = true; break;
    case 'invconn': if (e.d) { S.inv.conns.push(e.d); S.inv.dirty = true; } break;
    case 'invdns': if (e.d) { S.inv.dns.push(e.d); S.inv.dirty = true; } break;
    case 'invlisten': if (e.d) { S.inv.listen.push(e.d); S.inv.dirty = true; } break;
    case 'invfinding': if (e.d) { S.inv.findings.push(e.d); S.inv.dirty = true; } break;
    case 'netmeta':
      S.net.meta = e.d; S.net.nodes = []; S.net.edges = [];
      S.net.browserNodes = []; S.net.browserEdges = []; S.net.flows = [];
      S.net.samples = []; S.net.adapters = []; S.net.routes = []; S.net.dns = [];
      S.net.findings = []; S.net.historyMeta = null; S.net.selected = ''; S.net.dirty = true;
      break;
    case 'nethistory': S.net.historyMeta = e.d; S.net.dirty = true; break;
    case 'netadapter': if (e.d) { S.net.adapters.push(e.d); S.net.dirty = true; } break;
    case 'netroute': if (e.d) { S.net.routes.push(e.d); S.net.dirty = true; } break;
    case 'netnode':
      if (e.d) {
        if (e.d.graph === 'browser') { S.net.browserNodes.push(e.d); }
        else { S.net.nodes.push(e.d); }
        S.net.dirty = true;
      }
      break;
    case 'netedge':
      if (e.d) {
        if (e.d.graph === 'browser') { S.net.browserEdges.push(e.d); }
        else { S.net.edges.push(e.d); }
        S.net.dirty = true;
      }
      break;
    case 'netflow': if (e.d) { S.net.flows.push(e.d); S.net.dirty = true; } break;
    case 'netfinding': if (e.d) { S.net.findings.push(e.d); S.net.dirty = true; } break;
    case 'pslogmeta': S.pslog.meta = e.d; S.pslog.events = []; S.pslog.blocks = []; S.pslog.findings = []; S.pslog.dirty = true; break;
    case 'pslogevent': if (e.d) { S.pslog.events.push(e.d); S.pslog.dirty = true; } break;
    case 'pslogblock': if (e.d) { S.pslog.blocks.push(e.d); S.pslog.dirty = true; } break;
    case 'pslogfinding': if (e.d) { S.pslog.findings.push(e.d); S.pslog.dirty = true; } break;
    case 'netsample':
      if (e.d) {
        S.net.samples.push(e.d);
        if (e.d.final) {
          var nm = S.net.meta || {};
          for (var nk in e.d) { if (e.d.hasOwnProperty(nk)) { nm[nk] = e.d[nk]; } }
          S.net.meta = nm;
        }
        S.net.dirty = true;
      }
      break;
    case 'triageitem': if (e.d) { S.triage.items.push(e.d); S.triage.dirty = true; } break;
    case 'triagesvc': if (e.d) { S.triage.svcs.push(e.d); S.triage.dirty = true; } break;
    case 'triageplan': if (e.d) { S.triage.plan.push(e.d); S.triage.dirty = true; } break;
    case 'triageaction':
      S.triage.lastAction = true;
      pushConsole('ok', 'Decision saved locally: ' + (e.d ? e.d.id : '') + ' -> ' + (e.d ? e.d.decision : ''), 'triage');
      break;
    case 'avmeta': S.av.meta = e.d; S.av.products = []; S.av.events = []; S.av.findings = []; S.av.dirty = true; break;
    case 'avproduct': if (e.d) { S.av.products.push(e.d); S.av.dirty = true; } break;
    case 'avevent': if (e.d) { S.av.events.push(e.d); S.av.dirty = true; } break;
    case 'avfinding': if (e.d) { S.av.findings.push(e.d); S.av.dirty = true; } break;
    case 'datacat': if (e.d) { S.data.cats.push(e.d); S.data.dirty = true; } break;
    case 'datafile': if (e.d) { S.data.files.push(e.d); S.data.dirty = true; } break;
    case 'datameta': S.data.meta = e.d; S.data.dirty = true; break;
    case 'datafinding': if (e.d) { S.data.findings.push(e.d); S.data.dirty = true; } break;
    case 'datapurgeitem': if (e.d) { S.data.purge.push(e.d); S.data.dirty = true; } break;
    case 'done': onDone(st, e); break;
    default: break;
  }
}

function onBoot(st, e) {
  var d = e.d || {};
  st.sawBoot = true;
  S.adminKnown = true;
  S.admin = !!d.admin;
  S.adminGroup = !!d.adminGroup;
  if (S.admin) {
    el('adminBadge').className = 'badge admin';
    el('adminBadge').innerHTML = 'ADMIN';
  } else if (S.adminGroup) {
    el('adminBadge').className = 'badge warn';
    el('adminBadge').innerHTML = 'ADMIN*';
    el('adminBadge').title = 'Account is in Administrators but this process has a filtered token. Relaunch with Launch-Elevated.cmd for Security-log proof.';
  }
  if (d.mode === 'watch') { S.monitor = true; }
  refreshChips();
  renderSession();
}

function onHost(d) {
  if (!d || !d.ip) { return; }
  if (!S.hosts[d.ip]) {
    S.hosts[d.ip] = { ip: d.ip, mac: '', name: '', rtt: d.rtt, ports: [], sev: 'info', banner: '' };
    S.hostOrder.push(d.ip);
  } else if (d.rtt !== null && d.rtt !== undefined) {
    S.hosts[d.ip].rtt = d.rtt;
  }
  S.hostDirty = true;
}

function onHostMeta(d) {
  if (!d || !d.ip) { return; }
  var h = S.hosts[d.ip];
  if (!h) { return; }
  if (d.mac) { h.mac = d.mac; }
  if (d.name) { h.name = d.name; }
  S.hostDirty = true;
}

function onPort(d) {
  if (!d || !d.ip) { return; }
  var h = S.hosts[d.ip];
  if (!h) {
    h = S.hosts[d.ip] = { ip: d.ip, mac: '', name: '', rtt: null, ports: [], sev: 'info', banner: '' };
    S.hostOrder.push(d.ip);
  }
  for (var i = 0; i < h.ports.length; i++) {
    if (h.ports[i].port === d.port) { return; }
  }
  h.ports.push({ port: d.port, svc: d.svc || '', sev: d.sev || 'info', banner: d.banner || '' });
  h.sev = maxSev(h.sev, d.sev || 'info');
  if (d.banner) { h.banner = d.banner; }
  S.stats.ports++;
  S.hostDirty = true;
  updateStats();
}

function onAlert(d) {
  if (!d) { return; }
  d._seq = ++S.alertSeq;
  S.alerts.unshift(d);
  if (S.alerts.length > 160) { S.alerts.length = 160; }
  S.stats.alerts++;
  if (d.ip && S.hosts[d.ip]) {
    S.hosts[d.ip].sev = maxSev(S.hosts[d.ip].sev, d.sev);
    S.hostDirty = true;
  }
  renderAlerts();
  updateStats();
  if (d.sev === 'high') { setChip('Ips', 'bad', 'ALERT'); }
  addAlertToast(d);
}

function onPosture(d) {
  if (!d) { return; }
  S.posture.push(d);
  S.postureDirty = true;
}

function onProc(d) {
  if (!d) { return; }
  S.procs.push(d);
  S.procDirty = true;
}

function onProcDone(d) {
  S.procDirty = true;
  S.procStamp = new Date().getTime();
  if (d && el('procState')) { el('procState').innerHTML = (d.shown || 0) + ' PROCS'; }
  if (d && el('btnProcRefresh')) { el('btnProcRefresh').disabled = false; }
  renderProcs();
  renderProcDetail();
}

function onResMeta(d) {
  if (!d) { return; }
  S.research.meta = d;
  S.research.blocks = (d.blocks && d.blocks.length) ? d.blocks : [];
  S.research.blockCount = (d.blockCount !== null && d.blockCount !== undefined) ? d.blockCount : S.research.blocks.length;
  S.research.dirty = true;
  populateResearchFilters();
}

function onResControl(d) {
  if (!d) { return; }
  S.research.controls.push(d);
  S.research.dirty = true;
}

function researchEntry(host) {
  var list = S.research.catalog;
  var key = String(host || '').toLowerCase();
  for (var i = 0; i < list.length; i++) {
    if (String(list[i].host || '').toLowerCase() === key) { return list[i]; }
  }
  return null;
}

function onResTech(d) {
  if (!d || !d.host) { return; }
  var t = researchEntry(d.host);
  if (!t) {
    t = {
      id: d.id || '', name: d.name || d.host, host: d.host, family: '', risk: '',
      platform: d.platform || '', group: d.group || '', method: d.method || '',
      catalog: d.catalog || '', presenceNote: '',
      abuse: '', detection: '', hardening: [], needs: [], controls: [],
      present: null, signature: '', signer: '', version: '', path: '', gap: '', signals: '',
      basis: '', tree: [], cmdMatch: [], cmdWhy: '', asr: [], netWatch: '', netPorts: '', fix: [],
      blocks: []
    };
    S.research.catalog.push(t);
  }
  t.id = d.id || t.id;
  t.name = d.name || t.name;
  t.family = d.family || t.family;
  t.risk = d.risk || t.risk;
  if (d.platform) { t.platform = d.platform; }
  if (d.group) { t.group = d.group; }
  if (d.method) { t.method = d.method; }
  if (d.catalog) { t.catalog = d.catalog; }
  t.present = (d.present === null || d.present === undefined) ? null : (d.present === true);
  t.presenceNote = d.presenceNote || t.presenceNote || '';
  t.signature = d.signature || '';
  t.signer = d.signer || '';
  t.version = d.version || '';
  t.path = d.path || '';
  t.gap = d.gap || '';
  t.basis = d.basis || t.basis || '';
  t.signals = d.signals || '';
  if (d.abuse) { t.abuse = d.abuse; }
  if (d.detection) { t.detection = d.detection; }
  if (d.hardening && d.hardening.length) { t.hardening = d.hardening; }
  if (d.fix && d.fix.length) { t.fix = d.fix; }
  if (d.tree && d.tree.length) { t.tree = d.tree; }
  if (d.cmdMatch && d.cmdMatch.length) { t.cmdMatch = d.cmdMatch; }
  if (d.cmdWhy) { t.cmdWhy = d.cmdWhy; }
  if (d.asr && d.asr.length) { t.asr = d.asr; }
  if (d.netWatch) { t.netWatch = d.netWatch; }
  if (d.netPorts) { t.netPorts = d.netPorts; }
  t.blocks = (d.blocks && d.blocks.length) ? d.blocks : [];
  S.research.dirty = true;
}

function onResFind(d) {
  if (!d) { return; }
  S.research.findings.push(d);
  S.research.dirty = true;
}

function onResProof(d) {
  if (!d) { return; }
  S.research.proof = d;
  S.research.dirty = true;
}

function onResProbe(d) {
  if (!d) { return; }
  S.research.probes.push(d);
  S.research.dirty = true;
}

function onStat(d) {
  if (!d) { return; }
  var pct = 0;
  if (d.total && d.done) { pct = Math.round((d.done / d.total) * 100); }
  if (pct > 100) { pct = 100; }
  el('bar').style.width = pct + '%';
  if (d.phase === 'sweep') { el('barLabel').innerHTML = 'SWEEP ' + d.done + '/' + d.total; }
  else if (d.phase === 'ports') { el('barLabel').innerHTML = 'PORTS ' + d.done + '/' + d.total; }
}

function onBlockList(d) {
  S.blocked = (d && d.items) ? d.items : [];
  renderBlocked();
  refreshChips();
}

function onRuleset(d) {
  if (!d) { return; }
  S.ruleset = d.version || '-';
  el('sbRules').innerHTML = 'RULES ' + S.ruleset + ' (' + (d.listen || 0) + '/' + (d.remote || 0) + ')';
  renderSession();
}

function onTerm(d, msg) {
  if (!d && (msg === undefined || msg === null)) { return; }
  var text = (msg === undefined || msg === null) ? (d && d.m ? d.m : '') : msg;
  var cls = d && d.s === 'err' ? 'err' : '';
  if (S.termPaused) { queueTerm(cls, text); return; }
  appendTerm(cls, text);
}

function onTermExit(d) {
  if (!d) { return; }
  var text = '[process exited with code ' + d.code + ']';
  if (S.termPaused) { queueTerm('dim', text); return; }
  appendTerm('dim', text);
}

function onDone(st, e) {
  st.done = true;
  var d = e.d || {};
  if (d.phase === 'sweep') {
    el('bar').style.width = '100%';
    el('barLabel').innerHTML = (d.hosts || 0) + ' HOSTS / ' + (d.ports || 0) + ' PORTS';
  }
  if (d.phase === 'watch') {
    S.monitor = false;
    el('watchState').innerHTML = 'STANDBY';
    el('btnWatch').disabled = false;
  }
  if (d.phase === 'probe') {
    el('postureState').innerHTML = 'COMPLETE';
    el('btnProbe').disabled = false;
  }
  if (d.phase === 'processes') {
    if (el('procState')) { el('procState').innerHTML = (d.shown || 0) + ' PROCS'; }
    if (el('btnProcRefresh')) { el('btnProcRefresh').disabled = false; }
  }
  if (d.phase === 'kill') {
    if (e.lvl === 'ok' && el('view-processes') && el('view-processes').className.indexOf('active') >= 0) {
      window.setTimeout(refreshProcesses, 500);
    }
  }
  if (d.phase === 'research') {
    S.research.running = false;
    setResearchBusy(false);
    if (e.lvl === 'err') {
      el('researchState').innerHTML = 'FAILED';
    } else {
      el('researchState').innerHTML = (d.techniques || 0) + ' TECH / ' + (d.blind || 0) + ' BLIND';
    }
    renderResearch();
  }
  if (d.phase === 'pslog') {
    S.pslog.dirty = true;
    if (el('btnPsLogRun')) { el('btnPsLogRun').disabled = false; }
    if (el('pslogState')) {
      el('pslogState').innerHTML = (e.lvl === 'err') ? 'FAILED' : pslogDoneText(d);
    }
    renderPsLog();
  }
  if (d.phase === 'flow') {
    S.flow.dirty = true;
    if (el('flowState')) { el('flowState').innerHTML = e.lvl === 'err' ? 'FAILED' : (d.nodes || 0) + ' NODES'; }
    if (el('btnFlowRun')) { el('btnFlowRun').disabled = false; }
    renderFlow();
  }
  if (d.phase === 'webscan') {
    S.web.dirty = true;
    if (el('webState')) { el('webState').innerHTML = e.lvl === 'err' ? 'FAILED' : (d.findings || 0) + ' FINDINGS'; }
    if (el('btnWebRun')) { el('btnWebRun').disabled = false; }
    renderWeb();
  }
  if (d.phase === 'codeaudit') {
    S.code.dirty = true;
    if (el('codeState')) { el('codeState').innerHTML = e.lvl === 'err' ? 'FAILED' : (d.files || 0) + ' FILES'; }
    if (el('btnCodeRun')) { el('btnCodeRun').disabled = false; }
    renderCode();
  }
  if (d.phase === 'coderead') {
    S.code.writeBusy = false;
    S.code.dirty = true;
    if (e.lvl === 'err') {
      S.code.raw = null;
      S.code.rawMode = false;
      S.code.rawDirty = false;
      pushConsole('err', 'Raw source read refused: ' + (e.m || 'path or confirmation failed'), 'code');
    } else {
      pushConsole('warn', 'Raw source opened for editing. Values are not masked; disable write mode when finished.', 'code');
    }
    renderCode();
  }
  if (d.phase === 'codewrite') {
    S.code.writeBusy = false;
    S.code.dirty = true;
    if (e.lvl === 'ok') {
      S.code.rawDirty = false;
      S.code.lastWrite = d.backup || '';
      if (S.code.raw) { S.code.raw.original = S.code.raw.buffer || ''; }
      pushConsole('warn', 'Source saved. Original backed up at ' + (d.backup || 'the state folder') + '.', 'code');
    } else {
      pushConsole('err', 'Source was not saved: ' + (e.m || 'write refused'), 'code');
    }
    renderCode();
  }
  if (d.phase === 'investigate') {
    S.inv.dirty = true;
    if (el('invState')) { el('invState').innerHTML = e.lvl === 'err' ? 'FAILED' : (d.peers || 0) + ' PEERS'; }
    if (el('btnInvRun')) { el('btnInvRun').disabled = false; }
    renderInv();
  }
  if (d.phase === 'netinv') {
    S.net.dirty = true;
    setNetBusy(false);
    if (el('netState')) {
      if (S.net.live) { el('netState').innerHTML = netLiveStateText(); }
      else { el('netState').innerHTML = e.lvl === 'err' ? 'FAILED'
        : (d.flows || 0) + ' FLOWS / ' + (d.findings || 0) + ' FINDINGS'; }
    }
    renderNet();
    if (e.lvl === 'err') {
      if (S.net.live) { stopNetLive(false); }
      S.net.pendingSnapshot = false;
    } else if (S.net.live) {
      window.setTimeout(startNetLiveCycle, 800);
    } else if (S.net.pendingSnapshot) {
      S.net.pendingSnapshot = false;
      window.setTimeout(function () { runNetInventory(0); }, 400);
    }
  }
  if (d.phase === 'triage') {
    S.triage.dirty = true;
    if (el('triageState')) {
      el('triageState').innerHTML = S.triage.lastAction ? 'DECISION SAVED'
        : (e.lvl === 'err' ? 'NO EXPORT' : (d.items || 0) + ' ALERTS');
    }
    if (el('btnTriageRun')) { el('btnTriageRun').disabled = false; }
    renderTriage();
  }
  if (d.phase === 'av') {
    S.av.dirty = true;
    if (el('avState')) { el('avState').innerHTML = e.lvl === 'err' ? 'FAILED' : (d.events || 0) + ' EVENTS'; }
    if (el('btnAvRun')) { el('btnAvRun').disabled = false; }
    renderAv();
  }
  if (d.phase === 'datacheck') {
    S.data.dirty = true;
    if (el('dataState')) { el('dataState').innerHTML = e.lvl === 'err' ? 'FAILED' : (d.files || 0) + ' FILES'; }
    if (el('btnDataRun')) { el('btnDataRun').disabled = false; }
    renderData();
  }
  if (d.phase === 'datapurge') {
    S.data.dirty = true;
    S.data.armed = false;
    var purgeBtn = el('btnDataPurge');
    if (purgeBtn) { purgeBtn.disabled = false; purgeBtn.innerHTML = 'PURGE OLD DATA'; }
    if (e.lvl === 'err') {
      if (el('dataState')) { el('dataState').innerHTML = 'PURGE FAILED'; }
    } else if (d.deleted !== undefined) {
      S.data.purge = [];
      if (el('dataState')) { el('dataState').innerHTML = d.deleted + ' DELETED'; }
      pushConsole('warn', 'Purge deleted ' + d.deleted + ' NetTruder-owned file(s). Personal folders were never in scope.', 'data');
    } else {
      if (el('dataState')) { el('dataState').innerHTML = (d.preview || 0) + ' PREVIEWED'; }
      pushConsole('warn', 'Purge preview: ' + (d.preview || 0) + ' file(s), ' + (d.bytes || 0) + ' bytes. Nothing was deleted. Review the list, then confirm.', 'data');
    }
    if (el('btnDataPreview')) { el('btnDataPreview').disabled = false; }
    renderData();
  }
  if (st.key === 'term') {
    S.termBusy = false;
    var inp = el('termInput');
    inp.disabled = false;
    inp.focus();
    el('btnTermRun').disabled = false;
  }
  refreshChips();
  renderSession();
}

/* ------------------------------- hosts -------------------------------- */
function renderHosts() {
  var tb = el('hostBody');
  if (!tb) { return; }
  var rows = [];

  var ordered = S.hostOrder.slice(0);
  ordered.sort(function (a, b) {
    var ra = rank(S.hosts[a].sev), rb = rank(S.hosts[b].sev);
    if (ra !== rb) { return rb - ra; }
    return a < b ? -1 : (a > b ? 1 : 0);
  });

  for (var i = 0; i < ordered.length; i++) {
    var ip = ordered[i];
    var h = S.hosts[ip];
    var ports = h.ports.slice(0).sort(function (x, y) { return x.port - y.port; });
    var phtml = '';
    if (ports.length === 0) {
      phtml = '<span class="dim">none</span>';
    } else {
      for (var p = 0; p < ports.length; p++) {
        var pp = ports[p];
        phtml += '<span class="port sev-' + esc(pp.sev) + '">' + pp.port + (pp.svc ? '/' + esc(pp.svc) : '') + '</span>';
      }
    }
    var cls = (ip === S.selected) ? ' class="sel"' : '';
    rows.push('<tr data-ip="' + esc(ip) + '"' + cls + '>'
      + '<td class="mono">' + esc(ip) + (h.name ? '<span class="hostname">' + esc(h.name) + '</span>' : '') + '</td>'
      + '<td class="mono dim">' + (h.mac ? esc(h.mac) : '-') + '</td>'
      + '<td class="mono">' + (h.rtt !== null && h.rtt !== undefined ? h.rtt + ' ms' : '-') + '</td>'
      + '<td>' + phtml + '</td>'
      + '<td><span class="risk risk-' + esc(h.sev) + '">' + esc(h.sev.toUpperCase()) + '</span></td>'
      + '</tr>');
  }

  tb.innerHTML = rows.join('');
  el('hostEmpty').style.display = ordered.length === 0 ? 'block' : 'none';
  S.stats.hosts = ordered.length;
  updateStats();
}

function renderDetail() {
  var box = el('hostDetail');
  if (!S.selected || !S.hosts[S.selected]) {
    box.innerHTML = '<span class="micro">SELECT A HOST ROW FOR DETAIL</span>';
    return;
  }
  var h = S.hosts[S.selected];
  var parts = [];
  parts.push('<span class="dt"><b>' + esc(h.ip) + '</b></span>');
  if (h.name) { parts.push('<span class="dt">' + esc(h.name) + '</span>'); }
  if (h.mac) { parts.push('<span class="dt">MAC ' + esc(h.mac) + '</span>'); }
  parts.push('<span class="dt">' + h.ports.length + ' open port(s)</span>');
  parts.push('<span class="dt">risk <b>' + esc(h.sev.toUpperCase()) + '</b></span>');
  if (h.banner) { parts.push('<span class="dt">banner "' + esc(h.banner) + '"</span>'); }
  box.innerHTML = parts.join('<span class="sep">|</span>');
}

/* ------------------------------- alerts ------------------------------- */
function renderAlerts() {
  var box = el('alertList');
  if (!box) { return; }
  var out = [];
  for (var i = 0; i < S.alerts.length; i++) {
    var a = S.alerts[i];
    var canBlock = a.ip && a.sev !== 'info' && a.sev !== 'low';
    var acts = '';
    acts += '<button class="abtn alt" data-act="remedy" data-seq="' + (a._seq || 0) + '">REMEDY</button>';
    if (canBlock) { acts += '<button class="abtn" data-act="block" data-ip="' + esc(a.ip) + '">BLOCK</button>'; }
    if (a.pid) {
      acts += '<button class="abtn alt" data-act="proc" data-pid="' + a.pid + '">PROCESS</button>';
      acts += '<button class="abtn" data-act="kill" data-pid="' + a.pid + '" data-name="' + esc(a.proc || '') + '">KILL</button>';
    } else if (a.proc) {
      acts += '<button class="abtn alt" data-act="proc" data-name="' + esc(a.proc) + '">PROCESS</button>';
    }
    acts += '<button class="abtn alt" data-act="tm">TASKMGR</button>';
    out.push('<div class="alert ' + esc(a.sev) + '">'
      + '<div class="abody">'
      + '<div class="atop"><span class="aid">' + esc(a.id) + '</span>'
      + '<span class="atitle">' + esc(a.title) + '</span></div>'
      + '<div class="adetail">' + esc(a.detail) + '</div>'
      + '<div class="ameta">'
      + (a.ip ? 'remote <span class="ip">' + esc(a.ip) + '</span> ' : '')
      + (a.proc ? 'proc ' + esc(a.proc) : '')
      + (a.pid ? ' <span class="ip">pid ' + a.pid + '</span>' : '')
      + (a.ports ? ' ports <span class="ip">' + esc(a.ports) + '</span>' : '')
      + (a.hosts && a.hosts.length ? ' peers <span class="ip">' + esc(a.hosts.join(', ')) + '</span>' : '')
      + '</div></div>'
      + '<div class="aacts">' + acts + '</div>'
      + '</div>');
  }
  box.innerHTML = out.join('');
  el('alertEmpty').style.display = S.alerts.length ? 'none' : 'block';
  el('alertCount').innerHTML = plural(S.alerts.length, 'EVENT');
}

function renderBlocked() {
  var box = el('blockList');
  if (!box) { return; }
  var now = Math.floor(new Date().getTime() / 1000);
  var out = [];
  for (var i = 0; i < S.blocked.length; i++) {
    var b = S.blocked[i];
    var left = parseInt(b.expiresEpoch, 10) - now;
    if (left < 0) { left = 0; }
    var mins = Math.ceil(left / 60);
    out.push('<div class="blockrow">'
      + '<span class="bip">' + esc(b.ip) + '</span>'
      + '<span class="bexp">' + mins + 'm</span>'
      + '<button class="bx" data-unblock="' + esc(b.ip) + '" title="Release">x</button>'
      + '</div>');
  }
  box.innerHTML = out.join('');
  el('blockEmpty').style.display = S.blocked.length ? 'none' : 'block';
}

/* ------------------------------- posture ------------------------------ */
var POSTURE_ACTIONS = {
  'defender-rt': { label: 'SECURITY', tool: 'windowsdefender://' },
  'defender-sig': { label: 'SECURITY', tool: 'windowsdefender://' },
  'defender': { label: 'SECURITY', tool: 'windowsdefender://' },
  'firewall': { label: 'FIREWALL', tool: 'wf.msc' },
  'smbv1': { label: 'FEATURES', tool: 'optionalfeatures.exe' },
  'rdp': { label: 'REMOTE', tool: 'SystemPropertiesRemote.exe' },
  'bitlocker': { label: 'BITLOCKER', tool: 'control.exe /name Microsoft.BitLockerDriveEncryption' },
  'wuauserv': { label: 'UPDATE', tool: 'ms-settings:windowsupdate' },
  'exposed-listeners': { label: 'PROCESSES', view: 'processes' },
  'ips': { label: 'FIREWALL', tool: 'wf.msc' }
};

function renderPosture() {
  var box = el('postureList');
  if (!box) { return; }
  var out = [];
  for (var i = 0; i < S.posture.length; i++) {
    var p = S.posture[i];
    var fix = POSTURE_ACTIONS[p.id];
    var act = '';
    if (fix) {
      if (fix.view) { act = '<button class="pfix" data-view="' + esc(fix.view) + '">' + esc(fix.label) + '</button>'; }
      else { act = '<button class="pfix" data-tool="' + esc(fix.tool) + '">' + esc(fix.label) + '</button>'; }
    }
    out.push('<div class="prow sev-' + esc(p.sev) + '">'
      + '<div class="pstate">' + esc(String(p.state).toUpperCase()) + '</div>'
      + '<div class="pbody"><div class="plabel">' + esc(p.label) + '</div>'
      + '<div class="pdetail">' + esc(p.detail) + '</div></div>'
      + act + '</div>');
  }
  box.innerHTML = out.join('');
  el('postureEmpty').style.display = S.posture.length ? 'none' : 'block';
}

/* ------------------------------ research ------------------------------ */
var GAP_CLASS = {
  'OK': 'ok',
  'CONTENT GAP': 'med',
  'NETWORK GAP': 'med',
  'LINUX GAP': 'linux',
  'BLIND': 'high',
  'NOT EVALUATED': 'info'
};

function gapClass(g) { return GAP_CLASS[g] || 'info'; }

function gapRank(g) {
  if (g === 'BLIND') { return 5; }
  if (g === 'CONTENT GAP' || g === 'NETWORK GAP' || g === 'LINUX GAP') { return 4; }
  if (g === 'OK') { return 1; }
  if (g === 'NOT EVALUATED') { return 2; }
  return 0;
}

function shortStamp(s) {
  if (!s) { return '-'; }
  return String(s).replace('T', ' ').substring(0, 19);
}

function labDir() { return S.root + '\\lab'; }

var RESEARCH_CATALOG_FILES = [
  { file: 'techniques.json', label: 'LOLBAS', platform: 'windows' },
  { file: 'worm.json', label: 'Worm-like', platform: 'windows' },
  { file: 'gtfobins.json', label: 'GTFOBins', platform: 'linux' },
  { file: 'hevd-catalog.json', label: 'HEVD Source', platform: 'windows' }
];

function loadResearchCatalog() {
  var R = S.research;
  if (R.loaded) { return true; }
  var versions = [];
  var loadedAny = false;

  for (var f = 0; f < RESEARCH_CATALOG_FILES.length; f++) {
    var cf = RESEARCH_CATALOG_FILES[f];
    var path = S.base + '\\research\\' + cf.file;
    try {
      var text = readAll(path).replace(/^\uFEFF/, '');
      var doc = JSON.parse(text);
      var list = doc.techniques || [];
      if (cf.file === 'techniques.json') { R.catalogVersion = doc.version || '?'; }
      versions.push(cf.label + ' ' + (doc.version || '?'));
      loadedAny = true;
      for (var i = 0; i < list.length; i++) {
        var t = list[i];
        R.catalog.push({
          id: t.id || '',
          name: t.name || t.host || '?',
          host: t.host || '',
          family: t.family || '',
          platform: t.platform || cf.platform,
          group: t.group || t.family || '',
          method: t.method || 'General',
          catalog: cf.label,
          risk: t.risk || '',
          abuse: t.abuse || '',
          detection: t.detection || '',
          hardening: t.hardening || [],
          needs: t.needs || [],
          controls: t.controls || [],
          basis: '',
          tree: t.tree || [],
          cmdMatch: (t.cmd && t.cmd.m) ? t.cmd.m : [],
          cmdWhy: (t.cmd && t.cmd.w) ? t.cmd.w : '',
          asr: t.asr || [],
          netWatch: (t.net && t.net.w) ? t.net.w : '',
          netPorts: (t.net && t.net.ports) ? t.net.ports : '',
          fix: t.fix || [],
          blocks: [],
          presenceNote: '',
          present: null,
          signature: '',
          signer: '',
          version: '',
          path: '',
          gap: '',
          signals: ''
        });
      }
    } catch (e) {
      pushConsole('err', 'Could not read research\\' + cf.file + ': ' + e.message, 'research');
    }
  }

  R.catalogVersions = versions.join(' | ');
  if (!loadedAny) { return false; }
  R.loaded = true;
  R.dirty = true;
  populateResearchFilters();
  return true;
}

function fillResearchSelect(node, items, allLabel, current) {
  if (!node) { return; }
  var out = ['<option value="">' + esc(allLabel) + '</option>'];
  var found = false;
  for (var i = 0; i < items.length; i++) {
    if (items[i].value === current) { found = true; }
    out.push('<option value="' + esc(items[i].value) + '">' + esc(items[i].label) + '</option>');
  }
  node.innerHTML = out.join('');
  node.value = found ? current : '';
}

function populateResearchFilters() {
  var R = S.research;
  var groups = [];
  var groupSeen = {};
  var platforms = [];
  var platformSeen = {};

  function addGroup(name, count) {
    if (!name || groupSeen[name]) { return; }
    groupSeen[name] = true;
    groups.push({ value: name, label: count ? (name + ' (' + count + ')') : name });
  }
  function addPlatform(name, count) {
    if (!name || platformSeen[name]) { return; }
    platformSeen[name] = true;
    var label = name.toUpperCase();
    if (count) { label += ' (' + count + ')'; }
    platforms.push({ value: name, label: label });
  }

  if (R.meta) {
    if (R.meta.groups) {
      for (var g = 0; g < R.meta.groups.length; g++) { addGroup(R.meta.groups[g].name, R.meta.groups[g].count); }
    }
    if (R.meta.platforms) {
      for (var p = 0; p < R.meta.platforms.length; p++) { addPlatform(R.meta.platforms[p].name, R.meta.platforms[p].count); }
    }
  }
  for (var i = 0; i < R.catalog.length; i++) {
    addGroup(R.catalog[i].group, 0);
    addPlatform(R.catalog[i].platform, 0);
  }

  groups.sort(function (a, b) { return a.value < b.value ? -1 : (a.value > b.value ? 1 : 0); });
  platforms.sort(function (a, b) { return a.value < b.value ? -1 : (a.value > b.value ? 1 : 0); });

  fillResearchSelect(el('resGroup'), groups, 'ALL GROUPS', R.filters.group);
  fillResearchSelect(el('resPlatform'), platforms, 'ALL PLATFORMS', R.filters.platform);
  if (el('resGroup')) { R.filters.group = el('resGroup').value || ''; }
  if (el('resPlatform')) { R.filters.platform = el('resPlatform').value || ''; }
}

function resetResearch() {
  var R = S.research;
  var bridged = R.bridged || [];
  R.meta = null;
  R.blocks = [];
  R.blockCount = 0;
  R.controls = [];
  R.findings = [];
  /* Masked Code Audit findings bridged from the HEVD study lab are a local
     artifact, not a host-inventory result. Keep them across an inventory run. */
  for (var b = 0; b < bridged.length; b++) { R.findings.push(bridged[b]); }
  R.probes = [];
  R.proof = null;
  R.selected = '';
  R.dirty = true;
  for (var i = 0; i < R.catalog.length; i++) {
    var t = R.catalog[i];
    t.present = null;
    t.signature = '';
    t.signer = '';
    t.version = '';
    t.path = '';
    t.gap = '';
    t.signals = '';
    t.blocks = [];
    t.presenceNote = '';
  }
}

function setResearchBusy(on) {
  S.research.running = !!on;
  if (el('btnResearchRun')) { el('btnResearchRun').disabled = !!on; }
  if (el('btnResearchProbes')) { el('btnResearchProbes').disabled = !!on; }
}

function researchGapCounts() {
  var c = { ok: 0, content: 0, network: 0, blind: 0, linux: 0, notEval: 0, shown: 0, total: 0 };
  var list = S.research.catalog;
  c.total = list.length;
  for (var i = 0; i < list.length; i++) {
    var g = list[i].gap;
    if (g === 'OK') { c.ok++; }
    else if (g === 'CONTENT GAP') { c.content++; }
    else if (g === 'NETWORK GAP') { c.network++; }
    else if (g === 'BLIND') { c.blind++; }
    else if (g === 'LINUX GAP') { c.linux++; }
    else if (g === 'NOT EVALUATED') { c.notEval++; }
  }
  return c;
}

function renderResearchMeta() {
  var box = el('resSumm');
  if (!box) { return; }
  var R = S.research;
  var out = [];
  var m = R.meta;
  if (!m) {
    out.push('<span class="rsum"><b>CATALOGS</b>' + esc(R.catalogVersions || R.catalogVersion || '?') + '</span>');
    out.push('<span class="rsum"><b>ENTRIES</b>' + R.catalog.length + '</span>');
    out.push('<span class="rsum dim">NO INVENTORY RUN // READ-ONLY LAB</span>');
    box.innerHTML = out.join('');
    return;
  }
  var c = researchGapCounts();
  var catalogText = m.catalog || R.catalogVersions || '-';
  out.push('<span class="rsum" title="' + esc(catalogText) + '"><b>HOST</b>' + esc(m.host || '-') + (m.admin ? ' <i class="radm">ADMIN</i>' : '') + '</span>');
  out.push('<span class="rsum" title="' + esc(catalogText) + '"><b>CATALOGS</b>' + esc(catalogText.length > 54 ? catalogText.substring(0, 51) + '...' : catalogText) + '</span>');
  out.push('<span class="rsum"><b>RUN</b>' + esc(shortStamp(m.generated)) + '</span>');
  out.push('<span class="rsum bad"><b>BLIND</b>' + c.blind + '</span>');
  out.push('<span class="rsum warn"><b>CONTENT</b>' + c.content + '</span>');
  out.push('<span class="rsum warn"><b>NETWORK</b>' + c.network + '</span>');
  out.push('<span class="rsum warn"><b>LINUX GAP</b>' + c.linux + '</span>');
  out.push('<span class="rsum dim"><b>NOT EVAL</b>' + c.notEval + '</span>');
  out.push('<span class="rsum good"><b>OK</b>' + c.ok + '</span>');
  out.push('<span class="rsum"><b>FINDINGS</b>' + R.findings.length + '</span>');
  out.push('<span class="rsum ' + (R.blockCount ? 'good' : 'dim') + '"><b>BLOCKS</b>' + R.blockCount + '</span>');
  if (m.probesRun) { out.push('<span class="rsum"><b>PROBES</b>' + R.probes.length + '</span>'); }
  if (R.proof && R.proof.ran) {
    var pf = R.proof;
    var secShown = pf.secAccessible ? (pf.secMatched > 0 ? '+' + pf.secMatched : '0') : 'n/a';
    var sysShown = pf.sysmonAccessible ? (pf.sysmonMatched > 0 ? '+' + pf.sysmonMatched : '0') : 'n/a';
    var psShown = pf.psAccessible ? (pf.psMatched > 0 ? '+' + pf.psMatched : '0') : 'n/a';
    out.push('<span class="rsum ' + (pf.secMatched === 0 && pf.secAccessible ? 'bad' : (pf.secMatched > 0 ? 'good' : 'dim')) + '"><b>PROOF 4688</b>'
      + secShown + '</span>');
    out.push('<span class="rsum ' + (pf.sysmonMatched === 0 && pf.sysmonAccessible ? 'warn' : (pf.sysmonMatched > 0 ? 'good' : 'dim')) + '"><b>PROOF SYSMON</b>'
      + sysShown + '</span>');
    out.push('<span class="rsum ' + (pf.psMatched === 0 && pf.psAccessible ? 'warn' : (pf.psMatched > 0 ? 'good' : 'dim')) + '"><b>PROOF 4104</b>'
      + psShown + '</span>');
  }
  if (m.wsl) {
    var wslText = 'none';
    if (m.wsl.available) { wslText = (m.wsl.readable && m.wsl.readable.length) ? m.wsl.readable.join(', ') : 'readable'; }
    else if (m.wsl.checked) { wslText = 'not readable'; }
    out.push('<span class="rsum ' + (m.wsl.available ? 'good' : 'dim') + '" title="' + esc(m.wsl.error || '') + '"><b>WSL</b>' + esc(wslText) + '</span>');
  }
  if (m.psLog) { out.push('<span class="rsum dim" title="PowerShell event channel state. This is not the script-block or module logging policy; those are separate control rows."><b>PSLOG CH</b>' + esc(m.psLog) + '</span>'); }
  if (m.sysmonLog) { out.push('<span class="rsum dim" title="Sysmon operational channel state, not whether every Sysmon event policy is enabled."><b>SYSMON CH</b>' + esc(m.sysmonLog) + '</span>'); }
  box.innerHTML = out.join('');
}

function renderResearchControls() {
  var box = el('resControls');
  if (!box) { return; }
  var list = S.research.controls;
  var out = [];
  for (var i = 0; i < list.length; i++) {
    var c = list[i];
    var cls = 'prow';
    if (c.neutral) { cls += ' sev-info'; }
    else if (c.badWhenOn) { cls += (c.value ? ' sev-med' : ' sev-ok'); }
    else if (c.value) { cls += ' sev-ok'; }
    else { cls += (String(c.severity || '').toLowerCase() === 'high' ? ' sev-high' : ' sev-med'); }
    var label = c.name || '';
    if (c.badWhenOn) { label += ' (safer when off)'; }
    out.push('<div class="' + cls + ' resctlrow" data-ctl="' + i + '" title="Click for state detail and remediation">'
      + '<div class="pstate">' + (c.value ? 'ON' : 'OFF') + '</div>'
      + '<div class="pbody"><div class="plabel">' + esc(label) + '</div>'
      + '<div class="pdetail">' + esc(c.source || '') + '</div></div>'
      + '<button class="pfix" data-ctl="' + i + '">' + (c.neutral ? 'DETAIL' : 'FIX') + '</button>'
      + '</div>');
  }
  if (!list.length) {
    box.innerHTML = '<div class="empty small">NO CONTROL DATA // RUN THE INVENTORY</div>';
  } else {
    box.innerHTML = out.join('');
  }
  if (el('resCtlCount')) { el('resCtlCount').innerHTML = list.length ? (list.length + ' CHECKS') : ''; }
}

function renderResearchTable() {
  var tb = el('resBody');
  if (!tb) { return; }
  var R = S.research;
  var list = [];
  var anyGap = false;
  var fg = R.filters.group || '';
  var fp = R.filters.platform || '';

  for (var i = 0; i < R.catalog.length; i++) {
    var t0 = R.catalog[i];
    if (fg && t0.group !== fg) { continue; }
    if (fp && String(t0.platform || '').toLowerCase() !== fp.toLowerCase()) { continue; }
    if (t0.gap) { anyGap = true; }
    list.push(t0);
  }

  if (anyGap) {
    list.sort(function (a, b) {
      var ra = gapRank(a.gap), rb = gapRank(b.gap);
      if (ra !== rb) { return rb - ra; }
      if (a.group !== b.group) { return a.group < b.group ? -1 : 1; }
      return a.name < b.name ? -1 : (a.name > b.name ? 1 : 0);
    });
  } else {
    list.sort(function (a, b) {
      if (a.group !== b.group) { return a.group < b.group ? -1 : 1; }
      return a.name < b.name ? -1 : (a.name > b.name ? 1 : 0);
    });
  }

  var rows = [];
  for (var j = 0; j < list.length; j++) {
    var t = list[j];
    var present = '<span class="dim">N/E</span>';
    if (t.present === true) { present = '<span class="oktxt">YES</span>'; }
    else if (t.present === false) { present = '<span class="dim">NO</span>'; }
    var gap = t.gap ? '<span class="gap gap-' + esc(gapClass(t.gap)) + '">' + esc(t.gap) + '</span>' : '<span class="dim">-</span>';
    var act = t.signals ? '<span class="sig">' + esc(t.signals.replace(/,/g, ' ')) + '</span>' : '<span class="dim">-</span>';
    if (t.blocks && t.blocks.length) {
      act += ' <span class="blkbadge" title="Observed defensive block recorded for this technique">BLK ' + t.blocks.length + '</span>';
    }
    var plat = String(t.platform || '').toLowerCase();
    var platBadge = '<span class="pbadge ' + (plat === 'linux' ? 'linux' : 'win') + '">' + (plat === 'linux' ? 'LNX' : 'WIN') + '</span>';
    var grp = platBadge + ' ' + esc(t.group || t.catalog || '-');
    var cls = (t.host === R.selected) ? ' class="sel"' : '';
    rows.push('<tr data-host="' + esc(t.host) + '"' + cls + '>'
      + '<td class="mono dim">' + esc(t.id) + '</td>'
      + '<td class="mono">' + esc(t.host) + '</td>'
      + '<td class="resgrp">' + grp + '</td>'
      + '<td>' + present + '</td>'
      + '<td>' + gap + '</td>'
      + '<td>' + act + '</td>'
      + '</tr>');
  }
  tb.innerHTML = rows.join('');

  if (el('resEmpty')) {
    if (list.length) { el('resEmpty').style.display = 'none'; }
    else {
      el('resEmpty').style.display = 'block';
      el('resEmpty').innerHTML = R.catalog.length ? 'NO ENTRIES MATCH THE GROUP / PLATFORM FILTER' : 'NO COVERAGE DATA // RUN THE INVENTORY';
    }
  }
  if (el('resCount')) {
    var text = list.length + ' ENTRIES';
    if (list.length !== R.catalog.length) { text = list.length + ' / ' + R.catalog.length + ' ENTRIES'; }
    el('resCount').innerHTML = text;
  }
}

function resStepHtml(step, idx) {
  var out = [];
  out.push('<div class="tstep">');
  out.push('<div class="tnum">' + (idx + 1) + '</div>');
  out.push('<div class="tinfo">');
  out.push('<div class="tstage"><b>' + esc(step.s || 'step') + '</b>'
    + (step.t ? '<span class="tmitre">' + esc(step.t) + '</span>' : '') + '</div>');
  if (step.p) { out.push('<div class="tproc">' + esc(step.p) + '</div>'); }
  if (step.a) { out.push('<div class="tdesc">' + esc(step.a) + '</div>'); }
  if (step.d) { out.push('<div class="ttele"><b>LOG</b> ' + esc(step.d) + '</div>'); }
  if (step.c) { out.push('<code class="tsample">' + esc(step.c) + '</code>'); }
  out.push('</div></div>');
  return out.join('');
}

function resListHtml(items, cls) {
  if (!items || !items.length) { return ''; }
  var out = [];
  for (var i = 0; i < items.length; i++) {
    out.push('<div class="' + (cls || 'resdli') + '">' + esc(items[i]) + '</div>');
  }
  return out.join('');
}

function resBlockHtml(b, compact) {
  if (!b) { return ''; }
  var h = [];
  h.push('<div class="blkcard">');
  h.push('<div class="blkhead">'
    + '<span class="blkid">' + esc(b.id || 'BLOCK') + '</span>'
    + '<span class="blkkind">' + esc(b.kind || '') + '</span>'
    + '<span class="blkresult">' + esc(b.result || '') + '</span>'
    + '</div>');
  if (b.tech) { h.push('<div class="blkline"><b>TECH</b> ' + esc(b.tech) + (b.technique ? ' ' + esc(b.technique) : '') + '</div>'); }
  if (b.host) { h.push('<div class="blkline"><b>HOST</b> ' + esc(b.host) + '</div>'); }
  if (b.product) { h.push('<div class="blkline"><b>PRODUCT</b> ' + esc(b.product) + '</div>'); }
  if (b.vector) { h.push('<div class="blkline"><b>VECTOR</b> ' + esc(b.vector) + '</div>'); }
  if (b.cmd) { h.push('<div class="blkline"><b>COMMAND</b> <code class="blkcode">' + esc(b.cmd) + '</code></div>'); }
  if (b.signal) { h.push('<div class="blkline"><b>SIGNAL</b> ' + esc(b.signal) + '</div>'); }
  if (!compact) {
    if (b.date) { h.push('<div class="blkline"><b>DATE</b> ' + esc(b.date) + '</div>'); }
    if (b.scope) { h.push('<div class="blkline"><b>SCOPE</b> ' + esc(b.scope) + '</div>'); }
    if (b.valid) { h.push('<div class="blkline"><b>VALID</b> ' + esc(b.valid) + '</div>'); }
  }
  if (b.teaches) { h.push('<div class="blkline"><b>TEACHES</b> ' + esc(b.teaches) + '</div>'); }
  if (!compact && b.followup) { h.push('<div class="blkline"><b>FOLLOW-UP</b> ' + esc(b.followup) + '</div>'); }
  if (!compact && b.detect) { h.push('<div class="blkline"><b>DETECT</b> ' + esc(b.detect) + '</div>'); }
  if (!compact && b.variants && b.variants.length) {
    h.push('<div class="blkline"><b>VARIANTS</b></div>');
    for (var i = 0; i < b.variants.length; i++) {
      h.push('<div class="blkvar"><code>' + esc(b.variants[i].cmd || '') + '</code>'
        + '<span>' + esc(b.variants[i].result || '') + '</span></div>');
    }
  }
  h.push('</div>');
  return h.join('');
}

function presenceLine(t) {
  if (t.present === true) { return '<span class="oktxt">present</span>'; }
  if (t.present === false) { return '<span class="dim">not present</span>'; }
  return '<span class="dim">not evaluated</span>';
}

/* Reset the independent detail scrollers when a different technique is shown.
   Streaming inventory events redraw the same detail, so do not yank the user
   back to the top unless the selected entry actually changed. */
function resetResearchDetailScroll() {
  var box = el('resDetail');
  if (!box || !box.getElementsByClassName) { return; }
  var cols = box.getElementsByClassName('resdcol');
  for (var i = 0; cols && i < cols.length; i++) { cols[i].scrollTop = 0; }
  var metas = box.getElementsByClassName('resdmeta');
  for (var j = 0; metas && j < metas.length; j++) { metas[j].scrollTop = 0; }
}

function renderResearchDetail() {
  var box = el('resDetail');
  if (!box) { return; }
  var t = researchEntry(S.research.selected);
  if (!t) {
    S.research.detailKey = '';
    box.innerHTML = '<div class="resdempty"><span class="micro">SELECT A TECHNIQUE ROW FOR THE PROCESS TREE, DETECTION AND FIXES</span></div>';
    return;
  }

  var plat = String(t.platform || '').toLowerCase();
  var h = [];
  h.push('<div class="resdmeta">');
  h.push('<div class="resdhead">');
  h.push('<span class="resdname">' + esc(t.name) + '</span>');
  if (t.id) { h.push('<span class="dt">' + esc(t.id) + '</span>'); }
  if (t.host) { h.push('<span class="dt">' + esc(t.host) + '</span>'); }
  if (plat) { h.push('<span class="pbadge ' + (plat === 'linux' ? 'linux' : 'win') + '">' + (plat === 'linux' ? 'LINUX' : 'WINDOWS') + '</span>'); }
  if (t.group) { h.push('<span class="dt">' + esc(t.group) + '</span>'); }
  if (t.method) { h.push('<span class="dt dim">' + esc(t.method) + '</span>'); }
  if (t.catalog) { h.push('<span class="dt dim">' + esc(t.catalog) + '</span>'); }
  if (t.gap) { h.push('<span class="gap gap-' + esc(gapClass(t.gap)) + '">' + esc(t.gap) + '</span>'); }
  if (t.signature) { h.push('<span class="dt dim">sig ' + esc(t.signature) + (t.signer ? ' / ' + esc(t.signer) : '') + '</span>'); }
  h.push('</div>');

  var presence = '<div class="resdline"><b>PRESENCE</b> ' + presenceLine(t);
  if (t.presenceNote) { presence += ' <span class="dim">' + esc(t.presenceNote) + '</span>'; }
  if (t.path) { presence += ' <span class="resdpath">' + esc(t.path) + '</span>'; }
  presence += '</div>';
  h.push(presence);

  if (t.basis) {
    h.push('<div class="resdbasis"><b>BASIS</b> ' + esc(t.basis) + '</div>');
  }
  if (t.abuse) {
    h.push('<div class="resdline"><b>ABUSE</b> ' + esc(t.abuse) + '</div>');
  }
  h.push('</div>');

  h.push('<div class="resdbody">');

  /* ---- left: process / event chain ---- */
  h.push('<div class="resdcol resdleft">');
  h.push('<div class="resdlabel">PROCESS TREE / EVENT CHAIN<span class="resdnote">what to look for, not a payload</span></div>');
  if (t.tree && t.tree.length) {
    for (var i = 0; i < t.tree.length; i++) { h.push(resStepHtml(t.tree[i], i)); }
  } else {
    h.push('<div class="resdli dim">No chain data in this catalog entry.</div>');
  }
  h.push('</div>');

  /* ---- right: detect / asr / network / blocks / remediate ---- */
  h.push('<div class="resdcol resdright">');

  h.push('<div class="resdlabel">DETECT</div>');
  if (t.detection) { h.push('<div class="resdli">' + esc(t.detection) + '</div>'); }
  if (t.cmdMatch && t.cmdMatch.length) {
    for (var c = 0; c < t.cmdMatch.length; c++) {
      h.push('<code class="tmatch">' + esc(t.cmdMatch[c]) + '</code>');
    }
  }
  if (t.cmdWhy) { h.push('<div class="resdwhy">' + esc(t.cmdWhy) + '</div>'); }

  h.push('<div class="resdlabel">ATTACK SURFACE REDUCTION</div>');
  if (t.asr && t.asr.length) {
    for (var a = 0; a < t.asr.length; a++) {
      h.push('<div class="asrrow"><code class="asrguid">' + esc(t.asr[a].g) + '</code>'
        + '<span class="asrname">' + esc(t.asr[a].n) + '</span></div>');
    }
    h.push('<code class="tsample">Add-MpPreference -AttackSurfaceReductionRules_Ids &lt;guid&gt; -AttackSurfaceReductionRules_Actions Enabled</code>');
    h.push('<div class="resdwhy">Shown for reference. NetTruder never applies this; it needs an administrator to run it.</div>');
  } else {
    h.push('<div class="resdli dim">No ASR rule maps directly to this host.</div>');
  }

  h.push('<div class="resdlabel">NETWORK MONITORING</div>');
  if (t.netWatch) {
    h.push('<div class="resdli">' + esc(t.netWatch) + '</div>');
    h.push('<div class="resdnet"><b>EGRESS PORTS</b> ' + esc(t.netPorts || 'any') + '</div>');
    h.push('<div class="resdwhy">The IDS flags an alert named EGRESS_' + esc(String(t.host || '').toUpperCase())
      + ' when this process opens an outbound session, and records the command line if it can read it.</div>');
  } else {
    h.push('<div class="resdli dim">No egress rule for this host.</div>');
  }

  if (t.blocks && t.blocks.length) {
    h.push('<div class="resdlabel">OBSERVED BLOCKS<span class="resdnote">positive control result, not a coverage pass</span></div>');
    for (var b = 0; b < t.blocks.length; b++) { h.push(resBlockHtml(t.blocks[b], true)); }
  }

  h.push('<div class="resdlabel">REMEDIATE</div>');
  h.push(resListHtml(t.fix, 'resdli fix'));
  h.push(resListHtml(t.hardening, 'resdli policy'));
  if ((!t.fix || !t.fix.length) && (!t.hardening || !t.hardening.length)) {
    h.push('<div class="resdli dim">No remediation recorded for this entry.</div>');
  }
  h.push('<div class="resdwhy">NetTruder never weakens a control. Enable and harden actions need an administrator.</div>');

  h.push('</div></div>');

  var detailKey = t.id || t.host || t.name || '';
  box.innerHTML = h.join('');
  if (S.research.detailKey !== detailKey) {
    resetResearchDetailScroll();
    S.research.detailKey = detailKey;
  }
}

function renderResearchFindings() {
  var box = el('resFindings');
  if (!box) { return; }
  var R = S.research;
  var out = [];

  function proofClass(accessible, matched) {
    if (!accessible) { return 'med'; }
    return (matched > 0) ? 'low' : 'med';
  }
  function proofCard(label, accessible, matched, verdict, detail) {
    return '<div class="find ' + proofClass(accessible, matched) + '">'
      + '<div class="ftop"><span class="fsev">' + esc(label) + '</span>' + esc(verdict || '') + '</div>'
      + (detail ? '<div class="fdet">' + esc(detail) + '</div>' : '')
      + '</div>';
  }

  for (var i = 0; i < R.findings.length; i++) {
    var f = R.findings[i];
    var sev = String(f.severity || '').toUpperCase();
    var cls = sev === 'HIGH' ? 'high' : (sev === 'MEDIUM' ? 'med' : (sev === 'LOW' ? 'low' : ''));
    out.push('<div class="find ' + cls + ' clk" data-find="' + i + '" title="Click for remediation">'
      + '<div class="ftop"><span class="fsev">' + esc(sev) + '</span>' + esc(f.title)
      + '<button class="ffix" data-find="' + i + '">FIX</button></div>'
      + '<div class="fdet">' + esc(f.detail) + '</div>'
      + (f.control ? '<div class="fctl">CONTROL ' + esc(f.control) + '</div>' : '')
      + '</div>');
  }

  if (R.proof) {
    var pr = R.proof;
    out.push('<div class="findhead">TELEMETRY PROOF</div>');
    if (!pr.ran) {
      out.push('<div class="find"><div class="fdet">Marker probes were not run. Gap labels are configuration-derived, not measured.</div></div>');
    } else {
      var secDetail = 'accessible=' + (pr.secAccessible ? 'yes' : 'no')
        + ' matched=' + (pr.secAccessible ? pr.secMatched : 'n/a')
        + ' before=' + pr.secBefore + ' after=' + pr.secAfter
        + ' delta=' + (pr.secDelta === null ? 'n/a' : pr.secDelta)
        + ' observed=' + (pr.processObserved === true ? 'yes' : (pr.processObserved === false ? 'no' : 'n/a'));
      out.push(proofCard('4688', pr.secAccessible, pr.secMatched, pr.secVerdict, secDetail));

      var sysDetail = 'accessible=' + (pr.sysmonAccessible ? 'yes' : 'no')
        + ' matched=' + (pr.sysmonAccessible ? pr.sysmonMatched : 'n/a');
      out.push(proofCard('SYSMON 1', pr.sysmonAccessible, pr.sysmonMatched, pr.sysmonVerdict, sysDetail));

      var psDetail = 'accessible=' + (pr.psAccessible ? 'yes' : 'no')
        + ' matched=' + (pr.psAccessible ? pr.psMatched : 'n/a')
        + ' before=' + pr.psBefore + ' after=' + pr.psAfter
        + ' delta=' + (pr.psDelta === null ? 'n/a' : pr.psDelta)
        + ' observed=' + (pr.contentObserved === true ? 'yes' : (pr.contentObserved === false ? 'no' : 'n/a'));
      out.push(proofCard('4104', pr.psAccessible, pr.psMatched, pr.psVerdict, psDetail));

      if (pr.processSource || pr.contentSource) {
        out.push('<div class="find"><div class="fdet">process source: ' + esc(pr.processSource || 'n/a')
          + ' / content source: ' + esc(pr.contentSource || 'n/a') + '</div></div>');
      }
      if (pr.thirdPartyEdr) {
        out.push('<div class="find"><div class="fdet">third-party EDR: ' + esc(pr.thirdPartyEdr) + '</div></div>');
      }
      if (pr.caveat) { out.push('<div class="find"><div class="fdet">' + esc(pr.caveat) + '</div></div>'); }
    }
    if (pr.elevation) {
      var el2 = pr.elevation;
      var elevText = 'tokenElevated=' + (el2.tokenElevated === undefined ? (el2.elevated ? 'yes' : 'no') : (el2.tokenElevated ? 'yes' : 'no'))
        + ' / adminGroup=' + (el2.adminGroup ? 'yes' : 'no')
        + ' / integrity=' + (el2.integrity || 'unknown')
        + ' / elevationType=' + (el2.elevationType || 'unknown')
        + ' / securityReadable=' + (el2.securityReadable ? 'yes' : 'no')
        + ' / SeSecurityPrivilege present=' + (el2.privilegePresent ? 'yes' : 'no')
        + ' enabled=' + (el2.privilegeEnabled ? 'yes' : 'no')
        + ' attempt=' + (el2.privilegeAttemptResult ? String(el2.privilegeAttemptResult) : 'n/a')
        + ' / user=' + (el2.user || '-');
      out.push('<div class="find ' + (el2.securityReadable ? '' : 'med') + ' clk" data-elevfix="1" title="Click for elevation remediation">'
        + '<div class="ftop"><span class="fsev">ELEVATION</span>proof context'
        + '<button class="ffix" data-elevfix="1">FIX</button></div>'
        + '<div class="fdet">' + esc(elevText) + '</div>'
        + (el2.securityHint ? '<div class="fctl">' + esc(el2.securityHint) + '</div>' : '')
        + '</div>');
      if (el2.securityError) { out.push('<div class="find med"><div class="fdet">Security log error: ' + esc(el2.securityError) + '</div></div>'); }
      if (el2.auditpolError) { out.push('<div class="find med"><div class="fdet">auditpol error: ' + esc(el2.auditpolError) + (el2.auditpolHint ? ' - ' + esc(el2.auditpolHint) : '') + '</div></div>'); }
      if (el2.sysmonError) { out.push('<div class="find"><div class="fdet">Sysmon log: ' + esc(el2.sysmonError) + '</div></div>'); }
    }
  }

  if (R.probes.length) {
    out.push('<div class="findhead">MARKER PROBES</div>');
    for (var j = 0; j < R.probes.length; j++) {
      var p = R.probes[j];
      out.push('<div class="find ' + (p.marker ? 'low' : 'med') + '">'
        + '<div class="ftop"><span class="fsev">' + esc(p.probe) + '</span>' + esc(p.host) + '</div>'
        + '<div class="fdet">executed=' + (p.executed ? 'yes' : 'no')
        + ' / marker=' + (p.marker ? 'yes' : 'no')
        + (p.error ? ' / ' + esc(p.error) : '') + '</div></div>');
    }
  }

  if (!out.length) {
    box.innerHTML = '<div class="empty small">NO FINDINGS</div>';
  } else {
    box.innerHTML = out.join('');
  }
  if (el('resFindCount')) {
    el('resFindCount').innerHTML = R.findings.length ? (R.findings.length + ' ITEMS') : '';
  }
}

function renderResearch() {
  S.research.dirty = false;
  renderResearchMeta();
  renderResearchControls();
  renderResearchTable();
  renderResearchFindings();
  renderResearchDetail();
}

function runResearch(probes) {
  if (S.streams.research && !S.streams.research.done) {
    pushConsole('warn', 'A coverage inventory is already running.', 'research');
    return;
  }
  if (!loadResearchCatalog()) { return; }
  if (probes) {
    if (!confirm('Run the four inert marker probes?\n\nEach probe opens normally, writes one line to markers.log and exits. No payload, no network, no persistence, no hidden window.\n\nOnly continue on a host you are authorised to test.')) { return; }
  }
  resetResearch();
  renderResearch();
  el('researchState').innerHTML = probes ? 'PROBES' : 'SCANNING';
  setResearchBusy(true);
  pushConsole('ok', (probes ? 'Marker probe run started. ' : 'Coverage inventory started. ') + 'Read-only checks.', 'research');
  var st = startStream('research', 'research', { Probes: !!probes, Yes: !!probes });
  if (st && st.done) {
    setResearchBusy(false);
    el('researchState').innerHTML = 'FAILED';
  }
}

/* --------------------------- remediation UI --------------------------- */
var DEFAULT_REMEDY_NOTE = 'NetTruder never weakens a control. The actions here enable, harden or inspect the host; they never turn a security control off. Administrator rights are required.';

function clipboardText(text) {
  if (!text) { return; }
  try {
    if (window.clipboardData) { window.clipboardData.setData('Text', text); }
    else { throw new Error('clipboard is unavailable'); }
    pushConsole('ok', 'Copied to the clipboard.', 'remedy');
  } catch (e) {
    pushConsole('err', 'Could not copy to the clipboard: ' + e.message, 'remedy');
  }
}

function openElevatedShell() {
  try {
    S.sh.Run('powershell.exe -NoProfile -Command "Start-Process powershell.exe -Verb RunAs -ArgumentList \'-NoExit\',\'-NoProfile\'"', 1, false);
    pushConsole('warn', 'Elevated PowerShell launched. The remediation script is in the clipboard; paste it, review it, then run it. NetTruder never weakens a control.', 'remedy');
  } catch (e) {
    pushConsole('err', 'Could not launch an elevated shell: ' + e.message, 'remedy');
  }
}

function showModal(p) {
  S.modal = p || {};
  var wrap = el('modalWrap');
  if (!wrap) { return; }
  if (el('modalTitle')) { el('modalTitle').innerHTML = esc(S.modal.title || 'REMEDIATION'); }
  var h = [];
  if (S.modal.kicker) {
    var sev = String(S.modal.sev || '').toLowerCase();
    if (sev !== 'high' && sev !== 'med' && sev !== 'low' && sev !== 'ok') { sev = ''; }
    h.push('<div class="mkicker ' + sev + '">' + esc(S.modal.kicker) + '</div>');
  }
  if (S.modal.detail) { h.push('<div class="mdetail">' + esc(S.modal.detail) + '</div>'); }
  if (S.modal.html) { h.push(S.modal.html); }
  if (S.modal.fix && S.modal.fix.length) {
    h.push('<div class="mlabel">STEPS</div>');
    h.push('<div class="msteps">');
    for (var i = 0; i < S.modal.fix.length; i++) {
      h.push('<div class="mstep">' + esc(S.modal.fix[i]) + '</div>');
    }
    h.push('</div>');
  }
  if (S.modal.enable) {
    h.push('<div class="mlabel">ENABLE / HARDEN SCRIPT</div>');
    h.push('<code class="mscript">' + esc(S.modal.enable) + '</code>');
    h.push('<div class="mnote">The script is provided for an administrator and is never executed by NetTruder. Review it before running.</div>');
  }
  h.push('<div class="mnote">' + esc(S.modal.note || DEFAULT_REMEDY_NOTE) + '</div>');
  if (el('modalBody')) {
    el('modalBody').innerHTML = h.join('');
    el('modalBody').scrollTop = 0;
  }
  var b = [];
  if (S.modal.pid) { b.push('<button class="mbtn" data-mact="process">PROCESS</button>'); }
  if (S.modal.enable) {
    b.push('<button class="mbtn primary" data-mact="copy">COPY SCRIPT</button>');
    b.push('<button class="mbtn" data-mact="elevated">ELEVATED SHELL</button>');
  }
  if (S.modal.fix && S.modal.fix.length) { b.push('<button class="mbtn" data-mact="copyfix">COPY STEPS</button>'); }
  if (S.modal.copyText) { b.push('<button class="mbtn" data-mact="copytext">COPY DETAIL</button>'); }
  if (S.modal.native) { b.push('<button class="mbtn" data-mact="native">NATIVE UI</button>'); }
  b.push('<button class="mbtn" data-mact="close">CLOSE</button>');
  if (el('modalFoot')) { el('modalFoot').innerHTML = b.join(''); }
  wrap.style.display = 'flex';
}

function hideModal() {
  var wrap = el('modalWrap');
  if (wrap) { wrap.style.display = 'none'; }
  S.modal = null;
}

function modalAction(act) {
  var m = S.modal;
  if (!m) { hideModal(); return; }
  if (act === 'close') { hideModal(); return; }
  if (act === 'copy') { clipboardText(m.enable || ''); return; }
  if (act === 'copyfix') {
    var t = (m.fix || []).join('\r\n');
    if (m.enable) { t += '\r\n\r\n' + m.enable; }
    clipboardText(t);
    return;
  }
  if (act === 'copytext') { clipboardText(m.copyText || ''); return; }
  if (act === 'elevated') {
    clipboardText(m.enable || '');
    openElevatedShell();
    return;
  }
  if (act === 'native') {
    var tool = m.native;
    hideModal();
    if (tool) { openTool(tool); }
    return;
  }
  if (act === 'process') {
    var pid = m.pid; var proc = m.proc;
    hideModal();
    if (pid) { focusProcess(pid, proc); }
    return;
  }
}

function showControlRemedy(c) {
  if (!c) { return; }
  var bad = !!c.badWhenOn;
  var detail = c.detail || '';
  if (c.neutral) { detail += ' This row records channel or context state; it is not a policy gap.'; }
  if (bad && c.value) {
    detail += ' This control is safer when off on hosts that do not need it. NetTruder will not turn a control off for you; review that change with the platform owner.';
  }
  var sev = c.value ? 'ok' : (String(c.severity || '').toLowerCase() === 'high' ? 'high' : 'med');
  showModal({
    title: c.name || 'CONTROL',
    kicker: (c.value ? 'ON' : 'OFF') + (c.source ? ' / ' + c.source : '') + (bad ? ' / SAFER WHEN OFF' : ''),
    sev: sev,
    detail: detail,
    fix: c.fix || [],
    native: c.native || '',
    enable: (!c.value && !c.neutral) ? (c.enable || '') : '',
    note: DEFAULT_REMEDY_NOTE
  });
}

function showFindingRemedy(f) {
  if (!f) { return; }
  var sev = String(f.severity || '').toLowerCase();
  showModal({
    title: f.title || 'FINDING',
    kicker: String(f.severity || '').toUpperCase() + (f.control ? ' / CONTROL ' + f.control : ''),
    sev: (sev === 'high' || sev === 'medium' ? 'high' : (sev === 'low' ? 'low' : 'med')),
    detail: f.detail || '',
    fix: f.fix || [],
    enable: f.enable || '',
    native: f.native || '',
    note: DEFAULT_REMEDY_NOTE
  });
}

function showElevationRemedy(e) {
  e = e || {};
  var elevated = (e.tokenElevated === undefined) ? !!e.elevated : !!e.tokenElevated;
  var steps = [];
  if (e.securityReadable) {
    steps = [
      'The Security log is readable in this session; no elevation change is needed.',
      'Keep the marker-probe proof with the report so the 4688 claim stays measured.',
      'If a later run loses access, relaunch with Launch-Elevated.cmd and re-run the inventory.'
    ];
  } else if (!e.adminGroup && !elevated) {
    steps = [
      'Use an account that is a member of Administrators on this host.',
      'Right-click Launch-Elevated.cmd and choose Run as administrator, then accept the UAC prompt.',
      'Re-run the coverage inventory with marker probes; proof should show tokenElevated=yes.',
      'NetTruder never disables UAC or changes account rights silently.'
    ];
  } else if (e.adminGroup && !elevated) {
    steps = [
      'Close NetTruder, then right-click Launch-Elevated.cmd and choose Run as administrator.',
      'Accept the UAC prompt. Group membership alone does not give this process the Security log.',
      'Re-run the coverage inventory with marker probes and confirm tokenElevated=yes.',
      'If it stays no, check that UAC is enabled and that the prompt is not being auto-denied by policy.',
      'NetTruder never disables UAC and never auto-elevates.'
    ];
  } else {
    steps = [
      'Confirm the process token: whoami /groups shows the Mandatory Label and Administrators state.',
      'Confirm the privilege: whoami /priv lists SeSecurityPrivilege and whether it is enabled.',
      'Review secpol.msc - Local Policies - User Rights Assignment - Manage auditing and security log.',
      'Inspect the channel access: wevtutil gl Security, and compare the SDDL with the account SID.',
      'Re-run the inventory. NetTruder reports the exact error and never weakens auditing to make a probe pass.'
    ];
  }
  showModal({
    title: 'SESSION ELEVATION AND SECURITY LOG',
    kicker: 'tokenElevated=' + (elevated ? 'YES' : 'NO') + ' / adminGroup=' + (e.adminGroup ? 'YES' : 'NO')
      + ' / securityReadable=' + (e.securityReadable ? 'YES' : 'NO'),
    sev: e.securityReadable ? 'ok' : 'med',
    detail: (e.securityHint || 'Group membership and an elevated token are different facts. The Security log needs the elevated token and SeSecurityPrivilege.')
      + (e.securityError ? '\nLast error: ' + e.securityError : ''),
    fix: steps,
    native: 'secpol.msc',
    note: 'NetTruder never weakens a control. These steps inspect or enable the session; they never disable UAC, auditing, Defender or any security service.'
  });
}


function showAlertRemedy(a) {
  if (!a) { return; }
  var rx = a.remedy || null;
  var steps = (rx && rx.steps && rx.steps.length) ? rx.steps : [
    'Review the process, destination and command line in the alert.',
    'Use Task Manager, Resource Monitor and the firewall console to confirm the owner.',
    'Preserve evidence before changing the host. NetTruder never weakens a control.'
  ];
  var detail = a.detail || '';
  if (a.hosts && a.hosts.length) { detail += '\nPeers: ' + a.hosts.join(', '); }
  if (a.ports) { detail += '\nPorts: ' + a.ports; }
  showModal({
    title: a.title || a.id || 'ALERT REMEDIATION',
    kicker: (a.id || 'ALERT') + ' / ' + String(a.sev || '').toUpperCase() + (a.proc ? ' / ' + a.proc : ''),
    sev: a.sev || 'med',
    detail: detail,
    fix: steps,
    native: rx ? (rx.native || '') : 'taskmgr.exe',
    note: (rx && rx.note) ? rx.note : DEFAULT_REMEDY_NOTE,
    pid: a.pid || 0,
    proc: a.proc || ''
  });
}

function showBlocksModal() {
  var R = S.research;
  var blocks = R.blocks;
  if ((!blocks || !blocks.length) && R.meta && R.meta.blocks) { blocks = R.meta.blocks; }
  var h = [];
  if (!blocks || !blocks.length) {
    h.push('<div class="mdetail">No block register is loaded. The register lives in research\\blocks.json and is separate from the catalogs.</div>');
  } else {
    h.push('<div class="mdetail">A block is a positive control result, not a coverage pass. It says nothing about the variants that were not attempted, and no bypass was attempted.</div>');
    for (var i = 0; i < blocks.length; i++) { h.push(resBlockHtml(blocks[i], false)); }
  }
  showModal({
    title: 'OBSERVED DEFENSIVE BLOCKS',
    kicker: (blocks ? blocks.length : 0) + ' RECORDED',
    html: h.join(''),
    note: 'Host-specific evidence from research\\blocks.json. NetTruder records blocks and never attempts to bypass an endpoint control.'
  });
}

function findAlert(seq) {
  var n = parseInt(seq, 10) || 0;
  for (var i = 0; i < S.alerts.length; i++) {
    if (S.alerts[i]._seq === n) { return S.alerts[i]; }
  }
  return null;
}

function addAlertToast(a) {
  var box = el('toasts');
  if (!box || !a) { return; }
  if (String(a.sev || '').toLowerCase() === 'info') { return; }
  var sev = String(a.sev || 'med').toLowerCase();
  if (sev !== 'high' && sev !== 'med' && sev !== 'low') { sev = 'med'; }
  var div = document.createElement('div');
  var seq = ++S.toastSeq;
  div.className = 'toast ' + sev;
  div.setAttribute('data-toast', String(seq));
  div._alert = a;
  var acts = '<button class="tact primary" data-tact="remedy">REMEDY</button>';
  if (a.pid) { acts += '<button class="tact" data-tact="process">PROCESS</button>'; }
  acts += '<button class="tact" data-tact="dismiss">DISMISS</button>';
  div.innerHTML = '<div class="thead"><span class="tid">' + esc(a.id || 'ALERT') + '</span>'
    + '<span class="tsev">' + esc(sev.toUpperCase()) + '</span></div>'
    + '<div class="ttitle">' + esc(a.title || '') + '</div>'
    + '<div class="tdetail">' + esc(a.detail || '') + '</div>'
    + '<div class="tacts">' + acts + '</div>';
  box.appendChild(div);
  while (box.childNodes.length > 4) { box.removeChild(box.firstChild); }
  window.setTimeout(function () {
    if (div.parentNode) { div.parentNode.removeChild(div); }
  }, 15000);
}

function toastAction(ev) {
  var e = ev || window.event;
  var t = e.target || e.srcElement;
  while (t && t.tagName !== 'BUTTON') { t = t.parentNode; }
  if (!t) { return; }
  var act = t.getAttribute('data-tact');
  var host = closestAttr(t, 'data-toast');
  if (!host) { return; }
  var a = host._alert;
  if (act === 'dismiss') {
    if (host.parentNode) { host.parentNode.removeChild(host); }
    return;
  }
  if (!a) { return; }
  if (host.parentNode) { host.parentNode.removeChild(host); }
  if (act === 'remedy') { showAlertRemedy(a); }
  else if (act === 'process') { focusProcess(a.pid, a.proc); }
}

/* ------------------------------ processes ----------------------------- */
function mbText(bytes) {
  var n = Number(bytes);
  if (!n || n <= 0) { return '0'; }
  return String(Math.round(n / (1024 * 1024)));
}

function procMatches(p, f) {
  if (!f) { return true; }
  var hay = (p.pid + ' ' + (p.name || '') + ' ' + (p.owner || '') + ' ' + (p.ports || '') + ' ' + (p.path || '') + ' ' + (p.cmd || '')).toLowerCase();
  return hay.indexOf(f) >= 0;
}

function findProc(pid) {
  for (var i = 0; i < S.procs.length; i++) {
    if (S.procs[i].pid === pid) { return S.procs[i]; }
  }
  return null;
}

function renderProcDetail() {
  var box = el('procDetail');
  if (!box) { return; }
  var p = findProc(S.procSelected);
  if (!p) {
    box.innerHTML = '<span class="micro">SELECT A PROCESS ROW FOR DETAIL</span>';
    return;
  }
  var bits = [];
  bits.push('<span class="dt"><b>' + esc(p.name) + '</b></span>');
  bits.push('<span class="dt">PID ' + p.pid + ' / PPID ' + (p.ppid || 0) + '</span>');
  bits.push('<span class="dt">' + esc(p.owner || 'owner unknown') + '</span>');
  bits.push('<span class="dt">CPU ' + (p.cpu || 0) + '%</span>');
  bits.push('<span class="dt">MEM ' + mbText(p.ws) + ' MB</span>');
  if (p.ports) { bits.push('<span class="dt">LISTEN ' + esc(p.ports) + '</span>'); }
  if (p.path) { bits.push('<span class="dt">' + esc(p.path) + '</span>'); }
  var html = bits.join('<span class="sep">|</span>');
  if (p.cmd) { html += '<div class="proccmdline">' + esc(p.cmd) + '</div>'; }
  box.innerHTML = html;
}

function renderProcs() {
  var tb = el('procBody');
  if (!tb) { return; }
  var f = el('procFilter') ? el('procFilter').value : S.procFilter;
  f = String(f || '').replace(/^\s+|\s+$/g, '').toLowerCase();
  S.procFilter = f;

  var list = [];
  for (var i = 0; i < S.procs.length; i++) {
    if (procMatches(S.procs[i], f)) { list.push(S.procs[i]); }
  }
  list.sort(function (a, b) {
    var la = a.ports ? 1 : 0, lb = b.ports ? 1 : 0;
    if (la !== lb) { return lb - la; }
    if ((b.cpu || 0) !== (a.cpu || 0)) { return (b.cpu || 0) - (a.cpu || 0); }
    return (b.ws || 0) - (a.ws || 0);
  });

  var rows = [];
  for (var j = 0; j < list.length; j++) {
    var p = list[j];
    var cls = (p.pid === S.procSelected) ? ' class="sel"' : '';
    var ports = p.ports ? '<span class="mono">' + esc(p.ports) + '</span>' : '<span class="dim">-</span>';
    var acts = '<button class="pact danger" data-act="kill" data-pid="' + p.pid + '" data-name="' + esc(p.name) + '">KILL</button>';
    if (p.path) { acts += '<button class="pact" data-act="locate" data-pid="' + p.pid + '">LOCATE</button>'; }
    rows.push('<tr data-pid="' + p.pid + '"' + cls + '>'
      + '<td class="mono">' + p.pid + '</td>'
      + '<td>' + esc(p.name) + '</td>'
      + '<td class="dim">' + esc(p.owner || '-') + '</td>'
      + '<td class="mono">' + (p.cpu || 0) + '%</td>'
      + '<td class="mono">' + mbText(p.ws) + ' MB</td>'
      + '<td>' + ports + '</td>'
      + '<td>' + acts + '</td>'
      + '</tr>');
  }
  tb.innerHTML = rows.join('');
  var empty = el('procEmpty');
  if (!list.length && S.procs.length) {
    empty.innerHTML = 'NO PROCESS MATCHES "' + esc(f) + '"';
    empty.style.display = 'block';
  } else if (!list.length) {
    empty.innerHTML = 'NO PROCESS DATA // REFRESH TO COLLECT';
    empty.style.display = 'block';
  } else {
    empty.style.display = 'none';
  }
  renderProcDetail();
}

/* ------------------------------- session ------------------------------ */
function renderSession() {
  var access = 'standard user';
  var accessCls = ' bad';
  if (S.admin) { access = 'elevated token'; accessCls = ' good'; }
  else if (S.adminGroup) { access = 'admin account / filtered token'; accessCls = ' bad'; }
  var group = '-';
  if (S.adminKnown) { group = S.adminGroup ? 'member' : 'not a member'; }
  var rows = [
    ['Session', S.streams.sweep ? S.streams.sweep.id : '-'],
    ['Targets', S.targets || '-'],
    ['Profile', S.profile],
    ['Ruleset', S.ruleset],
    ['Access', access],
    ['Admin group', group],
    ['Monitor', S.monitor ? 'ARMED' : 'standby'],
    ['Blocks', String(S.blocked.length)],
    ['Processes', S.procs.length ? String(S.procs.length) : '-']
  ];
  var out = [];
  for (var i = 0; i < rows.length; i++) {
    var cls = '';
    if (rows[i][0] === 'Access') { cls = accessCls; }
    if (rows[i][0] === 'Admin group') { cls = S.adminGroup ? ' good' : ''; }
    out.push('<div class="kvrow"><span class="k">' + rows[i][0] + '</span>'
      + '<span class="v' + cls + '">' + esc(rows[i][1]) + '</span></div>');
  }
  el('sessionKv').innerHTML = out.join('');
  el('sessState').innerHTML = S.monitor ? 'LIVE' : (busy() ? 'BUSY' : 'IDLE');
}

function updateStats() {
  el('sbHosts').innerHTML = 'HOSTS ' + S.stats.hosts;
  el('sbPorts').innerHTML = 'PORTS ' + S.stats.ports;
  el('sbAlerts').innerHTML = 'ALERTS ' + S.stats.alerts;
  el('sessState').innerHTML = S.monitor ? 'LIVE' : (busy() ? 'BUSY' : 'IDLE');
}

/* --------------------------- analysis views ---------------------------- */
function clipText(s, n) {
  var t = String(s === null || s === undefined ? '' : s);
  if (t.length <= n) { return t; }
  return t.substring(0, n - 3) + '...';
}

function fmtBytes(n) {
  var v = Number(n);
  if (!v || v <= 0) { return '0 B'; }
  if (v < 1024) { return v + ' B'; }
  if (v < 1048576) { return Math.round(v / 1024) + ' KB'; }
  if (v < 1073741824) { return (v / 1048576).toFixed(1) + ' MB'; }
  return (v / 1073741824).toFixed(2) + ' GB';
}

function sevCls(s) {
  var v = String(s || 'info').toLowerCase();
  if (v === 'medium') { return 'med'; }
  if (v === 'high' || v === 'med' || v === 'low' || v === 'info' || v === 'ok') { return v; }
  return 'info';
}

function kvHtml(rows) {
  var h = ['<div class="kv">'];
  for (var i = 0; i < rows.length; i++) {
    var r = rows[i];
    h.push('<div class="kvrow"><span class="k">' + esc(r[0]) + '</span><span class="v ' + esc(r[2] || '') + '">' + esc(r[1] === null || r[1] === undefined || r[1] === '' ? '-' : r[1]) + '</span></div>');
  }
  h.push('</div>');
  return h.join('');
}

function showHint(text) {
  var box = el('toasts');
  if (!box || !text) { return; }
  var div = document.createElement('div');
  div.className = 'toast guide';
  div.setAttribute('data-toast', String(++S.toastSeq));
  div.innerHTML = '<div class="thead"><span class="tid">GUIDE</span>'
    + '<button class="tact" data-tact="dismiss">GOT IT</button></div>'
    + '<div class="tdetail">' + esc(text) + '</div>';
  box.appendChild(div);
  while (box.childNodes.length > 4) { box.removeChild(box.firstChild); }
  window.setTimeout(function () { if (div.parentNode) { div.parentNode.removeChild(div); } }, 16000);
}

function asTextList(v) {
  if (v === null || v === undefined || v === '') { return []; }
  if (v instanceof Array) { return v; }
  return [String(v)];
}

function findingModal(f) {
  if (!f) { return; }
  var fix = asTextList(f.fix);
  var detail = f.why || f.detail || f.note || '';
  if (f.evidence && String(detail).indexOf(String(f.evidence)) < 0) {
    detail += (detail ? '\r\n' : '') + 'Static evidence: ' + f.evidence;
  }
  if (f.reach) { detail += (detail ? '\r\n' : '') + 'Reach: ' + f.reach; }
  if (f.preconditions) { detail += (detail ? '\r\n' : '') + 'Preconditions: ' + f.preconditions; }
  if (f.verdict) { detail += (detail ? '\r\n' : '') + 'STATE: ' + f.verdict; }
  if (f.url) { detail += (detail ? '\r\n' : '') + 'URL: ' + f.url; }
  if (f.file) { detail += (detail ? '\r\n' : '') + 'File: ' + f.file + (f.line ? ':' + f.line : ''); }
  if (f.owasp || f.cwe) { detail += (detail ? '\r\n' : '') + 'Mapping: ' + [f.owasp, f.cwe].join(' / '); }
  if (f.check && f.check.length) { fix = asTextList(f.check).concat(fix); }
  showFindingRemedy({
    title: f.title || f.id || 'FINDING',
    severity: f.sev || f.severity || 'med',
    detail: detail,
    fix: fix,
    control: f.control || f.research || f.id || '',
    native: f.native || ''
  });
}

function showCodeEvidence(f) {
  if (!f) { return; }
  var verdict = f.verdict || 'STATIC LEAD / NOT RUNTIME VERIFIED';
  var detail = 'STATE: ' + verdict
    + '\r\n\r\nSTATIC EVIDENCE\r\n' + (f.evidence || 'No static evidence field was recorded for this finding.')
    + '\r\n\r\nREACH AND LIMITS\r\n' + (f.reach || 'Review the call chain in source before treating this as reachable.')
    + '\r\n\r\nPRECONDITIONS\r\n' + (f.preconditions || f.why || '-')
    + '\r\n\r\nLOCATION\r\n' + (f.file || '-') + ':' + (f.line || '-')
    + '\r\nRULE\r\n' + (f.id || '-') + (f.cwe ? ' / ' + f.cwe : '');
  var steps = asTextList(f.check);
  var fix = asTextList(f.fix);
  for (var i = 0; i < fix.length; i++) { steps.push('Documented fix: ' + fix[i]); }
  showModal({
    title: f.title || 'STATIC FINDING',
    kicker: 'STATE: ' + verdict,
    sev: sevCls(f.sev || f.severity),
    detail: detail,
    fix: steps,
    note: 'This is static evidence and an authorised-lab review checklist only. NetTruder does not run exploit code, send IOCTLs, load drivers or claim runtime exploitability.'
  });
}

function findingRows(list, attr) {
  var h = [];
  for (var i = 0; i < list.length; i++) {
    var f = list[i] || {};
    var sev = sevCls(f.sev || f.severity);
    var detail = f.detail || f.why || f.evidence || f.note || f.url || '';
    h.push('<div class="frow sev-' + sev + '" ' + attr + '="' + i + '">'
      + '<span class="fsev">' + esc(sev.toUpperCase()) + '</span>'
      + '<span class="ftitle">' + esc(f.title || f.id || 'FINDING') + '</span>'
      + '<span class="fdetail">' + esc(clipText(detail, 160)) + '</span></div>');
  }
  return h.join('');
}

/* Shared n8n-style graph. Nodes flow left to right by depth; every node is a
   clickable <g> and every edge is an explicit bezier path. IE11 needs literal
   fill/stroke attributes, so no CSS is used for SVG colour. */
function graphSvgHtml(nodes, edges, selected, filter, opts) {
  if (!nodes || !nodes.length) { return ''; }
  var o = opts || {};
  var f = String(filter || '').toLowerCase().replace(/^\s+|\s+$/g, '');
  var cwBase = o.cw || 196, ch = o.ch || 46;
  var padX = (o.padX === undefined ? 16 : o.padX), padY = (o.padY === undefined ? 16 : o.padY);
  var nodeWBase = o.nodeW || 158, nodeH = o.nodeH || 36;
  var fontA = o.fontA || 10, fontB = o.fontB || 9;
  var clipA = o.clipA || 21, clipB = o.clipB || 25;
  var lineW = o.lineW || 1.3;
  var availW = Number(o.availW) || 0;
  var map = {}, indeg = {}, adj = {}, i;
  for (i = 0; i < nodes.length; i++) {
    map[nodes[i].id] = nodes[i];
    nodes[i]._show = !f || nodeMatches(nodes[i], f);
    indeg[nodes[i].id] = 0;
  }
  for (i = 0; i < edges.length; i++) {
    var e = edges[i];
    if (!map[e.from] || !map[e.to]) { continue; }
    if (!adj[e.from]) { adj[e.from] = []; }
    adj[e.from].push(e.to);
    indeg[e.to] = (indeg[e.to] || 0) + 1;
  }
  var depth = {}, seen = {}, queue = [];
  for (i = 0; i < nodes.length; i++) {
    if (!indeg[nodes[i].id]) {
      depth[nodes[i].id] = 0; seen[nodes[i].id] = true; queue.push(nodes[i].id);
    }
  }
  if (!queue.length) {
    depth[nodes[0].id] = 0; seen[nodes[0].id] = true; queue.push(nodes[0].id);
  }
  var qi = 0;
  while (qi < queue.length) {
    var cur = queue[qi++], kids = adj[cur] || [];
    for (i = 0; i < kids.length; i++) {
      if (seen[kids[i]]) { continue; }
      depth[kids[i]] = depth[cur] + 1; seen[kids[i]] = true; queue.push(kids[i]);
    }
  }
  for (i = 0; i < nodes.length; i++) {
    if (depth[nodes[i].id] === undefined) { depth[nodes[i].id] = 0; }
  }
  var cols = {}, maxDepth = 0, maxRows = 1, d;
  for (i = 0; i < nodes.length; i++) {
    d = depth[nodes[i].id];
    if (!cols[d]) { cols[d] = []; }
    cols[d].push(nodes[i]);
    if (d > maxDepth) { maxDepth = d; }
  }
  for (d = 0; d <= maxDepth; d++) {
    if (cols[d] && cols[d].length > maxRows) { maxRows = cols[d].length; }
  }
  var cw = cwBase;
  var nodeW = nodeWBase;
  if (availW > 200) {
    var fitCw = (availW - padX * 2) / (maxDepth + 1);
    cw = Math.max(150, Math.min(cwBase, fitCw));
    nodeW = Math.max(132, Math.min(nodeWBase, cw - 26));
    clipA = Math.max(12, Math.floor((nodeW - 28) / (fontA * 0.62)));
    clipB = Math.max(14, Math.floor((nodeW - 16) / (fontB * 0.62)));
  }
  var W = padX * 2 + (maxDepth + 1) * cw;
  var H = padY * 2 + maxRows * ch;
  var pos = {}, j;
  for (d = 0; d <= maxDepth; d++) {
    var col = cols[d] || [];
    for (j = 0; j < col.length; j++) {
      pos[col[j].id] = { x: padX + d * cw, y: padY + j * ch };
    }
  }
  var h = ['<svg xmlns="http://www.w3.org/2000/svg" width="' + W + '" height="' + H + '" viewBox="0 0 ' + W + ' ' + H
    + '" data-cols="' + (maxDepth + 1) + '" data-rows="' + maxRows + '">'];
  for (i = 0; i < edges.length; i++) {
    var ed = edges[i], a = pos[ed.from], b = pos[ed.to];
    if (!a || !b) { continue; }
    var hidden = (!map[ed.from]._show || !map[ed.to]._show);
    var midA = Math.round(nodeH / 2) - 1, midB = Math.round(nodeH / 2) - 1;
    var x1 = a.x + nodeW, y1 = a.y + midA, x2 = b.x, y2 = b.y + midB;
    var mx = (x1 + x2) / 2;
    var stroke = ed.colour || (ed.label === 'spawn' ? '#2f7899' : (ed.label === 'links' ? '#5f6f9b' : '#3d9c7a'));
    h.push('<path d="M' + x1 + ',' + y1 + ' C' + mx + ',' + y1 + ' ' + mx + ',' + y2 + ' ' + x2 + ',' + y2
      + '" fill="none" stroke="' + stroke + '" stroke-width="' + lineW + '" opacity="' + (hidden ? '0.07' : '0.8') + '"></path>');
  }
  for (i = 0; i < nodes.length; i++) {
    var n = nodes[i], p = pos[n.id];
    var sv = sevCls(n.sev);
    var colour = n.colour || (sv === 'high' ? '#ff3d5e' : (sv === 'med' ? '#ffb020' : (sv === 'low' ? '#38bdf8' : '#35f0a0')));
    var fill = n.type === 'remote' ? '#1b1430' : (n.type === 'data' ? '#14252b' : '#0b151c');
    var mid = Math.round(nodeH / 2) - 1;
    var outline = n.id === selected ? '<rect x="' + (p.x - 2) + '" y="' + (p.y - 2) + '" width="' + (nodeW + 4) + '" height="' + (nodeH + 4) + '" rx="4" fill="none" stroke="#ffffff" stroke-width="2"></rect>' : '';
    h.push('<g data-node="' + esc(n.id) + '"' + (n._show ? '' : ' style="display:none"') + '>');
    h.push(outline);
    h.push('<rect x="' + p.x + '" y="' + p.y + '" width="' + nodeW + '" height="' + nodeH + '" rx="3" fill="' + fill + '" stroke="' + colour + '" stroke-width="1"></rect>');
    h.push('<circle cx="' + (p.x + 10) + '" cy="' + (p.y + mid - 5) + '" r="3" fill="' + colour + '"></circle>');
    h.push('<text x="' + (p.x + 19) + '" y="' + (p.y + mid - 2) + '" fill="#dceaf2" font-family="Consolas,monospace" font-size="' + fontA + '">' + esc(clipText(n.label, clipA)) + '</text>');
    h.push('<text x="' + (p.x + 8) + '" y="' + (p.y + mid + 12) + '" fill="#7895a5" font-family="Consolas,monospace" font-size="' + fontB + '">' + esc(clipText(nodeDetail(n), clipB)) + '</text>');
    h.push('</g>');
  }
  h.push('</svg>');
  return h.join('');
}

function nodeDetail(n) {
  if (n.detail) { return n.detail; }
  if (n.pid) { return 'pid ' + n.pid + ' / ' + (n.type || 'process'); }
  return n.type || '';
}

function nodeMatches(n, f) {
  var fields = [n.label, n.detail, n.evidence, n.why, n.type, n.pid, n.ppid, n.owner, n.path, n.cmd, n.remote, n.port, n.categories, n.url, n.urlSource];
  for (var i = 0; i < fields.length; i++) {
    if (fields[i] !== null && fields[i] !== undefined && String(fields[i]).toLowerCase().indexOf(f) >= 0) { return true; }
  }
  return false;
}

/* -------------------------------- flow -------------------------------- */
function runFlow() {
  if (S.streams.flow && !S.streams.flow.done) { return; }
  if (el('btnFlowRun')) { el('btnFlowRun').disabled = true; }
  if (el('flowState')) { el('flowState').innerHTML = 'COLLECTING'; }
  pushConsole('dim', 'Building a read-only process, parent and endpoint map.', 'flow');
  startStream('flow', 'flow', {});
}

function renderFlow() {
  S.flow.dirty = false;
  var m = S.flow.meta || {};
  if (el('flowCount')) { el('flowCount').innerHTML = S.flow.nodes.length + ' NODES / ' + S.flow.edges.length + ' EDGES'; }
  if (el('flowFindCount')) { el('flowFindCount').innerHTML = String(S.flow.findings.length); }
  var svg = el('flowSvg');
  if (svg) {
    var filter = el('flowFilter') ? el('flowFilter').value : '';
    var html = graphSvgHtml(S.flow.nodes, S.flow.edges, S.flow.selected, filter);
    svg.innerHTML = html;
    if (el('flowEmpty')) { el('flowEmpty').style.display = html ? 'none' : ''; }
  }
  var fb = el('flowFindings');
  if (fb) {
    fb.innerHTML = S.flow.findings.length ? findingRows(S.flow.findings, 'data-ffind')
      : '<div class="empty small">NO FINDINGS // RUN THE FLOW MAP</div>';
  }
  renderFlowDetail();
  if (m.policy && el('flowState') && el('flowState').innerHTML === 'NO DATA') {
    el('flowState').innerHTML = S.flow.nodes.length + ' NODES';
  }
}

function renderFlowDetail() {
  var box = el('flowDetail');
  if (!box) { return; }
  var n = null;
  for (var i = 0; i < S.flow.nodes.length; i++) {
    if (S.flow.nodes[i].id === S.flow.selected) { n = S.flow.nodes[i]; break; }
  }
  if (!n) {
    box.innerHTML = '<div class="empty small">CLICK A NODE IN THE GRAPH</div>';
    return;
  }
  var rows = [
    ['TYPE', n.type], ['PID', n.pid], ['PARENT', n.ppid], ['OWNER', n.owner],
    ['PATH', n.path], ['COMMAND', n.cmd], ['FLOWS', n.conns], ['DETAIL', n.detail]
  ];
  var h = [kvHtml(rows)];
  if (n.pid) { h.push('<button class="btn small" data-act="tm">TASK MANAGER</button>'); }
  box.innerHTML = h.join('');
}

/* --------------------------------- web --------------------------------- */
function runWebScan() {
  if (S.streams.web && !S.streams.web.done) { return; }
  var url = el('webUrl') ? el('webUrl').value : '';
  var allow = !!(el('chkWebPublic') && el('chkWebPublic').checked);
  if (el('btnWebRun')) { el('btnWebRun').disabled = true; }
  if (el('webState')) { el('webState').innerHTML = 'CHECKING'; }
  pushConsole('dim', 'Passive web check - no exploitation, no fuzzing, no payloads.', 'web');
  startStream('web', 'webscan', { url: url, allowPublic: allow });
}

function renderWeb() {
  S.web.dirty = false;
  var m = S.web.meta || {};
  var summ = el('webSumm');
  if (summ) {
    var out = [];
    out.push('<span class="rsum"><b>TARGETS</b>' + S.web.pages.length + '</span>');
    out.push('<span class="rsum bad"><b>FINDINGS</b>' + S.web.findings.length + '</span>');
    if (m.allowPublic) { out.push('<span class="rsum warn"><b>PUBLIC</b>authorised host</span>'); }
    if (m.window) { out.push('<span class="rsum dim"><b>WINDOW</b>' + esc(shortStamp(m.window)) + '</span>'); }
    out.push('<span class="rsum dim">' + esc(clipText(m.policy || 'PASSIVE ONLY', 150)) + '</span>');
    summ.innerHTML = out.join('');
  }
  if (el('webCount')) { el('webCount').innerHTML = String(S.web.pages.length); }
  if (el('webFindCount')) { el('webFindCount').innerHTML = String(S.web.findings.length); }
  var pb = el('webPages');
  if (pb) {
    if (!S.web.pages.length) {
      pb.innerHTML = '<div class="empty small" id="webEmpty">NO WEB CHECK YET // ENTER A LOOPBACK OR PRIVATE URL</div>';
    } else {
      var ph = [];
      for (var i = 0; i < S.web.pages.length; i++) {
        var p = S.web.pages[i];
        var sel = (p.url === S.web.selected) ? ' sel' : '';
        ph.push('<div class="wpage' + sel + '" data-url="' + esc(p.url) + '">');
        var gc = p.grade === 'n/a' ? 'info' : sevCls(p.grade === 'A' || p.grade === 'B' ? 'low' : (p.grade === 'C' ? 'med' : 'high'));
        ph.push('<div class="wprow"><b>' + esc(p.url) + '</b><span class="grade g-' + esc(gc) + '">' + esc(p.grade || '-') + '</span>'
          + '<span class="micro">HTTP ' + esc(p.status) + ' / ' + esc(p.ms) + 'ms / ' + fmtBytes(p.length) + '</span></div>');
        if (p.error) { ph.push('<div class="werr">' + esc(p.error) + '</div>'); }
        ph.push(kvHtml([
          ['ANSWERED', p.answered ? 'yes' : 'NO / HEADERS NOT EVALUATED'],
          ['TITLE', p.title], ['SERVER', p.server], ['POWERED', p.powered],
          ['TLS', p.tls && p.tls.ok ? (p.tls.protocol + ' / ' + p.tls.cipher) : (p.https ? 'not negotiated' : 'cleartext')],
          ['MISSING', (p.missing || []).join(', ')],
          ['FORMS', (p.forms || []).length + ' / SCRIPTS ' + (p.scripts || []).length + ' / LINKS ' + (p.links || []).length],
          ['RISK', (p.high || 0) + ' high / ' + (p.med || 0) + ' med / ' + (p.low || 0) + ' low']
        ]));
        if (p.url === S.web.selected) {
          ph.push(webTreeHtml(S.web.trees[p.url]));
          ph.push(webAssetRows(p));
        }
        ph.push('</div>');
      }
      pb.innerHTML = ph.join('');
    }
  }
  var fb = el('webFindings');
  if (fb) {
    fb.innerHTML = S.web.findings.length ? findingRows(S.web.findings, 'data-wfind')
      : '<div class="empty small" id="webFindEmpty">NO WEB FINDINGS</div>';
  }
  var flowUrl = S.web.selected;
  if (!flowUrl || !S.web.flows[flowUrl]) {
    for (var k in S.web.flows) { if (S.web.flows.hasOwnProperty(k)) { flowUrl = k; break; } }
  }
  var wf = S.web.flows[flowUrl];
  if (wf && wf.nodes && S.web.flowNode) {
    var foundNode = false;
    for (var ni = 0; ni < wf.nodes.length; ni++) {
      if (wf.nodes[ni].id === S.web.flowNode) { foundNode = true; break; }
    }
    if (!foundNode) { S.web.flowNode = ''; }
  }
  var flow = el('webFlow');
  if (flow) {
    var card = flow.parentNode;
    var size = 'empty';
    if (wf && wf.nodes) { size = wf.nodes.length >= 12 ? 'large' : (wf.nodes.length >= 8 ? 'mid' : 'small'); }
    if (card) { card.className = 'card webflowcard wf-' + size; }
    flow.innerHTML = wf ? graphSvgHtml(wf.nodes || [], wf.edges || [], S.web.flowNode, '', {
      cw: 224, ch: 62, padX: 20, padY: 18, nodeW: 190, nodeH: 46,
      fontA: 11, fontB: 10, clipA: 24, clipB: 30, lineW: 1.5
    }) : '<span class="wfempty">RUN A CHECK TO DRAW THE PATH</span>';
  }
}

/* ---------------- manual site posture report import ----------------
   The extension report is pasted by the operator. This parser keeps the text
   in memory for this render only. It does not open a profile, read a file,
   make a request, start a listener or write the pasted text to disk. */
var SITE_HEADER = 'NETTRUDER SITE POSTURE REPORT';
var SITE_SECRET_RE = /(authorization\s*:\s*bearer|cookie\s*:\s*|set-cookie\s*:\s*|\b(token|session|password|passwd|pwd)\s*[:=]\s*\S)/i;

function siteTrim(s) {
  return String(s === null || s === undefined ? '' : s).replace(/^\s+/, '').replace(/\s+$/, '');
}

function siteRedact(s) {
  var v = String(s === null || s === undefined ? '' : s);
  var q = v.indexOf('?');
  if (q >= 0) { v = v.substring(0, q); }
  var f = v.indexOf('#');
  if (f >= 0) { v = v.substring(0, f); }
  return clipText(v, 220);
}

function siteSev(state, section) {
  var v = siteTrim(state).toUpperCase();
  var sec = siteTrim(section).toUpperCase();
  if (v === 'REJECTED' || v === 'FOUND' || v === 'WEAK' || v === 'BLOCKED'
      || v === 'REVIEW' || v === 'HIGH') { return 'high'; }
  if (v === 'MISSING' || v === 'CHALLENGE OBSERVED' || v === 'HUMAN PASSED'
      || v === 'ABANDONED' || v === 'INDICATORS ONLY' || sec.indexOf('LOGIN / AITM') === 0) { return 'med'; }
  if (v === 'TRUSTED' || v === 'SAME ORIGIN' || v === 'OK' || v === 'PRESENT'
      || v === 'NONE SEEN' || v === 'NONE CAPTURED' || v === 'N/A' || v === 'NONE') { return 'ok'; }
  return 'info';
}

function siteMappingFinding() {
  return {
    section: 'ATT&CK MAPPING', state: 'MAPPED / INDICATORS ONLY',
    title: 'Proxy phishing chain mapping',
    detail: 'T1566.002 spearphishing link, T1539 web session cookie theft, T1071.001 web protocols and T1556.006 MFA outcome. T1556.007 is Hybrid Identity and needs separate AD FS / PTA evidence.',
    fix: 'Use IdP, EDR, proxy and SIEM correlation to test the chain. Do not treat extension evidence alone as proof of AiTM, MFA bypass, token replay or compromise.',
    sev: 'info'
  };
}

function siteHardeningFindings() {
  return [
    siteMappingFinding(),
    {
      section: 'IDENTITY HARDENING', state: 'NOT EVALUATED',
      title: 'FIDO2 / WebAuthn hardware security keys',
      detail: 'A browser report cannot verify IdP authentication-method policy or origin-bound credential enforcement. A valid TLS session does not prove a phishing-resistant method was required.',
      fix: 'Verify in the IdP under change control that phishing-resistant methods are required for relevant users. Review exclusions and legacy application gaps in sign-in logs. NetTruder does not change IdP policy.',
      sev: 'info'
    },
    {
      section: 'IDENTITY HARDENING', state: 'NOT EVALUATED',
      title: 'Continuous Access Evaluation (CAE)',
      detail: 'Token revocation from real-time location or IP drift is an identity-plane event. It is not visible to page DOM, local sockets or a copied site posture report.',
      fix: 'Confirm supported workloads, enable CAE or equivalent continuous evaluation through the identity provider under change control, and validate revocation telemetry. NetTruder does not revoke tokens.',
      sev: 'info'
    },
    {
      section: 'IDENTITY HARDENING', state: 'NOT EVALUATED',
      title: 'Conditional Access device compliance',
      detail: 'Managed and compliant device attributes are evaluated by the IdP. They cannot be inferred from a browser DOM read or a local host inventory.',
      fix: 'Require compliant or managed devices for the relevant cloud apps, restrict legacy authentication, and review exclusions in IdP sign-in logs. NetTruder does not change Conditional Access policy.',
      sev: 'info'
    }
  ];
}

function siteRejected(state, detail, fix) {
  return { rejected: true, state: state, detail: detail, fix: fix, meta: [], findings: [], hardening: [] };
}

function parseSiteReport(raw) {
  var lines = String(raw === null || raw === undefined ? '' : raw)
    .replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n');
  var i, line, trimmed;
  var headerAt = -1;

  for (i = 0; i < lines.length; i++) {
    if (siteTrim(lines[i]).indexOf(SITE_HEADER) >= 0) {
      headerAt = i;
      break;
    }
  }
  for (i = 0; i < lines.length; i++) {
    if (SITE_SECRET_RE.test(lines[i])) {
      return siteRejected('REJECTED // SECRET-LIKE TEXT',
        'The pasted text contains a cookie, token, authorization, session or password pattern. Nothing was parsed or displayed.',
        'Copy only the redacted report from the extension COPY REPORT button. Never paste cookie values, tokens, credentials, authorization headers, query strings or fragments.');
    }
  }
  if (headerAt < 0) {
    return siteRejected('REJECTED // FORMAT',
      'The pasted text does not contain the expected NETTRUDER SITE POSTURE REPORT header.',
      'Copy the full redacted report from the extension COPY REPORT button and paste it into the import area.');
  }

  var result = { rejected: false, state: 'IMPORTED // INDICATORS ONLY', meta: [], findings: [], hardening: [] };
  var section = '';
  var current = null;
  var secRe = /^[A-Z0-9][A-Z0-9 \/\-]*$/;

  for (i = headerAt; i < lines.length; i++) {
    line = lines[i];
    trimmed = siteTrim(line);
    if (!trimmed) { current = null; continue; }

    if (line.charAt(0) !== ' ' && secRe.test(trimmed) && trimmed.length < 64) {
      section = trimmed;
      current = null;
      continue;
    }

    if (trimmed.indexOf('Generated:') === 0) {
      result.meta.push(['GENERATED', siteRedact(trimmed.substring(10))]);
      continue;
    }
    if (trimmed.indexOf('Page:') === 0) {
      result.meta.push(['PAGE', siteRedact(trimmed.substring(5))]);
      continue;
    }
    if (trimmed.indexOf('Boundary:') === 0) {
      result.meta.push(['BOUNDARY', siteRedact(trimmed.substring(9))]);
      continue;
    }
    if (section.indexOf('LOGIN / AITM') === 0 && /^Trusted local hosts:/i.test(trimmed)) {
      result.meta.push(['TRUST LIST', siteRedact(trimmed)]);
      continue;
    }

    var fm = /^\[([^\]]+)\]\s*(.+)$/.exec(trimmed);
    if (fm) {
      if (result.findings.length >= 80) { current = null; continue; }
      current = {
        section: section,
        state: siteRedact(fm[1]),
        title: siteRedact(fm[2]),
        detail: '',
        fix: 'Review the source report and confirm with IdP, EDR or proxy telemetry where required.',
        sev: siteSev(fm[1], section)
      };
      result.findings.push(current);
      continue;
    }

    if (!current) { continue; }
    var fixm = /^\s{2}FIX:\s*(.*)$/.exec(line);
    if (fixm) {
      current.fix = siteRedact(fixm[1]) || 'No remediation was included in the source report.';
      continue;
    }
    var detm = /^\s{2}(.*)$/.exec(line);
    if (detm) {
      current.detail += (current.detail ? '\r\n' : '') + siteRedact(detm[1]);
    }
  }

  if (!result.findings.length) {
    return siteRejected('REJECTED // NO ROWS',
      'The report header was found, but no bracketed state rows could be parsed.',
      'Use the extension COPY REPORT output without editing its [STATE] Title, detail and FIX lines.');
  }
  return result;
}

function siteSectionState(list, name) {
  for (var i = 0; i < list.length; i++) {
    if (list[i].section && list[i].section.indexOf(name) >= 0) {
      var parts = list[i].section.split('/');
      return siteTrim(parts[parts.length - 1]) || 'NOT EVALUATED';
    }
  }
  return 'NOT EVALUATED';
}

function siteSummaryHtml(list) {
  var reviews = 0;
  for (var i = 0; i < list.length; i++) {
    var st = siteTrim(list[i].state).toUpperCase();
    if (st === 'REVIEW' || st === 'WEAK' || st === 'FOUND' || st === 'REJECTED') { reviews++; }
  }
  var out = [];
  out.push('<span class="rsum"><b>SOURCE</b>EXTENSION PASTE</span>');
  out.push('<span class="rsum dim"><b>PARSED</b>' + list.length + ' rows</span>');
  out.push('<span class="rsum warn"><b>REVIEW</b>' + reviews + ' row(s)</span>');
  out.push('<span class="rsum"><b>LOGIN</b>' + esc(siteSectionState(list, 'LOGIN / AITM')) + '</span>');
  out.push('<span class="rsum dim"><b>HEADERS</b>' + esc(siteSectionState(list, 'HEADER QUALITY')) + '</span>');
  out.push('<span class="rsum dim"><b>CORRELATION</b>4 ROWS</span>');
  out.push('<span class="rsum bad"><b>SCOPE</b>INDICATORS ONLY</span>');
  return out.join('');
}

function siteRowHtml(f, idx) {
  var cls = sevCls(f.sev || 'info');
  return '<div class="site-row sev-' + cls + '" data-srow="' + idx + '">'
    + '<span class="site-state">' + esc(f.state || '-') + '</span>'
    + '<span class="site-title">' + esc(f.title || 'FINDING') + '</span>'
    + '<span class="site-detail">' + esc(clipText(f.detail || '', 150)) + '</span>'
    + '<span class="site-fix">FIX: ' + esc(clipText(f.fix || 'No remediation was supplied.', 180)) + '</span>'
    + '</div>';
}

function renderSiteImport() {
  S.site.dirty = false;
  var st = el('siteImportState');
  if (st) { st.innerHTML = esc(S.site.state); }
  var summ = el('siteImportSumm');
  if (summ) {
    summ.innerHTML = S.site.imported ? siteSummaryHtml(S.site.findings)
      : '<span class="rsum dim">NO REPORT IMPORTED // INDICATORS ONLY</span>';
  }
  var rows = el('siteImportRows');
  if (!rows) { return; }
  var all = S.site.findings.concat(S.site.hardening);
  if (!S.site.imported || !all.length) {
    rows.innerHTML = '<div class="empty small" id="siteImportEmpty">IMPORT A REDACTED EXTENSION REPORT TO REVIEW STATE AND REMEDIATION</div>';
    return;
  }
  var h = [];
  for (var i = 0; i < all.length; i++) { h.push(siteRowHtml(all[i], i)); }
  rows.innerHTML = h.join('');
}

function applySiteRejection(reason) {
  if (el('siteReportText')) { el('siteReportText').value = ''; }
  S.site = {
    state: reason.state, meta: [], findings: [], hardening: [], imported: false, rejected: true, dirty: false
  };
  renderSiteImport();
  showModal({
    title: 'SITE REPORT NOT IMPORTED', kicker: 'STATE: ' + reason.state, sev: 'high',
    detail: reason.detail, fix: [reason.fix],
    note: 'The pasted value was not displayed, written to disk or sent anywhere. Only this rejection state is shown.'
  });
  pushConsole('warn', 'Site report paste rejected by the local paste guard.', 'web');
}

function importSiteReport() {
  var box = el('siteReportText');
  var raw = box ? box.value : '';
  if (!siteTrim(raw)) {
    applySiteRejection(siteRejected('REJECTED // EMPTY',
      'No report text was pasted.',
      'Copy the redacted report from the extension COPY REPORT button, then paste it into the import area.'));
    return;
  }
  var parsed = parseSiteReport(raw);
  if (parsed.rejected) { applySiteRejection(parsed); return; }

  S.site = {
    state: 'IMPORTED // INDICATORS ONLY',
    meta: parsed.meta,
    findings: parsed.findings,
    hardening: siteHardeningFindings(),
    imported: true,
    rejected: false,
    dirty: false
  };
  if (box) { box.value = ''; }
  renderSiteImport();
  pushConsole('dim', 'Site posture report parsed in memory only. No file, network, profile read or write.', 'web');
}

function clearSiteReport() {
  if (el('siteReportText')) { el('siteReportText').value = ''; }
  S.site = { state: 'NO DATA', meta: [], findings: [], hardening: [], imported: false, rejected: false, dirty: false };
  renderSiteImport();
  pushConsole('dim', 'Imported site report cleared from memory.', 'web');
}

function showSiteGuide() {
  showModal({
    title: 'HOW TO READ EXTENSION IMPORT', kicker: 'STATE: MANUAL PASTE / INDICATORS ONLY', sev: 'info',
    detail: 'The console parses the extension COPY REPORT text in memory. It does not read a browser profile, open a file, make a network request, start a listener or write the report to disk. Login, host and redirect rows are passive review triggers. They do not prove AiTM, cookie theft, MFA bypass, token replay or post-compromise state.',
    fix: [
      'Copy only the redacted report from the extension COPY REPORT button.',
      'A paste with secret-like text is rejected without displaying the value.',
      'Confirm identity claims with IdP sign-in, MFA, session and CAE telemetry.',
      'FIDO2 / WebAuthn, Continuous Access Evaluation and Conditional Access device compliance stay NOT EVALUATED until verified in the identity control plane.'
    ],
    note: 'Every row shows state and remediation. NOT EVALUATED, NONE SEEN and INDICATORS ONLY are never clean passes.'
  });
}

function showSiteRow(idx) {
  var all = S.site.findings.concat(S.site.hardening);
  var f = all[parseInt(idx, 10)];
  if (!f) { return; }
  showModal({
    title: f.title || 'SITE INDICATOR', kicker: 'STATE: ' + (f.state || '-'),
    sev: sevCls(f.sev || 'info'),
    detail: (f.section ? 'SECTION: ' + f.section + '\r\n\r\n' : '') + (f.detail || ''),
    fix: [f.fix || 'No remediation was supplied.'],
    note: 'Passive indicator or identity-plane review item only. Correlate with authorised IdP, EDR, proxy and SIEM telemetry before drawing a compromise conclusion.'
  });
}

function pageByUrl(url) {
  for (var i = 0; i < S.web.pages.length; i++) {
    if (S.web.pages[i].url === url) { return S.web.pages[i]; }
  }
  return null;
}

function assetValue(a, field) {
  if (a === null || a === undefined) { return ''; }
  if (typeof a === 'string') { return a; }
  var v = a[field];
  return (v === null || v === undefined) ? '' : String(v);
}

function webAssetRows(p) {
  if (!p) { return ''; }
  var h = [], i, x, label, meta;
  var links = p.links || [];
  if (links.length) {
    h.push('<div class="wassethead">LINK RESULTS (' + links.length + ')</div>');
    for (i = 0; i < links.length; i++) {
      x = links[i];
      label = assetValue(x, 'href') || assetValue(x, 'absolute') || assetValue(x, 'url') || String(x);
      meta = assetValue(x, 'text');
      h.push('<div class="wasset clk" data-asset="link" data-index="' + i + '">'
        + '<span class="watype">LINK</span><span class="waval">' + esc(clipText(label, 150)) + '</span>'
        + (meta ? '<span class="wameta">' + esc(clipText(meta, 60)) + '</span>' : '') + '</div>');
    }
  }
  var scripts = p.scripts || [];
  if (scripts.length) {
    h.push('<div class="wassethead">SCRIPT RESULTS (' + scripts.length + ')</div>');
    for (i = 0; i < scripts.length; i++) {
      x = scripts[i];
      label = assetValue(x, 'src');
      if (!label) { label = 'inline script (' + assetValue(x, 'bytes') + ' bytes)'; }
      meta = assetValue(x, 'kind') || (assetValue(x, 'inline') === 'true' ? 'inline' : 'external');
      h.push('<div class="wasset clk" data-asset="script" data-index="' + i + '">'
        + '<span class="watype">SCRIPT</span><span class="waval">' + esc(clipText(label, 150)) + '</span>'
        + '<span class="wameta">' + esc(meta) + '</span></div>');
    }
  }
  if (!h.length) { h.push('<div class="wassetempty">No links or scripts were present in the fetched HTML.</div>'); }
  return h.join('');
}

function currentFlow() {
  var url = S.web.selected;
  var wf = S.web.flows[url];
  if (wf) { return wf; }
  for (var k in S.web.flows) { if (S.web.flows.hasOwnProperty(k)) { return S.web.flows[k]; } }
  return null;
}

function flowNodeById(id) {
  var wf = currentFlow();
  if (!wf || !wf.nodes) { return null; }
  for (var i = 0; i < wf.nodes.length; i++) {
    if (wf.nodes[i].id === id) { return wf.nodes[i]; }
  }
  return null;
}

function inList(value, list) {
  for (var i = 0; i < list.length; i++) { if (list[i] === value) { return true; } }
  return false;
}

function webNodeFindings(n) {
  var out = [], i, f;
  var cats = (n && n.categories) ? n.categories : [];
  for (i = 0; i < S.web.findings.length; i++) {
    f = S.web.findings[i];
    if (inList(String(f.research || ''), cats)) { out.push(f); }
  }
  return out;
}

function showWebFlowNode(id) {
  var n = flowNodeById(id);
  if (!n) { return; }
  S.web.flowNode = id;
  var rows = [
    ['ID', n.id], ['TYPE', n.type], ['NODE', n.label], ['DETAIL', n.detail],
    ['EVIDENCE', n.evidence], ['WHY IT MATTERS', n.why], ['CONFIDENCE', n.confidence || 'passive observation']
  ];
  var related = webNodeFindings(n);
  var html = kvHtml(rows);
  if (related.length) {
    html += '<div class="mlabel">RELATED FINDINGS (' + related.length + ')</div><div class="mscript">';
    for (var i = 0; i < related.length && i < 12; i++) {
      html += esc(String(related[i].sev || '').toUpperCase()) + ' ' + esc(related[i].id)
        + ' - ' + esc(related[i].title) + '\r\n';
    }
    if (related.length > 12) { html += '... ' + (related.length - 12) + ' more\r\n'; }
    html += '</div>';
  }
  var steps = [];
  if (n.fix) { steps.push(n.fix); }
  steps.push('This node is derived from the passive response or from an explicitly labelled inference. No script was executed and no payload was sent.');
  showModal({
    title: 'DATA FLOW // ' + (n.label || n.id),
    kicker: String(n.type || 'node').toUpperCase() + (related.length ? ' / ' + related.length + ' FINDING(S)' : ''),
    sev: sevCls(n.sev),
    detail: n.detail || '',
    html: html,
    fix: steps,
    copyText: [n.id, n.type, n.label, n.detail, n.evidence, n.why].join('\r\n'),
    note: 'Nodes are evidence or labelled inference. The console never follows a discovered link or executes a discovered script.'
  });
  renderWeb();
}

function showWebAsset(kind, index) {
  var p = pageByUrl(S.web.selected);
  if (!p) { return; }
  var list = (kind === 'link') ? (p.links || []) : (p.scripts || []);
  var x = list[parseInt(index, 10)];
  if (!x) { return; }
  var rows = [], html = '', body = '', fix = [];
  if (kind === 'link') {
    var href = assetValue(x, 'href') || assetValue(x, 'absolute') || String(x);
    var text = assetValue(x, 'text');
    var rel = assetValue(x, 'rel');
    var target = assetValue(x, 'target');
    rows = [
      ['HREF', href], ['ABSOLUTE', assetValue(x, 'absolute')], ['LINK TEXT', text],
      ['REL', rel], ['TARGET', target], ['SCHEME', assetValue(x, 'scheme')],
      ['EXTERNAL', assetValue(x, 'external')], ['NOTE', assetValue(x, 'note')]
    ];
    body = href;
    fix = [
      'NetTruder did not follow this link. Open it only if the host and destination are in scope.',
      'Check that navigation and authorisation are enforced server-side, not by hiding the URL.',
      'Treat javascript: URLs as a code-review finding, not as a safe navigation target.'
    ];
    showModal({
      title: 'LINK // ' + clipText(href, 80), kicker: 'LINK RESULT', sev: 'ok',
      detail: text || 'Anchor found in the fetched HTML.',
      html: kvHtml(rows) + '<div class="mlabel">RAW HREF</div><code class="mscript">' + esc(body) + '</code>',
      fix: fix, copyText: href,
      note: 'Passive evidence only. The link was parsed from the response body and was not opened by NetTruder.'
    });
    return;
  }
  var src = assetValue(x, 'src');
  var inline = assetValue(x, 'inline') === 'true' || assetValue(x, 'inline') === true;
  rows = [
    ['KIND', assetValue(x, 'kind') || (inline ? 'inline' : 'external')],
    ['SRC', src], ['TYPE', assetValue(x, 'type')],
    ['INTEGRITY', assetValue(x, 'integrity')], ['CROSSORIGIN', assetValue(x, 'crossorigin')],
    ['ASYNC', assetValue(x, 'async')], ['DEFER', assetValue(x, 'defer')],
    ['BYTES', assetValue(x, 'bytes')], ['RISKY SINK', assetValue(x, 'risky')],
    ['NOTE', assetValue(x, 'note')]
  ];
  body = assetValue(x, 'code') || assetValue(x, 'attrs') || src || 'No inline body was captured.';
  fix = [
    'This script was parsed from HTML. NetTruder never executes it.',
    'Load cross-origin scripts over HTTPS with Subresource Integrity, or self-host them.',
    'Replace eval, document.write and innerHTML sinks with reviewed, sanitised DOM code.'
  ];
  showModal({
    title: inline ? 'INLINE SCRIPT' : 'SCRIPT // ' + clipText(src, 80),
    kicker: String(assetValue(x, 'kind') || (inline ? 'inline' : 'external')).toUpperCase(),
    sev: assetValue(x, 'risky') === 'true' ? 'high' : (assetValue(x, 'external') === 'true' ? 'med' : 'ok'),
    detail: inline ? 'Inline body is masked and truncated for safe review.' : 'External reference was not fetched or executed.',
    html: kvHtml(rows) + '<div class="mlabel">' + (inline ? 'MASKED INLINE BODY' : 'SCRIPT TAG ATTRIBUTES') + '</div><code class="mscript">' + esc(body) + '</code>',
    fix: fix, copyText: body,
    note: 'Static, passive evidence. Values that look like secrets are masked before display.'
  });
}

function webTreeHtml(tree) {
  if (!tree || !tree.nodes) { return ''; }
  var h = ['<div class="wtree">'];
  for (var i = 0; i < tree.nodes.length; i++) {
    var n = tree.nodes[i];
    h.push('<div class="wtnode wt-' + esc(sevCls(n.sev)) + '"><span class="wttype">' + esc(n.type) + '</span> '
      + esc(n.label) + (n.note ? '<span class="wtnote">' + esc(n.note) + '</span>' : '') + '</div>');
  }
  h.push('</div>');
  return h.join('');
}

function showZapRecipe() {
  var z = S.web.zap || {};
  var lines = [];
  lines.push('NetTruder never launches ZAP automatically. Confirm written authorisation for the target first.');
  if (z.baseline) { lines.push('BASELINE (passive): ' + z.baseline); }
  if (z.active) { lines.push('ACTIVE (intrusive, owned hosts only): ' + z.active); }
  if (!z.baseline) { lines.push('ZAP was not found on PATH or in the usual install folders. Install it yourself, then re-run the check.'); }
  var checks = z.checks || [];
  for (var i = 0; i < checks.length; i++) { lines.push('- ' + checks[i]); }
  showModal({
    title: 'OWASP ZAP ADAPTER',
    kicker: z.available ? 'ZAP FOUND' : (z.docker ? 'DOCKER FOUND' : 'RECIPE ONLY'),
    sev: 'ok',
    detail: z.note || '',
    fix: lines,
    note: 'Commands are copyable text only. NetTruder does not start ZAP, does not scan public hosts without opt-in, and does not weaken any endpoint control.'
  });
}

/* -------------------------------- code -------------------------------- */
function runCodeAudit() {
  if (S.streams.code && !S.streams.code.done) { return; }
  var path = el('codePath') ? el('codePath').value : '';
  S.code.hevd = !!(path && path.toLowerCase().indexOf('hevd-source') >= 0);
  resetCodeWriteMode();
  if (el('btnCodeRun')) { el('btnCodeRun').disabled = true; }
  if (el('codeState')) { el('codeState').innerHTML = 'READING'; }
  pushConsole('dim', 'Static code review - files are read, never executed.', 'code');
  startStream('code', 'codeaudit', path ? { path: path } : {});
}

/* -------------------------------- HEVD lab ------------------------------- */
/* Source-only defensive study. These helpers never build, sign, load or
   install the driver, and never send a device request. */
function hevdSourcePath() { return S.base + '\\research\\hevd-source'; }

function hevdBridgePath() { return S.root + '\\hevd-source-findings.json'; }

function asciiJson(value) {
  if (value === null || value === undefined) { return 'null'; }
  if (typeof value === 'boolean') { return value ? 'true' : 'false'; }
  if (typeof value === 'number') { return String(value); }
  if (typeof value === 'string') { return jsonStr(value); }
  if (value instanceof Array) {
    var a = [];
    for (var i = 0; i < value.length; i++) { a.push(asciiJson(value[i])); }
    return '[' + a.join(',') + ']';
  }
  var o = [];
  for (var k in value) {
    if (!value.hasOwnProperty(k)) { continue; }
    o.push(jsonStr(k) + ':' + asciiJson(value[k]));
  }
  return '{' + o.join(',') + '}';
}

function hevdSevLabel(sev) {
  var s = String(sev || '').toLowerCase();
  if (s === 'high') { return 'HIGH'; }
  if (s === 'med' || s === 'medium') { return 'MEDIUM'; }
  if (s === 'low') { return 'LOW'; }
  return 'INFO';
}

function showHevdGuide() {
  var guide = [
    'SCOPE: source-only defensive study. No build, no driver load, no IOCTL,',
    'no payload and no bypass. Security controls stay as they are.',
    '',
    '1. HEVD SOURCE fills the path and runs a read-only Code Audit.',
    '2. Click a file or finding to inspect masked, numbered source.',
    '3. KERNEL REVIEW opens a layered beginner and advanced explanation.',
    '4. KERNEL DBG opens a static WinDbg guide. Commands are copyable only.',
    '5. INT WRAP explains wrapped arithmetic in a bound check.',
    '6. SEND TO RESEARCH copies masked findings into the RESEARCH module.',
    '7. In RESEARCH, filter group "Kernel Source Review" for the catalog.',
    '',
    'From research\\hevd-source, the local helper can also print guides:',
    '.venv\\Scripts\\python.exe tools\\hevd_lab.py check',
    '.venv\\Scripts\\python.exe tools\\hevd_lab.py guide --level beginner',
    '.venv\\Scripts\\python.exe tools\\hevd_lab.py guide --level advanced',
    '.venv\\Scripts\\python.exe tools\\hevd_lab.py findings'
  ];
  pushConsole('dim', 'HEVD guide opened. The source is read as text only.', 'code');
  showModal({
    title: 'HEVD SOURCE STUDY LAB',
    kicker: 'STATIC / READ-ONLY / DEFENSIVE',
    sev: 'ok',
    detail: guide.join('\r\n'),
    fix: [
      'Keep Defender, firewall, VBS, HVCI and code integrity enabled.',
      'Never build, sign, load or install the vulnerable driver.',
      'Treat an Application Control block as a positive defensive result.',
      'Record a source finding as a review lead, never as proof of exploitability.'
    ],
    enable: '',
    native: '',
    note: 'A masked Code Audit finding is a study prompt with a documented fix, not a working exploit.'
  });
}

function showHevdReview() {
  var beginner = [
    'BEGINNER OVERVIEW',
    'A driver is kernel code. A bug in it can affect the whole machine, so this',
    'lab only reads the source as text. We do not build or load it.',
    '',
    'Think of a copy as moving parcels into a box. The destination box size',
    'must be known, and the parcel size must never be larger than the box.',
    'A Code Audit hit means: "please look here". It does not mean the bug',
    'was proven, and it never gives you steps to trigger it.',
    '',
    'When you open a finding, read three things: the masked line, the state',
    'label, and the safe verification checklist. The fix tells you what',
    'secure code should do instead.'
  ];
  var advanced = [
    'ADVANCED DEEP DIVE',
    '1. Boundary: name the dispatch entry point and the function that handles',
    '   the caller-controlled buffer. Record file:line for both.',
    '2. Flow: trace every length or size value from the boundary to the copy,',
    '   allocation or dereference. Note casts, truncation and arithmetic.',
    '3. Capacity: compare destination size with the maximum source length.',
    '   A bound that holds for one call path is not enough for all paths.',
    '4. Lifetime: map allocate, reference, free and pointer-clear operations',
    '   for one object. Ownership must remain unambiguous.',
    '5. User pointers: verify probe, single-copy-into-kernel-memory, and',
    '   validation order. Never reuse a user pointer after probing it.',
    '6. Evidence: write the call chain, preconditions, documented fix and',
    '   explicit limits. Static evidence is a review lead, never a runtime',
    '   proof of exploitability.',
    '',
    'No build, sign, install, load, IOCTL, payload, bypass or exploit step is',
    'part of this review. Keep all security controls enabled.'
  ];
  pushConsole('dim', 'Layered kernel review opened. Beginner first, advanced detail second.', 'code');
  showModal({
    title: 'KERNEL SOURCE REVIEW',
    kicker: 'LAYERED GUIDE / BEGINNER + ADVANCED / SOURCE ONLY',
    sev: 'ok',
    detail: beginner.join('\r\n') + '\r\n\r\n' + advanced.join('\r\n'),
    fix: [
      'Start with the beginner overview and explain the bug class in plain language.',
      'Use the advanced deep dive to record source evidence and limits only.',
      'Apply the documented secure pattern in your own source, never in this lab.',
      'Record Application Control or AV blocks as positive defensive results.'
    ],
    note: 'Review artifact only. NetTruder does not build, load or test the driver and does not produce exploit code.'
  });
}

/* Static kernel-debug guide. This is evidence handling and source correlation
   for authorised crash dumps. NetTruder never attaches to a kernel, changes
   boot debug settings, reads live memory, loads a driver or runs any command. */
function showKernelDbgGuide() {
  var scope = [
    'KERNEL DBG / STATIC WINDBG GUIDE',
    'For authorised crash-dump and source correlation only.',
    'NetTruder does not attach to a live kernel, change boot debug settings,',
    'read kernel memory, install or load a driver, or run any command below.',
    'Every command is copyable text for an administrator to review and run.',
    '',
    'WORKFLOW',
    '1. Preserve the dump. Work on a copy and record its hash and source host.',
    '2. Set a trusted symbol path in your own WinDbg session and verify symbols.',
    '3. Record the bugcheck, faulting module, stack and image timestamps.',
    '4. Map one stack frame to local source using file:line from Code Audit.',
    '5. Compare the source with the masked finding and its documented fix.',
    '6. Record the result as STATIC LEAD / NOT RUNTIME VERIFIED with limits.'
  ];
  var commands = [
    'REM copy-only WinDbg commands; do not paste into NetTruder',
    '!analyze -v',
    'vertarget',
    'lm',
    'lmvm <module>',
    'k, kv',
    '!thread',
    '!verifier 3'
  ];
  var limits = [
    'LIMITS',
    'A dump can contain user paths, tokens or other sensitive data; redact before sharing.',
    'Image and symbol versions must match the source tree or the mapping is only a hint.',
    'Do not enable local kernel debugging, load a driver or send an IOCTL for this review.',
    'Keep Defender, firewall, VBS, HVCI and code integrity enabled.'
  ];
  pushConsole('dim', 'Static kernel debug guide opened. Commands are copyable only.', 'code');
  showModal({
    title: 'KERNEL DBG - STATIC WINDBG GUIDE',
    kicker: 'READ-ONLY / COPYABLE COMMANDS / NO LIVE ATTACH',
    sev: 'ok',
    detail: scope.join('\r\n') + '\r\n\r\nCOMMANDS (COPY DETAIL)\r\n' + commands.join('\r\n') + '\r\n\r\n' + limits.join('\r\n'),
    fix: [
      'Confirm you are authorised to read the dump before opening it.',
      'Use a trusted symbol source and match the module version to the source tree.',
      'Run the commands in WinDbg yourself, then map one frame to a local file:line.',
      'Keep the masked Code Audit verdict: STATIC LEAD / NOT RUNTIME VERIFIED.',
      'Apply the documented secure pattern in your own source, never in the lab.'
    ],
    copyText: commands.join('\r\n'),
    note: 'NetTruder never runs these commands. Live kernel debugging, boot/debug configuration and kernel-memory reads are out of scope.'
  });
}

/* Plain-language teaching modal for the wrapped-size static rule. It explains
   the bug class and the fix; it never supplies a trigger or a size value. */
function showIntWrapGuide() {
  var lines = [
    'INTEGER WRAP / WHY THE CHECK PASSES',
    '',
    'WHAT IT IS',
    'A fixed-width number has a maximum. Add or multiply past that maximum',
    'and the high digits drop. The result becomes small. That is a wrap.',
    '',
    'WHY THE CHECK PASSES',
    'If a bound check compares the wrapped result, it sees a small number',
    'and accepts a request whose real size is too large. The later write',
    'has more data than the destination holds. The check read the wrong',
    'number; it did not prove the request was safe.',
    '',
    'WHAT TO LOOK FOR',
    'Arithmetic inside a comparison, for example a size plus a terminator',
    'compared with a buffer size. In the local copy see',
    'Driver/HEVD/Windows/IntegerOverflow.c line 117.',
    'Find the input type, its maximum value, and where the result is used',
    'as a size or length.',
    '',
    'WHAT THE FIX LOOKS LIKE',
    'Check the arithmetic before the comparison, reject sizes above a',
    'documented maximum, and use a consistent wide type for lengths.',
    '',
    'LIMIT',
    'This rule flags a pattern, not a proven wrap. NetTruder does not',
    'compile, run or measure the source, and it does not claim a trigger.',
    'This is a boundary, not a missing feature: the tool highlights the',
    'bug class and stops short of proof, triggering or enabling it.'
  ];
  pushConsole('dim', 'Integer wrap guide opened. Static review only.', 'code');
  showModal({
    title: 'INTEGER WRAP - STATIC REVIEW',
    kicker: 'HEVD-INT / WHY THE CHECK PASSES / NO RUNTIME CLAIM',
    sev: 'ok',
    detail: lines.join('\r\n'),
    fix: [
      'Use checked arithmetic helpers for every size or length calculation.',
      'Reject values above a documented maximum at the review boundary.',
      'Verify the bound after the calculation so a wrapped value cannot pass it.',
      'Keep the verdict STATIC LEAD / NOT RUNTIME VERIFIED.'
    ],
    enable: '',
    native: '',
    note: 'Read HEVD-INT in RESEARCH for detection and hardening rows. No build, load, IOCTL or payload is part of this review.'
  });
}

function runHevdCodeAudit() {
  var path = hevdSourcePath();
  if (el('codePath')) { el('codePath').value = path; }
  showView('code');
  if (S.streams.code && !S.streams.code.done) {
    pushConsole('dim', 'Code Audit is already running; wait for it to finish.', 'code');
    return;
  }
  S.code.hevd = true;
  pushConsole('dim', 'HEVD source-only audit: no file is built, loaded or executed.', 'code');
  runCodeAudit();
}

function buildHevdBridgeRows() {
  var out = [];
  for (var i = 0; i < S.code.findings.length; i++) {
    var f = S.code.findings[i] || {};
    var fix = f.fix;
    if (typeof fix === 'string') { fix = fix ? [fix] : []; }
    if (!fix || !fix.length) { fix = ['Review the masked snippet and apply the documented secure pattern.']; }
    var checks = asTextList(f.check);
    var detail = (f.why || '')
      + '\r\nLocation: ' + (f.file || '-') + ':' + (f.line || '-')
      + '\r\nRule: ' + (f.id || '-') + (f.cwe ? ' / ' + f.cwe : '')
      + '\r\nState: ' + (f.verdict || 'STATIC LEAD / NOT RUNTIME VERIFIED')
      + '\r\nEvidence: ' + (f.evidence || '-')
      + '\r\nReach: ' + (f.reach || '-')
      + '\r\nVerify: ' + (checks.length ? checks.join(' | ') : '-')
      + '\r\nSnippet (masked): ' + (f.snippet || '-');
    out.push({
      id: f.id || 'NT-CODE',
      rule: f.rule || f.id || '',
      severity: hevdSevLabel(f.sev || f.severity || 'info'),
      title: f.title || 'Code Audit finding',
      detail: detail,
      control: 'STATIC AUDIT / ' + (f.id || 'RULE'),
      fix: fix,
      enable: '',
      native: '',
      file: f.file || '',
      line: f.line || 0,
      cwe: f.cwe || '',
      evidence: f.evidence || '',
      reach: f.reach || '',
      preconditions: f.preconditions || '',
      check: checks,
      verdict: f.verdict || 'STATIC LEAD / NOT RUNTIME VERIFIED'
    });
  }
  return out;
}

function sendCodeToResearch() {
  if (!S.code.findings.length) {
    pushConsole('err', 'No Code Audit findings to send. Run an audit first.', 'code');
    return;
  }
  var rows = buildHevdBridgeRows();
  var doc = {
    generated: new Date().toISOString(),
    source: (S.code.meta && S.code.meta.path) || hevdSourcePath(),
    policy: 'Masked Code Audit findings only. No raw source is bridged and no code is executed.',
    findings: rows
  };
  var target = hevdBridgePath();
  try {
    writeText(target, asciiJson(doc));
  } catch (e) {
    pushConsole('err', 'Could not write the RESEARCH bridge file: ' + e.message, 'code');
    return;
  }
  var R = S.research;
  var kept = [];
  for (var k = 0; k < R.findings.length; k++) {
    if (!R.findings[k].__bridged) { kept.push(R.findings[k]); }
  }
  for (var m = 0; m < rows.length; m++) {
    rows[m].__bridged = true;
    kept.push(rows[m]);
  }
  R.findings = kept;
  R.bridged = rows;
  R.dirty = true;
  showView('research');
  renderResearch();
  pushConsole('ok', 'Bridged ' + rows.length + ' masked finding(s) to RESEARCH.', 'code');
  pushConsole('dim', 'Bridge file: ' + target, 'code');
  pushConsole('dim', 'Filter RESEARCH group "Kernel Source Review" for the HEVD study entries.', 'research');
}

function findCodeFile(path) {
  if (!path) { return null; }
  for (var i = 0; i < S.code.files.length; i++) {
    if (S.code.files[i].path === path) { return S.code.files[i]; }
  }
  return null;
}

function firstFindingForFile(path) {
  for (var i = 0; i < S.code.findings.length; i++) {
    if (S.code.findings[i].file === path) { return i; }
  }
  return -1;
}

function codeTrim(value) {
  return String(value === null || value === undefined ? '' : value).replace(/^\s+|\s+$/g, '');
}

function codeSeverityCounts(path) {
  var c = { high: 0, med: 0, low: 0, info: 0 };
  for (var i = 0; i < S.code.findings.length; i++) {
    var f = S.code.findings[i];
    if (!path || f.file === path) { c[sevCls(f.sev)]++; }
  }
  return c;
}

function codeStatsText(path) {
  var c = codeSeverityCounts(path);
  return '<span class="cfbadges"><span class="chigh">H' + c.high + '</span>'
    + '<span class="cmed">M' + c.med + '</span><span class="clow">L' + c.low + '</span></span>';
}

function applyCodeFilters() {
  var sev = String(S.code.sevFilter || '');
  var q = codeTrim(S.code.search || '').toLowerCase();
  var file = S.code.fileFilter || '';
  var pairs = [], i, f, hay;
  for (i = 0; i < S.code.findings.length; i++) {
    f = S.code.findings[i] || {};
    if (file && f.file !== file) { continue; }
    if (sev && sevCls(f.sev) !== sev) { continue; }
    if (q) {
      hay = String([f.id, f.title, f.file, f.line, f.sev, f.owasp, f.cwe, f.why, f.fix, f.snippet,
        f.evidence, f.reach, f.preconditions, f.verdict, f.check].join(' ')).toLowerCase();
      if (hay.indexOf(q) < 0) { continue; }
    }
    pairs.push({ idx: i, f: f });
  }
  var sort = S.code.sort || 'sev';
  pairs.sort(function (a, b) {
    var r = 0, av, bv;
    if (sort === 'file') {
      av = String(a.f.file || ''); bv = String(b.f.file || '');
      r = av < bv ? -1 : (av > bv ? 1 : 0);
      if (!r) { r = Number(a.f.line) - Number(b.f.line); }
    } else if (sort === 'rule') {
      av = String(a.f.id || ''); bv = String(b.f.id || '');
      r = av < bv ? -1 : (av > bv ? 1 : 0);
    } else if (sort === 'line') {
      r = Number(a.f.line) - Number(b.f.line);
      if (!r) { r = String(a.f.file || '') < String(b.f.file || '') ? -1 : 1; }
    } else {
      r = rank(b.f.sev) - rank(a.f.sev);
      if (!r) { r = Number(a.f.line) - Number(b.f.line); }
      if (!r) { r = String(a.f.file || '') < String(b.f.file || '') ? -1 : 1; }
    }
    if (!r) { r = a.idx - b.idx; }
    return r;
  });
  var list = [], map = [];
  for (i = 0; i < pairs.length; i++) { list.push(pairs[i].f); map.push(pairs[i].idx); }
  S.code.viewMap = map;
  return list;
}

function codeFindingRows(list, map) {
  var h = [];
  for (var i = 0; i < list.length; i++) {
    var f = list[i] || {};
    var sev = sevCls(f.sev || f.severity);
    var detail = f.why || f.evidence || f.note || f.snippet || '';
    h.push('<div class="cfrow sev-' + esc(sev) + (map[i] === S.code.selected ? ' sel' : '') + '" data-cfind="' + i + '">'
      + '<span class="cfrsev">' + esc(sev.toUpperCase()) + '</span>'
      + '<span class="cfmain"><b>' + esc(f.title || f.id || 'FINDING') + '</b>'
      + (f.verdict ? '<span class="cfstate">' + esc(f.verdict) + '</span>' : '')
      + '<span class="cfwhere">' + esc(f.file || '-') + ':' + esc(f.line || '-') + '</span>'
      + '<span class="cfdetail">' + esc(clipText(detail, 150)) + '</span></span>'
      + '<span class="cfmap">' + esc(f.id || '') + '<br>' + esc(f.cwe || f.owasp || '')
      + '<br><button class="cfcheck" data-chevidence="' + i + '">EVIDENCE</button></span></div>');
  }
  return h.join('');
}

function syncCodeToolbar() {
  if (el('codeSev')) { el('codeSev').value = S.code.sevFilter || ''; }
  if (el('codeSearch')) { el('codeSearch').value = S.code.search || ''; }
  if (el('codeSort')) { el('codeSort').value = S.code.sort || 'sev'; }
  var hasFile = !!findCodeFile(S.code.fileSelected);
  var hasFindings = S.code.findings.length > 0;
  if (el('btnCodeExport')) { el('btnCodeExport').disabled = !hasFindings; }
  if (el('btnCodeExternal')) { el('btnCodeExternal').disabled = !hasFile; }
  var wm = el('btnCodeWriteMode');
  if (wm) {
    wm.innerHTML = S.code.writeEnabled ? 'WRITE MODE ON' : 'WRITE MODE OFF';
    wm.className = S.code.writeEnabled ? 'mini danger' : 'mini';
    wm.disabled = !!S.code.writeBusy;
  }
  if (el('codeWriteState')) {
    el('codeWriteState').innerHTML = S.code.writeBusy ? 'BUSY'
      : (S.code.writeEnabled ? 'EDITS CAN SAVE' : 'REVIEW ONLY');
  }
}

function renderCode() {
  S.code.dirty = false;
  var m = S.code.meta || {};
  if (S.code.fileFilter && !S.code.fileSelected) { S.code.fileSelected = S.code.fileFilter; }
  var summ = el('codeSumm');
  if (summ) {
    var out = [];
    out.push('<span class="rsum"><b>FILES</b>' + (m.scanned || 0) + ' / ' + (m.files || 0) + '</span>');
    out.push('<span class="rsum bad"><b>HIGH</b>' + (m.high || 0) + '</span>');
    out.push('<span class="rsum warn"><b>MED</b>' + (m.med || 0) + '</span>');
    out.push('<span class="rsum dim"><b>LOW</b>' + (m.low || 0) + '</span>');
    out.push('<span class="rsum"><b>RULES</b>' + (m.rules || 0) + '</span>');
    out.push('<span class="rsum dim"><b>SKIPPED</b>' + (m.skipped || 0) + '</span>');
    out.push('<span class="rsum dim"><b>LANGS</b>' + ((m.languages && m.languages.length) || 0) + '</span>');
    if (m.limitHit) { out.push('<span class="rsum warn"><b>LIMIT</b>250 findings</span>'); }
    out.push('<span class="rsum dim">' + esc(clipText(m.policy || 'STATIC REVIEW', 110)) + '</span>');
    summ.innerHTML = out.join('');
  }
  if (el('codeCount')) { el('codeCount').innerHTML = String(S.code.files.length); }
  var fb = el('codeFiles'), ff = el('codeFindings');
  var fileScroll = fb ? fb.scrollTop : 0, findScroll = ff ? ff.scrollTop : 0;
  if (fb) {
    if (!S.code.files.length) {
      fb.innerHTML = '<div class="empty small" id="codeEmpty">RUN THE AUDIT TO LIST FILES WITH FINDINGS</div>';
    } else {
      var fh = ['<div class="cfile' + (S.code.fileSelected ? '' : ' sel') + '" data-file="">'
        + '<b>ALL FILES</b>' + codeStatsText('')
        + '<span class="micro">show every finding / ' + S.code.findings.length + ' hits</span></div>'];
      for (var i = 0; i < S.code.files.length; i++) {
        var r = S.code.files[i];
        var hits = (r.hits && r.hits.length) ? r.hits.length : r.findings;
        fh.push('<div class="cfile' + (S.code.fileSelected === r.path ? ' sel' : '') + '" data-file="' + esc(r.path) + '">'
          + '<b>' + esc(r.path) + '</b>' + codeStatsText(r.path)
          + '<span class="micro">' + esc(r.lang) + ' / ' + r.lines + ' lines / ' + hits + ' hits'
          + (r.contentWithheld ? ' / CONTENT WITHHELD' : '') + '</span></div>');
      }
      fb.innerHTML = fh.join('');
    }
  }
  var list = applyCodeFilters();
  if (ff) {
    ff.innerHTML = list.length ? codeFindingRows(list, S.code.viewMap)
      : '<div class="empty small" id="codeFindEmpty">NO FINDINGS MATCH THE CURRENT FILTERS</div>';
    ff.scrollTop = findScroll;
  }
  if (fb) { fb.scrollTop = fileScroll; }
  if (el('codeFindCount')) { el('codeFindCount').innerHTML = String(list.length) + ' / ' + S.code.findings.length; }
  syncCodeToolbar();
  renderCodeDetail();
}

function codeFullPath(rel) {
  var root = (S.code.meta && S.code.meta.path) || '';
  var r = String(rel || '');
  if (!root || !r) { return ''; }
  if (/^[A-Za-z]:/.test(r) || r.charAt(0) === '\\') { return ''; }
  var parts = r.replace(/\//g, '\\').split('\\'), i;
  for (i = 0; i < parts.length; i++) {
    if (parts[i] === '..') { return ''; }
  }
  try {
    var full = S.fso.GetAbsolutePathName(root + '\\' + parts.join('\\'));
    return S.fso.FileExists(full) ? full : '';
  } catch (e) { return ''; }
}

function copyCodeSnippet() {
  var f = S.code.findings[S.code.selected];
  if (!f) { return; }
  clipboardText(f.snippet || '');
  pushConsole('ok', 'Copied masked snippet for ' + (f.id || 'finding') + ' to the clipboard.', 'code');
}

function copyCodeSource() {
  var rec = findCodeFile(S.code.fileSelected);
  if (!rec || !rec.content || !rec.content.length) { return; }
  clipboardText(rec.content.join('\r\n'));
  pushConsole('ok', 'Copied masked source for ' + rec.path + ' to the clipboard.', 'code');
}

function copyRawSource() {
  if (!S.code.rawMode || !S.code.raw) { return; }
  var ta = el('codeRawText');
  var text = ta ? ta.value : (S.code.raw.buffer || '');
  clipboardText(text);
  pushConsole('warn', 'Copied raw source. Values are not masked.', 'code');
}

function openCodeExternal() {
  var path = S.code.fileSelected;
  if (!path && S.code.selected >= 0 && S.code.findings[S.code.selected]) {
    path = S.code.findings[S.code.selected].file;
  }
  var full = codeFullPath(path);
  if (!full) {
    pushConsole('err', 'Could not resolve the selected file inside the audited root.', 'code');
    return;
  }
  try {
    var editor = 'notepad.exe';
    var vscode = S.sh.ExpandEnvironmentStrings('%LOCALAPPDATA%\\Programs\\Microsoft VS Code\\Code.exe');
    if (S.fso.FileExists(vscode)) { editor = q(vscode); }
    S.sh.Run(editor + ' ' + q(full), 1, false);
    pushConsole('dim', 'Opened file in an external editor. NetTruder did not write to it.', 'code');
  } catch (e) {
    pushConsole('err', 'Could not open the external editor: ' + e.message, 'code');
  }
}

function exportCodeReport() {
  if (!S.code.findings.length) { return; }
  var m = S.code.meta || {}, h = [], i, f;
  h.push('NETTRUDER // STATIC CODE AUDIT REPORT');
  h.push('Generated: ' + new Date().toISOString());
  h.push('Root: ' + (m.path || '-'));
  h.push('Files scanned: ' + (m.scanned || 0) + ' / ' + (m.files || 0));
  h.push('Findings: ' + S.code.findings.length + ' (high ' + (m.high || 0) + ', med ' + (m.med || 0) + ', low ' + (m.low || 0) + ')');
  h.push('Policy: ' + (m.policy || 'Static review only.'));
  h.push('');
  h.push('FINDINGS');
  for (i = 0; i < S.code.findings.length; i++) {
    f = S.code.findings[i] || {};
    h.push('----------------------------------------------------------------');
    h.push((f.sev || 'info').toUpperCase() + ' | ' + (f.id || 'RULE') + ' | ' + (f.title || 'FINDING'));
    h.push('Location: ' + (f.file || '-') + ':' + (f.line || '-'));
    h.push('Mapping: ' + [f.owasp, f.cwe].join(' / '));
    h.push('Why: ' + (f.why || '-'));
    h.push('State: ' + (f.verdict || 'STATIC LEAD / NOT RUNTIME VERIFIED'));
    h.push('Evidence: ' + (f.evidence || '-'));
    h.push('Reach: ' + (f.reach || '-'));
    h.push('Preconditions: ' + (f.preconditions || '-'));
    var checks = asTextList(f.check);
    for (var ci = 0; ci < checks.length; ci++) { h.push('Verify ' + (ci + 1) + ': ' + checks[ci]); }
    h.push('Fix: ' + (typeof f.fix === 'string' ? f.fix : (f.fix || []).join(' | ')));
    h.push('Snippet (values masked):');
    h.push(f.snippet || '-');
  }
  h.push('');
  h.push('FUNCTION INDEX');
  for (i = 0; i < S.code.files.length; i++) {
    var rec = S.code.files[i];
    var fns = scanFunctions(rec.content || [], rec.lang);
    h.push('----------------------------------------------------------------');
    h.push('FILE: ' + rec.path + ' (' + rec.lines + ' lines)');
    for (var j = 0; j < fns.length; j++) {
      h.push('L' + fns[j].line + ' ' + fns[j].name + ' :: ' + fns[j].signature);
    }
  }
  var stamp = new Date().toISOString().replace(/:/g, '-').replace(/\./g, '-');
  var out = S.audit + '\\code-audit-' + stamp + '.txt';
  try {
    writeText(out, h.join('\r\n'));
    pushConsole('ok', 'Code report written to ' + out, 'code');
  } catch (e) {
    pushConsole('err', 'Could not write the code report: ' + e.message, 'code');
  }
}

function resetCodeWriteMode() {
  if (S.code.rawMode && S.code.rawDirty) {
    pushConsole('warn', 'Unsaved raw edits were discarded when write mode reset.', 'code');
  }
  S.code.writeEnabled = false;
  S.code.writeBusy = false;
  S.code.raw = null;
  S.code.rawMode = false;
  S.code.rawDirty = false;
  S.code.lastWrite = '';
  syncCodeToolbar();
}

function toggleCodeWriteMode() {
  if (S.code.writeBusy) { return; }
  if (S.code.writeEnabled) {
    resetCodeWriteMode();
    pushConsole('dim', 'Write mode disabled. Code Audit is review-only again.', 'code');
    renderCode();
    return;
  }
  var ok = window.confirm('Enable source write mode for this NetTruder session?\n\n'
    + '- Default is review-only.\n'
    + '- Raw source is not masked.\n'
    + '- Every save needs another confirmation and creates a backup.\n'
    + '- Write mode resets on the next audit and when NetTruder restarts.');
  if (!ok) { return; }
  S.code.writeEnabled = true;
  pushConsole('warn', 'Write mode enabled for this session. Review raw source carefully before saving.', 'code');
  renderCode();
}

function startCodeRaw() {
  if (!S.code.writeEnabled) {
    pushConsole('err', 'Enable write mode before opening raw source.', 'code');
    return;
  }
  if (S.code.writeBusy) { return; }
  if (S.streams.coderaw && !S.streams.coderaw.done) { return; }
  var rec = findCodeFile(S.code.fileSelected);
  if (!rec) { return; }
  var ok = window.confirm('Open the unmasked source for ' + rec.path + '?\n\n'
    + 'Values will be shown exactly as stored. NetTruder will not save anything until you confirm a separate save.');
  if (!ok) { return; }
  var root = (S.code.meta && S.code.meta.path) || '';
  S.code.writeBusy = true;
  syncCodeToolbar();
  startStream('coderaw', 'coderead', { path: root, itemId: rec.path, yes: true });
}

function onCodeRaw(d) {
  if (!d || !d.path) { return; }
  var arr = d.content || [];
  var text = arr.join('\n');
  S.code.raw = {
    path: d.path, root: d.root || '', lines: d.lines || arr.length,
    encoding: d.encoding || 'utf-8', eol: d.eol || 'lf', content: arr.slice(0),
    original: text, buffer: text
  };
  S.code.rawMode = true;
  S.code.rawDirty = false;
  S.code.fileSelected = d.path;
  S.code.fileFilter = d.path;
  var idx = firstFindingForFile(d.path);
  if (idx >= 0) {
    S.code.selected = idx;
    S.code.activeLine = parseInt(S.code.findings[idx].line, 10) || 0;
  }
  S.code.dirty = true;
}

function onCodeWrite(d) {
  if (d && d.path) { S.code.lastWrite = d.backup || S.code.lastWrite; }
}

function saveCodeRaw() {
  if (!S.code.writeEnabled || !S.code.rawMode || !S.code.raw || !S.code.rawDirty || S.code.writeBusy) { return; }
  if (S.streams.codewrite && !S.streams.codewrite.done) { return; }
  var metaRoot = (S.code.meta && S.code.meta.path) || '';
  if (metaRoot && S.code.raw.root && String(metaRoot).toLowerCase() !== String(S.code.raw.root).toLowerCase()) {
    pushConsole('err', 'The audited root changed. Re-run the audit before saving.', 'code');
    return;
  }
  var ok = window.confirm('Save changes to ' + S.code.raw.path + '?\n\n'
    + 'The original file will be backed up under the NetTruder state folder before the write.\n'
    + 'Only save source you own or are authorised to change.');
  if (!ok) { return; }
  var contentFile = S.runs + '\\' + runId() + '.codewrite.txt';
  try {
    writeUnicodeText(contentFile, S.code.raw.buffer || '');
  } catch (e) {
    pushConsole('err', 'Could not stage the edited content: ' + e.message, 'code');
    return;
  }
  S.code.writeBusy = true;
  syncCodeToolbar();
  startStream('codewrite', 'codewrite', {
    path: metaRoot || S.code.raw.root || '', itemId: S.code.raw.path,
    contentFile: contentFile, yes: true, ackRisk: true
  });
}

function revertCodeRaw() {
  if (!S.code.raw || !S.code.rawDirty) { return; }
  var ok = window.confirm('Discard unsaved edits and reload the version opened from disk?');
  if (!ok) { return; }
  S.code.raw.buffer = S.code.raw.original;
  S.code.rawDirty = false;
  renderCodeDetail();
}

function closeCodeRaw() {
  if (!S.code.raw) { return; }
  if (S.code.rawDirty) {
    var ok = window.confirm('Close the raw editor without saving? Unsaved changes will be lost.');
    if (!ok) { return; }
  }
  S.code.raw = null;
  S.code.rawMode = false;
  S.code.rawDirty = false;
  renderCode();
}

function onRawInput() {
  var ta = el('codeRawText');
  if (!ta) { return; }
  if (!S.code.rawMode || !S.code.raw) {
    refreshEditorChrome();
    return;
  }
  S.code.raw.buffer = ta.value;
  S.code.rawDirty = S.code.raw.buffer !== S.code.raw.original;
  refreshRawChrome();
}

function onEditorCaret() {
  var ta = el('codeRawText');
  if (!ta) { return; }
  var pos = ta.selectionStart;
  if (pos === undefined || pos === null) { return; }
  var line = ta.value.substring(0, pos).split('\n').length;
  if (line !== S.code.activeLine) {
    S.code.activeLine = line;
    refreshEditorChrome();
  } else {
    updateEditorStatus();
  }
}

/* A single editor surface is used for masked review and opt-in raw editing.
   The gutter and the hit underlay sit behind a real textarea, so clicks,
   selection, copying, caret movement and typing all work in IE11. */
function codeHitMap(path) {
  var hitByLine = {}, rec = findCodeFile(path), i, f;
  if (rec && rec.hits) {
    for (i = 0; i < rec.hits.length; i++) { hitByLine[String(rec.hits[i].line)] = rec.hits[i]; }
  }
  f = S.code.findings[S.code.selected];
  if (f && f.file === path && !hitByLine[String(f.line)]) {
    hitByLine[String(f.line)] = { line: f.line, id: f.id, sev: f.sev, title: f.title };
  }
  return hitByLine;
}

function editorPath() {
  if (S.code.rawMode && S.code.raw) { return S.code.raw.path; }
  return S.code.fileSelected || '';
}

function selectedCodeLine() {
  var f = S.code.findings[S.code.selected], path = editorPath();
  return (f && f.file === path) ? String(f.line) : '';
}

function renderRawGutter(lines) {
  var g = el('codeRawGutter'), ta = el('codeRawText');
  if (!g) { return; }
  if (!lines) {
    lines = (ta ? ta.value : (S.code.raw && S.code.raw.buffer) || '').split('\n');
  }
  var path = editorPath(), hitByLine = codeHitMap(path), selLine = selectedCodeLine();
  var active = String(S.code.activeLine || 0), h = [], i, key, hit;
  for (i = 0; i < lines.length; i++) {
    key = String(i + 1);
    hit = hitByLine[key];
    h.push('<div class="rgl' + (hit ? ' hit sev-' + esc(sevCls(hit.sev)) : '')
      + (key === selLine ? ' sel' : '') + (key === active ? ' active' : '') + '">' + key + '</div>');
  }
  var top = g.scrollTop;
  g.innerHTML = h.join('');
  g.scrollTop = top;
}

function renderCodeUnderlay(lines) {
  var under = el('codeEditorUnderlay'), ta = el('codeRawText');
  if (!under) { return; }
  if (!lines) {
    lines = (ta ? ta.value : (S.code.raw && S.code.raw.buffer) || '').split('\n');
  }
  var path = editorPath(), hitByLine = codeHitMap(path), selLine = selectedCodeLine();
  var active = String(S.code.activeLine || 0), h = [], i, key, hit, cls;
  for (i = 0; i < lines.length; i++) {
    key = String(i + 1);
    hit = hitByLine[key];
    cls = 'erow' + (hit ? ' hit sev-' + esc(sevCls(hit.sev)) : '')
      + (key === selLine ? ' sel' : '') + (key === active ? ' active' : '');
    h.push('<div class="' + cls + '" id="codeLine' + key + '">'
      + (hit ? '<span class="ehitbar"></span>' : '') + '</div>');
  }
  var top = under.scrollTop, left = under.scrollLeft;
  under.innerHTML = h.join('');
  under.scrollTop = top;
  under.scrollLeft = left;
}

function updateEditorStatus() {
  var ta = el('codeRawText'), st = el('codeEditorStatus');
  if (!ta || !st) { return; }
  var pos = ta.selectionStart;
  if (pos === undefined || pos === null) { pos = 0; }
  var before = ta.value.substring(0, pos);
  var line = before.split('\n').length;
  var col = pos - before.lastIndexOf('\n');
  var hit = codeHitMap(editorPath())[String(line)];
  var mode = (S.code.rawMode && S.code.raw) ? 'RAW EDIT' : 'MASKED / READ ONLY';
  var text = 'LN ' + line + '  COL ' + col + '  /  ' + mode;
  text += (hit ? '  /  HIT ' + esc(hit.id || hit.title || 'YES') : '');
  if (S.code.rawDirty) { text += '  /  UNSAVED'; }
  st.innerHTML = text;
}

function refreshEditorChrome() {
  var ta = el('codeRawText');
  if (!ta) { return; }
  if (S.code.rawMode && S.code.raw) { S.code.raw.buffer = ta.value; }
  var lines = ta.value.split('\n');
  renderRawGutter(lines);
  renderCodeUnderlay(lines);
  updateEditorStatus();
}

function syncRawGutter() {
  var ta = el('codeRawText'), g = el('codeRawGutter'), under = el('codeEditorUnderlay');
  if (!ta) { return; }
  if (g) { g.scrollTop = ta.scrollTop; }
  if (under) { under.scrollTop = ta.scrollTop; under.scrollLeft = ta.scrollLeft; }
}

function refreshRawChrome() {
  if (el('codeRawState')) {
    el('codeRawState').innerHTML = S.code.rawDirty ? 'UNSAVED CHANGES' : 'NO UNSAVED CHANGES';
  }
  var save = el('btnCodeRawSave');
  if (save) { save.disabled = !(S.code.writeEnabled && S.code.rawDirty && !S.code.writeBusy); }
  refreshEditorChrome();
}

function codeCommentMarkers(lang) {
  var l = String(lang || '').toLowerCase();
  if (l === 'html' || l === 'htm' || l === 'xml' || l === 'svg') { return { pre: '<!-- ', post: ' -->' }; }
  if (l === 'py' || l === 'ps1' || l === 'sh' || l === 'bash' || l === 'yml' || l === 'yaml' || l === 'rb') {
    return { pre: '# ', post: '' };
  }
  return { pre: '// ', post: '' };
}

function insertCodeFix() {
  if (!S.code.writeEnabled || !S.code.rawMode || !S.code.raw) { return; }
  var ta = el('codeRawText');
  if (!ta) { return; }
  var f = S.code.findings[S.code.selected];
  if (!f) {
    pushConsole('err', 'Select a finding before inserting a fix template.', 'code');
    return;
  }
  var lines = ta.value.split('\n'), at;
  if (f.file === S.code.raw.path) {
    at = Math.max(0, (parseInt(f.line, 10) || 1) - 1);
  } else {
    var pos = ta.selectionStart || 0;
    at = Math.max(0, ta.value.substring(0, pos).split('\n').length - 1);
  }
  var rec = findCodeFile(S.code.raw.path), markers = codeCommentMarkers(rec ? rec.lang : '');
  var fix = (typeof f.fix === 'string') ? [f.fix] : (f.fix || []);
  var block = ['NETTRUDER FIX TEMPLATE - REVIEW BEFORE SAVING',
    'RULE ' + (f.id || '-') + ' / ' + (f.sev || '-') + ' / ' + (f.file || '-') + ':' + (f.line || '-')];
  var i;
  for (i = 0; i < fix.length && i < 8; i++) { block.push(String(fix[i])); }
  var ins = [];
  for (i = 0; i < block.length; i++) { ins.push(markers.pre + block[i] + markers.post); }
  lines.splice.apply(lines, [at, 0].concat(ins));
  ta.value = lines.join('\n');
  var start = 0;
  for (i = 0; i < at; i++) { start += lines[i].length + 1; }
  if (ta.setSelectionRange) { ta.setSelectionRange(start, start); }
  ta.focus();
  onRawInput();
  pushConsole('dim', 'Inserted a commented fix template. Review it before saving.', 'code');
}

function sourceLinesForCode(rawActive) {
  /* During renderCodeDetail the old textarea is still in the DOM. Reading it
     here would feed the masked/truncated audit copy back into the raw editor.
     renderCodeDetail copies any live edits into raw.buffer first, so the
     buffer is the authoritative source for the raw surface. */
  if (rawActive && S.code.raw) {
    return String(S.code.raw.buffer || '').split('\n');
  }
  var rec = findCodeFile(S.code.fileSelected);
  return (rec && rec.content) ? rec.content : [];
}

function scanFunctions(lines, lang) {
  var pats = [
    /^\s*(?:NTSTATUS|VOID|PVOID|ULONG_PTR|ULONG|BOOLEAN|SIZE_T|HRESULT|UCHAR|WCHAR|LONG|INT|UINT)\s+(?:NTAPI\s+|__stdcall\s+)?([A-Za-z_][\w]*)\s*\(/,
    /^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(/,
    /^\s*(?:public|private|protected|internal|static|virtual|override|async|extern|declare)\s+[\w<>,\[\]\.]+\s+([A-Za-z_][\w]*)\s*\(/,
    /^\s*(?:def|func|fun)\s+([A-Za-z_][\w]*)\s*\(/,
    /^\s*(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?function\b/,
    /^\s*(?:(?:var|let|const)\s+)?([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?\([^)]*\)\s*=>/,
    /^\s*([A-Za-z_$][\w$]*)\s*=\s*function\b/,
    /^\s*([A-Za-z_][\w]*)\s*:\s*function\s*\(/
  ];
  var reserved = ['if', 'for', 'while', 'switch', 'catch', 'return', 'else', 'try', 'do', 'with'];
  var out = [], i, j, k, m, name, isReserved;
  for (i = 0; i < lines.length && out.length < 80; i++) {
    name = '';
    for (j = 0; j < pats.length; j++) {
      m = String(lines[i]).match(pats[j]);
      if (m && m[1]) { name = m[1]; break; }
    }
    isReserved = false;
    for (k = 0; k < reserved.length; k++) { if (reserved[k] === name) { isReserved = true; break; } }
    if (!name || isReserved) { continue; }
    out.push({ name: name, line: i + 1, signature: clipText(codeTrim(lines[i]), 160), endLine: i + 1 });
  }
  for (i = 0; i < out.length; i++) {
    var end = Math.min(out[i].line + 39, lines.length);
    if (i + 1 < out.length) { end = Math.min(end, out[i + 1].line - 1); }
    out[i].endLine = Math.max(out[i].line, end);
  }
  return out;
}

function copyCodeFunction(idx) {
  var fn = S.code.functions[idx];
  if (!fn) { return; }
  var rawActive = S.code.rawMode && S.code.raw && S.code.raw.path === S.code.fileSelected;
  var lines = sourceLinesForCode(rawActive);
  var text = lines.slice(fn.line - 1, fn.endLine).join('\n');
  clipboardText(text);
  pushConsole('ok', 'Copied function ' + fn.name + ' from line ' + fn.line + '.', 'code');
}

function gotoCodeLine(line, focus) {
  var n = parseInt(line, 10);
  if (!n || n < 1) { return; }
  S.code.activeLine = n;
  var ta = el('codeRawText');
  if (!ta) { return; }
  var lines = ta.value.split('\n');
  var idx = Math.min(Math.max(n - 1, 0), Math.max(lines.length - 1, 0));
  var before = '', i;
  for (i = 0; i < idx; i++) { before += lines[i] + '\n'; }
  var start = before.length, end = start + (lines[idx] ? lines[idx].length : 0);
  try {
    if (focus) { ta.focus(); }
    if (ta.setSelectionRange) { ta.setSelectionRange(start, end); }
  } catch (e) { }
  /* IE11 can ignore scrollTop until the textarea has been laid out. Force a
     reflow, set the scroll, then repeat once the browser has caught up. */
  var apply = function () {
    if (!ta) { return; }
    var top = Math.max(0, (idx - 4) * 17);
    void ta.offsetHeight;
    ta.scrollTop = top;
    syncRawGutter();
    refreshEditorChrome();
  };
  apply();
  window.setTimeout(apply, 0);
}

function selectCodeHit(line, id) {
  var path = S.code.fileSelected;
  if (!path) { return; }
  S.code.activeLine = parseInt(line, 10) || 0;
  for (var i = 0; i < S.code.findings.length; i++) {
    var f = S.code.findings[i];
    if (f.file === path && String(f.line) === String(line) && (!id || f.id === id)) {
      S.code.selected = i;
      renderCodeDetail();
      gotoCodeLine(line, true);
      return;
    }
  }
  renderCodeDetail();
  gotoCodeLine(line, true);
}

function editorToolbar(rawActive, rec) {
  var go = '<span class="micro">GO LINE</span>'
    + '<input id="codeGoLine" class="gotoline" type="text" spellcheck="false" size="5" maxlength="6" />'
    + '<button class="mini" data-act="goline">GO</button>';
  if (rawActive) {
    return '<div class="iderawbar">'
      + '<span class="micro" id="codeRawState">' + (S.code.rawDirty ? 'UNSAVED CHANGES' : 'NO UNSAVED CHANGES') + '</span>'
      + go
      + '<button class="mini" data-act="insertfix">INSERT FIX TEMPLATE</button>'
      + '<button class="mini" data-act="revert">REVERT</button>'
      + '<button class="mini primary" id="btnCodeRawSave" data-act="save"' + (S.code.rawDirty ? '' : ' disabled="disabled"') + '>SAVE</button>'
      + '</div>';
  }
  return '<div class="idemodebar">'
    + '<span class="micro">MASKED SOURCE // CLICK, SELECT AND COPY ARE ENABLED</span>'
    + '<span class="grow"></span>'
    + go
    + '<button class="mini' + (S.code.writeEnabled ? ' danger' : '') + '" data-act="openraw"'
    + ((S.code.writeEnabled && rec) ? '' : ' disabled="disabled"') + '>OPEN RAW</button>'
    + '</div>';
}

function renderCodeDetail() {
  var box = el('codeDetail');
  if (!box) { return; }
  var liveRaw = el('codeRawText');
  /* The old surface can be the masked, read-only editor when raw mode has just
     been opened. Only copy back from a real editable raw surface. */
  if (liveRaw && S.code.raw && !liveRaw.readOnly) {
    S.code.raw.buffer = liveRaw.value;
    S.code.rawDirty = S.code.raw.buffer !== S.code.raw.original;
  }
  var idx = S.code.selected;
  var f = (idx >= 0 && idx < S.code.findings.length) ? S.code.findings[idx] : null;
  var path = S.code.fileSelected || (f ? f.file : '');
  var rec = findCodeFile(path);
  if (!rec && f) { rec = findCodeFile(f.file); if (rec) { path = f.file; } }
  var rawActive = !!(S.code.rawMode && S.code.raw && S.code.raw.path === path);
  if (!rec && !f && !rawActive) {
    box.innerHTML = '<div class="ideempty">SELECT A FILE WITH HITS OR A FINDING TO OPEN THE SOURCE VIEW</div>';
    return;
  }
  var source = sourceLinesForCode(rawActive);
  if (S.code.funcPath !== path) { S.code.selectedFunction = -1; }
  S.code.functions = scanFunctions(source, rec ? rec.lang : '');
  S.code.funcPath = path;
  var hits = (rec && rec.hits) ? rec.hits : [];
  if (!hits.length && f) { hits = [{ line: f.line, id: f.id, sev: f.sev, title: f.title }]; }
  var selLine = (f && f.file === path) ? String(f.line) : '';
  if (!S.code.activeLine && selLine) { S.code.activeLine = parseInt(selLine, 10) || 0; }
  var i, h = [];

  h.push('<div class="idewrap">');
  h.push('<div class="idecode">');
  h.push('<div class="idehead"><span class="idetitle">FILE INSPECTOR</span>'
    + '<span class="idemeta">' + esc(path) + '</span>'
    + '<button class="mini" data-act="copysource">COPY FILE</button>'
    + (rawActive
      ? '<button class="mini" data-act="copyraw">COPY RAW</button><button class="mini danger" data-act="closeraw">CLOSE RAW</button>'
      : '')
    + '</div>');
  h.push('<div class="idehits">');
  if (hits.length) {
    for (i = 0; i < hits.length; i++) {
      h.push('<button class="idehit sev-' + esc(sevCls(hits[i].sev))
        + (String(hits[i].line) === selLine ? ' active' : '')
        + '" title="' + esc(hits[i].why || hits[i].title || hits[i].id || '')
        + '" data-act="hit" data-line="' + esc(hits[i].line) + '" data-id="' + esc(hits[i].id) + '">L'
        + esc(hits[i].line) + ' ' + esc(clipText(hits[i].title || hits[i].id, 42)) + '</button>');
    }
  } else {
    h.push('<span class="micro">NO HIT INDEX FOR THIS FILE</span>');
  }
  h.push('</div>');
  var note = '';
  if (rawActive) {
    note = 'RAW SOURCE // ' + String(S.code.raw.encoding).toUpperCase() + ' / '
      + String(S.code.raw.eol || 'lf').toUpperCase() + (S.code.rawDirty ? ' // UNSAVED' : '');
  } else if (rec && rec.contentWithheld) { note = 'CONTENT WITHHELD // SECRET OR CREDENTIAL FILE'; }
  else if (rec && rec.contentTruncated) { note = 'TRUNCATED AFTER ' + (rec.contentLines || 0) + ' LINES // HITS BEYOND THIS POINT REMAIN LISTED'; }
  h.push('<div class="idesubhead">' + (rawActive ? 'RAW EDITOR' : 'SOURCE')
    + (note ? '<span class="idenote">' + esc(note) + '</span>' : '') + '</div>');
  h.push(editorToolbar(rawActive, rec));
  h.push('<div class="ideeditor">'
    + '<div id="codeRawGutter" class="rawgutter"></div>'
    + '<div class="editorbody">'
    + '<div id="codeEditorUnderlay" class="editorunderlay"></div>'
    + '<textarea id="codeRawText" class="rawtext" spellcheck="false" wrap="off"'
    + (rawActive ? '' : ' readonly="readonly"') + '></textarea>'
    + '</div></div>');
  h.push('<div class="idestatus" id="codeEditorStatus"></div>');
  h.push('</div>');

  h.push('<div class="idedetail" id="codeDetailPane">');
  if (f) {
    h.push('<div class="mlabel">SELECTED FINDING</div>');
    h.push(kvHtml([
      ['RULE', f.id], ['SEVERITY', f.sev], ['LOCATION', f.file + ':' + f.line],
      ['OWASP', f.owasp], ['CWE', f.cwe], ['CONFIDENCE', f.confidence]
    ]));
    h.push('<div class="mlabel">WHY IT MATTERS</div><div class="mdetailinline">' + esc(f.why || '') + '</div>');
    if (f.evidence || f.reach || f.verdict || (f.check && f.check.length)) {
      h.push('<div class="mlabel">STATIC EVIDENCE / VERIFY CHECKLIST</div>');
      h.push('<div class="mnote">STATE: ' + esc(f.verdict || 'STATIC LEAD / NOT RUNTIME VERIFIED') + '</div>');
      if (f.evidence) { h.push('<div class="mdetailinline">' + esc(f.evidence) + '</div>'); }
      if (f.reach) { h.push('<div class="mdetailinline dimline">' + esc(f.reach) + '</div>'); }
      if (f.preconditions) { h.push('<div class="mdetailinline dimline">Preconditions: ' + esc(f.preconditions) + '</div>'); }
      var checks = asTextList(f.check);
      if (checks.length) {
        h.push('<div class="checklist">');
        for (i = 0; i < checks.length; i++) {
          h.push('<div class="checkrow">' + esc(checks[i]) + '</div>');
        }
        h.push('</div>');
      }
      h.push('<div class="ideactions"><button class="btn small" data-act="evidence">EVIDENCE / VERIFY</button></div>');
    }
    h.push('<div class="mlabel">SNIPPET (VALUES MASKED)</div><pre class="codeSnip">' + esc(f.snippet || '') + '</pre>');
    h.push('<div class="ideactions"><button class="btn small" data-act="copysnip">COPY SNIPPET</button>'
      + '<button class="btn small" data-act="remedy">REMEDY / FIX</button></div>');
  } else {
    h.push('<div class="empty small">Click a hit above or a finding in the list to load its line and fix.</div>');
  }
  h.push('<div class="mlabel">FUNCTION INDEX</div>');
  if (S.code.functions.length) {
    h.push('<div class="fnlist">');
    for (i = 0; i < S.code.functions.length && i < 40; i++) {
      var fn = S.code.functions[i];
      h.push('<div class="fnrow' + (S.code.selectedFunction === i ? ' sel' : '') + '" data-act="function"'
        + ' data-line="' + fn.line + '" data-fn="' + i + '">'
        + '<button class="mini" data-act="copyfunction" data-fn="' + i + '">COPY</button>'
        + '<b>' + esc(fn.name) + '</b><span class="micro">L' + fn.line + ' / ' + esc(fn.signature) + '</span></div>');
    }
    h.push('</div>');
  } else {
    h.push('<div class="empty small">NO FUNCTION DECLARATIONS FOUND IN THIS FILE</div>');
  }
  h.push('<div class="mlabel">HANDOFF</div>');
  h.push('<div class="ideactions"><button class="btn small" data-act="external">OPEN IN EDITOR</button>'
    + '<button class="btn small" data-act="export">EXPORT REPORT</button></div>');
  if (S.code.lastWrite) {
    h.push('<div class="mnote">Last backup: ' + esc(clipText(S.code.lastWrite, 180)) + '</div>');
  }
  h.push('</div></div>');
  box.innerHTML = h.join('');
  /* IE11 can preserve scroll offsets when innerHTML is replaced. Always show
     the top of the selected finding panel and the card itself. */
  box.scrollTop = 0;
  var pane = el('codeDetailPane');
  if (pane) { pane.scrollTop = 0; }

  var ta = el('codeRawText');
  if (ta) {
    ta.value = source.join('\n');
    ta.readOnly = !rawActive;
    ta.onkeyup = function (ev) { onRawInput(); onEditorCaret(); };
    ta.oninput = onRawInput;
    ta.onpropertychange = function () {
      if (window.event && window.event.propertyName === 'value') { onRawInput(); }
    };
    ta.onclick = onEditorCaret;
    ta.onmouseup = onEditorCaret;
    ta.onselect = onEditorCaret;
    ta.onscroll = syncRawGutter;
    renderRawGutter(source);
    renderCodeUnderlay(source);
    updateEditorStatus();
    if (!source.length && el('codeEditorStatus')) {
      el('codeEditorStatus').innerHTML = rec && rec.contentWithheld
        ? 'CONTENT WITHHELD BY THE ENGINE'
        : 'NO SOURCE BODY CAPTURED';
    }
    var go = el('codeGoLine');
    if (go) {
      go.onkeyup = function (ev) {
        if (ev && ev.keyCode === 13) { gotoCodeLine(this.value, true); }
      };
    }
    if (selLine) { gotoCodeLine(selLine, false); }
  }
  syncCodeToolbar();
}

/* ---------------------------- investigation ---------------------------- */
function runInv() {
  if (S.streams.inv && !S.streams.inv.done) { return; }
  S.inv.conns = []; S.inv.dns = []; S.inv.listen = []; S.inv.findings = []; S.inv.meta = null;
  if (el('btnInvRun')) { el('btnInvRun').disabled = true; }
  if (el('invState')) { el('invState').innerHTML = 'READING'; }
  pushConsole('dim', 'Read-only socket, DNS cache and listener investigation.', 'inv');
  startStream('inv', 'investigate', {});
}

function renderInv() {
  S.inv.dirty = false;
  var m = S.inv.meta || {};
  var f = String(el('invFilter') ? el('invFilter').value : '').toLowerCase().replace(/^\s+|\s+$/g, '');
  var rows = [];
  for (var i = 0; i < S.inv.conns.length; i++) {
    var c = S.inv.conns[i];
    if (f && String(c.ip + ' ' + c.ports + ' ' + c.processes + ' ' + c.mac).toLowerCase().indexOf(f) < 0) { continue; }
    rows.push('<tr data-ip="' + esc(c.ip) + '"><td class="mono">' + esc(c.ip) + (c.mac ? '<span class="hostname">' + esc(c.mac) + '</span>' : '') + '</td>'
      + '<td>' + (c.private ? '<span class="risk risk-low">PRIVATE</span>' : '<span class="risk risk-high">PUBLIC</span>') + '</td>'
      + '<td class="mono">' + esc(c.conns) + '</td>'
      + '<td class="mono">' + esc(c.ports) + '</td>'
      + '<td>' + esc(clipText(c.processes, 110)) + '</td></tr>');
  }
  var body = el('invBody');
  if (body) { body.innerHTML = rows.join(''); }
  if (el('invTable')) { el('invTable').style.display = rows.length ? '' : 'none'; }
  if (el('invEmpty')) { el('invEmpty').style.display = rows.length ? 'none' : ''; }
  if (el('invCount')) { el('invCount').innerHTML = S.inv.conns.length + ' / ' + (m.peers || 0) + ' PEERS'; }
  var fb = el('invFindings');
  if (fb) {
    fb.innerHTML = S.inv.findings.length ? findingRows(S.inv.findings, 'data-ifind')
      : '<div class="empty small" id="invFindEmpty">NO THREAT FINDINGS</div>';
  }
  if (el('invFindCount')) { el('invFindCount').innerHTML = String(S.inv.findings.length); }
  var lb = el('invListen');
  if (lb) {
    if (!S.inv.listen.length) {
      lb.innerHTML = '<div class="empty small">RUN THE INVESTIGATION TO LIST LISTENING PORTS</div>';
    } else {
      var lh = [];
      for (var j = 0; j < S.inv.listen.length; j++) {
        var l = S.inv.listen[j];
        var sens = [21, 23, 135, 139, 445, 3389, 5900, 5985, 5986].indexOf(Number(l.port)) >= 0;
        lh.push('<div class="lrow' + (sens ? ' sens' : '') + '"><span class="mono">' + esc(l.address) + ':' + esc(l.port) + '</span>'
          + '<span>' + esc(l.service || 'tcp') + '</span><span>' + esc(l.owner) + ' (' + esc(l.pid) + ')</span></div>');
      }
      lb.innerHTML = lh.join('');
    }
    if (el('invListenCount')) { el('invListenCount').innerHTML = String(S.inv.listen.length); }
  }
}

function showPeerDetail(ip) {
  var rows = [];
  for (var i = 0; i < S.inv.conns.length; i++) {
    if (S.inv.conns[i].ip === ip) { rows.push(S.inv.conns[i]); }
  }
  if (!rows.length) { return; }
  var r = rows[0];
  var html = kvHtml([
    ['PEER', r.ip], ['MAC', r.mac], ['SCOPE', r.private ? 'private' : 'public'],
    ['FLOWS', r.conns], ['PORTS', r.ports], ['STATES', r.states], ['PROCESSES', r.processes]
  ]);
  html += '<div class="mlabel">NEXT CHECKS</div><div class="msteps">'
    + '<div class="mstep">Open Task Manager and confirm the owning process and command line.</div>'
    + '<div class="mstep">Review the egress firewall and DNS filter for this destination.</div>'
    + '<div class="mstep">Preserve the event evidence before changing anything.</div></div>';
  showModal({ title: 'PEER ' + ip, kicker: 'NETWORK EVIDENCE', sev: r.private ? 'med' : 'high', html: html,
    note: 'NetTruder never blocks or modifies a host from this view. Use the firewall console for enforcement.' });
}

/* ------------------------------ network -------------------------------- */
function netLiveStateText() {
  var last = S.net.samples.length ? S.net.samples[S.net.samples.length - 1] : null;
  var tick = last && last.tick !== undefined ? Number(last.tick) : 0;
  return 'LIVE 30s // CYCLE ' + S.net.liveCycle + ' // TICK ' + tick;
}

function netLiveUi() {
  var l = el('btnNetLive'), x = el('btnNetStop'), s = el('netState'), card = el('netSumm');
  var live = !!S.net.live;
  var running = !!(S.streams.netinv && !S.streams.netinv.done);
  if (l) {
    l.className = live ? 'btn liveon' : 'btn';
    l.innerHTML = live ? 'LIVE ON' : 'LIVE 30s';
    l.title = live ? 'Live refresh is on. Click to stop automatic 30s refresh.'
      : 'Start automatic read-only refresh every 30 seconds.';
  }
  if (x) { x.disabled = !live && !running; }
  if (s) { s.className = live ? 'micro liveon' : 'micro'; }
  if (card) { card.className = 'card ressumm' + (live ? ' liveon' : ''); }
  S.net.dirty = true;
  renderNet();
}

function startNetLiveCycle() {
  if (!S.net.live) { return; }
  if (S.streams.netinv && !S.streams.netinv.done) { return; }
  S.net.liveCycle++;
  S.net.liveLastStart = new Date().getTime();
  if (el('netState')) { el('netState').innerHTML = 'LIVE 30s // CYCLE ' + S.net.liveCycle + ' // STARTING'; }
  var st = runNetInventory(30, true);
  if (st && st.done) {
    setNetBusy(false);
    pushConsole('err', 'Live cycle could not start. Automatic refresh is off.', 'netinv');
    stopNetLive(false);
  }
}

function netLiveWatchdog() {
  if (!S.net.live || !S.net.liveLastStart) { return; }
  var st = S.streams.netinv;
  var now = new Date().getTime();
  if (st && !st.done) {
    if (now - st.started > 50000) {
      pushConsole('err', 'Live cycle exceeded 50s. Stopping automatic refresh; collected rows remain visible.', 'netinv');
      stopNetLive(true);
    }
    return;
  }
  if (now - S.net.liveLastStart > 50000) {
    pushConsole('err', 'Live cycle did not report completion. Stopping automatic refresh.', 'netinv');
    stopNetLive(false);
  }
}

function startNetLive() {
  S.net.live = true;
  S.net.liveCycle = 0;
  S.net.pendingSnapshot = false;
  netLiveUi();
  pushConsole('ok', 'Live refresh armed. NETWORK will repeat a read-only 30s connection sample until stopped. No packets or payloads are captured.', 'netinv');
  startNetLiveCycle();
}

function stopNetLive(abort) {
  if (!S.net.live) { return; }
  var st = S.streams.netinv;
  S.net.live = false;
  S.net.pendingSnapshot = false;
  netLiveUi();
  if (abort && st && !st.done) {
    try { writeText(S.runs + '\\' + st.id + '.stop', '1'); } catch (e) { }
    pushConsole('warn', 'Live refresh stopped. Collected rows remain visible.', 'netinv');
  } else {
    pushConsole('dim', 'Live refresh stopped.', 'netinv');
  }
  if (el('netState')) { el('netState').innerHTML = 'LIVE STOPPED'; }
}

function runNetInventory(liveSec, fromLive) {
  if (!fromLive && S.net.live) {
    S.net.live = false;
    S.net.pendingSnapshot = (Number(liveSec) || 0) === 0;
    netLiveUi();
    pushConsole('dim', 'Live refresh stopped for a manual inventory.', 'netinv');
  }
  if (S.streams.netinv && !S.streams.netinv.done) { return; }
  var s = Number(liveSec) || 0;
  if (s > 120) { s = 120; }
  if (s < 0) { s = 0; }
  var hist = !!(el('netHistory') && el('netHistory').checked);
  setNetBusy(true);
  if (el('netState')) {
    el('netState').innerHTML = (fromLive && S.net.live) ? netLiveStateText()
      : (s > 0 ? ('SAMPLING ' + s + 's') : 'COLLECTING');
  }
  pushConsole('dim', s > 0
    ? ('Live connection sampling for ' + s + ' seconds. No packets or payloads. No live DNS lookup unless browser history is opted in.')
    : 'Read-only network inventory: sockets, owners, adapters, routes and DNS cache.', 'netinv');
  if (fromLive && S.net.live) {
    pushConsole('dim', 'Refresh cycle ' + S.net.liveCycle + ' started. The view is replaced when each 30s window completes.', 'netinv');
  }
  if (hist) { pushConsole('warn', 'Browser history opt-in is enabled for this run. Local history is read only and matched by host or resolved IP; up to 24 read-only A-record lookups may be used.', 'netinv'); }
  return startStream('netinv', 'netinv', { sampleSec: s, intervalSec: 2, maxFlows: 400, browserHistory: hist });
}

function setNetBusy(busy) {
  var b = el('btnNetRun'), l = el('btnNetLive'), x = el('btnNetStop');
  if (b) { b.disabled = !!busy && !S.net.live; }
  if (l) { l.disabled = !!busy && !S.net.live; }
  if (x) { x.disabled = !busy && !S.net.live; }
  netLiveUi();
}

function netNodeId(f) {
  if (!f) { return ''; }
  return 'p' + String(f.pid);
}

function netRemoteId(f) {
  if (!f || !f.remoteAddr || f.remoteAddr === '-') { return ''; }
  return 'r' + String(f.remoteAddr + '-' + f.remotePort).replace(/[^A-Za-z0-9]/g, '_');
}

function netFlowById(id) {
  for (var i = 0; i < S.net.flows.length; i++) {
    if (S.net.flows[i].id === id) { return S.net.flows[i]; }
  }
  return null;
}

function netRowHtml(f, ix, attr, showUrl) {
  var inbound = f.dir === 'inbound' || f.dir === 'listen' || f.dir === 'recent';
  var cl = f.cls === 'browser' ? 'b' : (f.cls === 'system' ? 's' : 'g');
  var host = f.host ? '<span class="hostname">' + esc(clipText(f.host, 24)) + '</span>' : '';
  var endpoint = '<td class="mono">' + esc(clipText(f.remote, 28)) + host + '</td>';
  if (showUrl) {
    var u = f.url || f.derivedUrl || f.remote || '-';
    var hist = f.urlSource === 'browser-history';
    var src = hist ? 'HISTORY' : 'HOST ONLY';
    endpoint = '<td class="mono"><span class="neturl" title="' + esc(u) + '">' + esc(u) + '</span>'
      + '<span class="neturlsrc' + (hist ? ' history' : '') + '">' + src + '</span>'
      + '<span class="netendpoint">' + esc(clipText(f.remote, 24)) + '</span></td>';
  }
  return '<tr class="nt-' + cl + '" data-' + attr + '="' + ix + '">'
    + '<td><span class="netdir ' + (inbound ? 'in' : 'out') + '">' + esc(String(f.dir || '').toUpperCase()) + '</span></td>'
    + '<td class="mono">' + esc(f.proto) + '</td>'
    + '<td class="mono">' + esc(clipText(f.local, 24)) + '</td>'
    + endpoint
    + '<td>' + esc(clipText(f.name || ('pid ' + f.pid), 18)) + '</td>'
    + '<td class="mono">' + esc(f.state) + '</td>'
    + '<td class="mono">' + esc(f.samples) + '</td></tr>';
}

function netTransport(f) {
  if (!f) { return ''; }
  if (f.dir === 'inbound') {
    return 'ARRIVAL: ' + f.remote + ' contacted the local listener ' + f.local + '. '
      + 'The socket is owned by ' + (f.name || ('pid ' + f.pid)) + '. The matching route and adapter are listed under PATHS.';
  }
  if (f.dir === 'listen') {
    return 'ARRIVAL PATH: ' + f.name + ' is bound to ' + f.local + ' and is waiting for inbound connections. No session is open yet.';
  }
  if (f.dir === 'udp') {
    return 'DATAGRAMS: ' + f.name + ' holds a UDP endpoint at ' + f.local + '. UDP has no connection state, '
      + 'so the remote side is not reported by this read-only view.';
  }
  if (f.dir === 'recent') {
    return 'RECENT SOCKET: ' + f.local + ' to ' + f.remote + ' was seen in a closing or wait state. '
      + 'It is evidence of a completed transfer, not a live session.';
  }
  return 'EGRESS: ' + f.name + ' sent from ' + f.local + ' to ' + f.remote
    + (f.host ? ' (cached name ' + f.host + ')' : '') + '. '
    + 'Routing uses the most specific local route for the remote address; see PATHS for adapters and gateways.';
}

function netGraphOptions(wrapId) {
  var w = el(wrapId) ? el(wrapId).clientWidth : 0;
  return {
    cw: 268, ch: 80, padX: 24, padY: 22, nodeW: 228, nodeH: 56,
    fontA: 12, fontB: 11, clipA: 28, clipB: 34, lineW: 1.7, availW: w
  };
}

function netBrowserNodeId(f) {
  if (!f) { return ''; }
  return 'bp' + String(f.pid);
}

function netBrowserRemoteId(f) {
  if (!f || !f.remoteAddr || f.remoteAddr === '-') { return ''; }
  return 'br' + String(f.remoteAddr + '-' + f.remotePort).replace(/[^A-Za-z0-9]/g, '_');
}

function renderNet() {
  S.net.dirty = false;
  var m = S.net.meta || {};
  var hs = S.net.historyMeta || {};
  var flows = S.net.flows || [];
  if (el('netState') && S.net.live) { el('netState').innerHTML = netLiveStateText(); }
  var browser = [], background = [], systemFlows = [], i;
  for (i = 0; i < flows.length; i++) {
    if (flows[i].cls === 'browser') { browser.push(flows[i]); }
    else if (flows[i].cls === 'system') { systemFlows.push(flows[i]); }
    else { background.push(flows[i]); }
  }

  var summ = el('netSumm');
  if (summ) {
    var last = S.net.samples.length ? S.net.samples[S.net.samples.length - 1] : null;
    var ticks = last && last.tick !== undefined ? Number(last.tick) : (Number(m.ticks) || 0);
    var htext = hs.enabled ? ('HISTORY ' + String(hs.status || '') + ' / ' + (Number(hs.rows) || 0)
      + ' / RESOLVED ' + (Number(hs.resolved) || 0)) : 'HOST URLS ONLY';
    summ.innerHTML = '<span class="rsum"><b>FLOWS</b>' + flows.length + '</span>'
      + '<span class="rsum"><b>BROWSER</b>' + browser.length + '</span>'
      + '<span class="rsum"><b>BACKGROUND</b>' + background.length + '</span>'
      + '<span class="rsum"><b>SYSTEM</b>' + systemFlows.length + '</span>'
      + '<span class="rsum"><b>FINDINGS</b>' + S.net.findings.length + '</span>'
      + (S.net.live ? '<span class="rsum live">LIVE 30s</span>' : '')
      + '<span class="rsum dim">SAMPLES ' + ticks + ' // ' + htext + ' // READ-ONLY</span>';
  }
  if (el('netGraphCount')) { el('netGraphCount').innerHTML = S.net.nodes.length + ' NODES / ' + S.net.edges.length + ' LINKS'; }
  if (el('netBrowserGraphCount')) { el('netBrowserGraphCount').innerHTML = S.net.browserNodes.length + ' NODES / ' + S.net.browserEdges.length + ' LINKS'; }
  if (el('netFindCount')) { el('netFindCount').innerHTML = String(S.net.findings.length); }
  if (el('netBrowserCount')) { el('netBrowserCount').innerHTML = browser.length + ' FLOWS'; }
  if (el('netBgCount')) { el('netBgCount').innerHTML = background.length + ' FLOWS'; }

  var filter = el('netFilter') ? el('netFilter').value : '';
  var sel = netFlowById(S.net.selected);
  var g = el('netGraph');
  if (g) {
    var html = graphSvgHtml(S.net.nodes, S.net.edges, sel ? netNodeId(sel) : '', filter, netGraphOptions('netWrap'));
    g.innerHTML = html;
    if (el('netEmpty')) { el('netEmpty').style.display = html ? 'none' : ''; }
  }
  var bg = el('netBrowserGraph');
  if (bg) {
    var bhtml = graphSvgHtml(S.net.browserNodes, S.net.browserEdges, sel ? netBrowserNodeId(sel) : '', filter, netGraphOptions('netBrowserWrap'));
    bg.innerHTML = bhtml;
    if (el('netBrowserEmpty')) { el('netBrowserEmpty').style.display = bhtml ? 'none' : ''; }
  }

  var f = String(filter).toLowerCase().replace(/^\s+|\s+$/g, '');
  var bh = [], gh = [], bi = 0, gi = 0;
  for (i = 0; i < flows.length; i++) {
    var row = flows[i];
    var hay = String([row.local, row.remote, row.host, row.name, row.owner, row.proto,
      row.dir, row.state, row.path, row.url, row.urlSource, row.urlTitle].join(' ')).toLowerCase();
    if (f && hay.indexOf(f) < 0) { continue; }
    if (row.cls === 'browser') { bh.push(netRowHtml(row, i, 'nflow', true)); bi++; }
    else { gh.push(netRowHtml(row, i, 'nflow', false)); gi++; }
  }
  var bb = el('netBrowserBody');
  if (bb) {
    bb.innerHTML = bi ? ('<table class="ntable"><thead><tr><th>DIR</th><th>PROTO</th><th>LOCAL</th>'
      + '<th>URL / ENDPOINT</th><th>PROCESS</th><th>STATE</th><th>N</th></tr></thead><tbody>'
      + bh.join('') + '</tbody></table>')
      : '<div class="empty small">NO BROWSER FLOWS MATCH THIS FILTER</div>';
  }
  var gb = el('netBgBody');
  if (gb) {
    gb.innerHTML = gi ? ('<table class="ntable"><thead><tr><th>DIR</th><th>PROTO</th><th>LOCAL</th>'
      + '<th>REMOTE / NAME</th><th>PROCESS</th><th>STATE</th><th>N</th></tr></thead><tbody>'
      + gh.join('') + '</tbody></table>')
      : '<div class="empty small">NO BACKGROUND FLOWS MATCH THIS FILTER</div>';
  }
  if (el('netShown')) { el('netShown').innerHTML = bi + ' BROWSER / ' + gi + ' OTHER SHOWN'; }
  renderNetDetail();

  if (m.policy && el('netState') && el('netState').innerHTML === 'NO DATA') {
    el('netState').innerHTML = flows.length + ' FLOWS';
  }
}

function netDetailRows(f) {
  if (!f) { return []; }
  return [
    ['DIRECTION', String(f.dir || '').toUpperCase(), 'mono'],
    ['PROTOCOL', f.proto, 'mono'],
    ['FLOW CLASS', f.cls === 'browser' ? 'BROWSER WEB FLOWS' : (f.cls === 'system' ? 'SYSTEM FLOWS' : 'BACKGROUND FLOWS')],
    ['URL', f.url || f.derivedUrl || 'NOT AVAILABLE', 'mono'],
    ['URL SOURCE', f.urlSource === 'browser-history' ? 'BROWSER HISTORY (OPT-IN)' : 'DERIVED FROM DNS CACHE / SOCKET', 'mono'],
    ['HISTORY TITLE', f.urlTitle, 'mono'],
    ['LOCAL ENDPOINT', f.local, 'mono'],
    ['REMOTE ENDPOINT', f.remote, 'mono'],
    ['CACHED NAME', f.host, 'mono'],
    ['HISTORY HOST', f.urlHost, 'mono'],
    ['RECENT URLS FOR THIS IP', f.urlCandidates && f.urlCandidates.length ? f.urlCandidates.join(' | ') : '', 'mono'],
    ['PORT NAME', f.portName, 'mono'],
    ['SCOPE', f.private ? 'PRIVATE / RFC1918' : (f.remote === '-' ? 'LOCAL' : 'PUBLIC OR NON-RFC1918')],
    ['SOCKET STATE', f.state, 'mono'],
    ['PROCESS', f.name || 'NOT READABLE'],
    ['PID', f.pid, 'mono'],
    ['OWNER', f.owner, 'mono'],
    ['PARENT PID', f.parent, 'mono'],
    ['PATH', f.path, 'mono'],
    ['COMMAND (MASKED)', f.cmd, 'mono'],
    ['FIRST SEEN', f.firstSeen, 'mono'],
    ['LAST SEEN', f.lastSeen, 'mono'],
    ['SAMPLES', f.samples, 'mono'],
    ['HOW IT IS SENT / ARRIVES', netTransport(f)],
    ['WHY THIS MATTERS', f.why],
    ['HOW TO CHECK / FIX', f.fix],
    ['EVIDENCE SOURCE', f.evidence, 'mono']
  ];
}

function renderNetDetail() {
  var box = el('netDetail');
  if (!box) { return; }
  var rows = netDetailRows(netFlowById(S.net.selected));
  box.innerHTML = rows.length ? kvHtml(rows) : '<div class="empty small">CLICK A NODE, A FLOW ROW OR A FINDING</div>';
}

function showNetDetail() {
  var f = netFlowById(S.net.selected);
  if (!f) {
    showModal({ title: 'NO FLOW SELECTED', kicker: 'SELECT FIRST', sev: 'ok',
      detail: 'Click a flow row or a graph node first, then open the detail card.',
      note: DEFAULT_REMEDY_NOTE });
    return;
  }
  var rows = netDetailRows(f);
  var copy = [];
  for (var i = 0; i < rows.length; i++) { copy.push(rows[i][0] + ': ' + rows[i][1]); }
  var h = [kvHtml(rows)];
  h.push('<div class="row buttons"><button class="btn small" data-nact="tm">TASK MANAGER</button>'
    + '<button class="btn small" data-nact="fw">FIREWALL</button></div>');
  showModal({
    title: 'SELECTED FLOW', kicker: String(f.name || ('pid ' + f.pid)), sev: 'ok',
    html: h.join(''), copyText: copy.join('\r\n'), note: DEFAULT_REMEDY_NOTE
  });
}

function showNetFindings() {
  var h = S.net.findings.length ? findingRows(S.net.findings, 'data-nfind')
    : '<div class="empty small">NO NETWORK FINDINGS // RUN THE INVENTORY</div>';
  showModal({
    title: 'NETWORK FINDINGS', kicker: String(S.net.findings.length) + ' REVIEW TRIGGERS', sev: 'ok',
    html: h, copyText: 'findings=' + S.net.findings.length, note: DEFAULT_REMEDY_NOTE
  });
}

function netDetailAction(a) {
  if (a === 'tm') { openTool('taskmgr.exe'); return true; }
  if (a === 'fw') { openTool('wf.msc'); return true; }
  return false;
}

function showNetBrowserSummary() {
  var hs = S.net.historyMeta || {};
  var browser = 0, i;
  for (i = 0; i < S.net.flows.length; i++) {
    if (S.net.flows[i].cls === 'browser') { browser++; }
  }
  var rows = [
    ['BROWSER FLOWS', browser, 'mono'],
    ['BROWSER GRAPH NODES', S.net.browserNodes.length, 'mono'],
    ['HISTORY OPT-IN', hs.enabled ? 'YES' : 'NO', 'mono'],
    ['HISTORY STATUS', hs.status || 'NOT REQUESTED', 'mono'],
    ['HISTORY ROWS', hs.rows || 0, 'mono'],
    ['HOSTS RESOLVED', hs.resolved || 0, 'mono']
  ];
  showModal({
    title: 'BROWSER NETWORK GRAPH', kicker: 'SEPARATE BROWSER CLASS', sev: 'ok',
    html: kvHtml(rows),
    detail: 'This graph contains only browser processes and the URLs or endpoints they contacted. Host-only URLs are always derived from the socket and DNS cache; full URLs appear only when history is opted in for that run, including bounded DNS resolution of recent history hosts when the Windows cache is empty.',
    note: 'NetTruder never changes a browser profile. History, when enabled, is read-only and matched by host or resolved IP only.'
  });
}

function showNetHistoryNotice() {
  showModal({
    title: 'BROWSER HISTORY OPT-IN', kicker: 'READ ONLY', sev: 'med',
    detail: 'This run may read local Edge, Chrome, Brave, Vivaldi and Firefox history databases in SQLite read-only mode. Full URLs and titles can be attached to browser flows when their host matches a live socket, or when a bounded read-only DNS lookup shows that the history host resolves to the socket IP. No profile file is copied, changed or deleted.',
    fix: [
      'Leave the checkbox unchecked for host-only URLs derived from sockets and the DNS cache.',
      'Check it only when full browser URLs are needed for this investigation.',
      'The opt-in also permits up to 24 read-only A-record lookups for recent history hosts when the Windows DNS cache is empty.',
      'Uncheck it again after the run; the choice applies to the next inventory only.'
    ],
    note: 'This is an explicit privacy opt-in. NetTruder does not transmit, copy or modify browser history; it only displays matching host URLs in the current run data.'
  });
}

function showNetPaths() {
  var m = S.net.meta || {};
  var h = [];
  h.push('<div class="mlabel">ADAPTERS / HOW TRAFFIC LEAVES AND ARRIVES</div>');
  if (!S.net.adapters.length) {
    h.push('<div class="empty small">NO ADAPTER DATA CAPTURED</div>');
  } else {
    h.push('<table class="ntable"><thead><tr><th>ADAPTER</th><th>IPV4</th><th>GATEWAY</th><th>DNS</th><th>MAC</th><th>STATUS</th></tr></thead><tbody>');
    for (var i = 0; i < S.net.adapters.length; i++) {
      var a = S.net.adapters[i];
      h.push('<tr><td class="mono">' + esc(a.name) + '</td><td class="mono">' + esc(a.ipv4) + '/' + esc(a.prefix) + '</td>'
        + '<td class="mono">' + esc(a.gateway) + '</td><td class="mono">' + esc(a.dns) + '</td>'
        + '<td class="mono">' + esc(a.mac) + '</td><td>' + esc(a.status) + '</td></tr>');
    }
    h.push('</tbody></table>');
  }
  h.push('<div class="mlabel">ROUTES / WHERE THE NEXT HOP IS</div>');
  if (!S.net.routes.length) {
    h.push('<div class="empty small">NO ROUTE DATA CAPTURED ON THIS HOST</div>');
  } else {
    h.push('<table class="ntable"><thead><tr><th>DESTINATION</th><th>NEXT HOP</th><th>INTERFACE</th><th>METRIC</th><th>SCOPE</th></tr></thead><tbody>');
    for (var j = 0; j < S.net.routes.length; j++) {
      var r = S.net.routes[j];
      h.push('<tr><td class="mono">' + esc(r.destination) + '</td><td class="mono">' + esc(r.gateway) + '</td>'
        + '<td>' + esc(r.interface) + '</td><td class="mono">' + esc(r.metric) + '</td><td>' + esc(r.scope) + '</td></tr>');
    }
    h.push('</tbody></table>');
  }
  showModal({
    title: 'PATHS AND INTERFACES', kicker: 'HOW TRAFFIC IS SENT', sev: 'ok', html: h.join(''),
    copyText: 'adapters=' + S.net.adapters.length + ' routes=' + S.net.routes.length
      + ' sampleSec=' + (Number(m.sampleSec) || 0),
    note: 'Adapter and route rows are read from the local routing table. Nothing is changed. '
      + DEFAULT_REMEDY_NOTE
  });
}

function showNetRecipe() {
  var recipe = (S.net.meta && S.net.meta.pktmon) ? S.net.meta.pktmon
    : 'OPTIONAL PACKET CAPTURE (administrator, run it yourself): pktmon start --etw -c 2 -p 0 ; pktmon filter add -p 443 ; reproduce the traffic ; pktmon stop ; pktmon etw2net C:\\Temp\\NtCapture.etl . NetTruder never runs pktmon, installs drivers or reads payloads.';
  showModal({
    title: 'OPTIONAL PACKET CAPTURE', kicker: 'MANUAL RECIPE', sev: 'ok',
    detail: 'NetTruder only reads connection metadata. For packet-level detail, an administrator can run this recipe manually outside NetTruder. Review the output on your own system and keep captures in an approved location.',
    fix: [
      'Open an elevated PowerShell window yourself. NetTruder does not launch it.',
      'Run: pktmon start --etw -c 2 -p 0',
      'Add only the filters you need, for example: pktmon filter add -p 443',
      'Reproduce the traffic, then run: pktmon stop',
      'Convert with: pktmon etw2net C:\\Temp\\NtCapture.etl .',
      'Keep the ETL and converted file under access control. They can contain sensitive metadata.'
    ],
    copyText: recipe,
    note: 'Do not use this on networks you are not authorised to observe. Never disable or bypass security tooling to collect traffic.'
  });
  pushConsole('dim', 'Opened the manual pktmon recipe. NetTruder never launches pktmon or reads the capture.', 'netinv');
}

function showNetLegend() {
  showModal({
    title: 'HOW TO READ NETWORK', kicker: 'CONNECTION INVENTORY', sev: 'ok',
    detail: 'The graph is local host -> owning process -> remote endpoint. Colours classify flows, not severity. Blue is browser web traffic, orange is background applications, green is system services and purple is a remote endpoint.',
    fix: [
      'Direction is inferred from the local listening-port set: LISTEN is an arrival path, INBOUND means a peer contacted a local listener, OUTBOUND means a local process opened the connection.',
      'Names come from the local DNS cache. A blank name is a visibility gap, not proof of a direct-IP connection. With browser history opted in, up to 24 read-only A-record lookups may pair a history host with an IP-only socket.',
      'UDP has no connection state; only the local bind and owner are measured.',
      'Use RUN INVENTORY for a snapshot or LIVE 30s for bounded sampling. Both are read-only and never inspect payloads.',
      'Findings are review triggers with remediation. NetTruder never changes a firewall, DNS setting or security control from this view.'
    ],
    note: DEFAULT_REMEDY_NOTE
  });
}

/* -------------------------------- triage ------------------------------- */
function runTriage(itemId, decision) {
  if (S.streams.triage && !S.streams.triage.done) { return; }
  S.triage.items = []; S.triage.svcs = []; S.triage.plan = []; S.triage.lastAction = false;
  var path = el('triagePath') ? el('triagePath').value : '';
  var args = { path: path };
  if (itemId && decision) { args.itemId = itemId; args.decision = decision; }
  if (el('btnTriageRun')) { el('btnTriageRun').disabled = true; }
  if (el('triageState')) { el('triageState').innerHTML = decision ? 'SAVING' : 'READING'; }
  pushConsole('dim', decision ? 'Saving a local triage decision. Upstream alerts are not changed.' : 'Building a local alert board from exported data.', 'triage');
  startStream('triage', 'triage', args);
}

function renderTriage() {
  S.triage.dirty = false;
  var summ = el('triageSumm');
  if (summ) {
    summ.innerHTML = '<span class="rsum"><b>ALERTS</b>' + S.triage.items.length + '</span>'
      + '<span class="rsum"><b>SERVICES</b>' + S.triage.svcs.length + '</span>'
      + '<span class="rsum dim">LOCAL BOARD // DECISIONS ARE RECORDED HERE, NEVER PUSHED UPSTREAM</span>';
  }
  if (el('triageCount')) { el('triageCount').innerHTML = String(S.triage.items.length); }
  var bb = el('triageBoard');
  if (bb) {
    if (!S.triage.items.length) {
      bb.innerHTML = '<div class="empty small" id="triageEmpty">NO ALERT EXPORT // DROP triage-*.json IN THE NETTRUDER DATA FOLDER</div>';
    } else {
      var h = [];
      for (var i = 0; i < S.triage.items.length; i++) {
        var it = S.triage.items[i];
        h.push('<div class="titem sev-' + sevCls(it.sev) + '">');
        h.push('<div class="thead"><span class="tsev">' + esc(sevCls(it.sev).toUpperCase()) + '</span><b>' + esc(it.title) + '</b><span class="tscore">' + esc(it.score) + ' pts</span></div>');
        h.push('<div class="tdetail">' + esc(it.service) + ' / ' + esc(it.env || '-') + ' / ' + esc(it.count) + ' hit(s) / ' + esc(it.ageMin) + ' min old'
          + (it.decision ? ' / DECISION ' + esc(it.decision.toUpperCase()) : '') + '</div>');
        if (it.note) { h.push('<div class="tdetail">' + esc(clipText(it.note, 180)) + '</div>'); }
        if (it.runbook) { h.push('<div class="tdetail">' + esc(it.runbook) + '</div>'); }
        h.push('<div class="tacts">'
          + '<button class="tact" data-act="ack" data-id="' + esc(it.id) + '">ACK</button>'
          + '<button class="tact" data-act="suppress" data-id="' + esc(it.id) + '">SUPPRESS</button>'
          + '<button class="tact" data-act="resolve" data-id="' + esc(it.id) + '">RESOLVE</button>'
          + '<button class="tact" data-act="reopen" data-id="' + esc(it.id) + '">REOPEN</button>'
          + '<button class="tact primary" data-act="route" data-kind="' + esc(it.service) + '">RESEARCH</button>'
          + '</div></div>');
      }
      bb.innerHTML = h.join('');
    }
  }
  var pb = el('triagePlan');
  if (pb) {
    if (!S.triage.plan.length) {
      pb.innerHTML = '<div class="empty small">RUN THE BOARD TO BUILD A PLAN</div>';
    } else {
      var ph = [];
      for (var j = 0; j < S.triage.plan.length; j++) {
        var p = S.triage.plan[j];
        ph.push('<div class="pitem" data-kind="' + esc(p.research || '') + '"><b>' + esc(p.kind || 'PLAN') + '</b>'
          + '<div>' + esc(p.text) + '</div><span class="micro">CLICK TO ROUTE TO RESEARCH</span></div>');
      }
      pb.innerHTML = ph.join('');
    }
  }
}

function routeResearch(kind) {
  var k = String(kind || '').toLowerCase();
  var view = 'research';
  if (k.indexOf('lateral') >= 0 || k.indexOf('egress') >= 0 || k.indexOf('dns') >= 0) { view = 'threats'; }
  else if (k.indexOf('process') >= 0 || k.indexOf('injection') >= 0) { view = 'flow'; }
  else if (k.indexOf('av') >= 0 || k.indexOf('block') >= 0) { view = 'av'; }
  else if (k.indexOf('data') >= 0 || k.indexOf('secret') >= 0) { view = 'data'; }
  else if (k.indexOf('web') >= 0 || k.indexOf('owasp') >= 0) { view = 'web'; }
  else if (k.indexOf('code') >= 0 || k.indexOf('runbook') >= 0) { view = 'code'; }
  showView(view);
  showHint('Routed from triage to ' + view.toUpperCase() + '. Topic: ' + (kind || 'research') + '. Research rows always explain the gap and the remediation.');
}

/* ------------------------------- exposure ------------------------------ */
function runAv() {
  if (S.streams.av && !S.streams.av.done) { return; }
  S.av.meta = null; S.av.products = []; S.av.events = []; S.av.findings = [];
  if (el('btnAvRun')) { el('btnAvRun').disabled = true; }
  if (el('avState')) { el('avState').innerHTML = 'REVIEWING'; }
  pushConsole('dim', 'Endpoint block review - a block is a control success, not a failure.', 'av');
  startStream('av', 'av', {});
}

function renderAv() {
  S.av.dirty = false;
  var m = S.av.meta || {};
  var summ = el('avSumm');
  if (summ) {
    summ.innerHTML = '<span class="rsum good"><b>EVENTS</b>' + S.av.events.length + '</span>'
      + '<span class="rsum"><b>PRODUCTS</b>' + S.av.products.length + '</span>'
      + '<span class="rsum warn"><b>NOTES</b>' + S.av.findings.length + '</span>'
      + '<span class="rsum dim"><b>REGISTER</b>' + (m.register || 0) + '</span>'
      + '<span class="rsum dim">' + esc(clipText(m.policy || 'A BLOCK IS A CONTROL SUCCESS', 120)) + '</span>';
  }
  if (el('avEventCount')) { el('avEventCount').innerHTML = String(S.av.events.length); }
  var eb = el('avEvents');
  if (eb) {
    if (!S.av.events.length) {
      eb.innerHTML = '<div class="empty small" id="avEventEmpty">NO READABLE BLOCK EVENTS // RUN THE REVIEW</div>';
    } else {
      var eh = [];
      for (var i = 0; i < S.av.events.length; i++) {
        var e = S.av.events[i];
        eh.push('<div class="aevent" data-aevent="' + i + '">'
          + '<div class="thead"><span class="tid">' + esc(e.product) + ' / ' + esc(e.eventId) + '</span><span class="tsev">' + esc(e.action) + '</span></div>'
          + '<div class="tdetail">' + esc(e.at) + (e.file ? ' / ' + esc(e.file) : '') + (e.user ? ' / ' + esc(e.user) : '') + '</div>'
          + '<div class="tdetail">' + esc(clipText(e.detail, 220)) + '</div></div>');
      }
      eb.innerHTML = eh.join('');
    }
  }
  var pbox = el('avProducts');
  if (pbox) {
    if (!S.av.products.length) {
      pbox.innerHTML = '<div class="empty small">NO PRODUCT DATA</div>';
    } else {
      var ph = [];
      for (var j = 0; j < S.av.products.length; j++) {
        var p = S.av.products[j];
        ph.push('<div class="aproduct"><b>' + esc(p.name) + '</b>'
          + kvHtml([['SERVICE', p.service], ['REALTIME', p.realtime], ['TAMPER', p.tamper], ['LOG', p.log], ['NOTE', p.note]]) + '</div>');
      }
      pbox.innerHTML = ph.join('');
    }
    if (el('avProductCount')) { el('avProductCount').innerHTML = String(S.av.products.length); }
  }
  var gbox = el('avGaps');
  if (gbox) {
    gbox.innerHTML = S.av.findings.length ? findingRows(S.av.findings, 'data-avfind')
      : '<div class="empty small">NO GAPS RECORDED</div>';
    if (el('avGapCount')) { el('avGapCount').innerHTML = String(S.av.findings.length); }
  }
}

/* --------------------------------- data -------------------------------- */
function runDataCheck() {
  if (S.streams.data && !S.streams.data.done) { return; }
  var path = el('dataPath') ? el('dataPath').value : '';
  S.data.meta = null; S.data.cats = []; S.data.files = []; S.data.findings = []; S.data.purge = [];
  if (el('btnDataRun')) { el('btnDataRun').disabled = true; }
  if (el('dataState')) { el('dataState').innerHTML = 'CLASSIFYING'; }
  pushConsole('dim', 'Read-only data classification. Pattern hits are review triggers, not a breach verdict.', 'data');
  startStream('data', 'datacheck', path ? { path: path } : {});
}

function runDataPurge(preview) {
  if (S.streams.data && !S.streams.data.done) { return; }
  S.data.purge = [];
  var days = parseInt(el('dataRetention') ? el('dataRetention').value : '30', 10) || 30;
  var audit = !!(el('chkDataAudit') && el('chkDataAudit').checked);
  var args = { retentionDays: days, includeAudit: audit, yes: !preview, ackRisk: !preview };
  if (el('btnDataPreview')) { el('btnDataPreview').disabled = true; }
  if (el('btnDataPurge')) { el('btnDataPurge').disabled = true; }
  if (el('dataState')) { el('dataState').innerHTML = preview ? 'PREVIEWING' : 'PURGING'; }
  pushConsole('warn', preview ? 'Preview only - nothing will be deleted.' : 'Confirmed purge of NetTruder-owned expired files only. Personal folders are never in scope.', 'data');
  startStream('data', 'datapurge', args);
}

function renderData() {
  S.data.dirty = false;
  var m = S.data.meta || {};
  var summ = el('dataSumm');
  if (summ) {
    summ.innerHTML = '<span class="rsum"><b>FILES</b>' + (m.files || 0) + '</span>'
      + '<span class="rsum"><b>BYTES</b>' + fmtBytes(m.bytes) + '</span>'
      + '<span class="rsum"><b>CATEGORIES</b>' + S.data.cats.length + '</span>'
      + '<span class="rsum bad"><b>FINDINGS</b>' + S.data.findings.length + '</span>'
      + '<span class="rsum dim"><b>ENCRYPTION</b>' + esc(m.encryption || '-') + '</span>'
      + '<span class="rsum dim">' + esc(clipText(m.policy || 'READ-ONLY CLASSIFICATION', 110)) + '</span>';
  }
  if (el('dataCount')) { el('dataCount').innerHTML = S.data.cats.length + ' CATS / ' + S.data.files.length + ' FILES'; }
  var fb = el('dataFiles');
  if (fb) {
    var h = [];
    for (var i = 0; i < S.data.cats.length; i++) {
      var c = S.data.cats[i];
      h.push('<div class="dcat"><b>' + esc(c.name) + '</b><span class="micro">' + esc(c.files !== undefined ? c.files + ' files' : '') + ' / ' + fmtBytes(c.bytes) + '</span></div>');
    }
    for (var j = 0; j < S.data.files.length; j++) {
      var f = S.data.files[j];
      h.push('<div class="dfile"><span class="mono">' + esc(f.path) + '</span><span class="micro">' + esc(f.category) + ' / '
        + fmtBytes(f.bytes) + ' / ' + esc(f.modified) + '</span></div>');
    }
    if (S.data.purge.length) {
      h.push('<div class="mlabel">PURGE PREVIEW (NOTHING DELETED)</div>');
      for (var k = 0; k < S.data.purge.length; k++) {
        h.push('<div class="dfile"><span class="mono">' + esc(S.data.purge[k].path) + '</span><span class="micro">'
          + fmtBytes(S.data.purge[k].bytes) + ' / ' + esc(S.data.purge[k].modified) + '</span></div>');
      }
    }
    fb.innerHTML = h.length ? h.join('') : '<div class="empty small" id="dataEmpty">RUN THE DATA CHECK</div>';
  }
  var findBox = el('dataFindings');
  if (findBox) {
    findBox.innerHTML = S.data.findings.length ? findingRows(S.data.findings, 'data-dfind')
      : '<div class="empty small" id="dataFindEmpty">NO DATA FINDINGS</div>';
    if (el('dataFindCount')) { el('dataFindCount').innerHTML = String(S.data.findings.length); }
  }
}

/* ------------------------- PowerShell logging readout ------------------- */
/* Read-only view. The engine checks policy state, samples Event ID 4104 with
   attribution fields, and reads explicit control-block events. It never enables,
   disables or clears a log, and never executes a captured script block. */
function pslogDoneText(d) {
  d = d || {};
  var state = d.enabled ? ('ON / ' + (d.sampled || 0) + ' SCRIPT') : 'OFF';
  return state + ' / ' + (d.blocked || 0) + ' BLOCK';
}

function runPsLog() {
  if (S.streams.pslog && !S.streams.pslog.done) {
    pushConsole('dim', 'PowerShell logging readout is already running.', 'pslog');
    return;
  }
  S.pslog.dirty = true;
  if (el('btnPsLogRun')) { el('btnPsLogRun').disabled = true; }
  if (el('pslogState')) { el('pslogState').innerHTML = 'READING'; }
  pushConsole('dim', 'Reading 4104 attribution and control-block events. No log or policy is changed.', 'pslog');
  startStream('pslog', 'pslog', {});
}

function pslogValue(v) {
  if (v === null || v === undefined || v === '') { return 'NOT RECORDED'; }
  return String(v);
}

function pslogMetaHtml(label, value) {
  return '<div class="pslmeta"><span class="pslk">' + esc(label)
    + '</span><span class="pslv">' + esc(pslogValue(value)) + '</span></div>';
}

function pslogCopyText(rows) {
  var h = [];
  for (var i = 0; i < rows.length; i++) {
    h.push(rows[i][0] + ': ' + pslogValue(rows[i][1]));
  }
  return h.join('\r\n');
}

function pslogDetailModal(title, kicker, rows, note) {
  showModal({
    title: title,
    kicker: kicker,
    sev: 'ok',
    html: kvHtml(rows),
    copyText: pslogCopyText(rows),
    note: note || 'Read-only event detail. WHO and WHERE show only fields present in the source event.'
  });
}

function pslogEventModal(i) {
  var e = S.pslog.events[i];
  if (!e) { return; }
  var rows = [
    ['TIME', e.time], ['EVENT', e.id], ['LEVEL', e.level], ['PROVIDER', e.provider],
    ['WHO', e.who], ['WHAT', e.what], ['WHERE', e.where],
    ['SCRIPT BLOCK ID', e.scriptBlockId],
    ['MESSAGE', pslogValue(e.messageNumber) + ' OF ' + pslogValue(e.messageTotal)],
    ['PATH', e.path], ['COMPUTER', e.computer], ['PROCESS ID', e.processId],
    ['THREAD ID', e.threadId], ['USER SID', e.userId], ['LOG', e.logName],
    ['RECORD', e.recordId], ['ACTIVITY', e.activityId], ['KEYWORDS', e.keywords],
    ['OPCODE', e.opcode], ['TASK', e.task], ['VERSION', e.version],
    ['SCRIPT TEXT', e.text]
  ];
  pslogDetailModal('POWERSHELL EVENT 4104 - VERBOSE', 'READ ONLY / EXISTING EVENT', rows,
    'Read-only telemetry detail. The script text is masked and truncated. Capture is evidence, not a verdict about intent.');
}

function pslogBlockModal(i) {
  var e = S.pslog.blocks[i];
  if (!e) { return; }
  var rows = [
    ['TIME', e.time], ['EVENT', e.id], ['SOURCE', e.source], ['PRODUCT', e.product],
    ['ACTION', e.action], ['LEVEL', e.level], ['PROVIDER', e.provider],
    ['WHO', e.who], ['WHAT', e.what], ['WHERE', e.where], ['PATH', e.path],
    ['COMPUTER', e.computer], ['PROCESS ID', e.processId], ['THREAD ID', e.threadId],
    ['USER SID', e.userId], ['LOG', e.logName], ['RECORD', e.recordId],
    ['ACTIVITY', e.activityId], ['KEYWORDS', e.keywords], ['OPCODE', e.opcode],
    ['TASK', e.task], ['VERSION', e.version], ['EVENT DETAIL', e.detail]
  ];
  pslogDetailModal('BLOCKED POWERSHELL - VERBOSE', 'READ ONLY / CONTROL EVENT', rows,
    'A block is a defensive control result. NetTruder read this event only; it did not re-run or bypass the blocked action.');
}

function pslogFindModal(i) {
  var f = S.pslog.findings[i];
  if (!f) { return; }
  var state = f.state || (S.pslog.meta && S.pslog.meta.enabled ? 'ON' : 'OFF');
  showFindingRemedy({
    title: f.title || 'PS LOG FINDING',
    severity: f.sev || f.severity || 'med',
    detail: 'STATE: ' + state + '\r\n' + (f.why || '') + '\r\n' + (f.detail || ''),
    fix: asTextList(f.fix),
    control: f.control || 'TELEMETRY / 4104',
    native: f.native || ''
  });
}

function pslogEventHtml(e, i, blocked) {
  var h = [];
  h.push('<div class="pslevent" ' + (blocked ? 'data-psblock="' : 'data-psevent="') + i + '"'
    + ' title="Click for verbose details">');
  h.push('<div class="pslhead"><span class="psltime">' + esc(e.time || '-') + '</span>'
    + '<span class="pslbadge">' + esc(e.id || (blocked ? 'BLOCK' : '4104')) + '</span>'
    + '<span class="psllevel">' + esc(e.level || '-') + '</span></div>');
  h.push(pslogMetaHtml('WHO', e.who));
  h.push(pslogMetaHtml('WHAT', e.what));
  h.push(pslogMetaHtml('WHERE', e.where));
  if (blocked) { h.push(pslogMetaHtml('SOURCE', e.product + ' / ' + e.action)); }
  h.push('<div class="psltext">' + esc(blocked ? (e.detail || 'NO EVENT DETAIL') : (e.text || 'NO TEXT RETURNED')) + '</div>');
  h.push('</div>');
  return h.join('');
}

function renderPsLog() {
  S.pslog.dirty = false;
  var m = S.pslog.meta || {};
  var summ = el('pslogSumm');
  if (summ) {
    if (!S.pslog.meta) {
      summ.className = 'card ressumm';
      summ.innerHTML = '<span class="rsum dim">NO READOUT // READ-ONLY POLICY, 4104 ATTRIBUTION AND CONTROL BLOCK EVENTS</span>';
    } else {
      summ.className = 'card ressumm' + (m.enabled ? '' : ' pslogoff');
      var out = [];
      var srcRead = m.blockSourceReadable || 0;
      var srcTotal = m.blockSources ? m.blockSources.length : 0;
      out.push('<span class="rsum ' + (m.enabled ? 'good' : 'bad') + '"><b>STATE</b>'
        + (m.enabled ? 'ON' : 'OFF') + '</span>');
      out.push('<span class="rsum ' + (m.logAccessible ? 'good' : 'warn') + '"><b>LOG</b>'
        + (m.logAccessible ? 'READABLE' : 'NO ACCESS') + '</span>');
      out.push('<span class="rsum"><b>SAMPLED</b>' + (m.sampled || 0)
        + ' / ' + (m.totalSeen || 0) + '</span>');
      out.push('<span class="rsum ' + (m.blockedCount ? 'warn' : '') + '"><b>BLOCKED</b>'
        + (m.blockedCount || 0) + '</span>');
      out.push('<span class="rsum ' + (srcTotal && srcRead < srcTotal ? 'warn' : 'dim') + '"><b>BLOCK SOURCES</b>'
        + srcRead + ' / ' + srcTotal + '</span>');
      out.push('<span class="rsum dim"><b>WINDOW</b>7 DAYS / MAX 40 SCRIPT / 200 PER SOURCE</span>');
      if (m.policySource) {
        out.push('<span class="rsum dim"><b>POLICY</b>' + esc(clipText(m.policySource, 70)) + '</span>');
      }
      if (m.logError) {
        out.push('<span class="rsum bad"><b>ERROR</b>' + esc(clipText(m.logError, 70)) + '</span>');
      }
      summ.innerHTML = out.join('');
    }
  }
  var evtBox = el('pslogEvents');
  if (evtBox) {
    if (!S.pslog.events.length) {
      evtBox.innerHTML = '<div class="empty small" id="pslogEmpty">NO 4104 SAMPLES // '
        + (m.enabled ? 'NONE FOUND IN THE SAMPLED WINDOW' : 'SCRIPT BLOCK LOGGING IS OFF') + '</div>';
    } else {
      var eh = [];
      for (var i = 0; i < S.pslog.events.length; i++) {
        eh.push(pslogEventHtml(S.pslog.events[i] || {}, i, false));
      }
      evtBox.innerHTML = eh.join('');
    }
    if (el('pslogEventCount')) { el('pslogEventCount').innerHTML = String(S.pslog.events.length); }
  }
  var blockBox = el('pslogBlocks');
  if (blockBox) {
    if (!S.pslog.blocks.length) {
      blockBox.innerHTML = '<div class="empty small" id="pslogBlockEmpty">NO BLOCKED POWERSHELL EVENTS // '
        + (m.blockSourceReadable ? 'CONTROL SOURCES READABLE' : 'CONTROL SOURCES NOT EVALUATED') + '</div>';
    } else {
      var bh = [];
      for (var b = 0; b < S.pslog.blocks.length; b++) {
        bh.push(pslogEventHtml(S.pslog.blocks[b] || {}, b, true));
      }
      blockBox.innerHTML = bh.join('');
    }
    if (el('pslogBlockCount')) { el('pslogBlockCount').innerHTML = String(S.pslog.blocks.length); }
  }
  var findBox = el('pslogFindings');
  if (findBox) {
    if (!S.pslog.findings.length) {
      findBox.innerHTML = '<div class="empty small" id="pslogFindEmpty">NO STATE FINDINGS // CHECK THE SUMMARY ABOVE</div>';
    } else {
      var fh = [];
      for (var j = 0; j < S.pslog.findings.length; j++) {
        var f = S.pslog.findings[j] || {};
        fh.push('<div class="frow psfind sev-' + esc(sevCls(f.sev || f.severity)) + '" data-psfind="' + j + '"'
          + ' title="Click for state and remediation">'
          + '<span class="fsev">' + esc(hevdSevLabel(f.sev || f.severity)) + '</span>'
          + '<span class="ftitle">' + esc(f.title || 'PS LOG FINDING')
          + '<span class="psstate">' + esc(f.state || '-') + '</span></span>'
          + '<span class="fdetail">' + esc(clipText(f.why || f.detail || '', 160)) + '</span></div>');
      }
      findBox.innerHTML = fh.join('');
    }
    if (el('pslogFindCount')) { el('pslogFindCount').innerHTML = String(S.pslog.findings.length); }
  }
}

/* ------------------------------- onboarding ----------------------------- */
var VIEW_HINTS = {
  sweep: 'Start here. Derive the local subnet, run a sweep, then select a host and open a finding for remediation.',
  ids: 'IDS/IPS shows alerts and posture. Control rows are clickable: they enable, harden or open native UI. NetTruder never turns a control off.',
  flow: 'The flow map is read-only. Boxes are processes and remote endpoints; lines are parent links and connections. Click a box for its command line.',
  web: 'Enter a loopback or private URL for a passive check. Public hosts need the explicit opt-in. The graph is inferred from the response.',
  code: 'Point this at a source folder for a static review. Kernel source review and the static WinDbg guide are read-only; files are never run.',
  threats: 'Review live peers, listeners and findings. Task Manager and the firewall console are one click away.',
  triage: 'Import an exported alert file to build a local board. Decisions stay local; upstream alerts are never changed.',
  av: 'Block events are defensive results. NetTruder records them with remediation and never re-runs a blocked action.',
  data: 'Classify files, review findings, then preview any purge. Purge is limited to NetTruder-owned data and needs a second confirmation.',
  terminal: 'Terminal commands are audit-logged and still available for discovery. NetTruder will not weaken Defender or try to evade it.',
  posture: 'The posture probe checks controls and visibility read-only. Filtered admin tokens are shown separately from a real elevated token.',
  processes: 'Inspect, locate and end processes here. Task Manager, Resource Monitor and Services stay available from the same view.',
  audit: 'Audit is the local activity record. Exports stay inside the NetTruder data root.',
  research: 'Research groups techniques by platform and class, shows observed blocks and control gaps, and gives remediation for every row.',
  network: 'Network inventories sockets, owners, adapters, routes and cached names. Browser and background flows are separated. Live sampling is bounded and never captures packets.',
  pslog: 'This read-only view checks Script Block Logging, shows masked 4104 records with the WHO / WHAT / WHERE fields present in each event, and reads explicit PowerShell block events from AppLocker, WDAC/CI and Defender. Click any event for verbose detail; click a finding for state and remediation.'
};

var TOUR = [
  { view: 'sweep', title: 'SEE THE NETWORK', body: 'Discover hosts and ports first. Everything downstream - alerts, flow, web and research - can be reached from this baseline.' },
  { view: 'flow', title: 'FOLLOW THE FLOW', body: 'The n8n-style graph shows parent-to-child process links and process-to-endpoint connections. Filter by pid or name and click any node.' },
  { view: 'web', title: 'CHECK WEB RISK PASSIVELY', body: 'Headers, TLS, cookies, forms, comments and exposure paths are checked with GET/OPTIONS only. OWASP ZAP commands are provided as copyable recipes, never launched for you.' },
  { view: 'code', title: 'INSPECT CODE', body: 'Static rules find risky patterns in local source. Kernel review and the static WinDbg guide are read-only; no source is executed.' },
  { view: 'threats', title: 'INVESTIGATE THREATS', body: 'Peer scope, flows, listeners and DNS-cache hints are shown read-only. Task Manager and firewall console are available in the same view.' },
  { view: 'triage', title: 'TRIAGE DEVOPS ALERTS', body: 'Normalise, dedupe and prioritise an exported alert file. Decisions are saved locally and routed to the relevant research view.' },
  { view: 'av', title: 'UNDERSTAND BLOCKS', body: 'Endpoint blocks are evidence that a control worked. The register records what was observed and what could not be evaluated - there is no bypass workflow.' },
  { view: 'data', title: 'MANAGE DATA SECURITY', body: 'Classify files, review secret and PII pattern hits, and preview retention. Purge is opt-in, limited to NetTruder data and confirmed twice.' },
  { view: 'research', title: 'USE THE RESEARCH LAB', body: 'Windows and Linux technique catalogs, observed blocks and elevation proof are kept separate so a gap is never reported as OK.' },
  { view: 'terminal', title: 'TERMINAL, SAFELY', body: 'Full cmd, long-output toggles and audit logging remain available. NetTruder never disables security software or tries to hide from it.' }
];

function onboardPath() { return S.state + '\\onboarding.json'; }

function loadOnboard() {
  var p = onboardPath();
  try {
    if (!S.fso.FileExists(p)) { return; }
    var o = JSON.parse(readAll(p));
    if (o && o.seen) {
      S.onboard.seen = true;
      S.onboard.role = o.role || '';
      S.onboard.level = o.level || '';
    }
  } catch (e) { }
}

function saveOnboard() {
  var o = {
    seen: !!S.onboard.seen,
    role: S.onboard.role || '',
    level: S.onboard.level || '',
    at: new Date().toISOString().replace(/\.\d+Z$/, 'Z')
  };
  try { writeText(onboardPath(), '{' + '"seen":' + (o.seen ? 'true' : 'false') + ','
    + '"role":' + jsonStr(o.role) + ',' + '"level":' + jsonStr(o.level) + ','
    + '"at":' + jsonStr(o.at) + '}'); } catch (e) { }
}

function showViewHint(name) {
  if (!S.onboard.seen || S.onboard.tour) { return; }
  if (!S.onboard.hints) { S.onboard.hints = {}; }
  if (S.onboard.hints[name]) { return; }
  S.onboard.hints[name] = true;
  if (VIEW_HINTS[name]) { showHint(VIEW_HINTS[name]); }
}

function openOnboard(first) {
  var wrap = el('onboardWrap');
  if (!wrap) { return; }
  S.onboard.tour = !first;
  S.onboard.step = first ? -1 : 0;
  wrap.style.display = 'flex';
  renderOnboard();
}

function closeOnboard() {
  var wrap = el('onboardWrap');
  if (wrap) { wrap.style.display = 'none'; }
  S.onboard.tour = false;
  S.onboard.seen = true;
  saveOnboard();
}

function renderOnboard() {
  var body = el('onboardBody');
  var foot = el('onboardFoot');
  var kick = el('onboardKicker');
  if (!body || !foot) { return; }
  if (S.onboard.step < 0) {
    if (kick) { kick.innerHTML = 'WELCOME / 30 SECOND SETUP'; }
    var role = S.onboard.role || 'soc';
    var level = S.onboard.level || 'new';
    var h = [];
    h.push('<div class="obtitle">NETTRUDER OPS CONSOLE</div>');
    h.push('<div class="obcopy">Read-only network, web, code, alert and data analysis in one place. Pick a starting point and take a short tour. You can reopen it any time with the GUIDE button.</div>');
    h.push('<div class="obq">WHAT DO YOU DO?</div>');
    h.push('<select id="obRole" class="ressel">'
      + optionHtml('soc', 'SOC / incident response', role)
      + optionHtml('dev', 'Developer / DevOps', role)
      + optionHtml('net', 'Network engineering', role)
      + optionHtml('appsec', 'Application security', role) + '</select>');
    h.push('<div class="obq">HOW FAMILIAR ARE YOU?</div>');
    h.push('<select id="obLevel" class="ressel">'
      + optionHtml('new', 'New - show me the basics', level)
      + optionHtml('some', 'Some experience', level)
      + optionHtml('expert', 'Experienced - get me to the tools', level) + '</select>');
    h.push('<div class="obnote">NetTruder never weakens a control. No service, firewall, update or telemetry change is offered.</div>');
    body.innerHTML = h.join('');
    foot.innerHTML = '<button class="mbtn" data-ob="skip">SKIP SETUP</button>'
      + '<button class="mbtn primary" data-ob="start">START TOUR</button>';
    return;
  }
  var i = S.onboard.step;
  var st = TOUR[i];
  if (!st) { closeOnboard(); return; }
  if (kick) { kick.innerHTML = 'TOUR ' + (i + 1) + ' / ' + TOUR.length; }
  body.innerHTML = '<div class="obtitle">' + esc(st.title) + '</div>'
    + '<div class="obcopy">' + esc(st.body) + '</div>'
    + '<div class="obview">VIEW: ' + esc(st.view.toUpperCase()) + '</div>';
  showView(st.view);
  var b = [];
  if (i > 0) { b.push('<button class="mbtn" data-ob="back">BACK</button>'); }
  b.push('<button class="mbtn" data-ob="skip">SKIP TOUR</button>');
  b.push('<button class="mbtn primary" data-ob="' + (i === TOUR.length - 1 ? 'finish' : 'next') + '">'
    + (i === TOUR.length - 1 ? 'FINISH' : 'NEXT') + '</button>');
  foot.innerHTML = b.join('');
}

function optionHtml(value, label, current) {
  return '<option value="' + esc(value) + '"' + (value === current ? ' selected' : '') + '>' + esc(label) + '</option>';
}

function onboardAction(act) {
  if (act === 'skip' || act === 'finish') { closeOnboard(); return; }
  if (act === 'start') {
    var r = el('obRole'), l = el('obLevel');
    if (r) { S.onboard.role = r.value; }
    if (l) { S.onboard.level = l.value; }
    S.onboard.seen = true;
    saveOnboard();
    S.onboard.tour = true;
    S.onboard.step = 0;
    renderOnboard();
    return;
  }
  if (act === 'next') { if (S.onboard.step < TOUR.length - 1) { S.onboard.step++; renderOnboard(); } return; }
  if (act === 'back') { if (S.onboard.step > 0) { S.onboard.step--; renderOnboard(); } }
}

function showView(name) {
  var views = ['sweep', 'ids', 'flow', 'web', 'code', 'threats', 'triage', 'av',
    'data', 'terminal', 'posture', 'processes', 'audit', 'research', 'network', 'pslog'];
  for (var i = 0; i < views.length; i++) {
    var v = el('view-' + views[i]);
    if (v) { v.className = 'view' + (views[i] === name ? ' active' : ''); }
  }
  var navs = document.getElementsByTagName('button');
  for (var j = 0; j < navs.length; j++) {
    if (navs[j].className && navs[j].className.indexOf('nav') === 0) {
      var dv = navs[j].getAttribute('data-view');
      navs[j].className = 'nav' + (dv === name ? ' active' : '');
    }
  }
  el('sbMode').innerHTML = 'MODE: ' + name.toUpperCase();
  if (name === 'terminal') { setTimeout(function () { el('termInput').focus(); }, 60); }
  if (name === 'audit') { refreshAuditList(); }
  if (name === 'research') {
    if (loadResearchCatalog()) { renderResearch(); }
  }
  if (name === 'ids') { startStream('ctl', 'status', {}); }
  if (name === 'flow') { if (S.flow.dirty) { renderFlow(); } }
  if (name === 'web') { if (S.web.dirty) { renderWeb(); } if (S.site.dirty) { renderSiteImport(); } }
  if (name === 'code') { if (S.code.dirty) { renderCode(); } }
  if (name === 'threats') { if (S.inv.dirty) { renderInv(); } }
  if (name === 'triage') { if (S.triage.dirty) { renderTriage(); } }
  if (name === 'av') { if (S.av.dirty) { renderAv(); } }
  if (name === 'data') { if (S.data.dirty) { renderData(); } }
  if (name === 'network') { if (S.net.dirty) { renderNet(); } }
  if (name === 'pslog') { if (S.pslog.dirty) { renderPsLog(); } }
  if (name === 'processes') {
    var stale = (new Date().getTime() - S.procStamp) > 30000;
    if (S.procDirty) { renderProcs(); }
    if ((!S.procs.length || stale) && !(S.streams.procs && !S.streams.procs.done)) { refreshProcesses(); }
  }
  showViewHint(name);
}

/* ------------------------------- actions ------------------------------ */
function localSubnet() {
  try {
    var loc = new ActiveXObject('WbemScripting.SWbemLocator');
    var svc = loc.ConnectServer('.', 'root\\cimv2');
    var set = svc.ExecQuery('SELECT IPAddress, IPSubnet FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = TRUE');
    var en = new Enumerator(set);
    for (; !en.atEnd(); en.moveNext()) {
      var o = en.item();
      var ips = o.IPAddress, subs = o.IPSubnet;
      if (!ips) { continue; }
      for (var i = 0; i < ips.length; i++) {
        var ip = String(ips[i]);
        var mask = subs ? String(subs[i]) : '';
        if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) { continue; }
        if (!isPrivate(ip)) { continue; }
        if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(mask)) { continue; }
        return toCidr(ip, mask);
      }
    }
  } catch (e) { }
  return '';
}

function toCidr(ip, mask) {
  var m = mask.split('.'), bits = 0, i, v;
  for (i = 0; i < 4; i++) {
    v = parseInt(m[i], 10);
    while (v > 0) { bits += (v & 1); v = v >> 1; }
  }
  if (bits < 22) {
    var o = ip.split('.');
    return o[0] + '.' + o[1] + '.' + o[2] + '.0/24';
  }
  var ipl = ip.split('.'), net = '';
  for (i = 0; i < 4; i++) {
    var mm = parseInt(m[i], 10);
    net += (parseInt(ipl[i], 10) & mm) + (i < 3 ? '.' : '');
  }
  return net + '/' + bits;
}

function gatewayIp() {
  try {
    var loc = new ActiveXObject('WbemScripting.SWbemLocator');
    var svc = loc.ConnectServer('.', 'root\\cimv2');
    var set = svc.ExecQuery('SELECT DefaultIPGateway FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = TRUE');
    var en = new Enumerator(set);
    for (; !en.atEnd(); en.moveNext()) {
      var o = en.item();
      if (o.DefaultIPGateway && o.DefaultIPGateway.length) { return String(o.DefaultIPGateway[0]); }
    }
  } catch (e) { }
  return '';
}

function validTargets(t) {
  return /^[0-9A-Za-z .,:/\-]+$/.test(t);
}

function startSweep() {
  var t = el('targets').value.replace(/^\s+|\s+$/g, '');
  if (!t) { pushConsole('err', 'No targets set.', 'sweep'); return; }
  if (!validTargets(t)) { pushConsole('err', 'Targets contain characters outside the allowlist.', 'sweep'); return; }
  S.targets = t;
  S.profile = el('profile').value;
  S.hosts = {};
  S.hostOrder = [];
  S.selected = '';
  S.stats.ports = 0;
  S.hostDirty = true;
  renderHosts();
  renderDetail();
  el('bar').style.width = '0%';
  el('barLabel').innerHTML = 'STARTING';
  pushConsole('ok', 'Sweep queued: ' + t + ' (' + S.profile + ')', 'sweep');
  startStream('sweep', 'scan', {
    Targets: t,
    Profile: S.profile,
    TimeoutMs: el('timeout').value
  });
  renderSession();
}

function abortRun() {
  var st = S.streams.sweep;
  if (st && !st.done) {
    writeText(S.runs + '\\' + st.id + '.stop', '1');
    pushConsole('warn', 'Abort requested.', 'sweep');
  } else {
    pushConsole('dim', 'Nothing to abort.', 'sweep');
  }
}

function armIds() {
  if (S.monitor) { pushConsole('warn', 'IDS already armed.', 'watch'); return; }
  el('btnWatch').disabled = true;
  el('watchState').innerHTML = 'ARMING';
  pushConsole('ok', 'Arming IDS monitor.', 'watch');
  startStream('watch', 'watch', {
    IntervalSec: 2,
    AutoBlock: el('chkAutoBlock').checked,
    DurationMin: 10
  });
}

function disarmIds() {
  var st = S.streams.watch;
  if (st && !st.done) {
    writeText(S.runs + '\\' + st.id + '.stop', '1');
    pushConsole('warn', 'Disarm requested.', 'watch');
  } else {
    pushConsole('dim', 'IDS is not running.', 'watch');
  }
}

function blockIp(ip) {
  var extra = '';
  if (isPrivate(ip)) {
    if (!confirm(ip + ' is a private/LAN address.\n\nBlocking a local peer can disrupt shared devices, printers or servers.\n\nBlock it anyway for 10 minutes?')) { return; }
    extra = ' (LAN override)';
  }
  pushConsole('warn', 'Blocking ' + ip + ' for 10 minutes' + extra + '.', 'ctl');
  startStream('ctl', 'block', { RemoteIp: ip, DurationMin: 10, Yes: isPrivate(ip) });
}

function unblockIp(ip) {
  pushConsole('ok', 'Releasing ' + ip + '.', 'ctl');
  startStream('ctl', 'unblock', { RemoteIp: ip });
}

function releaseAll() {
  if (!confirm('Release every NetTruder IPS rule?')) { return; }
  startStream('ctl', 'release', {});
}

function runProbe() {
  S.posture = [];
  S.postureDirty = true;
  renderPosture();
  el('postureState').innerHTML = 'PROBING';
  el('btnProbe').disabled = true;
  pushConsole('ok', 'Posture probe started (read-only).', 'posture');
  startStream('posture', 'probe', {});
}

/* ------------------------------ response ------------------------------ */
function pickFolder(initial) {
  try {
    var shell = new ActiveXObject('Shell.Application');
    var folder = shell.BrowseForFolder(0, 'Select a folder for read-only analysis', 0, initial || 0);
    if (folder && folder.Self && folder.Self.Path) { return folder.Self.Path; }
  } catch (e) { }
  return '';
}

function openTool(cmd) {
  try {
    S.sh.Run(cmd, 1, false);
    pushConsole('dim', 'Opened: ' + cmd, 'tool');
  } catch (e) {
    pushConsole('err', 'Could not open ' + cmd + ': ' + e.message, 'tool');
  }
}

function refreshProcesses() {
  if (S.streams.procs && !S.streams.procs.done) { return; }
  S.procs = [];
  S.procDirty = true;
  S.procSelected = 0;
  if (el('procBody')) { el('procBody').innerHTML = ''; }
  if (el('procDetail')) { el('procDetail').innerHTML = '<span class="micro">SELECT A PROCESS ROW FOR DETAIL</span>'; }
  el('procState').innerHTML = 'COLLECTING';
  el('btnProcRefresh').disabled = true;
  pushConsole('dim', 'Collecting local process inventory (read-only).', 'procs');
  var st = startStream('procs', 'processes', {});
  if (st && st.done) {
    el('btnProcRefresh').disabled = false;
    el('procState').innerHTML = 'FAILED';
  }
}

function focusProcess(pid, name) {
  S.procFilter = pid ? String(pid) : String(name || '');
  if (el('procFilter')) { el('procFilter').value = S.procFilter; }
  showView('processes');
  if (S.procs.length) { renderProcs(); } else { refreshProcesses(); }
}

function killProcess(pid, name) {
  pid = parseInt(pid, 10) || 0;
  if (pid <= 0) { return; }
  var label = name ? (name + ' (PID ' + pid + ')') : ('PID ' + pid);
  if (!confirm('Terminate ' + label + '?\n\nThe process is stopped immediately and the action is written to the audit log. Unsaved work in that process is lost.')) { return; }
  pushConsole('warn', 'Terminate requested: ' + label, 'procs');
  startStream('kill', 'kill', { ProcId: pid, Yes: true });
}

/* ------------------------------ terminal ------------------------------ */
function promptText() { return S.cwd + '>'; }

function setCwd(path) {
  S.cwd = path;
  el('termPrompt').innerHTML = esc(promptText());
  el('termCwd').innerHTML = esc(path);
}

function appendTerm(cls, text) {
  var t = el('term');
  var line = document.createElement('div');
  line.className = 'tl' + (cls ? ' ' + cls : '');
  line.appendChild(document.createTextNode(text === undefined || text === null ? '' : String(text)));
  t.appendChild(line);
  while (t.childNodes.length > 1200) { t.removeChild(t.firstChild); }
  S.termCount = t.childNodes.length;
  if (S.termFollow) { t.scrollTop = t.scrollHeight; }
  updateTermLines();
}

function queueTerm(cls, text) {
  S.termPending.push({ c: cls || '', t: (text === undefined || text === null) ? '' : String(text) });
  if (S.termPending.length > 4000) { S.termPending.shift(); }
  if (el('termHold')) { el('termHold').innerHTML = 'PAUSED ' + S.termPending.length; }
}

function flushTermPending() {
  var q = S.termPending;
  S.termPending = [];
  for (var i = 0; i < q.length; i++) { appendTerm(q[i].c, q[i].t); }
  if (S.termFollow) { var t = el('term'); t.scrollTop = t.scrollHeight; }
}

function updateTermLines() {
  if (el('termLines')) { el('termLines').innerHTML = S.termCount + ' LINES'; }
}

function clearTerm() {
  el('term').innerHTML = '';
  S.termCount = 0;
  updateTermLines();
}

function setToggle(id, on) {
  var b = el(id);
  if (b) { b.className = 'tgl' + (on ? ' on' : ''); }
}

function applyTermView() {
  var t = el('term');
  if (!t) { return; }
  t.className = 'term' + (S.termWrap ? ' wrap' : '') + (S.termCompact ? ' compact' : '');
  setToggle('btnTermWrap', S.termWrap);
  setToggle('btnTermFollow', S.termFollow);
  setToggle('btnTermPause', S.termPaused);
  setToggle('btnTermCompact', S.termCompact);
  if (el('termHold')) {
    var hold = el('termHold');
    hold.className = 'termhold' + ((!S.termPaused && S.termFollow) ? ' live' : '');
    hold.innerHTML = S.termPaused
      ? ('PAUSED' + (S.termPending.length ? ' ' + S.termPending.length : ''))
      : (S.termFollow ? 'LIVE' : 'HOLD');
  }
}

function termBanner() {
  el('term').innerHTML = '';
  S.termPending = [];
  S.termCount = 0;
  appendTerm('banner', 'NETTRUDER LOCAL SHELL // engine 1.0.0');
  appendTerm('dim', 'Commands run as the current user in this console session.');
  appendTerm('dim', 'Every command line is appended to the audit log.');
  appendTerm('dim', 'Type "help" for console built-ins.');
  appendTerm('dim', '');
  updateTermLines();
  applyTermView();
}

function runTerminal(raw) {
  var cmd = String(raw).replace(/^\s+|\s+$/g, '');
  if (!cmd) { return; }
  appendTerm('cmd', promptText() + ' ' + cmd);

  if (/^(cls|clear)$/i.test(cmd)) { clearTerm(); return; }
  if (/^help$/i.test(cmd)) {
    appendTerm('ok', 'Built-ins:');
    appendTerm('', '  cd <path>   change the working directory used by the shell');
    appendTerm('', '  cls         clear this pane');
    appendTerm('', '  help        this text');
    appendTerm('', 'Anything else is passed to cmd.exe /d /s /c.');
    return;
  }
  var m = cmd.match(/^cd(?:\s+|\s*\/d\s+)(.*)$/i);
  if (cmd.toLowerCase() === 'cd') {
    appendTerm('ok', S.cwd);
    return;
  }
  if (m) {
    var target = m[1].replace(/^"|"$/g, '');
    var next = target;
    if (!/^[A-Za-z]:/.test(target) && target.charAt(0) !== '\\') { next = S.cwd + '\\' + target; }
    try {
      if (S.fso.FolderExists(next)) { setCwd(S.fso.GetFolder(next).Path); appendTerm('ok', S.cwd); }
      else { appendTerm('err', 'Not a directory: ' + target); }
    } catch (e) { appendTerm('err', 'Not a directory: ' + target); }
    return;
  }
  if (S.termBusy) { appendTerm('err', 'A command is already running. Kill it first.'); return; }

  S.termBusy = true;
  el('termInput').disabled = true;
  el('btnTermRun').disabled = true;
  var st = startStream('term', 'shell', { CmdLine: cmd, WorkDir: S.cwd, MaxSeconds: 900 });
  if (st && st.done) {
    S.termBusy = false;
    el('termInput').disabled = false;
    el('btnTermRun').disabled = false;
  }
}

function killTerminal() {
  var st = S.streams.term;
  if (st && !st.done) {
    writeText(S.runs + '\\' + st.id + '.stop', '1');
    appendTerm('dim', '[kill requested]');
  }
}

/* ------------------------------- audit -------------------------------- */
function refreshAuditList() {
  var sel = el('auditFile');
  sel.innerHTML = '';
  var files = [];
  try {
    var f = S.fso.GetFolder(S.audit);
    var en = new Enumerator(f.Files);
    for (; !en.atEnd(); en.moveNext()) {
      var item = en.item();
      if (/^audit-\d{8}\.ndjson$/i.test(item.Name)) {
        files.push({ name: item.Name, size: item.Size, modified: item.DateLastModified });
      }
    }
  } catch (e) { }
  files.sort(function (a, b) { return a.name < b.name ? 1 : -1; });
  for (var i = 0; i < files.length; i++) {
    var opt = document.createElement('option');
    opt.value = files[i].name;
    opt.innerHTML = files[i].name + '  (' + Math.round(files[i].size / 1024) + ' KB)';
    sel.appendChild(opt);
  }
  if (files.length === 0) {
    var o = document.createElement('option');
    o.value = '';
    o.innerHTML = 'no audit files yet';
    sel.appendChild(o);
  }
}

function loadAudit() {
  var name = el('auditFile').value;
  if (!name) { el('auditOut').innerHTML = ''; el('auditMeta').innerHTML = 'NO FILE'; return; }
  var text = '';
  try { text = readAll(S.audit + '\\' + name); } catch (e) {
    el('auditMeta').innerHTML = 'READ FAILED';
    return;
  }
  var lines = text.split('\n');
  var out = [];
  var shown = 0;
  for (var i = lines.length - 1; i >= 0 && shown < 1500; i--) {
    var ln = lines[i].replace(/\r$/, '');
    if (!ln) { continue; }
    var e;
    try { e = JSON.parse(ln); } catch (err) { continue; }
    var detail = esc(e.detail || '');
    var meta = '';
    if (e.d && e.d.ip) { meta += ' <span class="a-ip">' + esc(e.d.ip) + '</span>'; }
    if (e.d && e.d.id) { meta += ' ' + esc(e.d.id); }
    out.push('<span class="a-line"><span class="a-kind">' + esc(e.kind || '?') + '</span> '
      + esc(String(e.t || '').replace('T', ' ').substring(0, 19)) + '  ' + detail + meta + '</span>');
    shown++;
  }
  el('auditOut').innerHTML = out.join('');
  el('auditMeta').innerHTML = shown + ' ENTRIES';
}

/* ------------------------------- wiring ------------------------------- */
function bind(id, evt, fn) {
  var node = el(id);
  if (node) { node[evt] = fn; }
}

function wire() {
  var navs = document.getElementsByTagName('button');
  for (var i = 0; i < navs.length; i++) {
    if (navs[i].className === 'nav' || navs[i].className === 'nav active') {
      navs[i].onclick = function () { showView(this.getAttribute('data-view')); };
    }
  }

  bind('btnLocal', 'onclick', function () {
    var s = localSubnet();
    if (s) { el('targets').value = s; } else { pushConsole('warn', 'Could not derive a local subnet.', 'sweep'); }
  });
  bind('btnGateway', 'onclick', function () {
    var g = gatewayIp();
    if (g) { el('targets').value = g; } else { pushConsole('warn', 'No default gateway reported.', 'sweep'); }
  });

  bind('btnSweep', 'onclick', startSweep);
  bind('btnAbort', 'onclick', abortRun);
  bind('btnProbeTop', 'onclick', function () { showView('posture'); runProbe(); });
  bind('btnProbe', 'onclick', runProbe);

  bind('btnWatch', 'onclick', armIds);
  bind('btnWatchStop', 'onclick', disarmIds);
  bind('btnRelease', 'onclick', releaseAll);
  bind('chkAutoBlock', 'onclick', function () {
    if (this.checked) {
      pushConsole('warn', 'Auto-block enabled: HIGH alerts on public IPs only, 10 minute TTL.', 'watch');
    } else {
      pushConsole('dim', 'Auto-block disabled.', 'watch');
    }
  });

  bind('clearConsole', 'onclick', function (ev) {
    if (ev && ev.preventDefault) { ev.preventDefault(); }
    el('console').innerHTML = '';
  });

  bind('hostBody', 'onclick', function (ev) {
    var e = ev || window.event;
    var t = e.target || e.srcElement;
    while (t && t.tagName !== 'TR') { t = t.parentNode; }
    if (!t) { return; }
    S.selected = t.getAttribute('data-ip');
    renderHosts();
    renderDetail();
  });

  bind('alertList', 'onclick', function (ev) {
    var e = ev || window.event;
    var t = e.target || e.srcElement;
    while (t && t.tagName !== 'BUTTON') { t = t.parentNode; }
    if (!t) { return; }
    var act = t.getAttribute('data-act') || '';
    if (act === 'remedy') { showAlertRemedy(findAlert(t.getAttribute('data-seq'))); }
    else if (act === 'block') { blockIp(t.getAttribute('data-ip')); }
    else if (act === 'kill') { killProcess(t.getAttribute('data-pid'), t.getAttribute('data-name')); }
    else if (act === 'proc') { focusProcess(t.getAttribute('data-pid'), t.getAttribute('data-name')); }
    else if (act === 'tm') { openTool('taskmgr.exe'); }
  });

  bind('postureList', 'onclick', function (ev) {
    var e = ev || window.event;
    var t = e.target || e.srcElement;
    if (!t || t.className !== 'pfix') { return; }
    var tool = t.getAttribute('data-tool');
    var view = t.getAttribute('data-view');
    if (tool) { openTool(tool); }
    else if (view) { showView(view); }
  });

  bind('procBody', 'onclick', function (ev) {
    var e = ev || window.event;
    var t = e.target || e.srcElement;

    var btn = t;
    while (btn && btn.tagName !== 'BUTTON') { btn = btn.parentNode; }
    if (btn && btn.getAttribute('data-act')) {
      var act = btn.getAttribute('data-act');
      var pid = parseInt(btn.getAttribute('data-pid'), 10) || 0;
      if (act === 'kill') { killProcess(pid, btn.getAttribute('data-name')); }
      else if (act === 'locate') {
        var p = findProc(pid);
        if (p && p.path) {
          try { S.sh.Run('explorer.exe /select,"' + p.path + '"', 1, false); }
          catch (e2) { pushConsole('err', 'Could not open the file location: ' + e2.message, 'procs'); }
        }
      }
      return;
    }

    var tr = t;
    while (tr && tr.tagName !== 'TR') { tr = tr.parentNode; }
    if (tr && tr.getAttribute('data-pid')) {
      S.procSelected = parseInt(tr.getAttribute('data-pid'), 10) || 0;
      renderProcs();
    }
  });

  bind('procFilter', 'onkeyup', function () {
    S.procFilter = this.value;
    renderProcs();
  });

  bind('btnProcRefresh', 'onclick', refreshProcesses);
  bind('btnProcTaskMgr', 'onclick', function () { openTool('taskmgr.exe'); });
  bind('btnProcResMon', 'onclick', function () { openTool('resmon.exe'); });
  bind('btnProcServices', 'onclick', function () { openTool('services.msc'); });
  bind('btnProcFirewall', 'onclick', function () { openTool('wf.msc'); });
  bind('btnIdsTaskMgr', 'onclick', function () { openTool('taskmgr.exe'); });
  bind('btnIdsFirewall', 'onclick', function () { openTool('wf.msc'); });
  bind('btnPostTaskMgr', 'onclick', function () { openTool('taskmgr.exe'); });
  bind('btnPostFirewall', 'onclick', function () { openTool('wf.msc'); });
  bind('btnBlockFirewall', 'onclick', function () { openTool('wf.msc'); });

  /* onboarding */
  bind('btnHelp', 'onclick', function () { openOnboard(false); });
  bind('onboardClose', 'onclick', closeOnboard);
  bind('onboardFoot', 'onclick', function (ev) {
    var e = ev || window.event;
    var t = e.target || e.srcElement;
    while (t && t.tagName !== 'BUTTON') { t = t.parentNode; }
    if (t) { onboardAction(t.getAttribute('data-ob') || ''); }
  });

  /* process flow */
  bind('btnFlowRun', 'onclick', runFlow);
  bind('btnFlowTaskMgr', 'onclick', function () { openTool('taskmgr.exe'); });
  bind('btnFlowFirewall', 'onclick', function () { openTool('wf.msc'); });
  bind('btnFlowLegend', 'onclick', function () {
    showModal({
      title: 'HOW TO READ THE FLOW MAP', kicker: 'PROCESS TREE / DATA FLOW', sev: 'ok',
      detail: 'Boxes are processes or remote endpoints. A blue line is a parent-to-child spawn; a green line is a network connection. Colour on the node border is severity. Left to right is depth from the root.',
      fix: [
        'The map is read-only and uses the live parent PID. Windows reuses PIDs, so an orphan link is not proof of injection.',
        'Use the filter to isolate one process, pid or path. Click a node to see its full command line.',
        'Task Manager and the firewall console open from the same view for follow-up.'
      ],
      note: DEFAULT_REMEDY_NOTE
    });
  });
  bind('flowFilter', 'onkeyup', function () { S.flow.dirty = true; renderFlow(); });
  bind('flowSvg', 'onclick', function (ev) {
    var e = ev || window.event;
    var t = closestAttr(e.target || e.srcElement, 'data-node');
    if (!t) { return; }
    S.flow.selected = t.getAttribute('data-node');
    renderFlow();
  });
  bind('flowFindings', 'onclick', function (ev) {
    var e = ev || window.event;
    var t = closestAttr(e.target || e.srcElement, 'data-ffind');
    if (!t) { return; }
    findingModal(S.flow.findings[parseInt(t.getAttribute('data-ffind'), 10)]);
  });
  bind('flowDetail', 'onclick', function (ev) {
    var e = ev || window.event;
    var t = e.target || e.srcElement;
    while (t && t.tagName !== 'BUTTON') { t = t.parentNode; }
    if (t && t.getAttribute('data-act') === 'tm') { openTool('taskmgr.exe'); }
  });

  /* web */
  bind('btnWebRun', 'onclick', runWebScan);
  bind('btnWebZap', 'onclick', showZapRecipe);
  bind('webUrl', 'onkeydown', function (ev) {
    var e = ev || window.event;
    if (e.keyCode === 13) { runWebScan(); if (e.preventDefault) { e.preventDefault(); } return false; }
    return true;
  });
  bind('chkWebPublic', 'onclick', function () {
    if (this.checked) { pushConsole('warn', 'Public target opt-in set. Only scan hosts you are authorised to test.', 'web'); }
  });
  bind('webPages', 'onclick', function (ev) {
    var e = ev || window.event;
    var t = e.target || e.srcElement;
    var a = closestAttr(t, 'data-asset');
    if (a) {
      showWebAsset(a.getAttribute('data-asset'), a.getAttribute('data-index'));
      return;
    }
    t = closestAttr(t, 'data-url');
    if (!t) { return; }
    S.web.selected = t.getAttribute('data-url');
    S.web.flowNode = '';
    renderWeb();
  });
  bind('webFlow', 'onclick', function (ev) {
    var e = ev || window.event;
    var t = closestAttr(e.target || e.srcElement, 'data-node');
    if (!t) { return; }
    var id = t.getAttribute('data-node');
    if (id) { showWebFlowNode(id); }
  });
  bind('webFindings', 'onclick', function (ev) {
    var e = ev || window.event;
    var t = closestAttr(e.target || e.srcElement, 'data-wfind');
    if (!t) { return; }
    findingModal(S.web.findings[parseInt(t.getAttribute('data-wfind'), 10)]);
  });

  /* manual extension report import */
  bind('btnSiteImport', 'onclick', importSiteReport);
  bind('btnSiteClear', 'onclick', clearSiteReport);
  bind('btnSiteGuide', 'onclick', showSiteGuide);
  bind('siteImportRows', 'onclick', function (ev) {
    var e = ev || window.event;
    var t = closestAttr(e.target || e.srcElement, 'data-srow');
    if (!t) { return; }
    showSiteRow(t.getAttribute('data-srow'));
  });

  /* code */
  bind('btnCodeRun', 'onclick', runCodeAudit);
  bind('btnHevdAudit', 'onclick', runHevdCodeAudit);
  bind('btnHevdGuide', 'onclick', showHevdGuide);
  bind('btnHevdReview', 'onclick', showHevdReview);
  bind('btnKernelDbg', 'onclick', showKernelDbgGuide);
  bind('btnIntWrap', 'onclick', showIntWrapGuide);
  bind('btnCodeToResearch', 'onclick', sendCodeToResearch);
  bind('btnCodeFolder', 'onclick', function () {
    var p = pickFolder(el('codePath') ? el('codePath').value : S.base);
    if (p) { el('codePath').value = p; }
  });
  bind('codeSev', 'onchange', function () { S.code.sevFilter = this.value || ''; renderCode(); });
  bind('codeSearch', 'onkeyup', function () { S.code.search = this.value || ''; renderCode(); });
  bind('codeSort', 'onchange', function () { S.code.sort = this.value || 'sev'; renderCode(); });
  bind('btnCodeExport', 'onclick', function () { exportCodeReport(); });
  bind('btnCodeExternal', 'onclick', function () { openCodeExternal(); });
  bind('btnCodeWriteMode', 'onclick', function () { toggleCodeWriteMode(); });
  bind('codeFiles', 'onclick', function (ev) {
    var e = ev || window.event;
    var t = closestAttr(e.target || e.srcElement, 'data-file');
    if (!t) { return; }
    var file = t.getAttribute('data-file') || '';
    S.code.fileSelected = file;
    S.code.fileFilter = file;
    if (file) {
      var idx = firstFindingForFile(file);
      if (idx >= 0) {
        S.code.selected = idx;
        S.code.activeLine = parseInt(S.code.findings[idx].line, 10) || 0;
      } else {
        S.code.activeLine = 0;
      }
    } else {
      S.code.selected = -1;
      S.code.activeLine = 0;
    }
    renderCode();
  });
  bind('codeFindings', 'onclick', function (ev) {
    var e = ev || window.event;
    var evBtn = closestAttr(e.target || e.srcElement, 'data-chevidence');
    if (evBtn) {
      var evIdx = parseInt(evBtn.getAttribute('data-chevidence'), 10);
      if (S.code.findings[evIdx]) { showCodeEvidence(S.code.findings[evIdx]); }
      return;
    }
    var t = closestAttr(e.target || e.srcElement, 'data-cfind');
    if (!t) { return; }
    var rowIdx = parseInt(t.getAttribute('data-cfind'), 10);
    var idx = S.code.viewMap ? S.code.viewMap[rowIdx] : rowIdx;
    if (idx === undefined || idx === null || idx < 0 || !S.code.findings[idx]) { idx = rowIdx; }
    if (idx === undefined || idx === null || idx < 0 || !S.code.findings[idx]) { return; }
    var f = S.code.findings[idx];
    S.code.selected = idx;
    S.code.fileSelected = f.file || S.code.fileSelected;
    S.code.activeLine = parseInt(f.line, 10) || 0;
    pushConsole('dim', 'Finding opened: ' + (f.title || f.id || 'RULE') + ' at '
      + (f.file || '-') + ':' + (f.line || '-') + '.', 'code');
    renderCode();
  });
  bind('codeDetail', 'onclick', function (ev) {
    var e = ev || window.event;
    var t = closestAttr(e.target || e.srcElement, 'data-act');
    if (!t) { return; }
    var act = t.getAttribute('data-act');
    var fnIdx;
    if (act === 'evidence') { showCodeEvidence(S.code.findings[S.code.selected]); }
    else if (act === 'remedy') { findingModal(S.code.findings[S.code.selected]); }
    else if (act === 'copysnip') { copyCodeSnippet(); }
    else if (act === 'copysource') { copyCodeSource(); }
    else if (act === 'copyraw') { copyRawSource(); }
    else if (act === 'hit') { selectCodeHit(t.getAttribute('data-line'), t.getAttribute('data-id')); }
    else if (act === 'function') {
      fnIdx = parseInt(t.getAttribute('data-fn'), 10);
      if (S.code.functions[fnIdx]) { S.code.selectedFunction = fnIdx; gotoCodeLine(t.getAttribute('data-line')); }
    }
    else if (act === 'copyfunction') { copyCodeFunction(parseInt(t.getAttribute('data-fn'), 10)); }
    else if (act === 'goline') {
      var go = el('codeGoLine');
      gotoCodeLine(go ? go.value : '', true);
    }
    else if (act === 'openraw') { startCodeRaw(); }
    else if (act === 'closeraw') { closeCodeRaw(); }
    else if (act === 'save') { saveCodeRaw(); }
    else if (act === 'revert') { revertCodeRaw(); }
    else if (act === 'insertfix') { insertCodeFix(); }
    else if (act === 'external') { openCodeExternal(); }
    else if (act === 'export') { exportCodeReport(); }
  });

  /* threats */
  bind('btnInvRun', 'onclick', runInv);
  bind('btnInvTaskMgr', 'onclick', function () { openTool('taskmgr.exe'); });
  bind('btnInvFirewall', 'onclick', function () { openTool('wf.msc'); });
  bind('invFilter', 'onkeyup', function () { S.inv.dirty = true; renderInv(); });
  bind('invBody', 'onclick', function (ev) {
    var e = ev || window.event;
    var t = e.target || e.srcElement;
    while (t && t.tagName !== 'TR') { t = t.parentNode; }
    if (t) { showPeerDetail(t.getAttribute('data-ip')); }
  });
  bind('invFindings', 'onclick', function (ev) {
    var e = ev || window.event;
    var t = closestAttr(e.target || e.srcElement, 'data-ifind');
    if (!t) { return; }
    findingModal(S.inv.findings[parseInt(t.getAttribute('data-ifind'), 10)]);
  });

  /* network */
  bind('btnNetRun', 'onclick', function () { runNetInventory(0); });
  bind('btnNetLive', 'onclick', function () {
    if (S.net.live) { stopNetLive(true); }
    else { startNetLive(); }
  });
  bind('btnNetStop', 'onclick', function () {
    if (S.net.live) { stopNetLive(true); return; }
    var st = S.streams.netinv;
    if (st && !st.done) {
      writeText(S.runs + '\\' + st.id + '.stop', '1');
      pushConsole('warn', 'Network sampling abort requested. Collected rows remain visible.', 'netinv');
    } else {
      pushConsole('dim', 'No network collection is running.', 'netinv');
    }
  });
  bind('btnNetPaths', 'onclick', showNetPaths);
  var recipeBtn = el('btnNetRecipe');
  if (recipeBtn) {
    recipeBtn.disabled = false;
    recipeBtn.className = 'mini primary';
    recipeBtn.title = 'Open the manual pktmon recipe';
  }
  bind('btnNetRecipe', 'onclick', function () {
    var b = el('btnNetRecipe');
    if (b) { b.disabled = false; }
    showNetRecipe();
  });
  bind('btnNetFind', 'onclick', showNetFindings);
  bind('btnNetDetail', 'onclick', showNetDetail);
  bind('netHistory', 'onchange', function () {
    if (this.checked) { showNetHistoryNotice(); }
  });
  bind('btnNetLegend', 'onclick', showNetLegend);
  bind('netFilter', 'onkeyup', function () { S.net.dirty = true; renderNet(); });

  function netGraphNodeClick(id, browser) {
    var found = null;
    for (var i = 0; i < S.net.flows.length; i++) {
      var f = S.net.flows[i];
      if (browser) {
        if (netBrowserNodeId(f) === id || netBrowserRemoteId(f) === id) { found = f; break; }
      } else {
        if (netNodeId(f) === id || netRemoteId(f) === id) { found = f; break; }
      }
    }
    if (found) {
      S.net.selected = found.id;
      renderNet();
      showNetDetail();
      return;
    }
    if (!browser && id === 'local') { showNetPaths(); return; }
    if (browser && id === 'blocal') { showNetBrowserSummary(); }
  }

  bind('netGraph', 'onclick', function (ev) {
    var e = ev || window.event;
    var t = closestAttr(e.target || e.srcElement, 'data-node');
    if (!t) { return; }
    netGraphNodeClick(t.getAttribute('data-node'), false);
  });
  bind('netBrowserGraph', 'onclick', function (ev) {
    var e = ev || window.event;
    var t = closestAttr(e.target || e.srcElement, 'data-node');
    if (!t) { return; }
    netGraphNodeClick(t.getAttribute('data-node'), true);
  });
  function netTableClick(ev) {
    var e = ev || window.event;
    var t = closestAttr(e.target || e.srcElement, 'data-nflow');
    if (!t) { return; }
    var ix = parseInt(t.getAttribute('data-nflow'), 10);
    if (!isNaN(ix) && S.net.flows[ix]) {
      S.net.selected = S.net.flows[ix].id;
      renderNet();
      showNetDetail();
    }
  }
  bind('netBrowserBody', 'onclick', netTableClick);
  bind('netBgBody', 'onclick', netTableClick);

  /* PowerShell logging (read-only) */
  bind('btnPsLogRun', 'onclick', runPsLog);
  bind('pslogEvents', 'onclick', function (ev) {
    var e = ev || window.event;
    var t = closestAttr(e.target || e.srcElement, 'data-psevent');
    if (!t) { return; }
    pslogEventModal(parseInt(t.getAttribute('data-psevent'), 10));
  });
  bind('pslogBlocks', 'onclick', function (ev) {
    var e = ev || window.event;
    var t = closestAttr(e.target || e.srcElement, 'data-psblock');
    if (!t) { return; }
    pslogBlockModal(parseInt(t.getAttribute('data-psblock'), 10));
  });
  bind('pslogFindings', 'onclick', function (ev) {
    var e = ev || window.event;
    var t = closestAttr(e.target || e.srcElement, 'data-psfind');
    if (!t) { return; }
    pslogFindModal(parseInt(t.getAttribute('data-psfind'), 10));
  });

  /* triage */
  bind('btnTriageRun', 'onclick', function () { runTriage(); });
  bind('btnTriageFolder', 'onclick', function () {
    var p = pickFolder(S.state);
    if (p) { el('triagePath').value = p; }
  });
  bind('triageBoard', 'onclick', function (ev) {
    var e = ev || window.event;
    var t = e.target || e.srcElement;
    while (t && t.tagName !== 'BUTTON') { t = t.parentNode; }
    if (!t) { return; }
    var act = t.getAttribute('data-act') || '';
    if (act === 'route') { routeResearch(t.getAttribute('data-kind')); return; }
    if (act === 'ack' || act === 'suppress' || act === 'resolve' || act === 'reopen') {
      runTriage(t.getAttribute('data-id'), act);
    }
  });
  bind('triagePlan', 'onclick', function (ev) {
    var e = ev || window.event;
    var t = closestAttr(e.target || e.srcElement, 'data-kind');
    if (t) { routeResearch(t.getAttribute('data-kind')); }
  });

  /* exposure */
  bind('btnAvRun', 'onclick', runAv);
  bind('btnAvRegister', 'onclick', function () { openTool('explorer.exe ' + q(S.base + '\\research')); });
  bind('btnAvTaskMgr', 'onclick', function () { openTool('taskmgr.exe'); });
  bind('btnAvFirewall', 'onclick', function () { openTool('wf.msc'); });
  bind('avEvents', 'onclick', function (ev) {
    var e = ev || window.event;
    var t = closestAttr(e.target || e.srcElement, 'data-aevent');
    if (!t) { return; }
    findingModal(S.av.events[parseInt(t.getAttribute('data-aevent'), 10)]);
  });
  bind('avGaps', 'onclick', function (ev) {
    var e = ev || window.event;
    var t = closestAttr(e.target || e.srcElement, 'data-avfind');
    if (!t) { return; }
    findingModal(S.av.findings[parseInt(t.getAttribute('data-avfind'), 10)]);
  });

  /* data */
  bind('btnDataRun', 'onclick', runDataCheck);
  bind('btnDataPreview', 'onclick', function () { S.data.armed = false; runDataPurge(true); });
  bind('btnDataPurge', 'onclick', function () {
    if (!S.data.armed) {
      S.data.armed = true;
      this.innerHTML = 'CONFIRM PURGE';
      pushConsole('warn', 'Purge armed. Click CONFIRM PURGE again to delete expired NetTruder-owned files. Personal folders are never in scope.', 'data');
      return;
    }
    S.data.armed = false;
    this.innerHTML = 'PURGE OLD DATA';
    runDataPurge(false);
  });
  bind('dataFindings', 'onclick', function (ev) {
    var e = ev || window.event;
    var t = closestAttr(e.target || e.srcElement, 'data-dfind');
    if (!t) { return; }
    findingModal(S.data.findings[parseInt(t.getAttribute('data-dfind'), 10)]);
  });

  bind('btnResearchRun', 'onclick', function () { runResearch(false); });
  bind('btnResearchProbes', 'onclick', function () { runResearch(true); });
  bind('btnResearchBlocks', 'onclick', showBlocksModal);
  bind('btnResearchReports', 'onclick', function () {
    var d = labDir();
    try { ensureDir(d); } catch (e) { }
    openTool('explorer.exe ' + q(d));
  });
  bind('btnResearchFolder', 'onclick', function () { openTool('explorer.exe ' + q(S.base + '\\research')); });
  bind('resGroup', 'onchange', function () {
    S.research.filters.group = this.value || '';
    renderResearchTable();
  });
  bind('resPlatform', 'onchange', function () {
    S.research.filters.platform = this.value || '';
    renderResearchTable();
  });
  bind('resBody', 'onclick', function (ev) {
    var e = ev || window.event;
    var t = e.target || e.srcElement;
    while (t && t.tagName !== 'TR') { t = t.parentNode; }
    if (!t) { return; }
    S.research.selected = t.getAttribute('data-host') || '';
    renderResearchTable();
    renderResearchDetail();
  });
  bind('resControls', 'onclick', function (ev) {
    var e = ev || window.event;
    var t = closestAttr(e.target || e.srcElement, 'data-ctl');
    if (!t) { return; }
    var i = parseInt(t.getAttribute('data-ctl'), 10);
    if (!isNaN(i)) { showControlRemedy(S.research.controls[i]); }
  });
  bind('resFindings', 'onclick', function (ev) {
    var e = ev || window.event;
    var t = closestAnyAttr(e.target || e.srcElement, ['data-find', 'data-elevfix']);
    if (!t) { return; }
    if (t.getAttribute('data-elevfix')) {
      showElevationRemedy(S.research.proof ? S.research.proof.elevation : null);
      return;
    }
    var i = parseInt(t.getAttribute('data-find'), 10);
    if (!isNaN(i)) { showFindingRemedy(S.research.findings[i]); }
  });

  bind('modalClose', 'onclick', hideModal);
  bind('modalWrap', 'onclick', function (ev) {
    var e = ev || window.event;
    var t = e.target || e.srcElement;
    if (t === el('modalWrap')) { hideModal(); }
  });
  bind('modalBody', 'onclick', function (ev) {
    var e = ev || window.event;
    var t = closestAttr(e.target || e.srcElement, 'data-nfind');
    if (t) {
      var ix = parseInt(t.getAttribute('data-nfind'), 10);
      if (!isNaN(ix) && S.net.findings[ix]) { findingModal(S.net.findings[ix]); }
      return;
    }
    t = closestAttr(e.target || e.srcElement, 'data-nact');
    if (t) { netDetailAction(t.getAttribute('data-nact') || ''); }
  });
  bind('modalFoot', 'onclick', function (ev) {
    var e = ev || window.event;
    var t = e.target || e.srcElement;
    while (t && t.tagName !== 'BUTTON') { t = t.parentNode; }
    if (!t) { return; }
    modalAction(t.getAttribute('data-mact') || '');
  });
  bind('toasts', 'onclick', toastAction);
  if (document.onkeydown === null || document.onkeydown === undefined) {
    document.onkeydown = function (ev) {
      var e = ev || window.event;
      if (e.keyCode === 27 && S.modal) { hideModal(); }
    };
  }

  bind('blockList', 'onclick', function (ev) {
    var e = ev || window.event;
    var t = e.target || e.srcElement;
    if (t && t.className === 'bx') { unblockIp(t.getAttribute('data-unblock')); }
  });

  bind('btnTermRun', 'onclick', function () {
    var v = el('termInput').value;
    if (v) { S.termHistory.push(v); S.termIdx = S.termHistory.length; }
    el('termInput').value = '';
    runTerminal(v);
  });
  bind('btnTermKill', 'onclick', killTerminal);
  bind('btnTermClear', 'onclick', clearTerm);
  bind('btnTermWrap', 'onclick', function () {
    S.termWrap = !S.termWrap;
    applyTermView();
  });
  bind('btnTermFollow', 'onclick', function () {
    S.termFollow = !S.termFollow;
    if (S.termFollow) { var t = el('term'); t.scrollTop = t.scrollHeight; }
    applyTermView();
  });
  bind('btnTermPause', 'onclick', function () {
    S.termPaused = !S.termPaused;
    if (S.termPaused) {
      appendTerm('dim', '[output paused - press PAUSE to resume]');
      if (el('termHold')) { el('termHold').innerHTML = 'PAUSED'; }
    } else {
      flushTermPending();
    }
    applyTermView();
  });
  bind('btnTermCompact', 'onclick', function () {
    S.termCompact = !S.termCompact;
    applyTermView();
  });
  bind('term', 'onmousewheel', function (ev) {
    var e = ev || window.event;
    if ((e.wheelDelta || 0) > 0 && S.termFollow) {
      S.termFollow = false;
      applyTermView();
    }
  });
  bind('term', 'onscroll', function () {
    var t = el('term');
    if (!t) { return; }
    var near = (t.scrollHeight - t.scrollTop - t.clientHeight) < 28;
    if (near !== S.termFollow) {
      S.termFollow = near;
      applyTermView();
    }
  });
  bind('termInput', 'onkeydown', function (ev) {
    var e = ev || window.event;
    var k = e.keyCode;
    if (k === 13) {
      var v = this.value;
      if (v) { S.termHistory.push(v); S.termIdx = S.termHistory.length; }
      this.value = '';
      runTerminal(v);
      if (e.preventDefault) { e.preventDefault(); }
      return false;
    }
    if (k === 38) {
      if (S.termIdx > 0) { S.termIdx--; this.value = S.termHistory[S.termIdx]; }
      if (e.preventDefault) { e.preventDefault(); }
      return false;
    }
    if (k === 40) {
      if (S.termIdx < S.termHistory.length - 1) { S.termIdx++; this.value = S.termHistory[S.termIdx]; }
      else { S.termIdx = S.termHistory.length; this.value = ''; }
      if (e.preventDefault) { e.preventDefault(); }
      return false;
    }
    if (k === 27) { this.value = ''; }
    return true;
  });

  var quick = document.getElementsByTagName('button');
  for (var j = 0; j < quick.length; j++) {
    if (quick[j].className === 'chipbtn') {
      quick[j].onclick = function () {
        var c = this.getAttribute('data-cmd');
        el('termInput').value = c;
        el('termInput').focus();
        runTerminal(c);
        el('termInput').value = '';
      };
    }
  }

  bind('btnAuditLoad', 'onclick', loadAudit);
  bind('btnAuditRefresh', 'onclick', refreshAuditList);
  bind('btnAuditOpen', 'onclick', function () {
    try { S.sh.Run('explorer.exe ' + q(S.audit), 1, false); } catch (e) { }
  });
}

/* ------------------------------- boot --------------------------------- */
function computeWindowLock() {
  /* Fit inside the work area, not just the screen. The extra margin covers
     the HTA caption, borders and display scaling so the bottom edge and the
     status bar do not end up under the taskbar. */
  var aw = screen.availWidth || 1280;
  var ah = screen.availHeight || 800;
  var w = aw - 40;
  var h = ah - 80;
  if (w > 1480) { w = 1480; }
  if (h > 940) { h = 940; }
  if (w < 820) { w = Math.max(640, aw - 12); }
  if (h < 520) { h = Math.max(420, ah - 40); }
  return { w: w, h: h, aw: aw, ah: ah };
}

function centerWindow() {
  try {
    var v = computeWindowLock();
    S.winLock.w = v.w;
    S.winLock.h = v.h;
    window.resizeTo(v.w, v.h);
    window.moveTo(Math.max(0, Math.floor((v.aw - v.w) / 2)),
                  Math.max(0, Math.floor((v.ah - v.h) / 2)));
  } catch (e) { }
}

/* Window size is fixed by centerWindow() at boot and never changed again.
   Runtime resizing could move the rail/status area off the display and fight
   a deliberate maximize. Kept as a documented no-op so a stray legacy call
   cannot resize anything. */
function clampWindow() {
  return;
}

function init() {
  S.fso = new ActiveXObject('Scripting.FileSystemObject');
  S.sh = new ActiveXObject('WScript.Shell');
  S.base = baseDir();
  S.engine = S.base + '\\engine\\NetTruder.ps1';
  S.shim = S.base + '\\engine\\shim.vbs';
  S.root = S.sh.ExpandEnvironmentStrings('%LOCALAPPDATA%') + '\\NetTruder';
  S.runs = S.root + '\\runs';
  S.audit = S.root + '\\audit';
  S.state = S.root + '\\state';

  if (document.documentMode && document.documentMode < 9) {
    alert('NetTruder needs IE document mode 9 or newer. The HTA reported mode ' + document.documentMode + '.');
  }

  try {
    ensureDir(S.root);
    ensureDir(S.runs);
    ensureDir(S.audit);
    ensureDir(S.state);
  } catch (e) {
    alert('NetTruder could not create its data folder:\n' + S.root + '\n\n' + e.message);
  }

  setCwd(S.sh.ExpandEnvironmentStrings('%USERPROFILE%'));
  termBanner();
  wire();
  centerWindow();

  if (!S.fso.FileExists(S.engine)) {
    pushConsole('err', 'Engine not found at ' + S.engine, 'boot');
  } else {
    pushConsole('ok', 'NETTRUDER ' + S.version + ' online', 'boot');
    pushConsole('dim', 'Read-only by default. IPS rules are prefixed NetTruder-IPS- and expire automatically.', 'boot');
  }

  var sub = localSubnet();
  if (sub) { el('targets').value = sub; }
  el('targets').onkeydown = function (ev) {
    var e = ev || window.event;
    if (e.keyCode === 13) { startSweep(); if (e.preventDefault) { e.preventDefault(); } return false; }
    return true;
  };

  renderHosts();
  renderDetail();
  renderSession();
  renderSiteImport();
  refreshAuditList();
  updateStats();
  refreshChips();
  loadOnboard();
  if (S.onboard.seen) { showViewHint('sweep'); }
  else { openOnboard(true); }

  window.setInterval(function () {
    el('clock').innerHTML = hhmmss();
  }, 1000);

  window.setInterval(pumpAll, 220);

  window.setInterval(function () {
    if (S.hostDirty) { S.hostDirty = false; renderHosts(); renderDetail(); }
    if (S.postureDirty) { S.postureDirty = false; renderPosture(); }
    if (S.research.dirty) { renderResearch(); }
    if (S.flow.dirty) { renderFlow(); }
    if (S.web.dirty) { renderWeb(); }
    if (S.site.dirty) { renderSiteImport(); }
    if (S.code.dirty) { renderCode(); }
    if (S.inv.dirty) { renderInv(); }
    if (S.net.dirty) { renderNet(); }
    if (S.triage.dirty) { renderTriage(); }
    if (S.av.dirty) { renderAv(); }
    if (S.data.dirty) { renderData(); }
    renderSession();
  }, 380);

  window.setInterval(function () {
    var st = S.streams.watch;
    if (st && !st.done) { startStream('expire', 'expire', {}); }
  }, 60000);

  if (S.fso.FileExists(S.engine)) {
    startStream('status', 'status', {});
  }
}

window.onload = init;
window.onunload = stopAllStreams;
