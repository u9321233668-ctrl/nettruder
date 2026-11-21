// NetTruder // LOLBAS Research Lab - inert marker probe
// Appends one line to %NETTRUDER_LAB_DIR%\markers.log and exits.
// No network, no persistence, no payload, no hidden window.

var fso = new ActiveXObject('Scripting.FileSystemObject');
var sh = new ActiveXObject('WScript.Shell');

var dir = sh.ExpandEnvironmentStrings('%NETTRUDER_LAB_DIR%');
if (dir === '%NETTRUDER_LAB_DIR%' || !dir) {
  dir = sh.ExpandEnvironmentStrings('%LOCALAPPDATA%') + '\\NetTruder\\lab';
}

ensureFolder(fso, dir);

var logPath = dir + '\\markers.log';
var f = fso.OpenTextFile(logPath, 8, true);
f.WriteLine(stamp() + ' | wsh-js | ' + WScript.ScriptName + ' | '
  + sh.ExpandEnvironmentStrings('%USERNAME%') + '@'
  + sh.ExpandEnvironmentStrings('%COMPUTERNAME%'));
f.Close();

function ensureFolder(fs, path) {
  if (fs.FolderExists(path)) { return; }
  var parent = fs.GetParentFolderName(path);
  if (parent) { ensureFolder(fs, parent); }
  fs.CreateFolder(path);
}

function pad2(n) {
  return (n < 10 ? '0' : '') + n;
}

function stamp() {
  var d = new Date();
  return d.getFullYear() + '-' + pad2(d.getMonth() + 1) + '-' + pad2(d.getDate())
    + ' ' + pad2(d.getHours()) + ':' + pad2(d.getMinutes()) + ':' + pad2(d.getSeconds());
}
