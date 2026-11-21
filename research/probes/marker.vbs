' NetTruder // LOLBAS Research Lab - inert marker probe
' Appends one line to %NETTRUDER_LAB_DIR%\markers.log and exits.
' No network, no persistence, no payload, no hidden window.

Option Explicit

Dim fso, sh, dir, f

Set fso = CreateObject("Scripting.FileSystemObject")
Set sh = CreateObject("WScript.Shell")

dir = sh.ExpandEnvironmentStrings("%NETTRUDER_LAB_DIR%")
If dir = "%NETTRUDER_LAB_DIR%" Or dir = "" Then
    dir = sh.ExpandEnvironmentStrings("%LOCALAPPDATA%") & "\NetTruder\lab"
End If

EnsureFolder fso, dir

Set f = fso.OpenTextFile(dir & "\markers.log", 8, True)
f.WriteLine Stamp() & " | wsh-vbs | " & WScript.ScriptName & " | " & sh.ExpandEnvironmentStrings("%USERNAME%") & "@" & sh.ExpandEnvironmentStrings("%COMPUTERNAME%")
f.Close

Sub EnsureFolder(fs, path)
    Dim parent
    If fs.FolderExists(path) Then Exit Sub
    parent = fs.GetParentFolderName(path)
    If parent <> "" Then EnsureFolder fs, parent
    fs.CreateFolder path
End Sub

Function Stamp()
    Dim d
    d = Now
    Stamp = Year(d) & "-" & Pad2(Month(d)) & "-" & Pad2(Day(d)) & " " & _
            Pad2(Hour(d)) & ":" & Pad2(Minute(d)) & ":" & Pad2(Second(d))
End Function

Function Pad2(n)
    Pad2 = Right("0" & CStr(n), 2)
End Function
