' NetTruder engine shim.
' Spawns one hidden, short-lived PowerShell worker for a single request file.
' The console never launches PowerShell directly; it writes a JSON request and
' calls this shim, which keeps the parent/child chain as mshta -> wscript -> PowerShell.
Option Explicit

Dim fso, sh, here, req, cmd
Set fso = CreateObject("Scripting.FileSystemObject")
Set sh = CreateObject("WScript.Shell")

here = fso.GetParentFolderName(WScript.ScriptFullName)

If WScript.Arguments.Count < 1 Then
  WScript.Quit 2
End If

req = WScript.Arguments(0)

cmd = "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden" & _
      " -File """ & here & "\NetTruder.ps1"" -RequestFile """ & req & """"

sh.Run cmd, 0, False
WScript.Quit 0
