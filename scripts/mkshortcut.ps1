$w = New-Object -ComObject WScript.Shell
$lnk = $w.CreateShortcut("$env:USERPROFILE\Desktop\Sentinel.lnk")
$lnk.TargetPath = "$PSScriptRoot\..\cmd\sentinel-gui\build\bin\sentinel-gui.exe"
$lnk.WorkingDirectory = "$PSScriptRoot\.."
$lnk.IconLocation = "$PSScriptRoot\..\cmd\sentinel-gui\build\windows\icon.ico"
$lnk.Save()
"lnk ok"
