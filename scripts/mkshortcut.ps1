$w = New-Object -ComObject WScript.Shell
$lnk = $w.CreateShortcut("$env:USERPROFILE\Desktop\Sentinel.lnk")
$lnk.TargetPath = "$PSScriptRoot\..\sentinel-gui.exe"
$lnk.WorkingDirectory = "$PSScriptRoot\.."
$lnk.IconLocation = "$PSScriptRoot\..\sentinel.ico"
$lnk.Save()
"lnk ok"
