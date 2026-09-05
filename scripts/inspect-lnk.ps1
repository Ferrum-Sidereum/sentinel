$w = New-Object -ComObject WScript.Shell
$s = $w.CreateShortcut("$env:USERPROFILE\Desktop\Sentinel.lnk")
"target=" + $s.TargetPath
"work=" + $s.WorkingDirectory
"icon=" + $s.IconLocation
