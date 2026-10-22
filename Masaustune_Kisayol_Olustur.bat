@echo off
chcp 65001 > nul
echo ThreatScout Masaüstü Kısayolu Oluşturuluyor...

set SCRIPT_DIR=%~dp0
set TARGET_BAT=%SCRIPT_DIR%baslat.bat
set SHORTCUT_PATH=%USERPROFILE%\Desktop\ThreatScout.lnk

powershell -Command "$ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut('%SHORTCUT_PATH%'); $s.TargetPath = '%TARGET_BAT%'; $s.WorkingDirectory = '%SCRIPT_DIR%'; $s.Description = 'ThreatScout Siber Tehdit İstihbarat Platformu'; $s.Save()"

echo.
echo [BAŞARILI] Masaüstünüze "ThreatScout" kısayolu eklendi!
echo Artık masaüstünüzdeki kısayola çift tıklayarak uygulamayı açabilirsiniz.
echo.
pause
