@echo off
title ThreatScout Launcher

cd /d "%~dp0threatscout"

if not exist .venv\Scripts\python.exe goto no_venv

echo [1/2] Tehdit Analiz Motoru Baslatiliyor...
start "" "http://127.0.0.1:8000"

echo [2/2] Sunucu aktif: http://127.0.0.1:8000
echo Kapatmak icin bu pencereyi kapatabilirsiniz.
echo.

.venv\Scripts\python.exe -m uvicorn threatscout.api:app --host 127.0.0.1 --port 8000
goto end

:no_venv
echo HATA: Sanal ortam (.venv) bulunamadi!
pause

:end
