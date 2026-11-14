@echo off
rem Double-click to share this PC's internet with the phone connected by USB.
rem Close this window or press Ctrl+C to stop.
cd /d "%~dp0"
revtether.exe run %*
pause
