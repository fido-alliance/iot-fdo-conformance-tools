@echo off
set GODEBUG=x509sha1=1
set CURRENT_PATH=%cd%
start "" "%CURRENT_PATH%\iot-fdo-conformance-tools-windows.exe" serve
