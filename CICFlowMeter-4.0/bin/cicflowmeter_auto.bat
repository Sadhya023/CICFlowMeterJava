@echo off
REM =====================================================
REM  Automate CICFlowMeter Live Capture for 2 Minutes
REM =====================================================

setlocal enabledelayedexpansion

REM --- BASE DIRECTORY (where script is located) ---
set "BASE_DIR=%~dp0"
set "CIC_BAT=%BASE_DIR%CICFlowMeter.bat"
set "OUTPUT_DIR=%BASE_DIR%output"
set "DATA_DIR=%BASE_DIR%data"
set "PCAP_FILE=%DATA_DIR%\livecapture.pcap"
set "DURATION=120"

echo.
echo ===============================
echo   CICFlowMeter Live Capture
echo ===============================
echo.

if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"
if not exist "%DATA_DIR%" mkdir "%DATA_DIR%"

echo Starting live network capture for %DURATION% seconds...
echo (Press Ctrl+C to stop early)
echo.

REM === Capture live traffic (choose correct interface index with dumpcap -D) ===
dumpcap -i 1 -a duration:%DURATION% -w "%PCAP_FILE%" >nul 2>&1

echo.
echo Capture finished. Converting to CSV...
echo.

REM === Convert PCAP to CSV ===
pushd "%BASE_DIR%"
call "%CIC_BAT%" "%PCAP_FILE%" "%OUTPUT_DIR%"
popd

echo.
echo CSV saved to: %OUTPUT_DIR%\livecapture.csv
echo.

pause
