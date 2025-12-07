@echo off
REM Clean Windows launcher to run the Python `cicflowmeter` wrapper script from repository root.
REM Usage: run_cicflowmeter.bat [args...]

SETLOCAL
SET SCRIPT_DIR=%~dp0
python "%SCRIPT_DIR%cicflowmeter" %*
ENDLOCAL
