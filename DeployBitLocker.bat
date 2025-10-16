@echo off
setlocal enabledelayedexpansion

set WORK_DIR=C:\ProgramData\BitLockerDeploy
set LOG_FILE=%WORK_DIR%\DeployBitLocker.log
set TARGET_EXE=%WORK_DIR%\EnableBitLocker.exe
set SOURCE_EXE=\\Server01\EnableBitLocker.exe

if not exist "%WORK_DIR%" (
    mkdir "%WORK_DIR%" >nul 2>&1
)

echo ================================================== >> "%LOG_FILE%"
echo [%date% %time%] Script started. User: %USERNAME% >> "%LOG_FILE%"
echo Running under: %COMPUTERNAME%\%USERNAME% >> "%LOG_FILE%"
whoami >> "%LOG_FILE%" 2>&1

if exist "%TARGET_EXE%" (
    echo [%date% %time%] Deleting old EXE: %TARGET_EXE% >> "%LOG_FILE%"
    del /f /q "%TARGET_EXE%" >nul 2>&1
)

echo [%date% %time%] Copying file from %SOURCE_EXE% to %TARGET_EXE% >> "%LOG_FILE%"
copy "%SOURCE_EXE%" "%TARGET_EXE%" >> "%LOG_FILE%" 2>&1

if not exist "%TARGET_EXE%" (
    echo [%date% %time%] ERROR: Failed to copy EXE file. >> "%LOG_FILE%"
    exit /b 1
)

echo [%date% %time%] Executing %TARGET_EXE% >> "%LOG_FILE%"
"%TARGET_EXE%" >> "%LOG_FILE%" 2>&1
set RETCODE=%ERRORLEVEL%

echo [%date% %time%] EXE finished with return code %RETCODE% >> "%LOG_FILE%"

echo [%date% %time%] Script finished. >> "%LOG_FILE%"
echo ================================================== >> "%LOG_FILE%"
exit /b %RETCODE%
