@echo off
title Mentorust Campus Auth
REM ============================================================
REM  CSUFT campus network authentication (Ruijie EAPOL)
REM
REM  Credentials are NOT stored in this file. The password is read
REM  from the console without echo and handed to the program over
REM  stdin (--cred-stdin), so it never appears in the process
REM  command line.
REM
REM  The adapter is taken from the GUI config next to the exe.
REM ============================================================

setlocal
set "EXE=%~dp0mentorust.exe"

if not exist "%EXE%" (
    echo mentorust.exe not found next to this script.
    pause
    exit /b 1
)

set "NIC="
if exist "%~dp0mentorust-gui.ini" (
    for /f "tokens=1,* delims==" %%a in ('findstr /b "nic=" "%~dp0mentorust-gui.ini"') do set "NIC=%%b"
)

if "%NIC%"=="" (
    echo No adapter recorded in mentorust-gui.ini.
    echo Open mentorust.exe once, pick the wired adapter, and connect.
    pause
    exit /b 1
)

set /p "USER=Account: "

set "PASSWORD="
for /f "delims=" %%p in ('set /p "PASSWORD=Password: "') do set "PASSWORD=%%p"

echo.
echo Authenticating as %USER% on %NIC% ...

rem --cred-stdin reads "user" and "password" as two lines from stdin.
( echo %USER% & echo %PASSWORD% ) | "%EXE%" auth -n "%NIC%" --cred-stdin

echo.
echo Authentication process exited.
pause
