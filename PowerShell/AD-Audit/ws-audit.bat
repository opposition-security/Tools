@echo off
:: Set the file name to the name of the workstation being audited
FOR /F "tokens=*" %%g IN ('hostname') do (SET hostname=%%g)
set filename=%hostname%

:: Open file for writing
call :sub > %filename%.txt
exit /b

:sub
:: Check if Domain Joined
echo --------------------------------Domain Status--------------------------------
systeminfo | findstr /B "Domain"
echo.

:: Get Password Policy
echo --------------------------------Computer Password Policy--------------------------------
net accounts
echo.

:: Get BitLocker Status
echo --------------------------------BitLocker Status--------------------------------
manage-bde -status
echo.

:: Get the current logged in user
echo --------------------------------Current Logged on User--------------------------------
query user
echo.

:: Get the local users group members
echo --------------------------------Local Users Group--------------------------------
net localgroup users
echo.

:: Get the local administrators group members
echo --------------------------------Local Administrators Group--------------------------------
net localgroup administrators
echo.

:: Close file
exit /b

set finish-message=The script has completed
echo %finish-message%