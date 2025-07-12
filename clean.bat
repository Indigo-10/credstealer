@echo off
echo Cleaning up build artifacts...

REM Remove build artifacts
if exist *.obj (
    echo [*] Removing object files...
    del /q *.obj
)

if exist *.exp (
    echo [*] Removing export files...
    del /q *.exp
)

if exist *.lib (
    echo [*] Removing library files...
    del /q *.lib
)

if exist *.pdb (
    echo [*] Removing debug files...
    del /q *.pdb
)

if exist *.ilk (
    echo [*] Removing incremental link files...
    del /q *.ilk
)

if exist *.idb (
    echo [*] Removing debug database files...
    del /q *.idb
)

if exist *.tmp (
    echo [*] Removing temporary files...
    del /q *.tmp
)

if exist *.log (
    echo [*] Removing log files...
    del /q *.log
)

REM Remove final DLL (optional - uncomment if you want to remove it too)
REM if exist credStealer.dll (
REM     echo [*] Removing credStealer.dll...
REM     del /q credStealer.dll
REM )

REM Remove credential files (if they exist)
if exist credentials.txt (
    echo [*] Removing credential files...
    del /q credentials.txt
)

if exist "c:\temp\credentials.txt" (
    echo [*] Removing credential files from c:\temp...
    del /q "c:\temp\credentials.txt"
)

echo [*] Cleanup complete!
echo [*] Note: credStealer.dll was preserved. Remove it manually if needed.
pause 