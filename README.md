# Credential Stealer - MSV1_0.dll Hook

This project demonstrates a technique for intercepting clear-text credentials during interactive logons by hooking the `SpAcceptCredentials` function in `msv1_0.dll`.

## Overview

The credential stealer works by:

1. **Loading into LSASS**: The DLL is injected into the `lsass.exe` process
2. **Pattern Scanning**: Searches for the `SpAcceptCredentials` function signature in `msv1_0.dll` memory
3. **Function Hooking**: Patches the function to redirect execution to our hook
4. **Credential Interception**: Captures clear-text credentials during interactive logons
5. **File Output**: Writes credentials to `c:\temp\credentials.txt`
6. **Unhooking**: Temporarily restores the original function to prevent crashes
7. **Re-hooking**: Reinstalls the hook after a delay

## Technical Details

### Target Function
- **Function**: `SpAcceptCredentials` in `msv1_0.dll`
- **Purpose**: Handles interactive logon authentication
- **Logon Types**: 2 (Interactive), 10 (RemoteInteractive)
- **Credentials**: Clear-text username, domain, and password

### Signature Pattern
```cpp
char startOfPatternSpAccecptedCredentials[] = { 
    0x48, 0x83, 0xec, 0x20, 0x49, 0x8b, 0xd9, 0x49, 0x8b, 0xf8, 0x8b, 0xf1, 0x48 
};
```

### Hook Mechanism
1. **Assembly Patch**: `mov rax, <hook_address>; jmp rax`
2. **Original Function**: Stored for later restoration
3. **Thread Safety**: Uses delay-based re-hooking to prevent infinite loops

## Build Instructions

### Prerequisites
- Visual Studio 2019/2022 with C++ development tools
- Windows SDK
- Administrator privileges for testing

### Build Steps
1. Open "Developer Command Prompt for VS 2019/2022"
2. Navigate to project directory
3. Run: `build.bat`

### Manual Build
```cmd
cl /LD credStealer.cpp /Fe:credStealer.dll /link /DEF:credStealer.def
```

## Usage

### Injection Methods
1. **Process Injection**: Use tools like Process Hacker, Process Explorer, or custom injectors
2. **DLL Injection**: Load the DLL into `lsass.exe` process
3. **Manual Testing**: Use debugging tools to test the hook

### Monitoring
- **Output File**: `c:\temp\credentials.txt`
- **Format**: `username@domain:password`
- **Server**: Optional Python server on port 8000 for remote monitoring

### Testing
1. Build the DLL
2. Inject into `lsass.exe` (requires elevated privileges)
3. Perform interactive logon (Ctrl+Alt+Del, RDP, etc.)
4. Check `c:\temp\credentials.txt` for captured credentials

## Files

- `credStealer.cpp` - Main DLL source code
- `credStealer.def` - Module definition file
- `build.bat` - Build script
- `server.py` - Optional HTTP server for credential monitoring
- `CppProperties.json` - VS Code configuration

## Security Considerations

⚠️ **WARNING**: This tool is for educational and authorized testing purposes only!

- **Legal Use**: Only use in authorized testing environments
- **Detection**: Modern EDR solutions may detect this technique
- **Persistence**: This is a memory-only technique, no persistence
- **Privileges**: Requires elevated privileges to inject into LSASS

## Detection & Mitigation

### Detection Methods
- **Memory Scanning**: Look for hooked functions in `msv1_0.dll`
- **File Monitoring**: Monitor `c:\temp\credentials.txt`
- **Process Injection**: Detect DLL injection into LSASS
- **Signature Scanning**: Detect the hook pattern

### Mitigation
- **Credential Guard**: Prevents credential theft
- **LSA Protection**: Protects LSASS from injection
- **Memory Protection**: DEP, ASLR, CFG
- **Monitoring**: EDR solutions with memory scanning

## Technical Notes

### Architecture
- **Target**: x64 Windows systems
- **Dependencies**: Windows Security APIs
- **Memory**: Requires RWX memory permissions for hooking

### Limitations
- **Windows Version**: May need signature updates for different Windows versions
- **Antivirus**: Likely to be detected by modern security solutions
- **Stability**: Hooking system functions can cause instability

## Disclaimer

This project is provided for educational purposes only. The authors are not responsible for any misuse of this code. Always ensure you have proper authorization before testing security tools in any environment. 