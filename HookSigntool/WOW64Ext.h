
#ifndef _WINDOWS_WOW64Ext___H
#define _WINDOWS_WOW64Ext___H


#define WIN32_LEAN_AND_MEAN

#define SPEC 
#include <windows.h>
#define PROCESS_INVALID  0  // eroo
#define PROCESS_X64      1  // X64
#define PROCESS_X86      2  // X86



extern "C"
{

	 DWORD64  VirtualAllocEx64(HANDLE hProcess, DWORD64 lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
	 BOOL  VirtualFreeEx64(HANDLE hProcess, DWORD64 lpAddress, SIZE_T dwSize, DWORD dwFreeType);
	 BOOL  VirtualProtectEx64(HANDLE hProcess, DWORD64 lpAddress, DWORD64 dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
	 
	 
	 BOOL  ReadProcessMemory64(HANDLE hProcess, DWORD64 lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead);
	 BOOL  WriteProcessMemory64(HANDLE hProcess, DWORD64 lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);
	 HANDLE  CreateRemoteThread64(HANDLE hProcess, DWORD64 lpStartAddress, DWORD64 lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
	 DWORD64 GetProcessModules64(HANDLE hRemoteProcess, const char* moduleName, long& len);
	 DWORD64 GetProcessModulesProc64(HANDLE hRemoteProcess, const char* moduleName, const char* procName);
	 BOOL TerminateProcess64( HANDLE hProcess, HANDLE hPpid, UINT uExitCode);
	 
	 DWORD64  InjectDll64(DWORD hProcess, const char* lpDllName);
	 
	 
	 BOOL WINAPI UninjectDll64(DWORD dwProcessId, DWORD64 hModule);
	 
	 long  GetProceBitess(DWORD dwProcessId);
	 long  GetProceBitess2(HANDLE hProcess);

}

#endif