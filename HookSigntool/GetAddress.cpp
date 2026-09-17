#define  _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <windows.h>
#include <Psapi.h>
#include <cmath>
#include "GetAddress.h"

#include <winternl.h>
#pragma comment(lib,"Psapi.lib")

LONG64 GetAddress::GetSignAddRess(const char* ModuleName, const char* str)
{
	if (!str)
	{
		return -1;
	}
	HMODULE addsr = 0;
	GetModuleHandleExA(NULL, ModuleName, &addsr);
	if (addsr == 0)
	{
		return -5;
	}

	MODULEINFO uts = { 0 };

	if (!GetModuleInformation(GetCurrentProcess(), addsr, &uts, sizeof(MODULEINFO)))
	{
		-7;
	}
	int slen = FindByteSet(uts.lpBaseOfDll, str, uts.SizeOfImage);
	if (slen < 0)
	{
		
		slen = -1;
		return slen;
	}
	UINT64 ret = (UINT64)uts.lpBaseOfDll + slen;
	return ret;
}

long GetAddress::FindByteSet(LPVOID addrs, const char* str, DWORD size)
{
	
	if (!addrs || !str || (ULONG64)addrs <= 0x10000 || size <= 1 || *str == '\0')
	{
		return -1; //
	}

	int strLen = strlen(str);
	char filteredChars[0x1000] = { 0 }; 

	
	for (size_t i = 0; i < strLen && strlen(filteredChars) < 0x1000 - 1; i++)
	{
		char c = str[i];
		
		if ((c >= '0' && c <= '9') ||
			(c >= 'A' && c <= 'F') ||
			(c >= 'a' && c <= 'f') ||
			c == '*' || c == '?')
		{
			filteredChars[strlen(filteredChars)] = c;
		}
	}

	// 
	toUpper(filteredChars);
	int filteredLen = strlen(filteredChars);
	if (filteredLen % 2 != 0)
	{
		return -2; 
	}

	const int MAX_PATTERN_LEN = 0x500;
	BYTE pattern[MAX_PATTERN_LEN] = { 0 };
	int patternLen = filteredLen / 2;
	if (patternLen <= 0 || patternLen > MAX_PATTERN_LEN)
	{
		return -3; 
	}

	char hexBuf[3] = { 0 }; 
	for (size_t i = 0; i < patternLen; i++)
	{
		memcpy(hexBuf, filteredChars + i * 2, 2);
		hexBuf[2] = '\0'; 

		
		if (hexBuf[0] == '*' || hexBuf[1] == '*' ||
			hexBuf[0] == '?' || hexBuf[1] == '?')
		{
			pattern[i] = 0xCC; 
		}
		else
		{
			
			UINT64 hexVal = HexToInt(hexBuf);
			if (hexVal > 0xFF) 
			{
				return -3; 
			}
			pattern[i] = (BYTE)hexVal;
		}
	}

	PUCHAR pMemBase = (PUCHAR)addrs;
	PUCHAR pPattern = pattern;
	DWORD totalSize = size; 

	
	DWORD maxOffset = totalSize - patternLen;
	if (maxOffset <= 0)
	{
		return -4; 
	}

	__try
	{
		
		if (totalSize <= 0x2000)
		{
			for (DWORD i = 0; i <= maxOffset; i++)
			{
				BOOL isMatch = TRUE;
				for (int j = 0; j < patternLen; j++)
				{
					
					if (pPattern[j] != 0xCC && pMemBase[i + j] != pPattern[j])
					{
						isMatch = FALSE;
						break;
					}
				}
				if (isMatch)
				{
					return i;
				}
			}
			return -4; 
		}

		
		SYSTEM_INFO sysInfo = { 0 };
#if _WIN64
		GetNativeSystemInfo(&sysInfo); 
#else
		GetSystemInfo(&sysInfo);      
#endif
		DWORD pageSize = sysInfo.dwPageSize;

		
		for (DWORD pageIdx = 0; ; pageIdx++)
		{
			DWORD64 pageOffset = (DWORD64)pageIdx * pageSize;
			LPVOID pageBase = (LPVOID)((DWORD64)pMemBase + pageOffset);

			
			MEMORY_BASIC_INFORMATION mbi = { 0 };
			if (!VirtualQuery(pageBase, &mbi, sizeof(mbi)))
			{
				break; 
			}

			if (mbi.State != MEM_COMMIT)
			{
				continue;
			}

			DWORD64 pageEndOffset = pageOffset + mbi.RegionSize;
			DWORD64 scanStart = pageOffset;
			DWORD64 scanEnd = min(pageEndOffset, (DWORD64)totalSize) - patternLen;

			if (scanStart > scanEnd)
			{
				continue; 
			}

			for (DWORD64 i = scanStart; i <= scanEnd; i++)
			{
				BOOL isMatch = TRUE;
				for (int j = 0; j < patternLen; j++)
				{
					if (pPattern[j] != 0xCC && pMemBase[i + j] != pPattern[j])
					{
						isMatch = FALSE;
						break;
					}
				}
				if (isMatch)
				{
					return (DWORD)i; 
				}
			}

			if (pageEndOffset >= totalSize)
			{
				break;
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) 
	{
		return -5; 
	}

	return -4; 
}

char GetAddress::toUpper(char* src)
{

	if (src == NULL)
	{
		return '\0'; 
	}

	char* p = src; 
	while (*p != '\0') 
	{
	
		if (*p >= 'a' && *p <= 'z')
		{
			*p -= 32; 
		}
		p++; 
	}

	return *src;
}

UINT64 __stdcall GetAddress::HexToInt(char* strhex)
{
	
	if (!strhex || *strhex == '\0')
	{
		return 0;
	}

	
	toUpper(strhex);
	UINT64 strLen = strlen(strhex);

	UINT64 startIdx = 0;
	if (strLen >= 2 && strhex[0] == '0' && strhex[1] == 'X')
	{
		startIdx = 2; 
	}

	char hexStr[256] = { 0 };
	UINT64 validLen = 0;
	for (UINT64 i = startIdx; i < strLen && validLen < 255; i++)
	{
		char c = strhex[i];

		if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F'))
		{
			hexStr[validLen++] = c;
		}
		else
		{
			return 0; 
		}
	}

	if (validLen == 0)
	{
		return 0; 
	}

	UINT64 result = 0;
	for (UINT64 i = 0; i < validLen; i++)
	{
		result <<= 4; 
		char c = hexStr[i];
		if (c >= '0' && c <= '9')
		{
			result += (c - '0');
		}
		else // A-F
		{
			result += (c - 'A' + 10);
		}
	}

	return result;
}





LPVOID GetSignAddRess(PVOID addrs, const char* str, DWORD size)
{
	GetAddress fid;
	int slen = fid.FindByteSet(addrs, str, size);
	if (slen < 0)
	{

		MessageBox(0, "没有找到地址", 0, 0);
		return (LPVOID)slen;
	}
	UINT64 ret = (UINT64)addrs + slen;

	return (LPVOID)ret;
}


DWORD MyGetFileSize(const char* file)
{
	long size = 0;
	FILE* fp = fopen(file, "r");
	if (!fp)
	{
		return 0;
	}
	fseek(fp, 0, SEEK_END);
	size = ftell(fp);
	//printf("size: %ld\n", size);
	/* fseek(fp, 0, SEEK_SET); */
	fclose(fp);
	return size;
	//原文链接：https ://blog.csdn.net/bluebird_shao/article/details/126248309
}

#define NT_SUCCESS(x) ((x) >= 0)
//#define ProcessBasicInformation 0

typedef NTSTATUS(NTAPI* pfnNtWow64QueryInformationProcess64)(
	IN HANDLE ProcessHandle,
	IN ULONG ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL
	);


typedef NTSTATUS(NTAPI* pfnNtWow64ReadVirtualMemory64)(
	IN HANDLE ProcessHandle,
	IN PVOID64 BaseAddress,
	OUT PVOID Buffer,
	IN ULONG64 Size,
	OUT PULONG64 NumberOfBytesRead
	);

typedef
NTSTATUS(WINAPI* pfnNtQueryInformationProcess)
(HANDLE ProcessHandle, ULONG ProcessInformationClass,
	PVOID ProcessInformation, UINT32 ProcessInformationLength,
	UINT32* ReturnLength);

typedef struct _PROCESS_BASIC_INFORMATION32 {
	NTSTATUS ExitStatus;
	UINT32 PebBaseAddress;
	UINT32 AffinityMask;
	UINT32 BasePriority;
	UINT32 UniqueProcessId;
	UINT32 InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION32;

typedef struct _UNICODE_STRING32
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING32, * PUNICODE_STRING32;

typedef struct _PEB32
{
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR BitField;
	ULONG Mutant;
	ULONG ImageBaseAddress;
	ULONG Ldr;
	ULONG ProcessParameters;
	ULONG SubSystemData;
	ULONG ProcessHeap;
	ULONG FastPebLock;
	ULONG AtlThunkSListPtr;
	ULONG IFEOKey;
	ULONG CrossProcessFlags;
	ULONG UserSharedInfoPtr;
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	ULONG ApiSetMap;
} PEB32, * PPEB32;

typedef struct _PEB_LDR_DATA32
{
	ULONG Length;
	BOOLEAN Initialized;
	ULONG SsHandle;
	LIST_ENTRY32 InLoadOrderModuleList;
	LIST_ENTRY32 InMemoryOrderModuleList;
	LIST_ENTRY32 InInitializationOrderModuleList;
	ULONG EntryInProgress;
} PEB_LDR_DATA32, * PPEB_LDR_DATA32;

typedef struct _LDR_DATA_TABLE_ENTRY32
{
	LIST_ENTRY32 InLoadOrderLinks;
	LIST_ENTRY32 InMemoryOrderModuleList;
	LIST_ENTRY32 InInitializationOrderModuleList;
	ULONG DllBase;
	ULONG EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING32 FullDllName;
	UNICODE_STRING32 BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union
	{
		LIST_ENTRY32 HashLinks;
		ULONG SectionPointer;
	};
	ULONG CheckSum;
	union
	{
		ULONG TimeDateStamp;
		ULONG LoadedImports;
	};
	ULONG EntryPointActivationContext;
	ULONG PatchInformation;
} LDR_DATA_TABLE_ENTRY32, * PLDR_DATA_TABLE_ENTRY32;

typedef struct _PROCESS_BASIC_INFORMATION64 {
	NTSTATUS ExitStatus;
	UINT32 Reserved0;
	UINT64 PebBaseAddress;
	UINT64 AffinityMask;
	UINT32 BasePriority;
	UINT32 Reserved1;
	UINT64 UniqueProcessId;
	UINT64 InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION64;
typedef struct _PEB64
{
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR BitField;
	ULONG64 Mutant;
	ULONG64 ImageBaseAddress;
	ULONG64 Ldr;
	ULONG64 ProcessParameters;
	ULONG64 SubSystemData;
	ULONG64 ProcessHeap;
	ULONG64 FastPebLock;
	ULONG64 AtlThunkSListPtr;
	ULONG64 IFEOKey;
	ULONG64 CrossProcessFlags;
	ULONG64 UserSharedInfoPtr;
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	ULONG64 ApiSetMap;
} PEB64, * PPEB64;

typedef struct _PEB_LDR_DATA64
{
	ULONG Length;
	BOOLEAN Initialized;
	ULONG64 SsHandle;
	LIST_ENTRY64 InLoadOrderModuleList;
	LIST_ENTRY64 InMemoryOrderModuleList;
	LIST_ENTRY64 InInitializationOrderModuleList;
	ULONG64 EntryInProgress;
} PEB_LDR_DATA64, * PPEB_LDR_DATA64;

typedef struct _UNICODE_STRING64
{
	USHORT Length;
	USHORT MaximumLength;
	ULONG64 Buffer;
} UNICODE_STRING64, * PUNICODE_STRING64;

typedef struct _LDR_DATA_TABLE_ENTRY64
{
	LIST_ENTRY64 InLoadOrderLinks;
	LIST_ENTRY64 InMemoryOrderModuleList;
	LIST_ENTRY64 InInitializationOrderModuleList;
	ULONG64 DllBase;
	ULONG64 EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING64 FullDllName;
	UNICODE_STRING64 BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union
	{
		LIST_ENTRY64 HashLinks;
		ULONG64 SectionPointer;
	};
	ULONG CheckSum;
	union
	{
		ULONG TimeDateStamp;
		ULONG64 LoadedImports;
	};
	ULONG64 EntryPointActivationContext;
	ULONG64 PatchInformation;
} LDR_DATA_TABLE_ENTRY64, * PLDR_DATA_TABLE_ENTRY64;





long GetAddress::GetX64EXE_Len(LONG64 exe, LONG64& bsar)
{
	HANDLE m_ProcessHandle = GetCurrentProcess();

	BOOL bSource = FALSE;

#if _WIN64

	bSource = TRUE;

#else

	bSource = FALSE;
	
#endif

	


	SYSTEM_INFO si;
	GetSystemInfo(&si);

	long ret = 0;
	HMODULE NtdllModule = GetModuleHandle("ntdll.dll");
	pfnNtWow64QueryInformationProcess64 NtWow64QueryInformationProcess64 = 0;
	pfnNtQueryInformationProcess NtQueryInformationProcess = 0;
	
	if ( bSource == TRUE)
	{
		
		pfnNtWow64QueryInformationProcess64 NtWow64QueryInformationProcess64 = (pfnNtWow64QueryInformationProcess64)GetProcAddress(NtdllModule, "NtQueryInformationProcess");
	
		PROCESS_BASIC_INFORMATION64 pbi64 = { 0 };
		if (NT_SUCCESS(NtWow64QueryInformationProcess64(m_ProcessHandle, ProcessBasicInformation, &pbi64, sizeof(pbi64), NULL)))
		{
			DWORD64 Ldr64 = 0;
			LIST_ENTRY64 ListEntry64 = { 0 };
			LDR_DATA_TABLE_ENTRY64 LDTE64 = { 0 };
			wchar_t ProPath64[256];
			if (ReadProcessMemory(m_ProcessHandle, (LPVOID)(pbi64.PebBaseAddress + offsetof(PEB64, Ldr)), &Ldr64, sizeof(Ldr64), NULL))
			{
				if (ReadProcessMemory(m_ProcessHandle, (LPVOID)(Ldr64 + offsetof(PEB_LDR_DATA64, InLoadOrderModuleList)), &ListEntry64, sizeof(LIST_ENTRY64), NULL))
				{
					if (ReadProcessMemory(m_ProcessHandle, (LPVOID)(ListEntry64.Flink), &LDTE64, sizeof(_LDR_DATA_TABLE_ENTRY64), NULL))
					{
						while (1)
						{
							if (LDTE64.InLoadOrderLinks.Flink == ListEntry64.Flink) break;
							if (ReadProcessMemory(m_ProcessHandle, (LPVOID)LDTE64.FullDllName.Buffer, ProPath64, sizeof(ProPath64), NULL))
							{
								//printf("模块基址:0x%llX\t 模块大小:0x%X\t 模块路径:%ls\n", LDTE64.DllBase, LDTE64.SizeOfImage, ProPath64);
								if (exe >= LDTE64.DllBase && exe <= (LDTE64.DllBase + LDTE64.SizeOfImage))
								{
									bsar = LDTE64.DllBase;
									ret = LDTE64.SizeOfImage;
									goto Ext;
								}

							}
							if (!ReadProcessMemory(m_ProcessHandle, (LPVOID)LDTE64.InLoadOrderLinks.Flink, &LDTE64, sizeof(_LDR_DATA_TABLE_ENTRY64), NULL)) break;
						}
					}
				}
			}
		}

	}
	else 
	{
		HMODULE NtdllModule = GetModuleHandle("ntdll.dll");
		pfnNtQueryInformationProcess NtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(NtdllModule, "NtQueryInformationProcess");
		PROCESS_BASIC_INFORMATION32 pbi32 = { 0 };
		if (NT_SUCCESS(NtQueryInformationProcess(m_ProcessHandle, ProcessBasicInformation, &pbi32, sizeof(pbi32), NULL)))
		{
			DWORD Ldr32 = 0;
			LIST_ENTRY32 ListEntry32 = { 0 };
			LDR_DATA_TABLE_ENTRY32 LDTE32 = { 0 };
			wchar_t ProPath32[256];
			if (ReadProcessMemory(m_ProcessHandle, (LPVOID)(pbi32.PebBaseAddress + offsetof(PEB32, Ldr)), &Ldr32, sizeof(Ldr32), NULL))
			{
				if (ReadProcessMemory(m_ProcessHandle, (LPVOID)(Ldr32 + offsetof(PEB_LDR_DATA32, InLoadOrderModuleList)),&ListEntry32, sizeof(LIST_ENTRY32), NULL))
				{
					if (ReadProcessMemory(m_ProcessHandle, (LPVOID)(ListEntry32.Flink), &LDTE32, sizeof(_LDR_DATA_TABLE_ENTRY32), NULL))
					{
						while (1)
						{
							if (LDTE32.InLoadOrderLinks.Flink == ListEntry32.Flink) break;
							if (ReadProcessMemory(m_ProcessHandle, LDTE32.FullDllName.Buffer, ProPath32, sizeof(ProPath32), NULL))
							{
								//printf("模块基址:0x%X\t 模块大小:0x%X\t 模块路径:%ls\n", LDTE32.DllBase, LDTE32.SizeOfImage, ProPath32);

								if (exe >= LDTE32.DllBase && exe <= (LDTE32.DllBase + LDTE32.SizeOfImage))
								{
									bsar = LDTE32.DllBase;
									ret = LDTE32.SizeOfImage;
									goto Ext;
								}

							}
							if (!ReadProcessMemory(m_ProcessHandle, (LPVOID)LDTE32.InLoadOrderLinks.Flink, &LDTE32, sizeof(_LDR_DATA_TABLE_ENTRY32), NULL)) break;
						}
					}
				}
			}
		}
	}

Ext:

	CloseHandle(m_ProcessHandle);

	return ret;
}