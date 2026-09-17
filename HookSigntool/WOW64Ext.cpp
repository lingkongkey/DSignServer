

#include "WOW64Ext.h"
#include <cstddef>
#include <stdlib.h> 

#include <stdio.h>
#include <process.h>
#include <psapi.h>
#include <tchar.h>
#include <TlHelp32.h>

#pragma comment(lib, "ntdll.lib")

typedef long NTSTATUS;

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)


typedef enum _DLL_BITNESS {
	DLL_INVALID = 0,
	DLL_64BIT = 1,
	DLL_32BIT = 2

} DLL_BITNESS;


class CMemPtr
{
private:
	void** m_ptr;
	bool watchActive;

public:
	CMemPtr(void** ptr) : m_ptr(ptr), watchActive(true) {}

	~CMemPtr()
	{
		if (*m_ptr && watchActive)
		{
			free(*m_ptr);
			*m_ptr = 0;
		}
	}

	void disableWatch() { watchActive = false; }
};

#define EMIT(a) __asm __emit (a)

#define X64_Start_with_CS(_cs) \
    { \
    EMIT(0x6A) EMIT(_cs)                         /*  push   _cs             */ \
    EMIT(0xE8) EMIT(0) EMIT(0) EMIT(0) EMIT(0)   /*  call   $+5             */ \
    EMIT(0x83) EMIT(4) EMIT(0x24) EMIT(5)        /*  add    dword [esp], 5  */ \
    EMIT(0xCB)                                   /*  retf                   */ \
    }

#define X64_End_with_CS(_cs) \
    { \
    EMIT(0xE8) EMIT(0) EMIT(0) EMIT(0) EMIT(0)                                 /*  call   $+5                   */ \
    EMIT(0xC7) EMIT(0x44) EMIT(0x24) EMIT(4) EMIT(_cs) EMIT(0) EMIT(0) EMIT(0) /*  mov    dword [rsp + 4], _cs  */ \
    EMIT(0x83) EMIT(4) EMIT(0x24) EMIT(0xD)                                    /*  add    dword [rsp], 0xD      */ \
    EMIT(0xCB)                                                                 /*  retf                         */ \
    }

#define X64_Start() X64_Start_with_CS(0x33)
#define X64_End() X64_End_with_CS(0x23)

#define _RAX  0
#define _RCX  1
#define _RDX  2
#define _RBX  3
#define _RSP  4
#define _RBP  5
#define _RSI  6
#define _RDI  7
#define _R8   8
#define _R9   9
#define _R10 10
#define _R11 11
#define _R12 12
#define _R13 13
#define _R14 14
#define _R15 15

#define X64_Push(r) EMIT(0x48 | ((r) >> 3)) EMIT(0x50 | ((r) & 7))
#define X64_Pop(r) EMIT(0x48 | ((r) >> 3)) EMIT(0x58 | ((r) & 7))

#define REX_W EMIT(0x48) __asm

//to fool M$ inline asm compiler I'm using 2 DWORDs instead of DWORD64
//use of DWORD64 will generate wrong 'pop word ptr[]' and it will break stack
union reg64
{
	DWORD64 v;
	DWORD dw[2];
};

#define WATCH(ptr) \
    CMemPtr watch_##ptr((void**)&ptr)

#define DISABLE_WATCH(ptr) \
    watch_##ptr.disableWatch()



#ifdef APSTUDIO_INVOKED
#ifndef APSTUDIO_READONLY_SYMBOLS
#define _APS_NEXT_RESOURCE_VALUE        101
#define _APS_NEXT_COMMAND_VALUE         40001
#define _APS_NEXT_CONTROL_VALUE         1001
#define _APS_NEXT_SYMED_VALUE           101
#endif
#endif

#ifndef STATUS_SUCCESS
#   define STATUS_SUCCESS 0
#endif

#pragma pack(push)
#pragma pack(1)
template <class T>
struct _LIST_ENTRY_T
{
	T Flink;
	T Blink;
};

template <class T>
struct _UNICODE_STRING_T
{
	union
	{
		struct
		{
			WORD Length;
			WORD MaximumLength;
		};
		T dummy;
	};
	T Buffer;
};

template <class T>
struct _NT_TIB_T
{
	T ExceptionList;
	T StackBase;
	T StackLimit;
	T SubSystemTib;
	T FiberData;
	T ArbitraryUserPointer;
	T Self;
};

template <class T>
struct _CLIENT_ID
{
	T UniqueProcess;
	T UniqueThread;
};

template <class T>
struct _TEB_T_
{
	_NT_TIB_T<T> NtTib;
	T EnvironmentPointer;
	_CLIENT_ID<T> ClientId;
	T ActiveRpcHandle;
	T ThreadLocalStoragePointer;
	T ProcessEnvironmentBlock;
	DWORD LastErrorValue;
	DWORD CountOfOwnedCriticalSections;
	T CsrClientThread;
	T Win32ThreadInfo;
	DWORD User32Reserved[26];
	//rest of the structure is not defined for now, as it is not needed
};

template <class T>
struct _LDR_DATA_TABLE_ENTRY_T
{
	_LIST_ENTRY_T<T> InLoadOrderLinks;
	_LIST_ENTRY_T<T> InMemoryOrderLinks;
	_LIST_ENTRY_T<T> InInitializationOrderLinks;
	T DllBase;
	T EntryPoint;
	union
	{
		DWORD SizeOfImage;
		T dummy01;
	};
	_UNICODE_STRING_T<T> FullDllName;
	_UNICODE_STRING_T<T> BaseDllName;
	DWORD Flags;
	WORD LoadCount;
	WORD TlsIndex;
	union
	{
		_LIST_ENTRY_T<T> HashLinks;
		struct
		{
			T SectionPointer;
			T CheckSum;
		};
	};
	union
	{
		T LoadedImports;
		DWORD TimeDateStamp;
	};
	T EntryPointActivationContext;
	T PatchInformation;
	_LIST_ENTRY_T<T> ForwarderLinks;
	_LIST_ENTRY_T<T> ServiceTagLinks;
	_LIST_ENTRY_T<T> StaticLinks;
	T ContextInformation;
	T OriginalBase;
	_LARGE_INTEGER LoadTime;
};

template <class T>
struct _PEB_LDR_DATA_T
{
	DWORD Length;
	DWORD Initialized;
	T SsHandle;
	_LIST_ENTRY_T<T> InLoadOrderModuleList;
	_LIST_ENTRY_T<T> InMemoryOrderModuleList;
	_LIST_ENTRY_T<T> InInitializationOrderModuleList;
	T EntryInProgress;
	DWORD ShutdownInProgress;
	T ShutdownThreadId;

};

template <class T, class NGF, int A>
struct _PEB_T
{
	union
	{
		struct
		{
			BYTE InheritedAddressSpace;
			BYTE ReadImageFileExecOptions;
			BYTE BeingDebugged;
			BYTE BitField;
		};
		T dummy01;
	};
	T Mutant;
	T ImageBaseAddress;
	T Ldr;
	T ProcessParameters;
	T SubSystemData;
	T ProcessHeap;
	T FastPebLock;
	T AtlThunkSListPtr;
	T IFEOKey;
	T CrossProcessFlags;
	T UserSharedInfoPtr;
	DWORD SystemReserved;
	DWORD AtlThunkSListPtr32;
	T ApiSetMap;
	T TlsExpansionCounter;
	T TlsBitmap;
	DWORD TlsBitmapBits[2];
	T ReadOnlySharedMemoryBase;
	T HotpatchInformation;
	T ReadOnlyStaticServerData;
	T AnsiCodePageData;
	T OemCodePageData;
	T UnicodeCaseTableData;
	DWORD NumberOfProcessors;
	union
	{
		DWORD NtGlobalFlag;
		NGF dummy02;
	};
	LARGE_INTEGER CriticalSectionTimeout;
	T HeapSegmentReserve;
	T HeapSegmentCommit;
	T HeapDeCommitTotalFreeThreshold;
	T HeapDeCommitFreeBlockThreshold;
	DWORD NumberOfHeaps;
	DWORD MaximumNumberOfHeaps;
	T ProcessHeaps;
	T GdiSharedHandleTable;
	T ProcessStarterHelper;
	T GdiDCAttributeList;
	T LoaderLock;
	DWORD OSMajorVersion;
	DWORD OSMinorVersion;
	WORD OSBuildNumber;
	WORD OSCSDVersion;
	DWORD OSPlatformId;
	DWORD ImageSubsystem;
	DWORD ImageSubsystemMajorVersion;
	T ImageSubsystemMinorVersion;
	T ActiveProcessAffinityMask;
	T GdiHandleBuffer[A];
	T PostProcessInitRoutine;
	T TlsExpansionBitmap;
	DWORD TlsExpansionBitmapBits[32];
	T SessionId;
	ULARGE_INTEGER AppCompatFlags;
	ULARGE_INTEGER AppCompatFlagsUser;
	T pShimData;
	T AppCompatInfo;
	_UNICODE_STRING_T<T> CSDVersion;
	T ActivationContextData;
	T ProcessAssemblyStorageMap;
	T SystemDefaultActivationContextData;
	T SystemAssemblyStorageMap;
	T MinimumStackCommit;
	T FlsCallback;
	_LIST_ENTRY_T<T> FlsListHead;
	T FlsBitmap;
	DWORD FlsBitmapBits[4];
	T FlsHighIndex;
	T WerRegistrationData;
	T WerShipAssertPtr;
	T pContextData;
	T pImageHeaderHash;
	T TracingFlags;
};

typedef _LDR_DATA_TABLE_ENTRY_T<DWORD> LDR_DATA_TABLE_ENTRY32;
typedef _LDR_DATA_TABLE_ENTRY_T<DWORD64> LDR_DATA_TABLE_ENTRY64;

typedef _TEB_T_<DWORD> TEB32;
typedef _TEB_T_<DWORD64> TEB64;

typedef _PEB_LDR_DATA_T<DWORD> PEB_LDR_DATA32;
typedef _PEB_LDR_DATA_T<DWORD64> PEB_LDR_DATA64;

typedef _PEB_T<DWORD, DWORD64, 34> PEB32;
typedef _PEB_T<DWORD64, DWORD, 30> PEB64;

struct _XSAVE_FORMAT64
{
	WORD ControlWord;
	WORD StatusWord;
	BYTE TagWord;
	BYTE Reserved1;
	WORD ErrorOpcode;
	DWORD ErrorOffset;
	WORD ErrorSelector;
	WORD Reserved2;
	DWORD DataOffset;
	WORD DataSelector;
	WORD Reserved3;
	DWORD MxCsr;
	DWORD MxCsr_Mask;
	_M128A FloatRegisters[8];
	_M128A XmmRegisters[16];
	BYTE Reserved4[96];
};

struct _CONTEXT64
{
	DWORD64 P1Home;
	DWORD64 P2Home;
	DWORD64 P3Home;
	DWORD64 P4Home;
	DWORD64 P5Home;
	DWORD64 P6Home;
	DWORD ContextFlags;
	DWORD MxCsr;
	WORD SegCs;
	WORD SegDs;
	WORD SegEs;
	WORD SegFs;
	WORD SegGs;
	WORD SegSs;
	DWORD EFlags;
	DWORD64 Dr0;
	DWORD64 Dr1;
	DWORD64 Dr2;
	DWORD64 Dr3;
	DWORD64 Dr6;
	DWORD64 Dr7;
	DWORD64 Rax;
	DWORD64 Rcx;
	DWORD64 Rdx;
	DWORD64 Rbx;
	DWORD64 Rsp;
	DWORD64 Rbp;
	DWORD64 Rsi;
	DWORD64 Rdi;
	DWORD64 R8;
	DWORD64 R9;
	DWORD64 R10;
	DWORD64 R11;
	DWORD64 R12;
	DWORD64 R13;
	DWORD64 R14;
	DWORD64 R15;
	DWORD64 Rip;
	_XSAVE_FORMAT64 FltSave;
	_M128A Header[2];
	_M128A Legacy[8];
	_M128A Xmm0;
	_M128A Xmm1;
	_M128A Xmm2;
	_M128A Xmm3;
	_M128A Xmm4;
	_M128A Xmm5;
	_M128A Xmm6;
	_M128A Xmm7;
	_M128A Xmm8;
	_M128A Xmm9;
	_M128A Xmm10;
	_M128A Xmm11;
	_M128A Xmm12;
	_M128A Xmm13;
	_M128A Xmm14;
	_M128A Xmm15;
	_M128A VectorRegister[26];
	DWORD64 VectorControl;
	DWORD64 DebugControl;
	DWORD64 LastBranchToRip;
	DWORD64 LastBranchFromRip;
	DWORD64 LastExceptionToRip;
	DWORD64 LastExceptionFromRip;
};
// Below defines for .ContextFlags field are taken from WinNT.h
#ifndef CONTEXT_AMD64
#define CONTEXT_AMD64 0x100000
#endif

#define CONTEXT64_CONTROL (CONTEXT_AMD64 | 0x1L)
#define CONTEXT64_INTEGER (CONTEXT_AMD64 | 0x2L)
#define CONTEXT64_SEGMENTS (CONTEXT_AMD64 | 0x4L)
#define CONTEXT64_FLOATING_POINT  (CONTEXT_AMD64 | 0x8L)
#define CONTEXT64_DEBUG_REGISTERS (CONTEXT_AMD64 | 0x10L)
#define CONTEXT64_FULL (CONTEXT64_CONTROL | CONTEXT64_INTEGER | CONTEXT64_FLOATING_POINT)
#define CONTEXT64_ALL (CONTEXT64_CONTROL | CONTEXT64_INTEGER | CONTEXT64_SEGMENTS | CONTEXT64_FLOATING_POINT | CONTEXT64_DEBUG_REGISTERS)
#define CONTEXT64_XSTATE (CONTEXT_AMD64 | 0x20L)

//extern "C"
//{
//	BOOL __cdecl VirtualProtectEx64(HANDLE hProcess, DWORD64 lpAddress, DWORD64 dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
//	DWORD64 __cdecl X64Call(DWORD64 func, int argC, ...);
//	DWORD64 __cdecl GetModuleHandle64(const char* lpModuleName);
//	DWORD64 __cdecl GetProcAddress64(DWORD64 hModule, const char* funcName);
//	DWORD64 __cdecl VirtualAllocEx64(HANDLE hProcess, DWORD64 lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
//	BOOL __cdecl VirtualFreeEx64(HANDLE hProcess, DWORD64 lpAddress, SIZE_T dwSize, DWORD dwFreeType);
//	BOOL __cdecl ReadProcessMemory64(HANDLE hProcess, DWORD64 lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead);
//	BOOL __cdecl WriteProcessMemory64(HANDLE hProcess, DWORD64 lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);
//	BOOL __cdecl GetThreadContext64(HANDLE hThread, _CONTEXT64* lpContext);
//	BOOL __cdecl SetThreadContext64(HANDLE hThread, _CONTEXT64* lpContext);
//	VOID __cdecl SetLastErrorFromX64Call(DWORD64 status);
//	extern "C" long __cdecl GetProceBitess(DWORD dwProcessId);
//}
#pragma pack(pop)
extern "C" DWORD64  X64Call(DWORD64 func, int argC, ...);
extern "C" DWORD64  GetModuleHandle64(const char* lpModuleName);
void getMem64(void* dstMem, DWORD64 srcMem, SIZE_T sz);


HANDLE g_heap;
BOOL g_isWow64;

typedef struct
{
	DWORD64 UniqueProcess;
	DWORD64 UniqueThread;
} CLIENT_ID, * PCLIENT_ID;
typedef struct
{
	DWORD64 UniqueProcess;
	DWORD64 UniqueThread;
} CLIENT_32, * PCLIENT_32;


typedef struct _MODULE_INFO_32 {
	DWORD_PTR BaseOfDll;
	DWORD SizeOfImage;
	DWORD_PTR EntryPoint;
} MODULE_INFO_32, * PMODULE_INFO_32;



DWORD64 getNTDLL64();
typedef unsigned long long uint64_t;
typedef long long          int64_t;
typedef unsigned char      uint8_t;

uint64_t HashString(const char* str)
{
	const uint64_t fnvPrime = 1099511628211ULL;
	const uint64_t fnvOffset = 14695981039346656037ULL;
	uint64_t hash = fnvOffset;
	while (*str) {
		hash ^= (uint8_t)*str++;
		hash *= fnvPrime;
	}
	return hash;
}

extern "C" DLL_BITNESS IsDllBitness(const char* dllPath)
{
	if (dllPath == NULL) {
		return DLL_INVALID;
	}


	HANDLE hFile = CreateFileA(
		dllPath,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);
	if (hFile == INVALID_HANDLE_VALUE) {
		return DLL_INVALID;
	}

	DLL_BITNESS result = DLL_INVALID;
	IMAGE_DOS_HEADER dosHeader;
	DWORD bytesRead;


	if (!ReadFile(hFile, &dosHeader, sizeof(IMAGE_DOS_HEADER), &bytesRead, NULL) ||
		bytesRead != sizeof(IMAGE_DOS_HEADER)) {
		CloseHandle(hFile);
		return DLL_INVALID;
	}


	if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
		CloseHandle(hFile);
		return DLL_INVALID;
	}


	LARGE_INTEGER fileOffset;
	fileOffset.QuadPart = dosHeader.e_lfanew;
	if (SetFilePointerEx(hFile, fileOffset, NULL, FILE_BEGIN) == 0) {
		CloseHandle(hFile);
		return DLL_INVALID;
	}


	DWORD peSignature;
	if (!ReadFile(hFile, &peSignature, sizeof(DWORD), &bytesRead, NULL) ||
		bytesRead != sizeof(DWORD) || peSignature != IMAGE_NT_SIGNATURE) {
		CloseHandle(hFile);
		return DLL_INVALID;
	}


	IMAGE_FILE_HEADER fileHeader;
	if (!ReadFile(hFile, &fileHeader, sizeof(IMAGE_FILE_HEADER), &bytesRead, NULL) ||
		bytesRead != sizeof(IMAGE_FILE_HEADER)) {
		CloseHandle(hFile);
		return DLL_INVALID;
	}


	switch (fileHeader.Machine) {
	case IMAGE_FILE_MACHINE_I386:
		result = DLL_32BIT;
		break;
	case IMAGE_FILE_MACHINE_AMD64:
		result = DLL_64BIT;
		break;
	default:
		result = DLL_INVALID;
		break;
	}

	CloseHandle(hFile);
	return result;
}



static DWORD GetX86ModuleHandle(HANDLE hX86Process, const char* lpX86DllName)
{


	if (hX86Process == INVALID_HANDLE_VALUE || !lpX86DllName) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}
#if _WIN64

#else
	return (DWORD)GetModuleHandleA(lpX86DllName);
#endif

	DWORD teb = 0;
	DWORD peb = 0;
	SIZE_T bytesRead = 0;

	DWORD cbNeeded = 0;
	HMODULE hModules[1024] = { 0 };

	if (EnumProcessModulesEx(hX86Process, hModules, sizeof(hModules), &cbNeeded, LIST_MODULES_32BIT)) {

		for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
			char szModuleName[MAX_PATH] = { 0 };

			if (GetModuleFileNameExA(hX86Process, hModules[i], szModuleName, MAX_PATH)) {

				char* lpFileName = strrchr(szModuleName, '\\');
				if (lpFileName) lpFileName++;
				else lpFileName = szModuleName;


				if (_stricmp(lpFileName, lpX86DllName) == 0) {
					return (DWORD_PTR)hModules[i];
				}
			}
		}
	}
	else {

	}


	return 0;
}

DWORD GetX86ProcAddress(HANDLE hX86Process, DWORD hModX86, const char* lpX86FuncName) {

	if (hX86Process == INVALID_HANDLE_VALUE || hModX86 == 0 || !lpX86FuncName) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}

#if _WIN64

#else
	return (DWORD)GetProcAddress((HMODULE)hModX86, lpX86FuncName);
#endif

	IMAGE_DOS_HEADER dosHeader;
	SIZE_T bytesRead;
	if (!ReadProcessMemory(hX86Process, (LPVOID)hModX86, &dosHeader, sizeof(IMAGE_DOS_HEADER), &bytesRead) ||
		bytesRead != sizeof(IMAGE_DOS_HEADER) || dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
		//printf("Failed to read DOS header\n");
		return 0;
	}


	IMAGE_NT_HEADERS32 ntHeader;
	if (!ReadProcessMemory(hX86Process, (LPVOID)(hModX86 + dosHeader.e_lfanew), &ntHeader, sizeof(IMAGE_NT_HEADERS32), &bytesRead) ||
		bytesRead != sizeof(IMAGE_NT_HEADERS32) || ntHeader.Signature != IMAGE_NT_SIGNATURE) {
		//printf("Failed to read NT header\n");
		return 0;
	}


	if (ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0 ||
		ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == 0) {
		printf("No export table found\n");
		return 0;
	}


	IMAGE_EXPORT_DIRECTORY exportDir;
	DWORD exportDirRVA = ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (!ReadProcessMemory(hX86Process, (LPVOID)(hModX86 + exportDirRVA), &exportDir, sizeof(IMAGE_EXPORT_DIRECTORY), &bytesRead) ||
		bytesRead != sizeof(IMAGE_EXPORT_DIRECTORY)) {
		printf("Failed to read export directory\n");
		return 0;
	}


	DWORD* funcNames = new DWORD[exportDir.NumberOfNames];
	DWORD* funcAddrs = new DWORD[exportDir.NumberOfFunctions];
	WORD* funcOrds = new WORD[exportDir.NumberOfNames];

	if (!ReadProcessMemory(hX86Process, (LPVOID)(hModX86 + exportDir.AddressOfNames), funcNames, exportDir.NumberOfNames * sizeof(DWORD), &bytesRead) ||
		bytesRead != exportDir.NumberOfNames * sizeof(DWORD)) {
		printf("Failed to read function names\n");
		delete[] funcNames;
		delete[] funcAddrs;
		delete[] funcOrds;
		return 0;
	}

	if (!ReadProcessMemory(hX86Process, (LPVOID)(hModX86 + exportDir.AddressOfFunctions), funcAddrs, exportDir.NumberOfFunctions * sizeof(DWORD), &bytesRead) ||
		bytesRead != exportDir.NumberOfFunctions * sizeof(DWORD)) {
		printf("Failed to read function addresses\n");
		delete[] funcNames;
		delete[] funcAddrs;
		delete[] funcOrds;
		return 0;
	}

	if (!ReadProcessMemory(hX86Process, (LPVOID)(hModX86 + exportDir.AddressOfNameOrdinals), funcOrds, exportDir.NumberOfNames * sizeof(WORD), &bytesRead) ||
		bytesRead != exportDir.NumberOfNames * sizeof(WORD)) {
		printf("Failed to read function ordinals\n");
		delete[] funcNames;
		delete[] funcAddrs;
		delete[] funcOrds;
		return 0;
	}


	DWORD_PTR funcAddr = 0;
	for (DWORD i = 0; i < exportDir.NumberOfNames; i++) {

		char funcName[MAX_PATH];
		if (!ReadProcessMemory(hX86Process, (LPVOID)(hModX86 + funcNames[i]), funcName, MAX_PATH, &bytesRead)) {
			continue;
		}


		if (_strcmpi(funcName, lpX86FuncName) == 0) {

			WORD ordinal = funcOrds[i];
			if (ordinal < exportDir.NumberOfFunctions) {
				funcAddr = hModX86 + funcAddrs[ordinal];
			}
			break;
		}
	}


	delete[] funcNames;
	delete[] funcAddrs;
	delete[] funcOrds;

	if (funcAddr == 0) {
		//printf("Function %s not found in module\n", lpX86FuncName);
		return 0;
	}

	//printf("Successfully found function %s at address 0x%p\n", lpX86FuncName, (void*)funcAddr);
	return funcAddr;
}


DWORD64 FindApiByHash64(DWORD64 hMod64 = 0, uint64_t targetHash = 0)
{
	HANDLE hProcess = GetCurrentProcess();

	if (hMod64 == 0 || targetHash == 0) return 0;

	if (hProcess != GetCurrentProcess() && hProcess == INVALID_HANDLE_VALUE) return 0;



	IMAGE_DOS_HEADER dosHeader = { 0 };
	SIZE_T bytesRead = 0;


	if (!ReadProcessMemory64(
		hProcess,
		hMod64,
		&dosHeader,
		sizeof(IMAGE_DOS_HEADER),
		&bytesRead
	) || bytesRead != sizeof(IMAGE_DOS_HEADER)) {
		return 0;
	}

	if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
		return 0;
	}



	DWORD64 ntHeaderAddr64 = hMod64 + dosHeader.e_lfanew;
	IMAGE_NT_HEADERS64 ntHeader = { 0 };

	bytesRead = 0;
	if (!ReadProcessMemory64(
		hProcess,
		ntHeaderAddr64,
		&ntHeader,
		sizeof(IMAGE_NT_HEADERS64),
		&bytesRead
	) || bytesRead != sizeof(IMAGE_NT_HEADERS64)) {
		return 0;
	}

	if (ntHeader.Signature != IMAGE_NT_SIGNATURE ||
		ntHeader.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		return 0;
	}



	IMAGE_DATA_DIRECTORY exportDirData = ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (exportDirData.VirtualAddress == 0) {
		return 0;
	}
	DWORD64 exportDirAddr64 = hMod64 + exportDirData.VirtualAddress;

	IMAGE_EXPORT_DIRECTORY exportDir = { 0 };
	bytesRead = 0;
	if (!ReadProcessMemory64(
		hProcess,
		exportDirAddr64,
		&exportDir,
		sizeof(IMAGE_EXPORT_DIRECTORY),
		&bytesRead
	) || bytesRead != sizeof(IMAGE_EXPORT_DIRECTORY)) {
		return 0;
	}



	DWORD64 funcNamesAddr64 = hMod64 + exportDir.AddressOfNames;
	DWORD64 funcOrdsAddr64 = hMod64 + exportDir.AddressOfNameOrdinals;
	DWORD64 funcAddrsAddr64 = hMod64 + exportDir.AddressOfFunctions;
	//long dx = 0;

	for (DWORD i = 0; i < exportDir.NumberOfNames; i++) {

		DWORD funcNameRva = 0;
		bytesRead = 0;
		if (!ReadProcessMemory64(
			hProcess,
			funcNamesAddr64 + i * sizeof(DWORD),
			&funcNameRva,
			sizeof(DWORD),
			&bytesRead
		) || bytesRead != sizeof(DWORD) || funcNameRva == 0) {
			continue;
		}


		DWORD64 funcNameAddr64 = hMod64 + funcNameRva;

		char funcNameBuf[256] = { 0 };
		bytesRead = 0;
		if (!ReadProcessMemory64(
			hProcess,
			funcNameAddr64,
			funcNameBuf,
			sizeof(funcNameBuf) - 1,
			&bytesRead
		) || bytesRead == 0) {
			continue;
		}

		DWORD64 dtl = HashString(funcNameBuf);
		if (dtl == targetHash)
		{

			WORD funcOrd = 0;
			bytesRead = 0;
			if (!ReadProcessMemory64(
				hProcess,
				funcOrdsAddr64 + i * sizeof(WORD),
				&funcOrd,
				sizeof(WORD),
				&bytesRead
			) || bytesRead != sizeof(WORD)) {
				continue;
			}
			DWORD funcAddrRva = 0;
			bytesRead = 0;
			if (!ReadProcessMemory64(
				hProcess,
				funcAddrsAddr64 + funcOrd * sizeof(DWORD),
				&funcAddrRva,
				sizeof(DWORD),
				&bytesRead
			) || bytesRead != sizeof(DWORD)) {
				continue;
			}

			return hMod64 + funcAddrRva;
		}
		//dx++;


	}


	return 0;
}

#if _WIN64

#else

DWORD64 FindApiByHash64_2(DWORD64 hMod64, const char* cha)
{
	if (hMod64 == 0 || cha == 0) return 0;

	IMAGE_DOS_HEADER dosHeader = { 0 };
	SIZE_T bytesRead = 0;


	getMem64(&dosHeader, hMod64, sizeof(IMAGE_DOS_HEADER));


	if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
	{
		return 0;
	}



	DWORD64 ntHeaderAddr64 = hMod64 + dosHeader.e_lfanew;
	IMAGE_NT_HEADERS64 ntHeader = { 0 };

	bytesRead = 0;
	getMem64(&ntHeader, ntHeaderAddr64, sizeof(IMAGE_NT_HEADERS64));


	if (ntHeader.Signature != IMAGE_NT_SIGNATURE ||
		ntHeader.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		return 0;
	}

	IMAGE_DATA_DIRECTORY exportDirData = ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (exportDirData.VirtualAddress == 0)
	{
		return 0;
	}
	DWORD64 exportDirAddr64 = hMod64 + exportDirData.VirtualAddress;

	IMAGE_EXPORT_DIRECTORY exportDir = { 0 };
	bytesRead = 0;
	getMem64(&exportDir, exportDirAddr64, sizeof(IMAGE_EXPORT_DIRECTORY));

	DWORD64 funcNamesAddr64 = hMod64 + exportDir.AddressOfNames;
	DWORD64 funcOrdsAddr64 = hMod64 + exportDir.AddressOfNameOrdinals;
	DWORD64 funcAddrsAddr64 = hMod64 + exportDir.AddressOfFunctions;
	//long dx = 0;

	for (DWORD i = 0; i < exportDir.NumberOfNames; i++) {

		DWORD funcNameRva = 0;
		bytesRead = 0;
		getMem64(&funcNameRva, funcNamesAddr64 + i * sizeof(DWORD), sizeof(DWORD));


		DWORD64 funcNameAddr64 = hMod64 + funcNameRva;

		char funcNameBuf[256] = { 0 };
		bytesRead = 0;
		getMem64(funcNameBuf, funcNameAddr64, sizeof(funcNameBuf) - 1);
		DWORD64 dtl = HashString(funcNameBuf);
		if (_strcmpi(funcNameBuf, cha) == 0)
		{

			WORD funcOrd = 0;
			bytesRead = 0;
			getMem64(&funcOrd, funcOrdsAddr64 + i * sizeof(WORD), sizeof(WORD));
			DWORD funcAddrRva = 0;
			bytesRead = 0;
			getMem64(&funcAddrRva, funcAddrsAddr64 + funcOrd * sizeof(DWORD), sizeof(DWORD));

			return hMod64 + funcAddrRva;
		}
		//dx++;


	}


	return 0;
}
#endif


typedef struct _UNICODE_STRING64 {
	USHORT Length;
	USHORT MaximumLength;
	DWORD64 Buffer;
}UNICODE_STRING64, * PUNICODE_STRING64;

typedef struct _UNICODE_STRING32 {
	USHORT Length;
	USHORT MaximumLength;
	ULONG  Buffer;
} UNICODE_STRING32, * PUNICODE_STRING32;

typedef struct _STRING {
	USHORT Length;
	USHORT MaximumLength;
	PCHAR Buffer;
} STRING;
typedef STRING* PSTRING;
typedef STRING ANSI_STRING;
typedef PSTRING PANSI_STRING;
typedef PSTRING PCANSI_STRING;
typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING* PUNICODE_STRING;
typedef CONST char* PCSZ;

typedef NTSTATUS(NTAPI* pRtlAnsiStringToUnicodeString)
(
	PUNICODE_STRING DestinationString,
	PCANSI_STRING SourceString,
	BOOLEAN AllocateDestinationString
	);
typedef NTSTATUS(NTAPI* pRtlInitAnsiString)(
	PANSI_STRING DestinationString,
	PCSZ SourceString
	);
typedef NTSTATUS(NTAPI* pRtlFreeUnicodeString)(
	PUNICODE_STRING UnicodeString
	);

#pragma pack(1)  



typedef struct _INJ64DLL {
	const BYTE con1[16] = { 0x48,0xC7,0xC1,0x00,0x00,0x00,0x00,0x48,0xC7,0xC2,0x00,0x00,0x00,0x00,0x49,0xB8 };
	DWORD64 dllpanth;                            //  mov       r9,0  //PVOID*  BaseAddr opt
	const BYTE con2[2] = { 0x49, 0xb9 };
	DWORD64 handle = 0;							   //  mov       r8,0  //PUNICODE_STRING Name
	const BYTE con3[2] = { 0x48, 0xb8 };
	DWORD64 LdrLoadDll = 0;
	const BYTE con4[12] = { 0x48,0x83,0xEC,0x28,0xFF,0xD0,0x48,0x83,0xC4,0x28,0x48,0xB9 };
	DWORD64 eroo = 0;
	const BYTE con5[4] = { 0x48, 0x89,0x01,0xC3 };
	DWORD64 erooret = 0;
	DWORD64 rethandle = 0;
	UNICODE_STRING64  pdllpanth;
	WCHAR             dll[1024] = { 0 };
}INJ64DLL, * PINJ64DLL;
typedef struct _INJ32DLL {
	const BYTE con1[2] = { 0xEB,0x08 };
	const DWORD RetBuffer_z = 0;  //
	const DWORD RetBuffer_esp = 0;
	const BYTE con2[2] = { 0x89,0x25 };
	DWORD m_esp = 0;
	const BYTE con3[1] = { 0x68 };
	DWORD RetBuffer = 0;
	const BYTE con4[1] = { 0x68 };
	DWORD DllPtr = 0;
	const BYTE con5[4] = { 0x6A,0,0x6A,0 };
	const BYTE con6[1] = { 0xB8 };
	DWORD  LdrLoadDll = 0;
	const BYTE con7[11] = { 0xFF,0xD0,0xA9,0x00,0x00,0x00,0x00,0x74,0x0A,0xC7,0x05 };
	DWORD  RetBuffer_z0 = 0;
	const DWORD RetBuffer_z0_1 = 0;
	const BYTE con8[2] = { 0x8B,0x25 };
	DWORD q_esp = 0;
	const BYTE con9[1] = { 0xC3 };
	UNICODE_STRING32 DllName = { 0 };
	WCHAR dllPath1[1024] = { 0 };
}INJ32DLL, * PINJ32DLL;

#pragma pack()  
BOOL SetINJ64DLL(DWORD64 addres, const char* dllpath, PINJ64DLL p)
{
	if ((DWORD64)p <= 0x40000 || addres <= 0x40000 || (DWORD64)dllpath <= 0x40000)
	{
		return FALSE;
	}

#if _WIN64

	p->LdrLoadDll = (DWORD64)GetProcAddress(GetModuleHandleA("ntdll.dll"), "LdrLoadDll");
#else
	p->LdrLoadDll = FindApiByHash64_2(GetModuleHandle64("ntdll.dll"), "LdrLoadDll");
#endif

	if (!p->LdrLoadDll)
	{
		return FALSE;
	}

	pRtlAnsiStringToUnicodeString pTo = (pRtlAnsiStringToUnicodeString)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlAnsiStringToUnicodeString");
	pRtlInitAnsiString   pina = (pRtlInitAnsiString)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitAnsiString");
	pRtlFreeUnicodeString fee = (pRtlFreeUnicodeString)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlFreeUnicodeString");
	ANSI_STRING AnsiStr1;
	UNICODE_STRING UNICODEstr;
	pina(&AnsiStr1, dllpath);
	NTSTATUS hr = pTo(&UNICODEstr, &AnsiStr1, TRUE);
	if (hr == STATUS_SUCCESS)
	{
		p->dllpanth = addres + offsetof(INJ64DLL, pdllpanth);
		p->handle = addres + offsetof(INJ64DLL, rethandle);
		p->eroo = addres + offsetof(INJ64DLL, erooret);
		memcpy(&p->pdllpanth, &UNICODEstr, sizeof(UNICODE_STRING64));

		memcpy(p->dll, UNICODEstr.Buffer, UNICODEstr.Length + 1);
		p->pdllpanth.Buffer = addres + offsetof(INJ64DLL, dll);
		fee(&UNICODEstr);
		return TRUE;
	}


	return FALSE;

}

BOOL SetINJ32DLL(HANDLE hX86Process, DWORD64 addres, const char* dllpath, PINJ32DLL p)
{
	if ((DWORD64)p <= 0x40000 || addres <= 0x40000 || (DWORD64)dllpath <= 0x40000)
	{
		return FALSE;
	}
#if _WIN64
	p->LdrLoadDll = GetX86ProcAddress(hX86Process, GetX86ModuleHandle(hX86Process, "ntdll.dll"), "LdrLoadDll");
#else
	p->LdrLoadDll = (DWORD64)GetProcAddress(GetModuleHandleA("ntdll.dll"), "LdrLoadDll");
#endif

	if (!p->LdrLoadDll)
	{
		return FALSE;
	}

	int wLen = MultiByteToWideChar(CP_ACP, 0, dllpath, -1, NULL, 0);
	if (wLen == 0 || wLen > 1023) return 0;

	WCHAR* wDllPath = new WCHAR[wLen];
	if (!wDllPath) return 0;

	if (!MultiByteToWideChar(CP_ACP, 0, dllpath, -1, wDllPath, wLen)) {
		delete[] wDllPath;
		return 0;
	}


	p->DllName.Length = (USHORT)((wLen - 1) * sizeof(WCHAR));
	p->DllName.MaximumLength = (USHORT)(wLen * sizeof(WCHAR));
	p->DllName.Buffer = addres + offsetof(INJ32DLL, dllPath1);
	PINJ32DLL p1 = (PINJ32DLL)addres;
	wcscpy_s(p->dllPath1, wLen, wDllPath);
	delete[] wDllPath;
	p->m_esp = addres + offsetof(INJ32DLL, RetBuffer_esp);
	p->q_esp = addres + offsetof(INJ32DLL, RetBuffer_esp);
	p->RetBuffer = addres + offsetof(INJ32DLL, RetBuffer_z);
	p->RetBuffer_z0 = addres + offsetof(INJ32DLL, RetBuffer_z);
	p->DllPtr = addres + offsetof(INJ32DLL, DllName);
	return TRUE;
}



extern "C"  DWORD64 InjectDll64(DWORD dwProcessId, const char* dllPathAnsi) {

	if (dwProcessId == 0 || !dllPathAnsi || *dllPathAnsi == '\0') {
		SetLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}

	if (strlen(dllPathAnsi) > MAX_PATH - 1) {
		SetLastError(ERROR_FILENAME_EXCED_RANGE);
		return 0;
	}

	long ispid = GetProceBitess(dwProcessId);
	long isdll = IsDllBitness(dllPathAnsi);

	if (ispid == PROCESS_INVALID || isdll == DLL_INVALID || ispid != isdll)
	{
		SetLastError(ERROR_INVALID_DLL);
		return 0;
	}


	HANDLE hProcess = NULL;
	DWORD64 codeAddr = 0;
	DWORD64 hThread = NULL;
	DWORD64 ret = 0;
	DWORD64 ret2 = 0;
	SIZE_T retl;
	DWORD lastError = 0;

	__try {

		hProcess = OpenProcess(
			PROCESS_ALL_ACCESS,
			FALSE,
			dwProcessId
		);
		if (!hProcess) {
			lastError = GetLastError();
			__leave;
		}


#if _WIN64
		codeAddr = (DWORD64)VirtualAllocEx(
			hProcess,
			NULL,
			sizeof(INJ64DLL),
			MEM_COMMIT | MEM_RESERVE,
			PAGE_EXECUTE_READWRITE
		);
#else
		if (ispid == PROCESS_X64)
		{
			codeAddr = VirtualAllocEx64(
				hProcess,
				NULL,
				sizeof(INJ64DLL),
				MEM_COMMIT | MEM_RESERVE,
				PAGE_EXECUTE_READWRITE
			);
		}
		else
		{
			codeAddr = (DWORD64)VirtualAllocEx(
				hProcess,
				NULL,
				sizeof(INJ64DLL),
				MEM_COMMIT | MEM_RESERVE,
				PAGE_EXECUTE_READWRITE
			);
		}

#endif


		if (codeAddr == 0) {
			lastError = GetLastError();
			__leave;
		}

		ret2 = codeAddr;

#if _WIN64
		if (ispid == PROCESS_X64)
		{
			INJ64DLL strjk;

			if (!SetINJ64DLL(codeAddr, dllPathAnsi, &strjk)) {
				lastError = GetLastError();
				if (lastError == 0) lastError = ERROR_INVALID_DATA;
				__leave;
			}

			if (!WriteProcessMemory(hProcess, (LPVOID)codeAddr, &strjk, sizeof(INJ64DLL), &retl))
			{
				lastError = GetLastError();
				__leave;
			}

		}
		else
		{
			INJ32DLL strjk = { 0 };
			if (!SetINJ32DLL(hProcess, codeAddr, dllPathAnsi, &strjk))
			{
				lastError = GetLastError();
				if (lastError == 0) lastError = ERROR_INVALID_DATA;
				__leave;
			}

			if (!WriteProcessMemory(hProcess, (LPVOID)codeAddr, &strjk, sizeof(INJ32DLL), &retl) || retl != sizeof(INJ32DLL))
			{
				lastError = GetLastError();
				__leave;
			}
		}
#else
		if (ispid == PROCESS_X64)
		{
			INJ64DLL strjk;
			if (!SetINJ64DLL(codeAddr, dllPathAnsi, &strjk)) {
				lastError = GetLastError();
				if (lastError == 0) lastError = ERROR_INVALID_DATA;
				__leave;
			}

			if (!WriteProcessMemory64(hProcess, codeAddr, &strjk, sizeof(INJ64DLL), &retl) || retl != sizeof(INJ64DLL))
			{
				lastError = GetLastError();
				__leave;
			}

		}
		else
		{
			INJ32DLL strjk;
			if (!SetINJ32DLL(hProcess, codeAddr, dllPathAnsi, &strjk))
			{
				lastError = GetLastError();
				if (lastError == 0) lastError = ERROR_INVALID_DATA;
				__leave;
			}

			if (!WriteProcessMemory(hProcess, (LPVOID)codeAddr, &strjk, sizeof(INJ32DLL), &retl) || retl != sizeof(INJ32DLL))
			{
				lastError = GetLastError();
				__leave;
			}
		}
#endif






		struct _CLIENT_ID {
			DWORD64 UniqueProcess;
			DWORD64 UniqueThread;
		};

		NTSTATUS status = 1;
#if _WIN64
		if (ispid == PROCESS_X64)
		{
			typedef NTSTATUS(NTAPI* PFUNC_RtlCreateUserThread)(
				HANDLE ProcessHandle,
				PSECURITY_DESCRIPTOR SecurityDescriptor,
				BOOLEAN CreateSuspended,
				ULONG StackZeroBits,
				PULONG StackReserved,
				PULONG StackCommit,
				PVOID StartAddress,
				PVOID StartParameter,
				PHANDLE ThreadHandle,
				PCLIENT_32 ClientId
				);
			PFUNC_RtlCreateUserThread star = (PFUNC_RtlCreateUserThread)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlCreateUserThread");
			if (star == 0)
			{
				lastError = GetLastError();
				__leave;
			}
			status = star(hProcess, NULL, FALSE, 0, 0, 0, (LPVOID)codeAddr, 0, (PHANDLE)&hThread, 0);
			if (!NT_SUCCESS(status) || !hThread)
			{
				lastError = status;
				__leave;
			}
		}
		else
		{
			hThread = (DWORD64)CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)codeAddr, NULL, 0, NULL);
			if (!hThread)
			{
				lastError = GetLastError();
				__leave;
			}
		}

#else
		if (ispid == PROCESS_X64)
		{

			DWORD64 pRtlCreateUserThread = FindApiByHash64_2(GetModuleHandle64("ntdll.dll"), "RtlCreateUserThread");
			if (!pRtlCreateUserThread)
			{
				lastError = GetLastError();
				if (lastError == 0) lastError = ERROR_PROC_NOT_FOUND;
				__leave;
			}
			// long tispid = ispid;
			status = (NTSTATUS)X64Call(
				pRtlCreateUserThread, 10,
				(DWORD64)hProcess, (DWORD64)NULL, (DWORD64)FALSE,
				(DWORD64)0, (DWORD64)NULL, (DWORD64)NULL,
				(DWORD64)codeAddr, (DWORD64)NULL,
				(DWORD64)&hThread, (DWORD64)0
			);
			//ispid = tispid;
		}
		else
		{
			typedef NTSTATUS(NTAPI* PFUNC_RtlCreateUserThread)(
				HANDLE ProcessHandle,
				PSECURITY_DESCRIPTOR SecurityDescriptor,
				BOOLEAN CreateSuspended,
				ULONG StackZeroBits,
				PULONG StackReserved,
				PULONG StackCommit,
				PVOID StartAddress,
				PVOID StartParameter,
				PHANDLE ThreadHandle,
				PCLIENT_32 ClientId
				);
			PFUNC_RtlCreateUserThread star = (PFUNC_RtlCreateUserThread)GetX86ProcAddress(hProcess, GetX86ModuleHandle(hProcess, "ntdll.dll"), "RtlCreateUserThread");
			if (star == 0)
			{
				lastError = GetLastError();
				if (lastError == 0) lastError = ERROR_PROC_NOT_FOUND;
				__leave;
			}
			status = star(hProcess, NULL, FALSE, 0, 0, 0, (LPVOID)codeAddr, NULL, (PHANDLE)&hThread, NULL);
		}

		if (!NT_SUCCESS(status) || !hThread)
		{
			lastError = status;
			__leave;
		}
#endif



		DWORD waitResult = WaitForSingleObject((HANDLE)hThread, 30000);
		if (waitResult != WAIT_OBJECT_0)
		{
			lastError = (waitResult == WAIT_TIMEOUT) ? ERROR_TIMEOUT : GetLastError();
			__leave;
		}
	}
	__finally
	{

		if (hThread)
		{

			BOOL readSuccess = FALSE;
#if _WIN64
			if (ispid == PROCESS_X64)
			{
				readSuccess = ReadProcessMemory(hProcess, (LPVOID)(ret2 + offsetof(INJ64DLL, rethandle)), &ret, sizeof(DWORD64), &retl);
			}
			else
			{
				readSuccess = ReadProcessMemory(hProcess, (LPVOID)(ret2 + offsetof(INJ32DLL, RetBuffer_z)), &ret, sizeof(DWORD), &retl);
			}
#else
			if (ispid == PROCESS_X64)
			{
				readSuccess = ReadProcessMemory64(hProcess, ret2 + offsetof(INJ64DLL, rethandle), &ret, sizeof(DWORD64), &retl);
			}
			else
			{
				readSuccess = ReadProcessMemory(hProcess, (LPVOID)(ret2 + offsetof(INJ32DLL, RetBuffer_z)), &ret, sizeof(DWORD), &retl);
			}
#endif


			if (!readSuccess && lastError == 0)
			{
				lastError = GetLastError();
				ret = 0;
			}

			CloseHandle((HANDLE)hThread);

		}

		if (ret2 && hProcess)
		{
			BOOL freeSuccess = FALSE;
#if _WIN64
			freeSuccess = VirtualFreeEx(hProcess, (LPVOID)ret2, 0, MEM_RELEASE);
#else
			if (ispid == PROCESS_X64)
			{
				freeSuccess = VirtualFreeEx64(hProcess, ret2, 0, MEM_RELEASE);
			}
			else
			{
				freeSuccess = VirtualFreeEx(hProcess, (LPVOID)ret2, 0, MEM_RELEASE);
			}
#endif


			if (!freeSuccess && lastError == 0)
			{
				lastError = GetLastError();
			}
		}

		if (hProcess)
		{
			CloseHandle(hProcess);
		}

		if (lastError != 0)
		{
			SetLastError(lastError);
		}
	}

	return ret;
}

extern "C" BOOL WINAPI UninjectDll64(DWORD dwProcessId, DWORD64 hModule) {

	if (dwProcessId == 0 || hModule == 0)
	{
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	long ispid = GetProceBitess(dwProcessId);
	if (ispid == PROCESS_INVALID)
	{
		SetLastError(ERROR_INVALID_HANDLE);
		return FALSE;
	}

	HANDLE hProcess = NULL;
	DWORD64 hThread = NULL;
	BOOL bResult = FALSE;
	DWORD lastError = 0;
	NTSTATUS status = 0;

	__try {
		hProcess = OpenProcess(
			PROCESS_ALL_ACCESS,
			FALSE,
			dwProcessId
		);

		if (!hProcess) {
			lastError = GetLastError();
			__leave;
		}

#if _WIN64
		if (ispid == PROCESS_X64)
		{
			HMODULE hNtDll = GetModuleHandleA("ntdll.dll");
			if (!hNtDll) {
				lastError = GetLastError();
				__leave;
			}

			FARPROC pLdrUnloadDll = GetProcAddress(hNtDll, "LdrUnloadDll");
			if (!pLdrUnloadDll) {
				lastError = GetLastError();
				__leave;
			}

			hThread = (DWORD64)CreateRemoteThread(
				hProcess,
				NULL,
				0,
				(LPTHREAD_START_ROUTINE)pLdrUnloadDll,
				(LPVOID)hModule,
				0,
				NULL
			);

			if (!hThread) {
				lastError = GetLastError();
				__leave;
			}
		}
		else {
			DWORD dwLdrUnloadDll = GetX86ProcAddress(
				hProcess,
				GetX86ModuleHandle(hProcess, "ntdll.dll"),
				"LdrUnloadDll"
			);

			if (dwLdrUnloadDll == 0) {
				lastError = GetLastError();
				__leave;
			}


			hThread = (DWORD64)CreateRemoteThread(
				hProcess,
				NULL,
				0,
				(LPTHREAD_START_ROUTINE)dwLdrUnloadDll,
				(LPVOID)(DWORD)hModule,
				0,
				NULL
			);

			if (!hThread) {
				lastError = GetLastError();
				__leave;
			}
		}
#else
		if (ispid == PROCESS_X64) {

			DWORD64 pLdrUnloadDll = FindApiByHash64_2(GetModuleHandle64("ntdll.dll"), "LdrUnloadDll");
			DWORD64 pRtlCreateUserThread = FindApiByHash64_2(GetModuleHandle64("ntdll.dll"), "RtlCreateUserThread");
			if (!pLdrUnloadDll || !pRtlCreateUserThread)
			{
				lastError = GetLastError();
				__leave;
			}
			status = (NTSTATUS)X64Call(
				pRtlCreateUserThread, 10,
				(DWORD64)hProcess, (DWORD64)NULL, (DWORD64)FALSE,
				(DWORD64)0, (DWORD64)NULL, (DWORD64)NULL,
				(DWORD64)pLdrUnloadDll, (DWORD64)hModule,
				(DWORD64)&hThread, (DWORD64)0
			);

			if (!NT_SUCCESS(status)) {
				lastError = status;
				__leave;
			}
		}
		else {

			HMODULE hNtDll = GetModuleHandleA("ntdll.dll");
			if (!hNtDll) {
				lastError = GetLastError();
				__leave;
			}

			FARPROC pLdrUnloadDll = GetProcAddress(hNtDll, "LdrUnloadDll");
			if (!pLdrUnloadDll) {
				lastError = GetLastError();
				__leave;
			}

			hThread = (DWORD64)CreateRemoteThread(
				hProcess,
				NULL,
				0,
				(LPTHREAD_START_ROUTINE)pLdrUnloadDll,
				(LPVOID)hModule,
				0,
				NULL
			);

			if (!hThread) {
				lastError = GetLastError();
				__leave;
			}
		}
#endif

		BOOL WIN64 = FALSE;
#if _WIN64
		WIN64 = TRUE;
#else
		WIN64 = FALSE;
#endif

		DWORD waitResult = WAIT_FAILED;
		if (hThread) {
			waitResult = WaitForSingleObject((HANDLE)hThread, 30000);
			if (waitResult == WAIT_OBJECT_0) {
				bResult = TRUE;
			}
			else {
				lastError = (waitResult == WAIT_TIMEOUT) ? ERROR_TIMEOUT : GetLastError();
			}
		}
		else if (ispid == PROCESS_X64 && !WIN64)
		{

		}
	}
	__finally {
		if (hThread) {
			CloseHandle((HANDLE)hThread);
		}

		if (hProcess) {
			CloseHandle(hProcess);
		}


		if (lastError != 0) {
			SetLastError(lastError);
		}
	}

	return bResult;
}

extern "C" long  GetProceBitess(DWORD dwProcessId)
{


	if (dwProcessId == 0 || dwProcessId == 0xFFFFFFFF)
	{
		return PROCESS_INVALID;
	}


	HANDLE hProcess = OpenProcess
	(
		PROCESS_ALL_ACCESS,
		FALSE,
		dwProcessId
	);

	if (!hProcess)
	{
		return PROCESS_INVALID;
	}

	BOOL oret = -5;
	if (!::IsWow64Process(hProcess, &oret))
	{
		CloseHandle(hProcess);
		return PROCESS_INVALID;
	}

	CloseHandle(hProcess);
	long ret = 0;

	if (oret)
	{
		ret = PROCESS_X86;
	}
	else if (!oret)
	{
		ret = PROCESS_X64;
	}


	return ret;

}

extern "C" long  GetProceBitess2(HANDLE hProcess)
{
	if (!hProcess)
	{
		return PROCESS_INVALID;
	}

	BOOL oret = -5;
	if (!::IsWow64Process(hProcess, &oret))
	{

		return PROCESS_INVALID;
	}


	long ret = 0;

	if (oret)
	{
		ret = PROCESS_X86;
	}
	else if (!oret)
	{
		ret = PROCESS_X64;
	}


	return ret;

}

// _stricmp function removed to avoid conflict with C runtime library
// Using the standard C runtime library implementation instead


bool InitWow64Ext()
{
	g_heap = GetProcessHeap();
	return IsWow64Process(GetCurrentProcess(), &g_isWow64) ? g_isWow64 : false;
}

#pragma warning(push)
#pragma warning(disable : 4297)
struct Wow64ExtInitializer
{
	Wow64ExtInitializer()
	{
		InitWow64Ext();
	}
};

static Wow64ExtInitializer g_wow64ExtInitializer;
#pragma warning(pop)

#pragma warning(push)
#pragma warning(disable : 4409)




#if _WIN64

#else
extern "C" DWORD64  X64Call(DWORD64 func, int argC, ...)
{
	if (!g_isWow64)
		return 0;

	va_list args;
	va_start(args, argC);
	reg64 _rcx = { (argC > 0) ? argC--, va_arg(args, DWORD64) : 0 };
	reg64 _rdx = { (argC > 0) ? argC--, va_arg(args, DWORD64) : 0 };
	reg64 _r8 = { (argC > 0) ? argC--, va_arg(args, DWORD64) : 0 };
	reg64 _r9 = { (argC > 0) ? argC--, va_arg(args, DWORD64) : 0 };
	reg64 _rax = { 0 };

	reg64 restArgs = { (DWORD64)&va_arg(args, DWORD64) };

	// conversion to QWORD for easier use in inline assembly
	reg64 _argC = { (DWORD64)argC };
	DWORD back_esp = 0;
	WORD back_fs = 0;

	__asm
	{
		;// reset FS segment, to properly handle RFG
		mov    back_fs, fs
			mov    eax, 0x2B
			mov    fs, ax

			;// keep original esp in back_esp variable
		mov    back_esp, esp

			;// align esp to 0x10, without aligned stack some syscalls may return errors !
		;// (actually, for syscalls it is sufficient to align to 8, but SSE opcodes 
		;// requires 0x10 alignment), it will be further adjusted according to the
		;// number of arguments above 4
		and esp, 0xFFFFFFF0

			X64_Start();

		;// below code is compiled as x86 inline asm, but it is executed as x64 code
		;// that's why it need sometimes REX_W() macro, right column contains detailed
		;// transcription how it will be interpreted by CPU

		;// fill first four arguments
		REX_W mov    ecx, _rcx.dw[0];// mov     rcx, qword ptr [_rcx]
		REX_W mov    edx, _rdx.dw[0];// mov     rdx, qword ptr [_rdx]
		push   _r8.v;// push    qword ptr [_r8]
		X64_Pop(_R8); ;// pop     r8
		push   _r9.v;// push    qword ptr [_r9]
		X64_Pop(_R9); ;// pop     r9
		;//
		REX_W mov    eax, _argC.dw[0];// mov     rax, qword ptr [_argC]
		;// 
		;// final stack adjustment, according to the    ;//
		;// number of arguments above 4                 ;// 
		test   al, 1;// test    al, 1
		jnz    _no_adjust;// jnz     _no_adjust
		sub    esp, 8;// sub     rsp, 8
	_no_adjust:;//
		;// 
		push   edi;// push    rdi
		REX_W mov    edi, restArgs.dw[0];// mov     rdi, qword ptr [restArgs]
		;// 
		;// put rest of arguments on the stack          ;// 
		REX_W test   eax, eax;// test    rax, rax
		jz     _ls_e;// je      _ls_e
		REX_W lea    edi, dword ptr[edi + 8 * eax - 8];// lea     rdi, [rdi + rax*8 - 8]
		;// 
	_ls:;// 
		REX_W test   eax, eax;// test    rax, rax
		jz     _ls_e;// je      _ls_e
		push   dword ptr[edi];// push    qword ptr [rdi]
		REX_W sub    edi, 8;// sub     rdi, 8
		REX_W sub    eax, 1;// sub     rax, 1
		jmp    _ls;// jmp     _ls
	_ls_e:;// 
		;// 
		;// create stack space for spilling registers   ;// 
		REX_W sub    esp, 0x20;// sub     rsp, 20h
		;// 
		call   func;// call    qword ptr [func]
		;// 
		;// cleanup stack                               ;// 
		REX_W mov    ecx, _argC.dw[0];// mov     rcx, qword ptr [_argC]
		REX_W lea    esp, dword ptr[esp + 8 * ecx + 0x20];// lea     rsp, [rsp + rcx*8 + 20h]
		;// 
		pop    edi;// pop     rdi
		;// 
// set return value                             ;// 
		REX_W mov    _rax.dw[0], eax;// mov     qword ptr [_rax], rax

		X64_End();

		mov    ax, ds
			mov    ss, ax
			mov    esp, back_esp

			;// restore FS segment
		mov    ax, back_fs
			mov    fs, ax
	}
	return _rax.v;
}
#pragma warning(pop)

void getMem64(void* dstMem, DWORD64 srcMem, SIZE_T sz)
{
	if ((nullptr == dstMem) || (0 == srcMem) || (0 == sz))
		return;

	reg64 _src = { srcMem };

	__asm
	{
		X64_Start();

		;// below code is compiled as x86 inline asm, but it is executed as x64 code
		;// that's why it need sometimes REX_W() macro, right column contains detailed
		;// transcription how it will be interpreted by CPU

		push   edi;// push     rdi
		push   esi;// push     rsi
		;//
		mov    edi, dstMem;// mov      edi, dword ptr [dstMem]        ; high part of RDI is zeroed
		REX_W mov    esi, _src.dw[0];// mov      rsi, qword ptr [_src]
		mov    ecx, sz;// mov      ecx, dword ptr [sz]            ; high part of RCX is zeroed
		;//
		mov    eax, ecx;// mov      eax, ecx
		and eax, 3;// and      eax, 3
		shr    ecx, 2;// shr      ecx, 2
		;//
		rep    movsd;// rep movs dword ptr [rdi], dword ptr [rsi]
		;//
		test   eax, eax;// test     eax, eax
		je     _move_0;// je       _move_0
		cmp    eax, 1;// cmp      eax, 1
		je     _move_1;// je       _move_1
		;//
		movsw;// movs     word ptr [rdi], word ptr [rsi]
		cmp    eax, 2;// cmp      eax, 2
		je     _move_0;// je       _move_0
		;//
	_move_1:;//
		movsb;// movs     byte ptr [rdi], byte ptr [rsi]
		;//
	_move_0:;//
		pop    esi;// pop      rsi
		pop    edi;// pop      rdi

		X64_End();
	}
}

bool cmpMem64(void* dstMem, DWORD64 srcMem, SIZE_T sz)
{
	if ((nullptr == dstMem) || (0 == srcMem) || (0 == sz))
		return false;

	bool result = false;
	reg64 _src = { srcMem };
	__asm
	{
		X64_Start();

		;// below code is compiled as x86 inline asm, but it is executed as x64 code
		;// that's why it need sometimes REX_W() macro, right column contains detailed
		;// transcription how it will be interpreted by CPU

		push   edi;// push      rdi
		push   esi;// push      rsi
		;//           
		mov    edi, dstMem;// mov       edi, dword ptr [dstMem]       ; high part of RDI is zeroed
		REX_W mov    esi, _src.dw[0];// mov       rsi, qword ptr [_src]
		mov    ecx, sz;// mov       ecx, dword ptr [sz]           ; high part of RCX is zeroed
		;//           
		mov    eax, ecx;// mov       eax, ecx
		and eax, 3;// and       eax, 3
		shr    ecx, 2;// shr       ecx, 2
		;// 
		repe   cmpsd;// repe cmps dword ptr [rsi], dword ptr [rdi]
		jnz     _ret_false;// jnz       _ret_false
		;// 
		test   eax, eax;// test      eax, eax
		je     _move_0;// je        _move_0
		cmp    eax, 1;// cmp       eax, 1
		je     _move_1;// je        _move_1
		;// 
		cmpsw;// cmps      word ptr [rsi], word ptr [rdi]
		jnz     _ret_false;// jnz       _ret_false
		cmp    eax, 2;// cmp       eax, 2
		je     _move_0;// je        _move_0
		;// 
	_move_1:;// 
		cmpsb;// cmps      byte ptr [rsi], byte ptr [rdi]
		jnz     _ret_false;// jnz       _ret_false
		;// 
	_move_0:;// 
		mov    result, 1;// mov       byte ptr [result], 1
		;// 
	_ret_false:;// 
		pop    esi;// pop      rsi
		pop    edi;// pop      rdi

		X64_End();
	}

	return result;
}

DWORD64 getTEB64()
{
	reg64 reg;
	reg.v = 0;

	X64_Start();
	// R12 register should always contain pointer to TEB64 in WoW64 processes
	X64_Push(_R12);
	// below pop will pop QWORD from stack, as we're in x64 mode now
	__asm pop reg.dw[0]
		X64_End();

	return reg.v;
}

extern "C" DWORD64  GetModuleHandle64(const char* lpModuleName)
{
	if (!g_isWow64)
		return 0;

	TEB64 teb64;
	getMem64(&teb64, getTEB64(), sizeof(TEB64));

	PEB64 peb64;
	getMem64(&peb64, teb64.ProcessEnvironmentBlock, sizeof(PEB64));
	PEB_LDR_DATA64 ldr;
	getMem64(&ldr, peb64.Ldr, sizeof(PEB_LDR_DATA64));

	DWORD64 LastEntry = peb64.Ldr + offsetof(PEB_LDR_DATA64, InLoadOrderModuleList);
	LDR_DATA_TABLE_ENTRY64 head;
	head.InLoadOrderLinks.Flink = ldr.InLoadOrderModuleList.Flink;
	do
	{
		getMem64(&head, head.InLoadOrderLinks.Flink, sizeof(LDR_DATA_TABLE_ENTRY64));


		wchar_t* unicodeBuf = (wchar_t*)malloc(head.BaseDllName.MaximumLength);
		if (nullptr == unicodeBuf)
			return 0;
		WATCH(unicodeBuf);
		getMem64(unicodeBuf, head.BaseDllName.Buffer, head.BaseDllName.MaximumLength);

		int ansiLen = WideCharToMultiByte(CP_ACP, 0, unicodeBuf, -1, nullptr, 0, nullptr, nullptr);
		if (ansiLen == 0)
			continue;

		char* ansiBuf = (char*)malloc(ansiLen);
		if (nullptr == ansiBuf)
			continue;
		WATCH(ansiBuf);
		WideCharToMultiByte(CP_ACP, 0, unicodeBuf, -1, ansiBuf, ansiLen, nullptr, nullptr);

		if (0 == _stricmp(lpModuleName, ansiBuf))
			return head.DllBase;
	} while (head.InLoadOrderLinks.Flink != LastEntry);

	return 0;
}

DWORD64 getLdrGetProcedureAddress()
{
	DWORD64 modBase = getNTDLL64();
	if (0 == modBase)
		return 0;

	IMAGE_DOS_HEADER idh;
	getMem64(&idh, modBase, sizeof(idh));

	IMAGE_NT_HEADERS64 inh;
	getMem64(&inh, modBase + idh.e_lfanew, sizeof(IMAGE_NT_HEADERS64));

	IMAGE_DATA_DIRECTORY& idd = inh.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	if (0 == idd.VirtualAddress)
		return 0;

	IMAGE_EXPORT_DIRECTORY ied;
	getMem64(&ied, modBase + idd.VirtualAddress, sizeof(ied));

	DWORD* rvaTable = (DWORD*)malloc(sizeof(DWORD) * ied.NumberOfFunctions);
	if (nullptr == rvaTable)
		return 0;
	WATCH(rvaTable);
	getMem64(rvaTable, modBase + ied.AddressOfFunctions, sizeof(DWORD) * ied.NumberOfFunctions);

	WORD* ordTable = (WORD*)malloc(sizeof(WORD) * ied.NumberOfFunctions);
	if (nullptr == ordTable)
		return 0;
	WATCH(ordTable);
	getMem64(ordTable, modBase + ied.AddressOfNameOrdinals, sizeof(WORD) * ied.NumberOfFunctions);

	DWORD* nameTable = (DWORD*)malloc(sizeof(DWORD) * ied.NumberOfNames);
	if (nullptr == nameTable)
		return 0;
	WATCH(nameTable);
	getMem64(nameTable, modBase + ied.AddressOfNames, sizeof(DWORD) * ied.NumberOfNames);

	// lazy search, there is no need to use binsearch for just one function
	for (DWORD i = 0; i < ied.NumberOfFunctions; i++)
	{
		if (!cmpMem64((void*)"LdrGetProcedureAddress", modBase + nameTable[i], sizeof("LdrGetProcedureAddress")))
			continue;
		else
			return modBase + rvaTable[ordTable[i]];
	}
	return 0;
}

DWORD64 getNTDLL64()
{
	static DWORD64 ntdll64 = 0;
	if (0 != ntdll64)
		return ntdll64;

	ntdll64 = GetModuleHandle64("ntdll.dll");
	return ntdll64;
}

extern "C" VOID __cdecl SetLastErrorFromX64Call(DWORD64 status)
{
	typedef ULONG(WINAPI* RtlNtStatusToDosError_t)(NTSTATUS Status);
	typedef ULONG(WINAPI* RtlSetLastWin32Error_t)(NTSTATUS Status);

	static RtlNtStatusToDosError_t RtlNtStatusToDosError = nullptr;
	static RtlSetLastWin32Error_t RtlSetLastWin32Error = nullptr;

	if ((nullptr == RtlNtStatusToDosError) || (nullptr == RtlSetLastWin32Error))
	{
		HMODULE ntdll = GetModuleHandleA("ntdll.dll");
		RtlNtStatusToDosError = (RtlNtStatusToDosError_t)GetProcAddress(ntdll, "RtlNtStatusToDosError");
		RtlSetLastWin32Error = (RtlSetLastWin32Error_t)GetProcAddress(ntdll, "RtlSetLastWin32Error");
	}

	if ((nullptr != RtlNtStatusToDosError) && (nullptr != RtlSetLastWin32Error))
	{
		RtlSetLastWin32Error(RtlNtStatusToDosError((DWORD)status));
	}
}

extern "C" DWORD64 __cdecl GetProcAddress64(DWORD64 hModule, const char* funcName)
{
	static DWORD64 _LdrGetProcedureAddress = 0;
	if (0 == _LdrGetProcedureAddress)
	{
		_LdrGetProcedureAddress = getLdrGetProcedureAddress();
		if (0 == _LdrGetProcedureAddress)
			return 0;
	}

	_UNICODE_STRING_T<DWORD64> fName = { 0 };
	fName.Buffer = (DWORD64)funcName;
	fName.Length = (WORD)strlen(funcName);
	fName.MaximumLength = fName.Length + 1;
	DWORD64 funcRet = 0;
	X64Call(_LdrGetProcedureAddress, 4, (DWORD64)hModule, (DWORD64)&fName, (DWORD64)0, (DWORD64)&funcRet);
	return funcRet;

	return 0;
}

extern "C" SIZE_T __cdecl VirtualQueryEx64(HANDLE hProcess, DWORD64 lpAddress, MEMORY_BASIC_INFORMATION64 * lpBuffer, SIZE_T dwLength)
{

	static DWORD64 ntqvm = 0;
	if (0 == ntqvm)
	{
		ntqvm = GetProcAddress64(getNTDLL64(), "NtQueryVirtualMemory");
		if (0 == ntqvm)
			return 0;
	}
	DWORD64 ret = 0;
	DWORD64 status = X64Call(ntqvm, 6, (DWORD64)hProcess, lpAddress, (DWORD64)0, (DWORD64)lpBuffer, (DWORD64)dwLength, (DWORD64)&ret);
	if (STATUS_SUCCESS != status)
		SetLastErrorFromX64Call(status);
	return (SIZE_T)ret;
}


extern "C" BOOL __cdecl GetThreadContext64(HANDLE hThread, _CONTEXT64 * lpContext)
{
	static DWORD64 gtc = 0;
	if (0 == gtc)
	{
		gtc = GetProcAddress64(getNTDLL64(), "NtGetContextThread");
		if (0 == gtc)
			return 0;
	}
	DWORD64 ret = X64Call(gtc, 2, (DWORD64)hThread, (DWORD64)lpContext);
	if (STATUS_SUCCESS != ret)
	{
		SetLastErrorFromX64Call(ret);
		return FALSE;
	}
	else
		return TRUE;
}

extern "C" BOOL __cdecl SetThreadContext64(HANDLE hThread, _CONTEXT64 * lpContext)
{
	static DWORD64 stc = 0;
	if (0 == stc)
	{
		stc = GetProcAddress64(getNTDLL64(), "NtSetContextThread");
		if (0 == stc)
			return 0;
	}
	DWORD64 ret = X64Call(stc, 2, (DWORD64)hThread, (DWORD64)lpContext);
	if (STATUS_SUCCESS != ret)
	{
		SetLastErrorFromX64Call(ret);
		return FALSE;
	}
	else
		return TRUE;
}

#endif

extern "C" DWORD64  VirtualAllocEx64(HANDLE hProcess, DWORD64 lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
{

	if (hProcess == NULL || hProcess == INVALID_HANDLE_VALUE || dwSize == 0)
	{
		SetLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}

	long ispid = GetProceBitess2(hProcess);
	if (ispid == PROCESS_INVALID)
	{
		SetLastError(ERROR_INVALID_HANDLE);
		return 0;
	}

#if _WIN64

	return (DWORD64)VirtualAllocEx(hProcess, (LPVOID)lpAddress, dwSize, flAllocationType, flProtect);
#else

	if (ispid == PROCESS_X64)
	{

		static DWORD64 ntavm = 0;
		if (0 == ntavm)
		{
			ntavm = GetProcAddress64(getNTDLL64(), "NtAllocateVirtualMemory");
			if (0 == ntavm)
			{
				SetLastError(ERROR_PROC_NOT_FOUND);
				return 0;
			}
		}

		DWORD64 tmpAddr = lpAddress;
		DWORD64 tmpSize = dwSize;
		DWORD64 ret = X64Call(ntavm, 6, (DWORD64)hProcess, (DWORD64)&tmpAddr, (DWORD64)0, (DWORD64)&tmpSize, (DWORD64)flAllocationType, (DWORD64)flProtect);
		if (STATUS_SUCCESS != ret)
		{
			SetLastErrorFromX64Call(ret);
			return 0;
		}
		else
		{
			return tmpAddr;
		}
	}
	else
	{
		return (DWORD64)VirtualAllocEx(hProcess, (LPVOID)lpAddress, dwSize, flAllocationType, flProtect);
	}
#endif
}

BOOL  VirtualProtectEx64(HANDLE hProcess, DWORD64 lpAddress, DWORD64 dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
{
	if (hProcess == NULL || hProcess == INVALID_HANDLE_VALUE || dwSize == 0)
	{
		SetLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}

	long ispid = GetProceBitess2(hProcess);
	if (ispid == PROCESS_INVALID)
	{
		SetLastError(ERROR_INVALID_HANDLE);
		return 0;
	}

#if _WIN64
	return VirtualProtectEx(hProcess, (LPVOID)lpAddress, dwSize, flNewProtect, lpflOldProtect);
#else
	if (ispid == PROCESS_X64)
	{
		static DWORD64 ntavm = 0;
		if (0 == ntavm)
		{
			ntavm = GetProcAddress64(getNTDLL64(), "NtProtectVirtualMemory");
			if (0 == ntavm)
			{
				SetLastError(ERROR_PROC_NOT_FOUND);
				return 0;
			}
		}


		DWORD64 tmpAddr = lpAddress;
		DWORD64 tmpSize = dwSize;
		DWORD64 ret = X64Call(ntavm, 5, (DWORD64)hProcess, (DWORD64)&tmpAddr, (DWORD64)&tmpSize, (DWORD64)flNewProtect, (DWORD64)lpflOldProtect);
		if (STATUS_SUCCESS != ret)
		{
			SetLastErrorFromX64Call(ret);
			return 0;
		}
		else
		{
			return ret;
		}
	}
	else
	{
		return (DWORD64)VirtualProtectEx(hProcess, (LPVOID)lpAddress, dwSize, flNewProtect, lpflOldProtect);
	}
#endif
}

extern "C" BOOL  VirtualFreeEx64(HANDLE hProcess, DWORD64 lpAddress, SIZE_T dwSize, DWORD dwFreeType)
{
	if (hProcess == NULL || hProcess == INVALID_HANDLE_VALUE || lpAddress == 0)
	{
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	long ispid = GetProceBitess2(hProcess);
	if (ispid == PROCESS_INVALID)
	{
		SetLastError(ERROR_INVALID_HANDLE);
		return FALSE;
	}

#if _WIN64
	return VirtualFreeEx(hProcess, (LPVOID)lpAddress, dwSize, dwFreeType);
#else
	if (ispid == PROCESS_X64)
	{
		static DWORD64 ntfvm = 0;
		if (0 == ntfvm)
		{
			ntfvm = GetProcAddress64(getNTDLL64(), "NtFreeVirtualMemory");
			if (0 == ntfvm)
			{
				SetLastError(ERROR_PROC_NOT_FOUND);
				return FALSE;
			}
		}

		DWORD64 tmpAddr = lpAddress;
		DWORD64 tmpSize = dwSize;
		DWORD64 ret = X64Call(ntfvm, 4, (DWORD64)hProcess, (DWORD64)&tmpAddr, (DWORD64)&tmpSize, (DWORD64)dwFreeType);
		if (STATUS_SUCCESS != ret)
		{
			SetLastErrorFromX64Call(ret);
			return FALSE;
		}
		else
		{
			return TRUE;
		}
	}
	else
	{
		return VirtualFreeEx(hProcess, (LPVOID)lpAddress, dwSize, dwFreeType);
	}
#endif
}
extern "C" BOOL  ReadProcessMemory64(HANDLE hProcess, DWORD64 lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T * lpNumberOfBytesRead)
{
	if (hProcess == NULL || hProcess == INVALID_HANDLE_VALUE || lpBuffer == NULL || nSize == 0)
	{
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	long ispid = GetProceBitess2(hProcess);
	if (ispid == PROCESS_INVALID)
	{
		SetLastError(ERROR_INVALID_HANDLE);
		return FALSE;
	}

#if _WIN64
	return ReadProcessMemory(hProcess, (LPVOID)lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
#else
	if (ispid == PROCESS_X64)
	{
		static DWORD64 nrvm = 0;
		if (0 == nrvm)
		{
			nrvm = GetProcAddress64(getNTDLL64(), "NtReadVirtualMemory");
			if (0 == nrvm)
			{
				SetLastError(ERROR_PROC_NOT_FOUND);
				return FALSE;
			}
		}

		DWORD64 numOfBytes = 0;
		DWORD64 ret = X64Call(nrvm, 5, (DWORD64)hProcess, lpBaseAddress, (DWORD64)lpBuffer, (DWORD64)nSize, (DWORD64)&numOfBytes);

		if (STATUS_SUCCESS != ret)
		{
			SetLastErrorFromX64Call(ret);
			return FALSE;
		}
		else
		{
			if (lpNumberOfBytesRead)
				*lpNumberOfBytesRead = (SIZE_T)numOfBytes;
			return TRUE;
		}
	}
	else
	{
		return ReadProcessMemory(hProcess, (LPVOID)lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
	}
#endif
}

extern "C" BOOL  WriteProcessMemory64(HANDLE hProcess, DWORD64 lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T * lpNumberOfBytesWritten)
{
	if (hProcess == NULL || hProcess == INVALID_HANDLE_VALUE || lpBuffer == NULL || nSize == 0)
	{
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	long ispid = GetProceBitess2(hProcess);
	if (ispid == PROCESS_INVALID)
	{
		SetLastError(ERROR_INVALID_HANDLE);
		return FALSE;
	}

#if _WIN64
	return WriteProcessMemory(hProcess, (LPVOID)lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
#else
	if (ispid == PROCESS_X64)
	{
		static DWORD64 nrvm = 0;
		if (0 == nrvm)
		{
			nrvm = GetProcAddress64(getNTDLL64(), "NtWriteVirtualMemory");
			if (0 == nrvm)
			{
				SetLastError(ERROR_PROC_NOT_FOUND);
				return FALSE;
			}
		}

		DWORD64 numOfBytes = 0;
		DWORD64 ret = X64Call(nrvm, 5, (DWORD64)hProcess, lpBaseAddress, (DWORD64)lpBuffer, (DWORD64)nSize, (DWORD64)&numOfBytes);

		if (STATUS_SUCCESS != ret)
		{
			SetLastErrorFromX64Call(ret);
			return FALSE;
		}
		else
		{
			if (lpNumberOfBytesWritten)
				*lpNumberOfBytesWritten = (SIZE_T)numOfBytes;
			return TRUE;
		}
	}
	else
	{
		return WriteProcessMemory(hProcess, (LPVOID)lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
	}
#endif
}

extern "C" HANDLE  CreateRemoteThread64(HANDLE hProcess, DWORD64 lpStartAddress, DWORD64 lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)
{
	if (hProcess == NULL || hProcess == INVALID_HANDLE_VALUE || lpStartAddress == 0)
	{
		SetLastError(ERROR_INVALID_PARAMETER);
		return NULL;
	}

	long ispid = GetProceBitess2(hProcess);
	if (ispid == PROCESS_INVALID)
	{
		SetLastError(ERROR_INVALID_HANDLE);
		return NULL;
	}

#if _WIN64
	return CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpStartAddress, (LPVOID)lpParameter, dwCreationFlags, lpThreadId);
#else
	if (ispid == PROCESS_X64)
	{
		struct _CLIENT_ID {
			DWORD64 UniqueProcess;
			DWORD64 UniqueThread;
		};

		DWORD64 pRtlCreateUserThread = GetProcAddress64(getNTDLL64(), "RtlCreateUserThread");;// FindApiByHash64(GetModuleHandle64("ntdll.dll"), 0xb22520d44402d2c6);
		if (!pRtlCreateUserThread)
		{
			SetLastError(ERROR_PROC_NOT_FOUND);
			return NULL;
		}

		BOOL createSuspended = (dwCreationFlags & CREATE_SUSPENDED) != 0;

		_CLIENT_ID clientId = { 0 };
		HANDLE threadHandle = NULL;
		NTSTATUS status = (NTSTATUS)X64Call(
			pRtlCreateUserThread, 10,
			(DWORD64)hProcess, (DWORD64)NULL, (DWORD64)createSuspended,
			(DWORD64)0, (DWORD64)NULL, (DWORD64)NULL,
			(DWORD64)lpStartAddress, (DWORD64)lpParameter,
			(DWORD64)&threadHandle, (DWORD64)&clientId
		);

		if (!NT_SUCCESS(status) || !threadHandle)
		{
			SetLastErrorFromX64Call(status);
			return NULL;
		}

		if (lpThreadId)
		{
			*lpThreadId = clientId.UniqueThread;
		}

		return threadHandle;
	}
	else
	{
		return CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpStartAddress, (LPVOID)lpParameter, dwCreationFlags, lpThreadId);
	}
#endif
}

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



UINT64 GetRemote64PEBAddress(HANDLE hRemoteProcess)
{
	PROCESS_BASIC_INFORMATION64 pbi64 = { 0 };
	DWORD dwReturnLength = 0;
	typedef NTSTATUS(NTAPI* PFN_NtWow64QueryInformationProcess64)(
		HANDLE ProcessHandle,
		ULONG ProcessInformationClass,
		PVOID ProcessInformation,
		ULONG ProcessInformationLength,
		PULONG ReturnLength
		);

	PFN_NtWow64QueryInformationProcess64 Wow64NtQueryInformationProcess64 = (PFN_NtWow64QueryInformationProcess64)GetProcAddress(
		LoadLibraryA("ntdll.dll"), "NtWow64QueryInformationProcess64"
	);
	if (!Wow64NtQueryInformationProcess64)
	{
		return 0;
	}
	typedef enum _PROCESSINFOCLASS {
		ProcessBasicInformation = 0,
		ProcessDebugPort = 7,
		ProcessWow64Information = 26,
		ProcessImageFileName = 27,
		ProcessBreakOnTermination = 29
	} PROCESSINFOCLASS;


	NTSTATUS status = Wow64NtQueryInformationProcess64(
		hRemoteProcess,
		ProcessBasicInformation,
		&pbi64,
		sizeof(PROCESS_BASIC_INFORMATION64),
		&dwReturnLength
	);
	if (status != STATUS_SUCCESS)
	{
		//printf("Wow64NtQueryInformationProcess64失败，NT状态码：0x%X\n", status);
		return FALSE;
	}

	return pbi64.PebBaseAddress;
}





#ifndef CONTAINING_RECORD
#define CONTAINING_RECORD(address, type, field) \
    ((type *)((PCHAR)(address) - (ULONG_PTR)(&((type *)0)->field)))
#endif


typedef struct _LIST_ENTRY_64 {
	ULONG64 Flink;
	ULONG64 Blink;
} LIST_ENTRY_64, * PLIST_ENTRY_64;

typedef struct _UNICODE_STRING_64 {
	USHORT Length;
	USHORT MaximumLength;
	ULONG64 Buffer;
} UNICODE_STRING_64, * PUNICODE_STRING_64;

typedef struct _LDR_DATA_TABLE_ENTRY_64 {
	LIST_ENTRY_64 InLoadOrderLinks;
	LIST_ENTRY_64 InMemoryOrderLinks;
	LIST_ENTRY_64 InInitializationOrderLinks;
	ULONG64 DllBase;
	ULONG64 EntryPoint;
	ULONG64 SizeOfImage;
	UNICODE_STRING_64 FullDllName;
	UNICODE_STRING_64 BaseDllName;
} LDR_DATA_TABLE_ENTRY_64, * PLDR_DATA_TABLE_ENTRY_64;




DWORD64 GetmemberAddr(DWORD64 currentEntryFlink)
{


	ULONG_PTR memberOffset = offsetof(LDR_DATA_TABLE_ENTRY_64, InLoadOrderLinks);
	DWORD64 structAddr = currentEntryFlink - memberOffset;
	return structAddr;
}

extern "C" DWORD64 GetProcessModules64(HANDLE hRemoteProcess, const char* mode, long& len)
{
	long x64 = GetProceBitess2(hRemoteProcess);
	if (x64 == PROCESS_INVALID)
	{
		return 0;
	}
	if (x64 == PROCESS_X86)
	{
		x64 = 0;
	}

#if _WIN64
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetProcessId(hRemoteProcess));
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		return 0;
	}
	MODULEENTRY32 pe = { sizeof(MODULEENTRY32) };
	BOOL ret = Module32First(hProcessSnap, &pe);
	if (!ret)
	{
		CloseHandle(hProcessSnap);
		return 0;
	}

	while (ret)
	{
		if (_stricmp(mode, pe.szModule) == 0)
		{
			len = pe.modBaseSize;
			CloseHandle(hProcessSnap);
			return (DWORD64)pe.modBaseAddr;
		}
		ret = Module32Next(hProcessSnap, &pe);
	}
	CloseHandle(hProcessSnap);
#else

	if (x64)
	{
		len = 0;
		DWORD64 pRemotePEB = GetRemote64PEBAddress(hRemoteProcess);
		if (hRemoteProcess == NULL || pRemotePEB == 0)
		{
			return 0;
		}

		ULONG64 pRemoteLdr64 = 0;
		DWORD64 pLdrOffset64 = pRemotePEB + 0x18;
		if (!ReadProcessMemory64(
			hRemoteProcess,
			pLdrOffset64,
			&pRemoteLdr64,
			sizeof(ULONG64),
			NULL
		))
		{
			return 0;
		}

		LIST_ENTRY_64 remoteModuleList64 = { 0 };
		DWORD64 pModuleListOffset64 = pRemoteLdr64 + 0x10;
		if (!ReadProcessMemory64(
			hRemoteProcess,
			pModuleListOffset64,
			&remoteModuleList64,
			sizeof(LIST_ENTRY_64),
			NULL
		))
		{
			return 0;
		}

		LIST_ENTRY_64 currentEntry64 = remoteModuleList64;
		DWORD dwModuleIndex = 0;

		do
		{
			DWORD64 pRemoteEntry64 = GetmemberAddr(currentEntry64.Flink);

			LDR_DATA_TABLE_ENTRY_64 moduleEntry64 = { 0 };
			if (!ReadProcessMemory64(
				hRemoteProcess,
				(DWORD64)pRemoteEntry64,
				&moduleEntry64,
				sizeof(LDR_DATA_TABLE_ENTRY_64),
				NULL
			))
			{
				break;
			}

			WCHAR szFullModulePath[MAX_PATH] = { 0 };
			if (moduleEntry64.FullDllName.Length > 0 && moduleEntry64.FullDllName.Buffer != 0)
			{
				ULONG uReadSize = (ULONG)min((ULONG)moduleEntry64.FullDllName.Length, sizeof(szFullModulePath) - 2);
				ReadProcessMemory64(
					hRemoteProcess,
					moduleEntry64.FullDllName.Buffer,
					szFullModulePath,
					uReadSize,
					NULL
				);
			}

			WCHAR szModuleName[MAX_PATH] = { 0 };
			if (moduleEntry64.BaseDllName.Length > 0 && moduleEntry64.BaseDllName.Buffer != 0)
			{
				ULONG uReadSize = (ULONG)min((ULONG)moduleEntry64.BaseDllName.Length, sizeof(szModuleName) - 2);
				ReadProcessMemory64(
					hRemoteProcess,
					moduleEntry64.BaseDllName.Buffer,
					szModuleName,
					uReadSize,
					NULL
				);
			}

			dwModuleIndex++;
			if (mode != NULL)
			{
				WCHAR szModeUnicode[MAX_PATH] = { 0 };
				MultiByteToWideChar(
					CP_ACP,
					0,
					mode,
					-1,
					szModeUnicode,
					MAX_PATH
				);

				if (_wcsicmp(szModeUnicode, szModuleName) == 0)
				{
					len = (long)moduleEntry64.SizeOfImage;
					return (DWORD64)moduleEntry64.DllBase;
				}
			}

			if (currentEntry64.Flink == 0)
			{
				break;
			}

			if (!ReadProcessMemory64(
				hRemoteProcess,
				currentEntry64.Flink,
				&currentEntry64,
				sizeof(LIST_ENTRY_64),
				NULL
			))
			{
				break;
			}

		} while ((ULONG64)currentEntry64.Flink != (ULONG64)remoteModuleList64.Flink);
	}
	else
	{
		long pid = GetProcessId(hRemoteProcess);
		if (!pid)
		{
			return 0;
		}
		HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
		if (hProcessSnap == INVALID_HANDLE_VALUE)
		{
			return 0;
		}
		MODULEENTRY32 pe = { sizeof(MODULEENTRY32) };
		BOOL ret = Module32First(hProcessSnap, &pe);
		if (!ret)
		{
			CloseHandle(hProcessSnap);
			return 0;
		}

		while (ret)
		{
			if (_stricmp(mode, pe.szModule) == 0)
			{
				len = pe.modBaseSize;
				CloseHandle(hProcessSnap);
				return (DWORD64)pe.modBaseAddr;
			}
			ret = Module32Next(hProcessSnap, &pe);
		}
		CloseHandle(hProcessSnap);

	}
#endif




	return 0;
}

DWORD64 GetProcessModulesProc64(HANDLE hRemoteProcess, const char* moduleName, const char* procName)
{
	long x64 = GetProceBitess2(hRemoteProcess);
	if (x64 == PROCESS_INVALID)
	{
		return 0;
	}

	if (x64 == PROCESS_X86)
	{
		x64 = 0;
	}


	long moduleSize = 0;
	DWORD64 moduleBase = GetProcessModules64(hRemoteProcess, moduleName, moduleSize);
	if (!moduleBase) return 0;

	IMAGE_DOS_HEADER dosHeader;
	SIZE_T bytesRead = 0;

	if (!ReadProcessMemory64(hRemoteProcess, moduleBase, &dosHeader, sizeof(IMAGE_DOS_HEADER), &bytesRead) ||
		bytesRead != sizeof(IMAGE_DOS_HEADER) || dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
	{
		return 0;
	}

	IMAGE_NT_HEADERS32 ntHeaders32;
	IMAGE_NT_HEADERS64 ntHeaders64;

	if (x64)
	{
		if (!ReadProcessMemory64(hRemoteProcess, moduleBase + dosHeader.e_lfanew, &ntHeaders64, sizeof(IMAGE_NT_HEADERS64), &bytesRead) ||
			bytesRead != sizeof(IMAGE_NT_HEADERS64) || ntHeaders64.Signature != IMAGE_NT_SIGNATURE)
		{
			return 0;
		}
		if (ntHeaders64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0 ||
			ntHeaders64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == 0)
		{
			return 0;
		}

	}
	else
	{
		if (!ReadProcessMemory64(hRemoteProcess, moduleBase + dosHeader.e_lfanew, &ntHeaders32, sizeof(IMAGE_NT_HEADERS32), &bytesRead) ||
			bytesRead != sizeof(IMAGE_NT_HEADERS32) || ntHeaders32.Signature != IMAGE_NT_SIGNATURE)
		{
			return 0;
		}
		if (ntHeaders32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0 ||
			ntHeaders32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == 0)
		{
			return 0;
		}
	}





	IMAGE_EXPORT_DIRECTORY exportDir;

	DWORD exportDirRVA = 0;
	if (x64)
	{
		exportDirRVA = ntHeaders64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	}
	else
	{
		exportDirRVA = ntHeaders32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	}


	if (!ReadProcessMemory64(hRemoteProcess, moduleBase + exportDirRVA, &exportDir, sizeof(IMAGE_EXPORT_DIRECTORY), &bytesRead) ||
		bytesRead != sizeof(IMAGE_EXPORT_DIRECTORY))
	{
		return 0;
	}

	DWORD* functionNames = new DWORD[exportDir.NumberOfNames];
	DWORD* functionAddrs = new DWORD[exportDir.NumberOfFunctions];
	WORD* functionOrds = new WORD[exportDir.NumberOfNames];

	if (!ReadProcessMemory64(hRemoteProcess, moduleBase + exportDir.AddressOfNames, functionNames, exportDir.NumberOfNames * sizeof(DWORD), &bytesRead) ||
		bytesRead != exportDir.NumberOfNames * sizeof(DWORD))
	{
		delete[] functionNames;
		delete[] functionAddrs;
		delete[] functionOrds;
		return 0;
	}

	if (!ReadProcessMemory64(hRemoteProcess, moduleBase + exportDir.AddressOfFunctions, functionAddrs, exportDir.NumberOfFunctions * sizeof(DWORD), &bytesRead) ||
		bytesRead != exportDir.NumberOfFunctions * sizeof(DWORD))
	{
		delete[] functionNames;
		delete[] functionAddrs;
		delete[] functionOrds;
		return 0;
	}

	if (!ReadProcessMemory64(hRemoteProcess, moduleBase + exportDir.AddressOfNameOrdinals, functionOrds, exportDir.NumberOfNames * sizeof(WORD), &bytesRead) ||
		bytesRead != exportDir.NumberOfNames * sizeof(WORD))
	{
		delete[] functionNames;
		delete[] functionAddrs;
		delete[] functionOrds;
		return 0;
	}

	DWORD64 functionAddr = 0;
	for (DWORD i = 0; i < exportDir.NumberOfNames; i++)
	{
		char funcName[MAX_PATH] = { 0 };
		if (!ReadProcessMemory64(hRemoteProcess, moduleBase + functionNames[i], funcName, MAX_PATH, &bytesRead) || bytesRead == 0)
		{
			continue;
		}

		if (_stricmp(funcName, procName) == 0)
		{
			WORD ordinal = functionOrds[i];
			if (ordinal < exportDir.NumberOfFunctions)
			{
				functionAddr = moduleBase + functionAddrs[ordinal];
			}
			break;
		}
	}

	delete[] functionNames;
	delete[] functionAddrs;
	delete[] functionOrds;

	return functionAddr;
}

DWORD64 GetProcessModulesProc64_2(HANDLE hRemoteProcess, DWORD64 moduleBase, const char* procName)
{
	long x64 = GetProceBitess2(hRemoteProcess);
	if (x64 == PROCESS_INVALID)
	{
		return 0;
	}

	if (x64 == PROCESS_X86)
	{
		x64 = 0;
	}


	long moduleSize = 0;

	if (!moduleBase) return 0;

	IMAGE_DOS_HEADER dosHeader;
	SIZE_T bytesRead = 0;

	if (!ReadProcessMemory64(hRemoteProcess, moduleBase, &dosHeader, sizeof(IMAGE_DOS_HEADER), &bytesRead) ||
		bytesRead != sizeof(IMAGE_DOS_HEADER) || dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
	{
		return 0;
	}

	IMAGE_NT_HEADERS32 ntHeaders32;
	IMAGE_NT_HEADERS64 ntHeaders64;

	if (x64)
	{
		if (!ReadProcessMemory64(hRemoteProcess, moduleBase + dosHeader.e_lfanew, &ntHeaders64, sizeof(IMAGE_NT_HEADERS64), &bytesRead) ||
			bytesRead != sizeof(IMAGE_NT_HEADERS64) || ntHeaders64.Signature != IMAGE_NT_SIGNATURE)
		{
			return 0;
		}
		if (ntHeaders64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0 ||
			ntHeaders64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == 0)
		{
			return 0;
		}

	}
	else
	{
		if (!ReadProcessMemory64(hRemoteProcess, moduleBase + dosHeader.e_lfanew, &ntHeaders32, sizeof(IMAGE_NT_HEADERS32), &bytesRead) ||
			bytesRead != sizeof(IMAGE_NT_HEADERS32) || ntHeaders32.Signature != IMAGE_NT_SIGNATURE)
		{
			return 0;
		}
		if (ntHeaders32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0 ||
			ntHeaders32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == 0)
		{
			return 0;
		}
	}





	IMAGE_EXPORT_DIRECTORY exportDir;

	DWORD exportDirRVA = 0;
	if (x64)
	{
		exportDirRVA = ntHeaders64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	}
	else
	{
		exportDirRVA = ntHeaders32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	}


	if (!ReadProcessMemory64(hRemoteProcess, moduleBase + exportDirRVA, &exportDir, sizeof(IMAGE_EXPORT_DIRECTORY), &bytesRead) ||
		bytesRead != sizeof(IMAGE_EXPORT_DIRECTORY))
	{
		return 0;
	}

	DWORD* functionNames = new DWORD[exportDir.NumberOfNames];
	DWORD* functionAddrs = new DWORD[exportDir.NumberOfFunctions];
	WORD* functionOrds = new WORD[exportDir.NumberOfNames];

	if (!ReadProcessMemory64(hRemoteProcess, moduleBase + exportDir.AddressOfNames, functionNames, exportDir.NumberOfNames * sizeof(DWORD), &bytesRead) ||
		bytesRead != exportDir.NumberOfNames * sizeof(DWORD))
	{
		delete[] functionNames;
		delete[] functionAddrs;
		delete[] functionOrds;
		return 0;
	}

	if (!ReadProcessMemory64(hRemoteProcess, moduleBase + exportDir.AddressOfFunctions, functionAddrs, exportDir.NumberOfFunctions * sizeof(DWORD), &bytesRead) ||
		bytesRead != exportDir.NumberOfFunctions * sizeof(DWORD))
	{
		delete[] functionNames;
		delete[] functionAddrs;
		delete[] functionOrds;
		return 0;
	}

	if (!ReadProcessMemory64(hRemoteProcess, moduleBase + exportDir.AddressOfNameOrdinals, functionOrds, exportDir.NumberOfNames * sizeof(WORD), &bytesRead) ||
		bytesRead != exportDir.NumberOfNames * sizeof(WORD))
	{
		delete[] functionNames;
		delete[] functionAddrs;
		delete[] functionOrds;
		return 0;
	}

	DWORD64 functionAddr = 0;
	for (DWORD i = 0; i < exportDir.NumberOfNames; i++)
	{
		char funcName[MAX_PATH] = { 0 };
		if (!ReadProcessMemory64(hRemoteProcess, moduleBase + functionNames[i], funcName, MAX_PATH, &bytesRead) || bytesRead == 0)
		{
			continue;
		}

		if (_stricmp(funcName, procName) == 0)
		{
			WORD ordinal = functionOrds[i];
			if (ordinal < exportDir.NumberOfFunctions)
			{
				functionAddr = moduleBase + functionAddrs[ordinal];
			}
			break;
		}
	}

	delete[] functionNames;
	delete[] functionAddrs;
	delete[] functionOrds;

	return functionAddr;
}

BOOL TerminateProcess64(HANDLE hProcess, HANDLE hPpid, UINT uExitCode)
{
	long x64 = GetProceBitess2(hProcess);
	if (x64 == PROCESS_INVALID)
	{
		return FALSE;
	}

	if (x64 == PROCESS_X86)
	{
		x64 = 0;
	}

#if _WIN64
	return TerminateProcess(hProcess, uExitCode);
#else
	if (x64)
	{
		DWORD64 Terminat = GetProcessModulesProc64(hPpid, "kernel32.dll", "TerminateProcess");
		if (!Terminat)
		{
			return FALSE;
		}
		return X64Call(Terminat, 2, hProcess, uExitCode);
	}
	else
	{
		return TerminateProcess(hProcess, uExitCode);
	}

#endif


	return 0;
}

