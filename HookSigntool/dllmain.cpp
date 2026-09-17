// dllmain.cpp :
#include "pch.h"
#include <wincrypt.h>
#include <string>
#include <vector>
#include <istream>
#include <sstream>
#include "hook.h"
#include "nmd_assembly.h"
#include <shellapi.h>
#include <strsafe.h>
#include "WOW64Ext.h"
#include "GetAddress.h"
#include <wchar.h>

LPWSTR* g_argv = NULL;
int g_argc = 0;


EXTERN_C ULONG_PTR GetWriteCodeLen(PVOID buffer);
typedef HANDLE (WINAPI* pCreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef HANDLE (WINAPI* pCreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL (WINAPI* pCloseHandle)( HANDLE );
pCreateFileW g_CreateFileW_or = 0;
pCreateFileA g_CreateFileA_or = 0;
pCloseHandle g_CloseHandle_or = 0;

hook g_CreateFileW;
hook g_CreateFileA;
hook g_CloseHandle;

#pragma pack(push, 1)
typedef struct _Myhokk
{
#if _WIN64

	const BYTE  by1[6] = { 0xFF, 0x25, 0, 0, 0, 0 };
	DWORD64 jmpl = 0;
#else

	const BYTE  by1[2] = { 0xFF, 0x25 };
	DWORD Getaddr = 0;
	DWORD jmpl = 0;
#endif // !_WIN64

} Myhokk, * PMyhokk;
typedef struct _Myhokk64
{


	const BYTE  by1[7] = {
		0x48,0x89,0x44,0x24,0x20,
		//0x48,0x83,0xEC,0x20,
		0x48,0xB8 };
	LPVOID call1 = 0;
	const BYTE  by2[9] = { 0xFF,0xD0,
		//0x48,0x83,0xC4,0x20,
		0xFF,0x25,0x01,0x00,0x00,0x00,
		0xC3 };
	LPVOID jmpl = 0;
} Myhokk64, * PMyhokk64k;

#pragma pack(pop)

typedef struct _TSA_Name
{
	int Namelen=0;
	WCHAR szProviderName[12] = {0};

}TSA_Name, * PTSA_Name;

typedef struct _TSA_url
{
	int urltpy = -1;
	int urllen = 0;

}TSA_url, * PTSA_url;


typedef struct _TSA_ITEM
{
	 WCHAR* szProviderName=0;
	WCHAR* szTsaUrl=0;
	WCHAR* szTsaUrl2=0;
} TSA_ITEM;

const WCHAR* g_TSA_ITEM_str[9] =
{
	L"TrustAsia",
	L"Symantec",
	L"Geotrust",
	L"Comodo",
	L"DigiCert",
	L"WoSign",
	L"Globalsign",
	L"Entrust",
	L"GoDaddy"
};


 TSA_Name g_TSA_ITEM[9] =
{
	{9},
	{8},
	{8},
	{6},
	{8},
	{6},
	{10},
	{7},
	{7}
};

TSA_ITEM myTable[9];

hook2 g_GetmyTable;
WCHAR g_newwchar[MAX_PATH] = { 0 };
void FreeTable();

BOOL GetmyTable(std::wstring url,std::string exe)
{
	if (url.empty()||exe.empty())
	{
		return FALSE;
	}
	TSA_url t_TSA_url;
	size_t charCount = url.size() + 1;
	WCHAR* urlp = g_newwchar;
	memcpy(g_newwchar,&t_TSA_url,8);
	PTSA_url p = (PTSA_url)g_newwchar;
	p->urllen = url.size();
	wcscpy_s((WCHAR*)(((DWORD)g_newwchar)+8), charCount, url.c_str());
	for (size_t i = 0; i < 9; i++)
	{
		myTable[i].szProviderName = (WCHAR*)(&g_TSA_ITEM[i].szProviderName);	
		wcscpy_s(myTable[i].szProviderName, g_TSA_ITEM[i].Namelen + 1, g_TSA_ITEM_str[i]);

		myTable[i].szTsaUrl = (WCHAR*)(((DWORD)g_newwchar) + 8);
		myTable[i].szTsaUrl2 = (WCHAR*)(((DWORD)g_newwchar) + 8);
	}	
	GetAddress tmp;
	LONG64 pos = tmp.GetSignAddRess(exe.c_str(), "BE 09 00 00 00 BB ???????? 8B 03");
	if (pos<0)
	{
		FreeTable();
		return FALSE;
	}
	long ptr = (long)&myTable;
	if (!g_GetmyTable.SetHook((LPVOID)(pos + 6), &ptr, sizeof(long)))
	{
		FreeTable();
		return FALSE;
	}
	return TRUE;
}

void FreeTable()
{
	g_GetmyTable.UnHook();
		
	return;
}




BOOL SetProcOr(LPVOID proc, LPVOID hookjmp)
{
	if ((DWORD64)proc <= 0x40000 || (DWORD64)hookjmp <= 0x40000)
	{
		return FALSE;
	}
	_try
	{
	ULONG_PTR len = GetWriteCodeLen(proc);
	if (len <= 4)
	{
		return FALSE;
	}

#if _WIN64
		Myhokk t_Myhokk;
		t_Myhokk.jmpl = (DWORD64)proc + len;
		memcpy(hookjmp, proc, len);
		memcpy((LPVOID)((DWORD64)hookjmp + len), &t_Myhokk, sizeof(Myhokk));

#else
		memcpy(hookjmp, proc, len);
		Myhokk t_Myhokk;

		t_Myhokk.jmpl = (DWORD64)proc + len;
		t_Myhokk.Getaddr = (DWORD)hookjmp + len + offsetof(Myhokk, jmpl);
		memcpy((LPVOID)((DWORD)hookjmp + len), &t_Myhokk, sizeof(Myhokk));

#endif
		return TRUE;
	}
		_except(EXCEPTION_EXECUTE_HANDLER)
	{
		return FALSE;
	}


	return FALSE;
}



void ParseCmdLine()
{
	
	LPWSTR pCmd = ::GetCommandLineW();
	g_argv = ::CommandLineToArgvW(pCmd, &g_argc);

}

#pragma comment(lib, "Crypt32.lib")

hook g_CertVerifyTimeValidity;
hook g_GetLocalTime;
hook g_GetSystemTimeAsFileTime;
hook g_GetSystemTime;
HWND g_hListView = NULL;

EXTERN_C ULONG_PTR GetWriteCodeLen(PVOID buffer)
{
	if (buffer == NULL)
	{
		return 0;
	}

	const size_t MAX_DECODE_LEN = 45;
	const uint8_t* code_base = (const uint8_t*)buffer;
	const uint8_t* code_end = code_base + MAX_DECODE_LEN;


	NMD_X86_MODE decode_mode = (sizeof(void*) == 8) ? NMD_X86_MODE_64 : NMD_X86_MODE_32;

	nmd_x86_instruction instruction = { 0 };
	size_t total_decoded_len = 0;

	while (total_decoded_len < MAX_DECODE_LEN)
	{
		size_t remaining_len = code_end - (code_base + total_decoded_len);
		if (remaining_len == 0)
			break;

		bool decode_ok = nmd_decode_x86(
			code_base + total_decoded_len,
			remaining_len,
			&instruction,
			decode_mode,
			NMD_X86_DECODER_FLAGS_MINIMAL
		);

		if (!decode_ok)
			break;

		total_decoded_len += instruction.length;

		if (total_decoded_len >= 5)
			return (ULONG_PTR)total_decoded_len;
	}


	return total_decoded_len > 0 ? (ULONG_PTR)total_decoded_len : 0;
}

std::vector<std::string> SplitString(const std::string& str, char delimiter)
{
	std::vector<std::string> tokens;
	std::string token;
	std::istringstream tokenStream(str);
	while (std::getline(tokenStream, token, delimiter)) {
		long ret = -1;
		for (size_t i = 0; i < token.length(); i++)
		{
			if (token[i] == '\r')
			{
				token[i] = 0;
				ret = i;
			}
		}
		std::string str = token.c_str();

		tokens.push_back(str);
	}
	return tokens;
}

std::vector<std::wstring> SplitWString(const std::wstring& str, wchar_t delimiter)
{
	std::vector<std::wstring> tokens;
	std::wstring token;
	std::wistringstream tokenStream(str);
	while (std::getline(tokenStream, token, delimiter))
	{
		size_t pos = token.find(L'\r');
		if (pos != std::wstring::npos)
		{
			token = token.substr(0, pos);
		}
	
		size_t start = token.find_first_not_of(L" \t");
		if (start == std::wstring::npos)
		{
			token.clear();
		}
		else
		{
			size_t end = token.find_last_not_of(L" \t");
			token = token.substr(start, end - start + 1);
		}
		if (!token.empty())
		{
			tokens.push_back(token);
		}
	}
	return tokens;
}

long IsFileExist(std::string file)
{
	DWORD dwAttrib = GetFileAttributesA(file.c_str());
	return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
		!(dwAttrib & FILE_ATTRIBUTE_DIRECTORY)) ? 1 : 0;
}

std::string MyReadFile(std::string file)
{
	std::string content;
	HANDLE hFile = CreateFileA(file.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return content;
	}

	DWORD dwFileSize = GetFileSize(hFile, NULL);
	if (dwFileSize > 0) {
		content.resize(dwFileSize);
		DWORD dwBytesRead = 0;
		BOOL bSuccess = ::ReadFile(hFile, &content[0], dwFileSize, &dwBytesRead, NULL);
		if (!bSuccess || dwBytesRead != dwFileSize) {
			content.clear();
		}
	}

	CloseHandle(hFile);
	return content;
}

long MyWriteFile(std::string file, std::string content)
{
	HANDLE hFile = CreateFileA(file.c_str(), GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return 0;
	}

	//
	if (SetFilePointer(hFile, 0, NULL, FILE_END) == INVALID_SET_FILE_POINTER && GetLastError() != NO_ERROR) {
		CloseHandle(hFile);
		return 0;
	}

	DWORD dwBytesWritten = 0;
	BOOL bSuccess = ::WriteFile(hFile, content.c_str(), content.length(), &dwBytesWritten, NULL);
	CloseHandle(hFile);

	return (bSuccess && dwBytesWritten == content.length()) ? 1 : 0;
}

LONG WINAPI MyCertVerifyTimeValidity(LPFILETIME pTimeToVerify,PCERT_INFO pCertInfo)
{
	return 0;
	////SignerSign
	//	SignerTimeStamp
}

SYSTEMTIME g_SYSTEMTIME = { 0 };


VOID WINAPI MyGetLocalTime(LPSYSTEMTIME lpSystemTime)
{
	if (lpSystemTime == nullptr)
		return;
	if (g_SYSTEMTIME.wYear)
	{
		memcpy_s(lpSystemTime, sizeof(SYSTEMTIME), &g_SYSTEMTIME, sizeof(SYSTEMTIME));
		return;
	}
	
	

		lpSystemTime->wYear = 2018;
		lpSystemTime->wMonth = 10;
		lpSystemTime->wDayOfWeek = 6;
		lpSystemTime->wDay = 6;
		lpSystemTime->wHour = 20;
		lpSystemTime->wMinute = 5;
		lpSystemTime->wSecond = 50;
		lpSystemTime->wMilliseconds = 350;
		memcpy_s(&g_SYSTEMTIME, sizeof(SYSTEMTIME), lpSystemTime, sizeof(SYSTEMTIME));
		return;
}


static BOOL IsLeapYear(WORD year)
{
	return ((year % 4 == 0) && (year % 100 != 0)) || (year % 400 == 0);
}

static BOOL MySystemTimeToFileTime(const SYSTEMTIME* st, LPFILETIME ft)
{
	static const WORD days_in_month[12] = { 31,28,31,30,31,30,31,31,30,31,30,31 };
	ULARGE_INTEGER ul = { 0 };
	WORD y = st->wYear;
	WORD m = st->wMonth;
	WORD d = st->wDay;

	if (y < 1601 || m < 1 || m >12 || d < 1 || d>31)
		return FALSE;


	for (WORD yy = 1601; yy < y; yy++)
	{
		ul.QuadPart += IsLeapYear(yy) ? 366ULL : 365ULL;
	}

	for (WORD mm = 1; mm < m; mm++)
	{
		ul.QuadPart += days_in_month[mm - 1];
		if (mm == 2 && IsLeapYear(y))
			ul.QuadPart += 1;
	}
	ul.QuadPart += (d - 1);


	ul.QuadPart = ul.QuadPart * 864000000000ULL;
	ul.QuadPart += (ULONGLONG)st->wHour * 36000000000ULL;
	ul.QuadPart += (ULONGLONG)st->wMinute * 600000000ULL;
	ul.QuadPart += (ULONGLONG)st->wSecond * 10000000ULL;
	ul.QuadPart += (ULONGLONG)st->wMilliseconds * 10000ULL;

	ft->dwLowDateTime = ul.LowPart;
	ft->dwHighDateTime = ul.HighPart;
	return TRUE;
}

VOID WINAPI MyGetSystemTimeAsFileTime(LPFILETIME lpSystemTimeAsFileTime)
{
	if (lpSystemTimeAsFileTime == NULL)
		return;

	MySystemTimeToFileTime(&g_SYSTEMTIME, lpSystemTimeAsFileTime);
	
}



hook g_GetSystemTimePreciseAsFileTime;
BOOL CALLBACK EnumChildRecursive(HWND hWnd, LPARAM lParam)
{
	WCHAR szClassName[256] = { 0 };
	::GetClassNameW(hWnd, szClassName, _countof(szClassName));

	
	if (_wcsicmp(szClassName, L"TListView") == 0 ||
		_wcsicmp(szClassName, L"SysListView32") == 0)
	{
		HWND hParent = ::GetParent(hWnd);
		WCHAR szParentTitle[256] = { 0 };
		if (hParent != NULL)
			::GetWindowTextW(hParent, szParentTitle, _countof(szParentTitle));
		

		if (_wcsicmp(szParentTitle, L"数字签名") == 0)
		{
			g_hListView = hWnd;
		
			return FALSE;
		}
	}


	::EnumChildWindows(hWnd, EnumChildRecursive, lParam);
	return TRUE;
}

HWND g_hMainWndTemp = NULL;
DWORD g_targetPidTemp = 0;

BOOL CALLBACK EnumTopWndCallback(HWND hWnd, LPARAM lParam)
{
	DWORD pid = 0;
	::GetWindowThreadProcessId(hWnd, &pid);
	if (pid == g_targetPidTemp && ::IsWindowVisible(hWnd))
	{
		g_hMainWndTemp = hWnd;
		return FALSE; 
	}
	return TRUE;
}

HWND GetProcessMainWindow(DWORD targetPid)
{
	g_hMainWndTemp = NULL;
	g_targetPidTemp = targetPid;
	::EnumWindows(EnumTopWndCallback, 0);
	return g_hMainWndTemp;
}

DWORD WINAPI EnumWindowThread(LPVOID lpParam)
{
	Sleep(3000);
	DWORD pid = ::GetCurrentProcessId();
	
	for (int nTry = 0; nTry < 30; nTry++)
	{
		HWND hMainWnd = GetProcessMainWindow(pid);
		if (hMainWnd)
		{
			g_hListView = NULL;
			::EnumChildWindows(hMainWnd, EnumChildRecursive, 0);
			if (g_hListView != NULL)
			{
				break;
			}
		}
		Sleep(300);
	}
	return 0;
}
LPVOID VirtualAlloc3();
BOOL FreeMem(LPVOID pMem);
HANDLE WINAPI MyCreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
HANDLE WINAPI MyCreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
BOOL WINAPI	MyCloseHandle(HANDLE hObject);


std::string GetSubBetween(const std::string content,const std::string tagLeft,const std::string tagRight,long searchOffset = 0)
{
	size_t searchPos = static_cast<size_t>(searchOffset);
	size_t startIdx, endIdx;

	if (tagLeft.empty())
	{
		startIdx = searchPos;
	}
	else
	{
		size_t leftPos = content.find(tagLeft, searchPos);
		if (leftPos == std::string::npos)
			return "";
		startIdx = leftPos + tagLeft.length();
	}

	if (tagRight.empty())
	{
		endIdx = content.length();
	}
	else
	{
		size_t rightPos = content.find(tagRight, startIdx);
		if (rightPos == std::string::npos)
			return "";
		endIdx = rightPos;
	}

	return content.substr(startIdx, endIdx - startIdx);
}


std::vector<std::wstring> g_file_list;
WCHAR g_szExeName[256] = { 0 }; 
long g_exefile = 0;
LPVOID g_orproc = 0;
CRITICAL_SECTION g_csHandleList;

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
		CHAR ch[MAX_PATH] = { 0 };
		::GetModuleFileNameA(hModule, ch, MAX_PATH);

		CHAR* pFileName1 = strrchr(ch, L'\\');
		pFileName1++;
		pFileName1[0] = '\0';
		std::string inipath = ch  ;
		inipath += "HookSigntool.ini";
		std::string inistr = MyReadFile(inipath);
		std::wstring wurl;
		
		if (inistr.empty())
		{
			JLZZ:
			inistr =
			{
				"WebUrl=\"http://127.0.0.1:8080\"\n"
				"SYSTEMTIME=\"2018,10,06,06,20,05,50,350\"\n"
			};
			DeleteFileA("HookSigntool.ini");
			MyWriteFile("HookSigntool.ini",inistr);
			g_SYSTEMTIME.wYear = 2018;
			g_SYSTEMTIME.wMonth = 10;
			g_SYSTEMTIME.wDayOfWeek = 6;
			g_SYSTEMTIME.wDay = 6;
			g_SYSTEMTIME.wHour=20;
			g_SYSTEMTIME.wMinute=05;
			g_SYSTEMTIME.wSecond=50;
			g_SYSTEMTIME.wMilliseconds=350;
			wurl = L"http://127.0.0.1:8080";
		}
		else
		{
			std::string str = GetSubBetween(inistr, "WebUrl=\"","\"");
			if (str.empty())
			{
				goto JLZZ;
			}
			wurl=std::wstring(str.begin(),str.end());
			str= GetSubBetween(inistr, "SYSTEMTIME=\"", "\"");
			if (str.empty())
			{
				goto JLZZ;
			}
			std::vector<std::string> cectr = SplitString(str, ',');
			if (cectr.empty()||cectr.size()!=8)
			{
				goto JLZZ;
			}
			g_SYSTEMTIME.wYear = atoi(cectr[0].c_str());
			g_SYSTEMTIME.wMonth = atoi(cectr[1].c_str());
			g_SYSTEMTIME.wDayOfWeek = atoi(cectr[2].c_str());
			g_SYSTEMTIME.wDay = atoi(cectr[3].c_str());;
			g_SYSTEMTIME.wHour = atoi(cectr[4].c_str());
			g_SYSTEMTIME.wMinute = atoi(cectr[5].c_str());
			g_SYSTEMTIME.wSecond = atoi(cectr[6].c_str());
			g_SYSTEMTIME.wMilliseconds = atoi(cectr[7].c_str());
		}

		g_CertVerifyTimeValidity.SetHook(CertVerifyTimeValidity, MyCertVerifyTimeValidity);
		
		HMODULE basedll = GetModuleHandleA("kernelbase.dll");

		LPVOID phh = GetProcAddress(basedll, "GetSystemTimeAsFileTime");

		g_GetSystemTimeAsFileTime.SetHook(phh, MyGetSystemTimeAsFileTime);
		phh = GetProcAddress(basedll, "GetLocalTime");
		g_GetLocalTime.SetHook(phh, MyGetLocalTime);
		phh = GetProcAddress(basedll, "GetSystemTimePreciseAsFileTime");
		g_GetSystemTimePreciseAsFileTime.SetHook(phh, MyGetSystemTimeAsFileTime);
		phh = GetProcAddress(basedll, "GetSystemTime");
		g_GetSystemTime.SetHook(GetProcAddress(basedll, "GetSystemTime"), MyGetLocalTime);

		g_orproc = VirtualAlloc3();
		g_CreateFileW_or = (pCreateFileW)g_orproc;
		g_CloseHandle_or = (pCloseHandle)((DWORD64)g_orproc + 0x50);

		HANDLE ha = OpenProcess(PROCESS_ALL_ACCESS, 0, GetCurrentProcessId());
		
		
		phh = (LPVOID)GetProcessModulesProc64(ha, "kernelbase.dll", "CreateFileW");

		SetProcOr(phh, g_CreateFileW_or);
		g_CreateFileW.SetHook(phh, MyCreateFileW);

		/*g_CreateFileA_or = (pCreateFileA)((DWORD64)g_orproc + 0xA0);
		phh = (LPVOID)GetProcessModulesProc64(ha, "kernelbase.dll", "CreateFileA");
		SetProcOr(phh, g_CreateFileA_or);
		g_CreateFileA.SetHook(phh, MyCreateFileA);*/

	    
		phh = (LPVOID)GetProcessModulesProc64(ha, "kernelbase.dll", "CloseHandle");// GetProcAddress(basedll, "CloseHandle");
		SetProcOr(phh, g_CloseHandle_or);
		CloseHandle(ha);
		g_CloseHandle.SetHook(phh, MyCloseHandle);

		


		InitializeCriticalSection(&g_csHandleList);
		::GetModuleFileNameW(NULL, g_szExeName, _countof(g_szExeName));

		WCHAR* pFileName = wcsrchr(g_szExeName, L'\\');
		if (pFileName)
		{
			pFileName++;
			


			if (_wcsicmp(pFileName, L"DSignTool.exe") == 0)
			{
				if (!GetmyTable(wurl, "DSignTool.exe"))
				{
					exit(0);
				}
				g_exefile = 1;

				CloseHandle(CreateThread(NULL, 0, EnumWindowThread, NULL, 0, NULL));

			}
			else if (_wcsicmp(pFileName, L"CSignTool.exe") == 0)
			{
				

				if (!GetmyTable(wurl, "CSignTool.exe"))
				{
					exit(0);
				}

				ParseCmdLine();
				if (g_argc >= 6)
				{
					LPWSTR pTargetFile = g_argv[5];
					g_file_list = SplitWString(pTargetFile, L',');
					if (g_file_list.empty())
					{
						DeleteCriticalSection(&g_csHandleList);
						exit(0);
					}
					g_exefile = 2;
					
					 
				}
				else
				{
					DeleteCriticalSection(&g_csHandleList);
					exit(0);
				}
			}
		}



		
        break;
    }
    case DLL_THREAD_ATTACH:
    {
        break;
    }
    case DLL_THREAD_DETACH:
    {
        break;
    }
    case DLL_PROCESS_DETACH:
    {
		FreeTable();
		g_CertVerifyTimeValidity.UnHook();
		g_GetLocalTime.UnHook();
		g_GetSystemTimeAsFileTime.UnHook();
		g_GetSystemTime.UnHook();
		g_GetSystemTimePreciseAsFileTime.UnHook();
		g_CreateFileW.UnHook();
		//g_CreateFileA.UnHook();
		g_CloseHandle.UnHook();

		DeleteCriticalSection(&g_csHandleList);
		FreeMem(g_orproc);

        break;
    }
        break;
    }
    return TRUE;
}

LPVOID VirtualAlloc3()
{
	
	LPVOID pMem = VirtualAlloc(NULL, 1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (pMem == nullptr)
	{
		return nullptr;
	}

	return pMem;
}

BOOL FreeMem(LPVOID pMem)
{
	if (pMem == nullptr)
		return FALSE;
	return VirtualFree(pMem, 0, MEM_RELEASE);
}

bool IsTargetFile(const std::wstring& filePath)
{
	for (auto& item : g_file_list)
	{
		if (_wcsicmp(filePath.c_str(), item.c_str()) == 0)
		{
			return true;
		}
	}
	
	return false;
}

#include <map>
#include <unordered_map>
#include <Commctrl.h>

std::unordered_map<HANDLE, std::wstring> g_HANDLE;

int GetListViewItemCount(HWND hLvWnd)
{
	if (!IsWindow(hLvWnd))
		return -1;

	LRESULT lRet = SendMessageW(hLvWnd, LVM_GETITEMCOUNT, 0, 0);
	return (int)lRet;
}


BOOL GetListViewSubItemText(HWND hLvWnd, int nRow, int nSubItem, LPWSTR szOut, int cchMax)
{
	if (!IsWindow(hLvWnd) || szOut == NULL || cchMax <= 0)
		return FALSE;

	ZeroMemory(szOut, cchMax * sizeof(WCHAR));

	// 1) Unicode: LVM_GETITEMTEXTW + LVITEMW
	LVITEMW lviW = { 0 };
	lviW.iSubItem   = nSubItem;
	lviW.pszText    = szOut;
	lviW.cchTextMax = cchMax;
	LRESULT lrW = SendMessageW(hLvWnd, LVM_GETITEMTEXTW, (WPARAM)nRow, (LPARAM)&lviW);
	if (lrW > 0 && szOut[0] != 0)
		return TRUE;

	char bufA[4096] = { 0 };
	LVITEMA lviA = { 0 };
	lviA.iSubItem   = nSubItem;
	lviA.pszText    = bufA;
	lviA.cchTextMax = (int)_countof(bufA);
	LRESULT lrA = SendMessageW(hLvWnd, LVM_GETITEMTEXTA, (WPARAM)nRow, (LPARAM)&lviA);
	if (lrA > 0 && bufA[0] != 0)
	{
		MultiByteToWideChar(CP_ACP, 0, bufA, -1, szOut, cchMax);
		return TRUE;
	}

	return FALSE;
}


LPCWSTR GetFileNamePart(LPCWSTR lpPath)
{
	if (lpPath == NULL)
		return L"";
	LPCWSTR pSlash = wcsrchr(lpPath, L'\\');
	LPCWSTR pSlash2 = wcsrchr(lpPath, L'/');
	if (pSlash2 > pSlash)
		pSlash = pSlash2;
	return pSlash ? pSlash + 1 : lpPath;
}

BOOL isListLenText(LPCWSTR lpFileName)
{
	long len = GetListViewItemCount(g_hListView);
	if (len<=0)
	{
		return FALSE;
	}
	LPCWSTR lpTargetName = GetFileNamePart(lpFileName);
	for (long i = 0; i < len; i++)
	{
		WCHAR szItem[4096] = { 0 };
		if (GetListViewSubItemText(g_hListView, i, 0, szItem, _countof(szItem)))
		{
			if (_wcsicmp(GetFileNamePart(szItem), lpTargetName) == 0)
			{
				return TRUE;
			}
		}
	}
	return FALSE;
}


thread_local bool g_bInSetTime = false;

HANDLE WINAPI MyCreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
	if (g_bInSetTime)
	{
		return g_CreateFileW_or(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
	}

	HANDLE hRet = g_CreateFileW_or(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
	if (hRet != INVALID_HANDLE_VALUE)
	{
		if (g_exefile==1)
		{
			if (!g_hListView)
			{
				return hRet;
			}
			if (GetListViewItemCount(g_hListView)<=0)
			{
				return hRet;
			}
			if (isListLenText(lpFileName))
			{
				EnterCriticalSection(&g_csHandleList);
				g_HANDLE[hRet] = lpFileName;

				LeaveCriticalSection(&g_csHandleList);
			}
		}
		else if (g_exefile == 2)
		{
			EnterCriticalSection(&g_csHandleList);
			if (IsTargetFile(lpFileName))
			{
				g_HANDLE[hRet] = lpFileName;
			}
			
			LeaveCriticalSection(&g_csHandleList);
		}
		

	}
	return hRet;
}

//HANDLE WINAPI MyCreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
//{
//
//	if (g_bInSetTime)
//	{
//		return g_CreateFileA_or(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
//	}
//
//	if (lpFileName)
//	{
//		int nLen = MultiByteToWideChar(CP_ACP, 0, lpFileName, -1, NULL, 0);
//		if (nLen > 0)
//		{
//			std::vector<WCHAR> vwPath(nLen, 0);
//			if (MultiByteToWideChar(CP_ACP, 0, lpFileName, -1, vwPath.data(), nLen) > 0)
//			{
//				return MyCreateFileW(vwPath.data(), dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
//			}
//		}
//	}
//	return g_CreateFileA_or(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
//}


static BOOL BuildFakeFileTimeUTC(LPFILETIME pftUTC)
{


	FILETIME ftLocal = { 0 };
	if (!MySystemTimeToFileTime(&g_SYSTEMTIME, &ftLocal))
		return FALSE;

	return LocalFileTimeToFileTime(&ftLocal, pftUTC);
}


static BOOL SetFakeFileTime(LPCWSTR pszPath, HANDLE hFallback)
{
	FILETIME ftUTC = { 0 };
	if (!BuildFakeFileTimeUTC(&ftUTC))
		return FALSE;

	if (SetFileTime(hFallback, &ftUTC, &ftUTC, &ftUTC))
		return TRUE;

	if (pszPath == NULL)
		return FALSE;

	HANDLE hFile = CreateFileW(pszPath,
		FILE_WRITE_ATTRIBUTES,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		NULL, OPEN_EXISTING,
		FILE_FLAG_BACKUP_SEMANTICS,   
		NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return FALSE;

	BOOL bOk = SetFileTime(hFile, &ftUTC, &ftUTC, &ftUTC);
	DWORD dwErr = bOk ? ERROR_SUCCESS : GetLastError();
	g_CloseHandle_or(hFile);  
	if (!bOk)
		SetLastError(dwErr);
	return bOk;
}

BOOL WINAPI	MyCloseHandle(HANDLE hObject)
{
	std::wstring strPath;
	BOOL bTracked = FALSE;

	EnterCriticalSection(&g_csHandleList);
	auto it = g_HANDLE.find(hObject);
	if (it != g_HANDLE.end())
	{
		strPath = it->second;
		g_HANDLE.erase(it);
		bTracked = TRUE;
	}
	LeaveCriticalSection(&g_csHandleList);

	
	if (bTracked && !g_bInSetTime)
	{
		g_bInSetTime = true;
		SetFakeFileTime(strPath.c_str(), hObject);
	
		g_bInSetTime = false;
	}
	FILETIME ftUTC = { 0 };
	if (BuildFakeFileTimeUTC(&ftUTC))
	{
		SetFileTime(hObject, &ftUTC, &ftUTC, &ftUTC);
	}

	return g_CloseHandle_or(hObject);
}
