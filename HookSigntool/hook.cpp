#define _CRT_SECURE_NO_WARNINGS
#include "hook.h"
#include <stdio.h>
#include <windows.h>
#include <Psapi.h>
#include <cmath>


#define   PAGE_EXECUTE_FLAGES \
 (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)

typedef LPVOID(*mypfun)(void* _Format, ...);
mypfun  myp;
#define  MYPROC(p,...)\
return myp(p,__VA_ARGS__);


void mysleep_bak_()
{
	MSG msg;
	while (PeekMessage(&msg, 0, 0, 0, 1) != 0)
	{
		DispatchMessage(&msg);
		TranslateMessage(&msg);
	}
}

long mysleep_(DWORD delaytime)
{
	if (!delaytime)
	{
		return 0;
	}
	//LARGE_INTEGER  large_interger;
	//double dff;
	//__int64  c1, c2;
	//QueryPerformanceFrequency(&large_interger);
	//dff = large_interger.QuadPart;
	//QueryPerformanceCounter(&large_interger);
	//c1 = large_interger.QuadPart;
	//DWORD result;
	//MSG msg;
	//while (1)
	//{
	//	QueryPerformanceCounter(&large_interger);
	//	c2 = large_interger.QuadPart;
	//	if (((c2 - c1) * 1000 / dff >= delaytime))
	//	{
	//		break;
	//	}

	//	mysleep_bak();

	//}
	//return 1;

	HANDLE hTimer = CreateWaitableTimerA(0, FALSE, 0);
	LARGE_INTEGER T_sj = { 0 };
	T_sj.QuadPart = -10000 * (LONGLONG)delaytime;//* delaytime
	SetWaitableTimer(hTimer, &T_sj, 0, 0, 0, FALSE);
	while (MsgWaitForMultipleObjects(1, &hTimer, FALSE, -1, 255) != 0)
	{
		mysleep_bak_();
	}
	CloseHandle(hTimer);
	return 1;
}

//HOOK
hook::hook()
{
	// 
}

hook::~hook()
{
	UnHook(); // 
}

// 
void hook::UnHook()
{
	if (!m_hook || m_addrs == nullptr)
		return;


	__try // 
	{
		DWORD dwOldProtect = 0;
		// 
		if (!VirtualProtect(m_addrs, sizeof(m_bybak), PAGE_EXECUTE_READWRITE, &dwOldProtect))
		{
			return;
		}

		// 
		memcpy(m_addrs, m_bybak, sizeof(m_bybak));

		// 
		VirtualProtect(m_addrs, sizeof(m_bybak), dwOldProtect, &dwOldProtect);

		m_hook = FALSE; // 
	}
	__except (EXCEPTION_EXECUTE_HANDLER) // 
	{
		
	}
	
}

// 
void hook::Clear()
{
	
	memset(m_bybak, 0, sizeof(m_bybak));
	memset(m_byhook + 1, 0, 4); // 
	m_hook = FALSE;
	m_addrs = nullptr;
	
}

// 
BOOL hook::SetHook(LPVOID hookp, LPVOID proc)
{


	// 
	if (m_hook || hookp == nullptr || proc == nullptr)
	{
		return FALSE;
	}

	// 
	if (!UMS_IsExecutableAddress(hookp) || !UMS_IsExecutableAddress(proc))
	{
		return FALSE;
	}

	m_addrs = hookp;
	DWORD dwOldProtect = 0;
	BOOL bRet = FALSE;

	__try
	{
		// 
		if (!VirtualProtect(m_addrs, sizeof(m_bybak), PAGE_EXECUTE_READWRITE, &dwOldProtect))
		{
			goto END;
		}

		// 
		memcpy(m_bybak, m_addrs, sizeof(m_bybak));

		// 
		// 
		INT32 iOffset = (INT32)((uintptr_t)proc - ((uintptr_t)m_addrs + sizeof(m_byhook)));
		memcpy(m_byhook + 1, &iOffset, sizeof(iOffset)); // 

		// 
		memcpy(m_addrs, m_byhook, sizeof(m_byhook));

		// 
		VirtualProtect(m_addrs, sizeof(m_bybak), dwOldProtect, &dwOldProtect);

		m_hook = TRUE;
		bRet = TRUE;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		//MessageBoxA(NULL, "SetHook: SEH Exception (Memory Access)", "Hook Error", MB_OK | MB_ICONERROR);
		// 
		if (dwOldProtect != 0)
		{
			VirtualProtect(m_addrs, sizeof(m_bybak), PAGE_EXECUTE_READWRITE, &dwOldProtect);
			memcpy(m_addrs, m_bybak, sizeof(m_bybak));
			VirtualProtect(m_addrs, sizeof(m_bybak), dwOldProtect, &dwOldProtect);
		}
		Clear(); // 
	}

END:
	return bRet;
}

// 
BOOL hook::SetHook_()
{
	if (m_hook || m_addrs == nullptr || m_byhook[0] != 0xE9)
	{
		return FALSE;
	}

	DWORD dwOldProtect = 0;
	BOOL bRet = FALSE;

	__try
	{
		if (!VirtualProtect(m_addrs, sizeof(m_byhook), PAGE_EXECUTE_READWRITE, &dwOldProtect))
		{
			goto END;
		}

		// 
		if (memcmp(m_bybak, 0, sizeof(m_bybak)) == 0)
		{
			memcpy(m_bybak, m_addrs, sizeof(m_bybak));
		}

		// 
		memcpy(m_addrs, m_byhook, sizeof(m_byhook));

		VirtualProtect(m_addrs, sizeof(m_byhook), dwOldProtect, &dwOldProtect);
		m_hook = TRUE;
		bRet = TRUE;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		//MessageBoxA(NULL, "SetHook_: SEH Exception", "Hook Error", MB_OK | MB_ICONERROR);
	}

END:
	return bRet;
}

// 
void hook::UnHook_()
{
	if (!m_hook || m_addrs == nullptr)
		return;

	__try
	{
		DWORD dwOldProtect = 0;
		if (!VirtualProtect(m_addrs, sizeof(m_bybak), PAGE_EXECUTE_READWRITE, &dwOldProtect))
		{
			return;
		}

		// 
		memcpy(m_addrs, m_bybak, sizeof(m_bybak));

		VirtualProtect(m_addrs, sizeof(m_bybak), dwOldProtect, &dwOldProtect);
		m_hook = FALSE;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		//MessageBoxA(NULL, "UnHook_: SEH Exception", "Hook Error", MB_OK | MB_ICONERROR);
	}


}

//
BOOL hook::UMS_IsExecutableAddress(LPVOID VirtualAddress)
{
	if (VirtualAddress == nullptr)
		return FALSE;

	MEMORY_BASIC_INFORMATION mbi = { 0 };
	// 
	if (VirtualQuery(VirtualAddress, &mbi, sizeof(mbi)) == 0)
		return FALSE;

	// PAGE_EXECUTE¡¢PAGE_EXECUTE_READ¡¢PAGE_EXECUTE_READWRITE¡¢PAGE_EXECUTE_WRITECOPY
	const DWORD EXEC_PROTECT_FLAGS = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
	return (mbi.State == MEM_COMMIT) && ((mbi.Protect & EXEC_PROTECT_FLAGS) != 0);
}



//HOOK
//HOOK2
// 
void hook2::UnHook()
{

	// 
	if (!m_hook || m_addrs == nullptr || m_hooklen <= 0 || m_hooklen > sizeof(m_bybak))
	{
		return;
	}

	__try // 
	{
		DWORD dwOldProtect = 0;
		// 
		if (!VirtualProtect(m_addrs, m_hooklen, PAGE_EXECUTE_READWRITE, &dwOldProtect))
		{
			return;
		}

		// 
		memcpy(m_addrs, m_bybak, m_hooklen);

		// 
		VirtualProtect(m_addrs, m_hooklen, dwOldProtect, &dwOldProtect);

		m_hook = FALSE; // 
	}
	__except (EXCEPTION_EXECUTE_HANDLER) // 
	{
	}

}

// 
void hook2::Clear()
{

	// 
	memset(m_bybak, 0, sizeof(m_bybak));
	m_addrs = nullptr;   // 
	m_hook = FALSE;      // 
	m_hooklen = 0;       // 

}

// 
BOOL hook2::SetHook(LPVOID hookp, LPVOID proc, int len)
{

	// 
	if (m_hook                  
		|| !hookp               
		|| !proc                
		|| len <= 0             
		|| len > sizeof(m_bybak))// 
	{
		return FALSE;
	}

	// 2. 
	m_addrs = hookp;
	m_hooklen = len;
	DWORD dwOldProtect = 0;
	BOOL bRet = FALSE;

	__try
	{
		// 
		if (!VirtualProtect(m_addrs, m_hooklen, PAGE_EXECUTE_READWRITE, &dwOldProtect))
		{
			goto END; // 
		}

		// 
		memcpy(m_bybak, m_addrs, m_hooklen);

		// 
		memcpy(m_addrs, proc, m_hooklen);

		// 
		VirtualProtect(m_addrs, m_hooklen, dwOldProtect, &dwOldProtect);

		// 
		m_hook = TRUE;
		bRet = TRUE;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		// 
		if (dwOldProtect != 0)
		{
			VirtualProtect(m_addrs, m_hooklen, PAGE_EXECUTE_READWRITE, &dwOldProtect);
			memcpy(m_addrs, m_bybak, m_hooklen);
			VirtualProtect(m_addrs, m_hooklen, dwOldProtect, &dwOldProtect);
		}
		Clear(); // 
	}

END:
	return bRet;
}
//HOOK2

// 
void hookX64::UnHook()
{

	// 
	if (!m_hook || m_addrs == nullptr)
	{
		return;
	}

	__try // 
	{
		DWORD dwOldProtect = 0;
		// 
		if (!VirtualProtect(m_addrs, sizeof(m_bybak), PAGE_EXECUTE_READWRITE, &dwOldProtect))
		{
			return;
		}

		// 
		memcpy(m_addrs, m_bybak, sizeof(m_bybak));

		// 
		VirtualProtect(m_addrs, sizeof(m_bybak), dwOldProtect, &dwOldProtect);

		m_hook = FALSE; // 
	}
	__except (EXCEPTION_EXECUTE_HANDLER) // 
	{
	}

}

// 
BOOL hookX64::SetHook(LPVOID hookp, LPVOID proc, int tpy)
{
	if (m_hook          
		|| !hookp       
		|| !proc)       
	{
		return FALSE;
	}

	m_addrs = hookp;
	DWORD dwOldProtect = 0;
	BOOL bRet = FALSE;

	__try
	{
		// 
		if (!VirtualProtect(m_addrs, sizeof(m_bybak), PAGE_EXECUTE_READWRITE, &dwOldProtect))
		{
			goto END;
		}

		//
		memcpy(m_bybak, m_addrs, sizeof(m_bybak));

		//
		BYTE tempByKey[12];
		memcpy(tempByKey, m_bykey, sizeof(tempByKey)); // 

		// 
		ULONG64 procAddr = (ULONG64)proc;
		memcpy(tempByKey + 2, &procAddr, sizeof(ULONG64)); // 

		//
		if (tpy != 0)
		{
			// tpy¡Ù0£ºMOV RSI, imm64£¨0x48 BE£© + JMP RSI£¨0xFF E6£©
			tempByKey[1] = 0xBE;    // 0x48 BE ¡ú MOV RSI, imm64
			tempByKey[11] = 0xE6;   // 0xFF E6 ¡ú JMP RSI
		}
		// tpy=0£º

		// 
		memcpy(m_addrs, tempByKey, sizeof(tempByKey));

		// 
		VirtualProtect(m_addrs, sizeof(m_bybak), dwOldProtect, &dwOldProtect);

		m_hook = TRUE;
		bRet = TRUE;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		//MessageBoxA(NULL, "SetHook: SEH Exception (Invalid Memory/Access Denied)", "hookX64 Error", MB_OK | MB_ICONERROR);
		
		if (dwOldProtect != 0)
		{
			VirtualProtect(m_addrs, sizeof(m_bybak), PAGE_EXECUTE_READWRITE, &dwOldProtect);
			memcpy(m_addrs, m_bybak, sizeof(m_bybak));
			VirtualProtect(m_addrs, sizeof(m_bybak), dwOldProtect, &dwOldProtect);
		}
		m_hook = FALSE; 
	}

END:
	return bRet;
}




