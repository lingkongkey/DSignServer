#pragma once
class GetAddress
{
public:
	//
	LONG64 GetSignAddRess(const char* ModuleName, const char* str);
	//
	long FindByteSet(LPVOID addrs, const char* str, DWORD size);
	
	char toUpper(char* src);
	// 
	UINT64 WINAPI HexToInt(char* strhex);
	//
	long GetX64EXE_Len(LONG64 exe, LONG64& bsar);
};

