#pragma once
#include <windows.h>
class hook
{
public:
	hook();
	~hook();

public:
	// 
	void UnHook();
	// 
	void Clear();
	// 
	BOOL SetHook(LPVOID hookp, LPVOID proc);
	// 
	BOOL SetHook_();
	// 
	void UnHook_();
	// 
	BOOL UMS_IsExecutableAddress(LPVOID VirtualAddress);

private:
	// 
	unsigned char m_bybak[5] = { 0 };
	// 
	unsigned char m_byhook[5] = { 0xE9, 0, 0, 0, 0 };
	// 
	BOOL m_hook = FALSE;
	// 
	LPVOID m_addrs = nullptr;
};


class hook2
{
public:
	hook2() {};
	~hook2() { UnHook(); };
public:
	void UnHook();
	void Clear();
	BOOL SetHook(LPVOID hookp, LPVOID proc,int len);
private:
	unsigned char m_bybak[0x2000] = { 0 };
	LPVOID m_addrs = 0;
	BOOL   m_hook = FALSE;
	int m_hooklen = 0;


};

class hookX64
{
public:
	hookX64() {};
	~hookX64() { UnHook(); }; 

public:
	void UnHook();
	BOOL SetHook(LPVOID hookp, LPVOID proc, int tpy = 0);

private:
	BYTE m_bybak[12] = { 0 }; 
	
	BYTE m_bykey[12] = { 0x48, 0xB8, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0xFF, 0xE0 };
	LPVOID m_addrs = nullptr;  
	BOOL   m_hook = FALSE;     
};




