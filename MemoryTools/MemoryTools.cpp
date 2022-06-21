// MemoryTools.cpp : Defines the functions for the static library.
//

#include "MemoryTools.h"
#include <cstdlib>
#include <string.h>
#include <WinSock2.h>
#include <Windows.h>
#include <Psapi.h>
#include <intsafe.h>
#include <malloc.h>
#include <winternl.h>
#include <intrin.h>
#include <list>
#include <mutex>
#include <map>
#include <iomanip>
#include <stdio.h>
#include <inttypes.h>
#include <Zydis/Zydis.h>
#include <Zycore/Zycore.h>
#include <DbgHelp.h>
#include <fstream>
#include "ThirdParty/MinHook/MinHook.h"
#include "ThirdParty/hde/hde32.h"
#include "ThirdParty/hde/hde64.h"
#include <ntstatus.h>
#include <tlhelp32.h>
#include <sstream>
#include <iomanip>


#ifdef THROWEXCEPTION
#include <exception>
#endif

#define HEX( x ) std::setw(2) << std::setfill('0') << std::hex << (int)(x)

typedef struct _THREAD_BASIC_INFORMATION
{
	NTSTATUS                ExitStatus;
	PVOID                   TebBaseAddress;
	CLIENT_ID               ClientId;
	KAFFINITY               AffinityMask;
	KPRIORITY               Priority;
	KPRIORITY               BasePriority;
} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;

#define INRANGE(x,a,b)    (x >= a && x <= b) 
#define getBits( x )    (INRANGE((x&(~0x20)),'A','F') ? ((x&(~0x20)) - 'A' + 0xa) : (INRANGE(x,'0','9') ? x - '0' : 0))
#define getByte( x )    (getBits(x[0]) << 4 | getBits(x[1]))


void InvalidParameterHandler(const wchar_t* wszExpression,
	const wchar_t* wszFunction,
	const wchar_t* wszFile,
	unsigned int nLine,
	uintptr_t pReserved)
{
	printf("MemoryTools :: Invalid parameters failure!");
}

_Ret_maybenull_ void* MTCALL MemoryTools::PatternScanMemoryRegion(_In_reads_bytes_(nRegionSize) void* pBaseAddress, _In_ size_t nRegionSize, _In_z_ const char* pszPattern)
{
	const char* pat = pszPattern;
	BYTE* firstMatch = 0;
	BYTE* rangeStart = (BYTE*)pBaseAddress;
	BYTE* rangeEnd = rangeStart + nRegionSize;

	// This may possibly cause issues on huge ranges
	for (BYTE* pCur = rangeStart;pCur < rangeEnd ; pCur++)
	{
		if (!*pat)
			return firstMatch;

		if (*(PBYTE)pat == '\?' || *(BYTE*)pCur == getByte(pat))
		{
			if (!firstMatch)
				firstMatch = pCur;

			if (!pat[2])
				return firstMatch;

			if (*(PWORD)pat == '\?\?' || *(PBYTE)pat != '\?')
				pat += 3;

			else
				pat += 2;    //one ?
		}
		else
		{
			pat = pszPattern;
			firstMatch = 0;
		}
	}

	return (void*)nullptr;
}

_Ret_maybenull_ void* MTCALL MemoryTools::PatternScanMemoryRegionReverse(_In_reads_bytes_(nRegionSize) void* pBaseAddress, _In_ size_t nRegionSize, _In_z_ const char* pszPattern)
{
	const char* pat = pszPattern;
	BYTE* firstMatch = 0;
	BYTE* rangeStart = (BYTE*)pBaseAddress;
	BYTE* rangeEnd = rangeStart - nRegionSize;

	char* pReversedString = MemoryTools::GetPatternReversed(pszPattern);

	if (!pReversedString)
		return nullptr;

	pszPattern = pReversedString;
	// This may possibly cause issues on huge ranges
	for (BYTE* pCur = rangeStart; pCur > rangeEnd; pCur--)
	{
		if (!*pat)
			return firstMatch;

		if (*(PBYTE)pat == '\?' || *(BYTE*)pCur == getByte(pat))
		{
			if (!firstMatch)
				firstMatch = pCur;

			if (!pat[2])
			{
				free((void*)pszPattern);
				return firstMatch;
			}

			if (*(PWORD)pat == '\?\?' || *(PBYTE)pat != '\?')
				pat += 3;

			else
				pat += 2;    //one ?
		}
		else
		{
			pat = pszPattern;
			firstMatch = 0;
		}
	}

	free((void*)pszPattern);
	return (void*)nullptr;
}

_Ret_maybenull_ void* MTCALL MemoryTools::PatternScanModuleHandle(_In_ void* hModule, _In_z_ const char* pszPattern)
{
	MODULEINFO modInfo;
	
	if (GetModuleInformation(GetCurrentProcess(), (HMODULE)hModule, &modInfo, sizeof(MODULEINFO)))
		return MemoryTools::PatternScanMemoryRegion((void*)modInfo.lpBaseOfDll, modInfo.SizeOfImage, pszPattern);
	
	__debugbreak();

	return (void*)nullptr;
}

_Ret_maybenull_ void* MTCALL MemoryTools::PatternScanModule(_In_z_ const char* pszModuleName, _In_z_ const char* pszPattern)
{
	HMODULE hModule;
	hModule = GetModuleHandleA(pszModuleName);

	if (!hModule)
		return (void*)nullptr;

	return PatternScanModuleHandle(hModule, pszPattern);
}

_Ret_maybenull_ void* MTCALL MemoryTools::PatternScanCurrentProcessModules(_In_z_ const char* pszPattern)
{
	HMODULE hMods[1024];
	DWORD cbNeeded;

	if (!EnumProcessModules(GetCurrentProcess(), hMods, sizeof(hMods), &cbNeeded))
		return (void*)nullptr;

	for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
	{
		void* pAddr = MemoryTools::PatternScanModuleHandle(hMods[i], pszPattern);

		if (pAddr)
			return pAddr;

	}

	return (void*)nullptr;
}

void* MTCALL MemoryTools::PatternScanMemoryRegionReportPartial(void* pBaseAddress, size_t nRegionSize, const char* pszPattern, bool& bPartial)  {
	const char* pat = pszPattern;
	BYTE* firstMatch = 0;
	BYTE* rangeStart = (BYTE*)pBaseAddress;
	BYTE* rangeEnd = rangeStart + nRegionSize;
	BYTE* pCur = rangeStart;
	for (; pCur < rangeEnd; pCur++)
	{
		if (!*pat)
			return firstMatch;

		if (*(PBYTE)pat == '\?' || *(BYTE*)pCur == getByte(pat))
		{
			if (!firstMatch)
				firstMatch = pCur;

			if (!pat[2])
				return firstMatch;

			if (*(PWORD)pat == '\?\?' || *(PBYTE)pat != '\?')
				pat += 3;

			else
				pat += 2;    //one ?
		}
		else
		{
			pat = pszPattern;
			firstMatch = 0;
		}
	}

	if (firstMatch && (pCur >= rangeEnd))
		bPartial = true;

	return firstMatch;
};
void _suspend_all_threads();
void _resume_all_threads();
_Ret_maybenull_ void* MTCALL MemoryTools::PatternScanCurrentProcess(_In_z_ const char* pszPattern, _In_ void* pStartVirtualAddress/* = 0*/)
{
	_suspend_all_threads();
	unsigned int i = (unsigned int)pStartVirtualAddress;
	for (; i < 0x7FFF0000; )
	{
		MEMORY_BASIC_INFORMATION meminfo;
		if (!VirtualQuery((LPCVOID)i, &meminfo, sizeof(meminfo)))
			i += 1;

		if (!meminfo.Protect || meminfo.Protect & PAGE_NOACCESS || meminfo.Protect & PAGE_GUARD || meminfo.Protect == 0xffff0001)
		{
			i += meminfo.RegionSize;
			continue;
		}

		bool bWasPartial = false;
		void* pAddress = PatternScanMemoryRegionReportPartial((void*)meminfo.BaseAddress, (size_t)meminfo.RegionSize, pszPattern, bWasPartial);


		if (!bWasPartial && pAddress)
		{
			_resume_all_threads();
			return pAddress;
		}

		i += meminfo.RegionSize;

		if (bWasPartial)
		{
			continue; // todo : finish
			char* buffer = (char*)_alloca(strlen(pszPattern)); // good enough
			size_t nOffset = ((char*)meminfo.BaseAddress + meminfo.RegionSize) - (char*)pAddress;
			memcpy(buffer, pAddress, nOffset);
			memset(&meminfo, 0, sizeof(MEMORY_BASIC_INFORMATION));
			if (!VirtualQuery((LPCVOID)i, &meminfo, sizeof(meminfo)))
				continue;

			if (!meminfo.Protect || meminfo.Protect & PAGE_NOACCESS || meminfo.Protect & PAGE_GUARD)
			{
				i += meminfo.RegionSize;
				continue;
			}

			memcpy(buffer + nOffset, meminfo.BaseAddress, strlen(pszPattern) - nOffset);

			if (PatternScanMemoryRegion(buffer, strlen(pszPattern), pszPattern))
			{
				_resume_all_threads();
				return pAddress;
			}
		}
	}
	_resume_all_threads();
	return (void*)nullptr;
}
_Ret_maybenull_ void* MTCALL MemoryTools::PatternScanHeap(_In_/*PROCESS_HEAP_ENTRY*/ void* pHeapEntry, _In_z_ const char* pszPattern)
{
	MEMORY_BASIC_INFORMATION MemInfo;
	DWORD dwOldProtect = 0;
	PROCESS_HEAP_ENTRY* pEntry = reinterpret_cast<PROCESS_HEAP_ENTRY*>(pHeapEntry);
	void* pRet = nullptr;

	if (!VirtualQueryEx(GetCurrentProcess(), pEntry, &MemInfo, sizeof(MEMORY_BASIC_INFORMATION)))
		return (void*)nullptr;

	if (MemInfo.State != MEM_COMMIT )
		return (void*)nullptr;

	if(!VirtualProtect(pEntry->lpData, pEntry->cbData, PAGE_EXECUTE_READWRITE, &dwOldProtect))
		return (void*)nullptr;

	pRet = MemoryTools::PatternScanMemoryRegion((void*)pEntry->lpData, pEntry->cbData, pszPattern);

	VirtualProtect((void*)pEntry->lpData, pEntry->cbData, dwOldProtect, &dwOldProtect);

	return pRet;
}


bool MTCALL MemoryTools::IsValidPEHeaderx86(void* pAddr)
{
	IMAGE_DOS_HEADER* pDOS = nullptr;
	IMAGE_FILE_HEADER* pFile = nullptr;
	IMAGE_OPTIONAL_HEADER* pOpt = nullptr;
	IMAGE_NT_HEADERS* pNT = nullptr;

	pDOS = reinterpret_cast<PIMAGE_DOS_HEADER>(pAddr);

	if (pDOS->e_magic != 0x5A4D) // MZ !?
		return false;

	pNT = reinterpret_cast<PIMAGE_NT_HEADERS>(pDOS->e_lfanew + (char*)pAddr);
	pOpt = &pNT->OptionalHeader;
	pFile = &pNT->FileHeader;



	if (!IsMemoryRangeReadable(pOpt + offsetof(IMAGE_OPTIONAL_HEADER, Magic), 4) || pOpt->Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
		return false;

	return true;
}


_Ret_maybenull_ void* MTCALL MemoryTools::PatternScanCurrentProcessHeaps(_In_z_ const char* pszPattern)
{
	DWORD dwNumberOfHeaps;
	DWORD HeapsIndex;
	DWORD HeapsLength;
	HANDLE hDefaultProcessHeap;
	PHANDLE aHeaps;
	SIZE_T BytesToAllocate;
	void* pFoundPattern = nullptr;
	void* pAddr = (void*)nullptr;

	dwNumberOfHeaps = GetProcessHeaps(0, NULL);

	if (!dwNumberOfHeaps)
		return (void*)nullptr;

	if(SIZETMult(dwNumberOfHeaps, sizeof(*aHeaps), &BytesToAllocate) != S_OK)
		return (void*)nullptr;

	hDefaultProcessHeap = GetProcessHeap();

	if (!hDefaultProcessHeap)
		return (void*)nullptr;

	aHeaps = (PHANDLE)HeapAlloc(hDefaultProcessHeap, 0, BytesToAllocate);

	if (!aHeaps)
		return (void*)nullptr;

	HeapsLength = dwNumberOfHeaps;

	dwNumberOfHeaps = GetProcessHeaps(HeapsLength, aHeaps);

	if (!dwNumberOfHeaps)
		return (void*)nullptr;

	for (HeapsIndex = 0; HeapsIndex < HeapsLength; ++HeapsIndex) {
		PROCESS_HEAP_ENTRY entry;

		HeapLock(aHeaps[HeapsIndex]);

		entry.lpData = NULL;
		while (HeapWalk(aHeaps[HeapsIndex], &entry))
		{
			//if (!(entry.wFlags & PROCESS_HEAP_REGION))
			//	continue;

			pAddr = MemoryTools::PatternScanHeap(&entry, pszPattern);

			if (pAddr)
				break;
		}

		HeapUnlock(aHeaps[HeapsIndex]);

		if (pAddr)
			break;

	}

	return pAddr;
}


_Ret_maybenull_ void* MTCALL MemoryTools::PatternScanStack(_In_ void* pThreadHandle, _In_z_ const char* pszPattern)
{
	THREAD_BASIC_INFORMATION tbiInfo;
	NT_TIB* pTib;


	if (NtQueryInformationThread((HANDLE)pThreadHandle, (THREADINFOCLASS)NULL/*ThreadBasicInformation*/, &tbiInfo, sizeof(THREAD_BASIC_INFORMATION), NULL) != S_OK)
		return nullptr;


	// Read TIB
	pTib = (NT_TIB*)tbiInfo.TebBaseAddress;
	return MemoryTools::PatternScanMemoryRegion((char*)pTib->StackLimit, (char*)pTib->StackBase - (char*)pTib->StackLimit, pszPattern);
}

_Ret_maybenull_ void* MTCALL  MemoryTools::PatternScanCurrentStack(_In_z_ const char* pszPattern)
{
	return MemoryTools::PatternScanStack(GetCurrentThread(), pszPattern);
}

_Success_(return != false) bool MTCALL MemoryTools::PlaceJumpRel32x86(_Out_writes_bytes_all_(5) void* pWriteAddress, _In_ void* pJumpAddress)
{
	if (!pWriteAddress || !pJumpAddress)
		return false;


	DWORD dwOldProtect;
	char* pRelativeDifference = nullptr;

	if (!VirtualProtect(pWriteAddress, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect))
		return false;

	memset(pWriteAddress, 0x90, 5);
	pRelativeDifference = (char*)(((char*)pJumpAddress - (char*)pWriteAddress) - 5);
	*(unsigned char*)(pWriteAddress) = 0xE9;
	*(void**)((char*)pWriteAddress + sizeof(unsigned char)) = pRelativeDifference;

	if (!VirtualProtect(pWriteAddress, 5, dwOldProtect, &dwOldProtect))
		return false;

	return true;
}

_Success_(return != false) bool MTCALL MemoryTools::PlaceCallRel32x86(_Out_writes_bytes_all_(5) void* pWriteAddress, _In_ void* pJumpAddress)
{
	if (!pWriteAddress || !pJumpAddress)
		return false;

	DWORD dwOldProtect;
	char* pRelativeDifference = nullptr;

	if (!VirtualProtect(pWriteAddress, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect))
		return false;

	memset(pWriteAddress, 0x90, 5);
	pRelativeDifference = (char*)(((char*)pJumpAddress - (char*)pWriteAddress) - 5);
	*(unsigned char*)(pWriteAddress) = 0xE8;
	*(void**)((char*)pWriteAddress + sizeof(unsigned char)) = pRelativeDifference;


	if (!VirtualProtect(pWriteAddress, 5, dwOldProtect, &dwOldProtect))
		return false;

	return true;
}

_Success_(return != false) bool MTCALL MemoryTools::WriteNOPs(_Out_writes_bytes_all_(nDataSize) void* pWriteAddress, _In_ size_t nDataSize)
{
	DWORD dwOldProtect;
	if (!VirtualProtect(pWriteAddress, nDataSize, PAGE_EXECUTE_READWRITE, &dwOldProtect))
		return false;

	memset(pWriteAddress, 0x90, nDataSize);
	
	if (!VirtualProtect(pWriteAddress, nDataSize, dwOldProtect, &dwOldProtect))
		return false;

	return true;
}


// https://stackoverflow.com/questions/18394647/can-i-check-if-memory-block-is-readable-without-raising-exception-with-c
// a lot cleaner solution than what I had 
// if passing nReadableAmount, value passed in must be 0

bool MTCALL MemoryTools::DoesMemoryHaveAttributes(_In_ void* ptr, _In_ size_t nDataSize, _In_ int PageState, _In_ int PageProtect, _In_ int PageType, _Inout_opt_ size_t* pnReadableAmount /*= nullptr*/)
{
	MEMORY_BASIC_INFORMATION mbi;
	if (!VirtualQuery(ptr, &mbi, sizeof(MEMORY_BASIC_INFORMATION)))
		return false;

	if (!(mbi.State & PageState))
		return false;

	if (!(mbi.Protect & PageProtect))
		return false;

	if (!(mbi.Protect & PageType))
		return false;

	size_t nBytesAfterBlockEnd = (size_t)(((char*)ptr + nDataSize) - ((char*)ptr + mbi.RegionSize));

	if (nBytesAfterBlockEnd < nDataSize)
	{
		bool bReturnValue = DoesMemoryHaveAttributes((char*)ptr + nBytesAfterBlockEnd,
			nBytesAfterBlockEnd, PageState, PageProtect, PageType, pnReadableAmount);

		if (bReturnValue && pnReadableAmount)
			*pnReadableAmount += mbi.RegionSize;

		return bReturnValue;
	}

	return true;
}

bool MTCALL MemoryTools::IsMemoryRangeReadable(_In_ void* ptr, _In_ size_t nDataSize, _Inout_opt_ size_t* pnReadableAmount /* = nullptr */)
{
	return MemoryTools::DoesMemoryHaveAttributes(ptr, nDataSize, MEM_COMMIT, PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READWRITE, 0xFFFFFFFF, pnReadableAmount);
}

_Ret_maybenull_ void* MTCALL MemoryTools::RelativeToAbsolute(_In_reads_(sizeof(void*)) void** ptr)
{
	//if (!MemoryTools::IsMemoryRangeReadable(ptr, sizeof(void*)))
	//	return nullptr;

	// Yes the casts are ugly
	return (void*)((int)((char*)ptr + sizeof(void*)) + *(char**)ptr);
}

_Ret_maybenull_ void* MTCALL MemoryTools::GetThreadTEB(_In_ void* hThread)
{
	THREAD_BASIC_INFORMATION tbiInfo;
	if (NtQueryInformationThread(hThread, (THREADINFOCLASS)NULL/*ThreadBasicInformation*/, &tbiInfo, sizeof(THREAD_BASIC_INFORMATION), NULL) != S_OK)
		return nullptr;

	return tbiInfo.TebBaseAddress;
}

void* MTCALL MemoryTools::GetCurrentTEB()
{
#ifdef _WIN64
	return (void*)__readgsqword(FIELD_OFFSET(NT_TIB, Self));
#else
	void* ppTIB = 0;
	_asm {
		mov eax, gs: [00]
		mov ppTIB, eax
	}
	return ppTIB;
#endif
}



_Ret_maybenull_
_Null_terminated_
_Must_inspect_result_
char* MTCALL MemoryTools::GetPatternReversed(_In_opt_z_ const char* szPattern)
{
	if (!szPattern)
		return nullptr;

	size_t nSize = 0;
	char* pszReversedString = nullptr;

	// Use SEH incase szPattern is massive!
	_invalid_parameter_handler pOldHandler = _get_invalid_parameter_handler();
	_set_invalid_parameter_handler(&InvalidParameterHandler);
	nSize = strnlen_s(szPattern, 8192);
	_set_invalid_parameter_handler(pOldHandler);

	if (!nSize)
		return nullptr;
	

	pszReversedString = (char*)calloc(nSize, sizeof(char));
	
	if (!pszReversedString)
		return nullptr;

	int j = nSize - 1;
	for (unsigned int i = 0; i < nSize - 1; i++, j--)
		pszReversedString[i] = j;

	return pszReversedString;
}

void MTCALL MemoryTools::MTFree(_In_opt_ void* ptr)
{
	if(ptr)
		free(ptr);
}


void MTCALL MemoryTools::CreateNewStackx86(_In_ size_t nMinStackSize, _In_opt_ bool bExecutable, _In_opt_ MemoryTools::StackStore_t* pStackStore)
{
#ifndef _WIN64
	NT_TIB* pTIB;
	DWORD dwOldProtect;
	size_t nNewStackSize;
	size_t nDataSize;
	void* pStack;
	void* pReturnAddress;
	void* pOldStack;

	_asm { 	// Get our current TIB
		mov eax, gs:00
		mov pTIB, eax
	}

	if (!pTIB)
		return;
	pOldStack = pTIB->StackLimit;
	nDataSize = (char*)pTIB->StackBase - (char*)pTIB->StackLimit;
	nNewStackSize = max(nDataSize, nMinStackSize);
	pStack = malloc(nNewStackSize);

	if (!pStack)
		return;

	memset(pStack, 0x00, nNewStackSize);

	pReturnAddress = _ReturnAddress();

	VirtualProtect((char*)pTIB->StackLimit, nDataSize, PAGE_READWRITE, &dwOldProtect);

	if (bExecutable) {
		if (!VirtualProtect(pStack, nNewStackSize, PAGE_EXECUTE_READWRITE, &dwOldProtect))
		{
			free(pStack);
			return;
		}
	}

	memcpy(pStack, (char*)pTIB->StackLimit, nDataSize);

	if (pStackStore)
	{
		pStackStore->m_pStack = pTIB->StackLimit;
		pStackStore->m_nStackSize = nDataSize;
	}

	pTIB->StackLimit = pStack;
	pTIB->StackBase = (char*)pStack + nNewStackSize;

	*((char**)&pStack) += nNewStackSize;

	_asm {
		mov edx, pOldStack
		sub edx, esp
		mov eax, pStack
		add eax, edx
		mov pStack, eax

		mov ecx, ebp
		sub ecx, esp
		mov eax, pStack
		mov ebx, pReturnAddress
		mov esp, eax
		add ecx, esp
		mov ebp, ecx

		push ebx
		ret
	}
#endif
}

void MTCALL MemoryTools::RestoreStackx86(_In_ MemoryTools::StackStore_t* pStackStore)
{

}

struct mapped_dll_info_t
{
	void* m_pModuleBase = nullptr;
	void* m_pLibraryLoader = nullptr;
	void* m_pProcFinder = nullptr;
	void* m_pRtlAddFunctionTable = nullptr;
	void* m_pEntryPoint = nullptr;

	bool m_bSEHSupport = true;
	bool m_bVEHSupport = false;
	bool m_b64Bit = false;

	bool m_bFailure = false;
};

_Ret_maybenull_ void* MTCALL MapDLLToProcess(
	_In_reads_bytes_(nFileSize) void* pPEFile,
	_In_ size_t nFileSize,
	_In_ HANDLE hProcess,
	_In_ bool bTLSCallBacks,
	_In_ bool bMapRequiredWithLoadLibrary,
	_In_ bool bEnableSEH,
	_In_ bool bEnableVEH)
{

	IMAGE_DOS_HEADER* pDOS = nullptr;
	IMAGE_FILE_HEADER* pFile = nullptr;
	IMAGE_OPTIONAL_HEADER* pOpt = nullptr;
	IMAGE_NT_HEADERS* pNT = nullptr;
	mapped_dll_info_t MapDLLInfo;
	mapped_dll_info_t* pMappedMapDLLInfo;

	pDOS = reinterpret_cast<PIMAGE_DOS_HEADER>(pPEFile);

	if (pDOS->e_magic != 0x5A4D) // MZ !?
		return nullptr;

	pNT = reinterpret_cast<PIMAGE_NT_HEADERS>(pDOS->e_lfanew + (char*)pPEFile);
	pOpt = &pNT->OptionalHeader;
	pFile = &pNT->FileHeader;


	LPVOID pMapBase = VirtualAllocEx(hProcess, NULL, pOpt->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (!pMapBase)
		return nullptr;

	MapDLLInfo.m_pModuleBase = pMapBase;

	if (bEnableSEH)
	{
#ifdef _WIN64
		MapDLLInfo.m_b64Bit = true;
		MapDLLInfo.m_pRtlAddFunctionTable = &RtlAddFunctionTable;
#else
		MapDLLInfo.m_pRtlAddFunctionTable = MemoryTools::PatternScanModule("ntdll.dll", "53 56 57 8D 45 F8 8B FA");

		if (!MapDLLInfo.m_pRtlAddFunctionTable)
		{
#ifdef THROWEXCEPTION
			throw std::exception("Couldn't Scan RtlInsertInvertedFunctionTable From ntdll!");
#else
			return nullptr;
#endif // THROWEXCEPTION
		}
#endif // _WIN64
	}

	if (bMapRequiredWithLoadLibrary)
	{
		MapDLLInfo.m_pLibraryLoader = &LoadLibraryA;
		MapDLLInfo.m_pProcFinder = &GetProcAddress;
	}
}


void __stdcall MapperShellCode(mapped_dll_info_t* pData)
{

}

struct _function_hook_t
{
	void* m_pTrampoline = nullptr;
	void* m_pHook = nullptr;
	void* m_pAddress = nullptr;
	bool m_bActive = false;
};

class HookContainer
{
public:

	void AddHookEntry(_function_hook_t hk)
	{
		m_Hooks.push_back(hk);
	}

	void RemoveHookEntry(void* pFunctionAddress)
	{
		std::list<_function_hook_t>::iterator itr = m_Hooks.begin();
		std::list<_function_hook_t>::iterator found_itr = m_Hooks.end();
		for (; itr != m_Hooks.end(); itr++)
		{
			if (itr->m_pAddress == pFunctionAddress)
				break;
		}

		if (itr != m_Hooks.end())
			m_Hooks.erase(itr);
	}

private:
	std::list<_function_hook_t> m_Hooks;
};

HookContainer g_Hooks;

_Success_(return != false) bool MTCALL MemoryTools::HookFunctionx86(_In_ void* pFunction, _In_ void* pHook, _Outptr_ void** ppOriginal)
{
#if 1
	// Temporarily Using Minhook
	static bool bInitialized{ false };

	if (!bInitialized)
	{
		auto ret = MH_Initialize();

		if (ret != MH_OK && ret != MH_ERROR_ALREADY_INITIALIZED)
			return false;

		bInitialized = true;

	}
	auto ret = MH_CreateHook(pFunction, pHook, ppOriginal);

	if (ret != MH_OK)
		return false;

	ret = MH_EnableHook(MH_ALL_HOOKS);

	return ret == MH_OK;
#else // Todo : Implement
	hde32s disasm;
	int nBytes = 0;
	_function_hook_t hkinfo;
	DWORD flOldProtect;

	// Calculate how many bytes need to be moved from the front of the function
	for (nBytes; nBytes < 5;)
	{
		nBytes += hde32_disasm((char*)pFunction + nBytes, &disasm);
	}

	hkinfo.m_pHook = MemoryTools::GenerateIntermediaryFunctionx86(pHook);
	
	// nBytes + 5 (jmp to func)
	LPVOID pTrampolineFunc = VirtualAlloc(nullptr, nBytes + 5, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	
	VirtualProtect(pFunction, nBytes, PAGE_EXECUTE_READWRITE, &flOldProtect);

	if (!pTrampolineFunc)
		return false;

	// Create Trampoline Function
	memcpy(pTrampolineFunc, pFunction, nBytes);
	*(char**)&pTrampolineFunc += nBytes;
	*(unsigned char*)pTrampolineFunc = 0xE9;
	*(char**)&pTrampolineFunc += 1;
	**(char***)pTrampolineFunc = (char*)pFunction + nBytes;

	memset(pFunction, 0x90, nBytes);
	
	*(unsigned char*)pFunction = 0xE9;
	*(char**)((char*)pFunction + 1) = (char*)hkinfo.m_pHook;

	*ppOriginal = pTrampolineFunc;

	hkinfo.m_bActive = true;
	hkinfo.m_pAddress = pFunction;
	hkinfo.m_pTrampoline = pTrampolineFunc;

	g_Hooks.AddHookEntry(hkinfo);

	return true;
#endif
}

_Ret_maybenull_ void* MTCALL MemoryTools::GenerateIntermediaryFunctionx86(
	_In_ void* pFunc
)
{
	unsigned char* Memory = (unsigned char*)VirtualAlloc(NULL, (sizeof(unsigned char) * 3) + sizeof(uintptr_t*), MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (!Memory)
		return nullptr;

	Memory[0] = 0xFF;
	Memory[1] = 0x25;
	*(uintptr_t**)((unsigned char*)Memory + (sizeof(unsigned char) * 2)) = (uintptr_t*)((unsigned char*)Memory + 3 + (sizeof(uintptr_t*)));
	*((unsigned char*)Memory + (sizeof(unsigned char) * 2) + sizeof(uintptr_t*)) = 0xCB;
	*(uintptr_t*)((unsigned char*)Memory + (sizeof(unsigned char) * 3) + (sizeof(uintptr_t*))) = (uintptr_t)pFunc;
	return Memory;
}


_Ret_maybenull_ void* MTCALL MemoryTools::FindFunctionPrologueFromReturnAddressx86(
	_In_ void* pReturnAddress,
	_In_opt_ int nMaxNumberOfBytes /* = 0*/,
	_In_ bool bCheckForPushEbp /*= false*/
)
{
	if (!pReturnAddress)
		return 0;

	if (!nMaxNumberOfBytes)
		nMaxNumberOfBytes = INT_MAX; // Works Well Enough

	unsigned char* pAddr = (unsigned char*)pReturnAddress;
	
	for (int i = 0; i < nMaxNumberOfBytes; i++, pAddr--)
	{
		if (i == (nMaxNumberOfBytes - 1))
			return nullptr;

		if (*pAddr == (unsigned char)0xCC)
		{
			if (bCheckForPushEbp && *(pAddr + 1) != 0x55)
				continue;

			break;
		}

	}

	pAddr++;
	
	return pAddr;
}



size_t MTCALL MemoryTools::CalculateVmtLength(_In_ void* vmt)
{
	size_t length = 0;
	MEMORY_BASIC_INFORMATION memoryInfo;
	while (VirtualQuery(LPCVOID(((uintptr_t*)vmt)[length]), &memoryInfo, sizeof(memoryInfo)) && memoryInfo.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
		++length;
	return length;
}

std::string MTCALL hexStr(BYTE* data, int len)
{
	std::stringstream ss;
	ss << std::hex;

	for (int i(0); i < len; ++i)
	{
		ss << std::setw(2) << std::setfill('0') << (int)data[i];
		ss << " ";
	}

	return ss.str();
}

std::string MTCALL GetHexCharacter(uint8_t Value)
{
	std::ostringstream ss;
	ss << std::hex << std::setw(2) << std::setfill('0');
	ss << std::uppercase;
	ss << static_cast<int>(Value);
	return ss.str();
}


void MTCALL MemoryTools::BuildSignaturex86(_Outptr_ void* pStrObject, _In_reads_(len) unsigned char* data, _In_ unsigned int len, _In_opt_ bool bUseWildCards)
{
	std::string* pOutput = reinterpret_cast<std::string*>(pStrObject);
	std::ostringstream sig;
	sig << std::uppercase;
	unsigned int nBytesDisassembled = 0;

	while (nBytesDisassembled < len)
	{
		hde32s disasm;
		uint8_t* pPos = (uint8_t*)((char*)data + nBytesDisassembled);
		nBytesDisassembled += hde32_disasm(pPos, &disasm);

		sig << GetHexCharacter(disasm.opcode) << " ";
		int nRead = 1;

		if (disasm.len == 1)
			continue;

		if (disasm.opcode2)
		{
			sig << GetHexCharacter(disasm.opcode2) << " ";
			nRead++;
			if (disasm.len == 2)
				continue;
		}

		if ((disasm.imm.imm32 && disasm.len >= 5) && bUseWildCards)
		{
			for (int i = 0; i < (disasm.len - nRead); i++)
				sig << "??" << " ";
		}
		else
		{
			pPos += nRead;
			for (int i = 0; i < (disasm.len - nRead); i++, pPos++)
				sig << GetHexCharacter(*pPos) << " ";
		}

	}

	*pOutput = sig.str();
}

void MTCALL MemoryTools::CreateVTableSigsx86(_In_ void* class_definition, _In_ int& nVtablesCount, _In_opt_ void* strArray, _In_opt_ int nSigSize, _In_opt_ bool bUseWildCards)
{
	nVtablesCount = MemoryTools::CalculateVmtLength((void*)*(uintptr_t*)class_definition);

	if (!nVtablesCount)
		return;

	if (!strArray)
		return; // Let them Know the VMT Lengtg

	HMODULE hHandle;
	for (int i = 0; i < nVtablesCount; i++)
	{
		unsigned char* pFunc = (*reinterpret_cast<unsigned char***>(class_definition))[i];

		if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)pFunc, &hHandle))
			continue;

		char buf[MAX_PATH];
		if (!GetModuleBaseNameA(GetCurrentProcess(), hHandle, buf, ARRAYSIZE(buf)))
			continue;

		std::string signature;
		MemoryTools::BuildSignaturex86(&signature, pFunc, nSigSize, bUseWildCards);
		((std::string*)strArray)[i] = std::format("Index {} : ({}) {}", i, buf, signature);
	}

	return;
}


void* MTCALL MemoryTools::GetVTableFuncAddress(_In_ void* class_definition, _In_ int nVtableOffset)
{
	unsigned char* pFunc = (*reinterpret_cast<unsigned char***>(class_definition))[nVtableOffset];
	return pFunc;
}

void MTCALL MemoryTools::GetAddressModuleName(
	_In_ void* pAddress,
	_In_ void* pString
)
{

	std::string* pStr = (std::string*)pString;
	*pStr = "INVALID";

	HMODULE hHandle;
	if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)pAddress, &hHandle))
		return;

	char buf[MAX_PATH];
	if (!GetModuleBaseNameA(GetCurrentProcess(), hHandle, buf, ARRAYSIZE(buf)))
		return;

	*pStr = buf;

}

std::string uchar2hex(unsigned char inchar)
{
	std::ostringstream oss(std::ostringstream::out);
	oss << std::setw(2) << std::setfill('0') << std::hex << (int)(inchar);
	return oss.str();
}


void MTCALL MemoryTools::DisassembleMemoryRegionx86(
	_In_ void* pStrObject,
	_In_reads_bytes_(nRegionSize) void* pMemory,
	_In_ size_t nRegionSize,
	_In_ int line_indentation /*= 0*/
)
{
	std::string* str = reinterpret_cast<std::string*>(pStrObject);

	// Initialize decoder context
	ZydisDecoder decoder;
	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_ADDRESS_WIDTH_32);

	// Initialize formatter
	ZydisFormatter formatter;
	ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

	ZyanUSize offset = 0;
	const ZyanUSize length = nRegionSize;

	ZyanU32 runtime_address = (ZyanU32)pMemory;
	ZydisDecodedInstruction instruction;
	ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
	

	hde32s disasm;


	while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, (char*)pMemory + offset, length - offset,
		&instruction)))
	{
		// Format & print the binary instruction structure to human readable format
		char buffer[256];
		ZydisFormatterFormatInstruction(&formatter, &instruction,
			 buffer, sizeof(buffer), (ZyanU64)((char*)pMemory + offset));
		//puts(buffer);
		// todo follow call and get symbol / signature

		// TODO : Clean This Up!!!
		std::string bytes;

		int i = 0;
		for (;i < instruction.length; i++)
		{
			unsigned char byte = ((unsigned char*)(ZyanU64)((char*)pMemory + offset))[i];

			bytes.append(uchar2hex(byte));
			bytes.append(" ");
		}

		for (; i < 8; i++)
			bytes.append("   ");
		

		str->append("\n");
		for (int i = 0; i < line_indentation; i++)
			str->append(" ");

		char addrbuffer[10] = { 0 };
		snprintf(addrbuffer, sizeof(addrbuffer), "%p", (ZyanU64)((char*)pMemory + offset));

		str->append(addrbuffer);
		str->append(" ");
		str->append(bytes);
		str->append(" ");
		str->append(buffer);

		if (*(unsigned char*)((char*)pMemory + offset) == 0xe8)
		{
			auto pFunc = RelativeToAbsolute((void**)((char*)pMemory + offset + 1));


			if (pFunc)
			{
				
				std::string func_name;
				GetFunctionSymbolName(&func_name, pFunc);
				if (!strstr(func_name.c_str(), "#no_symbol#"))
				{
					str->append("    | (");
					str->append(func_name);
					str->append(")");
				}
				else
				{
					std::string module_name;
					GetAddressModuleName(pFunc, &module_name);
					str->append("    | (");
					str->append(func_name);
					str->append(")");
					str->append(" @ ");
					str->append(module_name);			
				}
			}

		}


		offset += instruction.length;
		runtime_address += instruction.length;

	}

	return;
}


unsigned int MTCALL MemoryTools::InstructionSizex86(
	_In_ char* pAddress
)
{
	hde32s disasm;
	return hde32_disasm(pAddress, &disasm);
}

void MTCALL MemoryTools::GetDebugCallStackString(void* pStr, bool bFindFunctionProlouge, unsigned int nCallStackMax, unsigned int hThread)
{


	std::string* pOutString = reinterpret_cast<std::string*>(pStr);

	char** callstack = (char**)_malloca(nCallStackMax * sizeof(char*));

	DWORD** params = (DWORD**)malloc(sizeof(DWORD*) * nCallStackMax);

	for (int i = 0; i < nCallStackMax; i++)
	{
		params[i] = (DWORD*)malloc(sizeof(DWORD*) * 4);
		memset(params[i], 0x00, sizeof(DWORD) * 4);
	}

	unsigned int FuncsGot = GetCallStackx86(callstack, nCallStackMax * sizeof(char*), true, bFindFunctionProlouge, (unsigned int**)params, hThread);



	// Huge String ik....
	char buf[4096];
	snprintf(buf, ARRAYSIZE(buf), "\n\n\n\n--- Call Stack (%d calls) ---\n", FuncsGot);
	pOutString->append(buf);

	auto build_params_string = [](DWORD* _params, int nIndent) {
		std::string out_str;
		char buffer[4096];
		for (int i = 0; i < 4; i++)
		{
			for (int j = 0; j < nIndent; j++)
				out_str.append(" ");

			DWORD dwValue = _params[i];
			snprintf(buffer, sizeof(buffer), "%d : (%s)|(%d) \n", 
				i,
				hexStr((BYTE*)(&dwValue),
					sizeof(DWORD)).c_str(), dwValue
			);
			out_str.append(buffer);
		}
		return out_str;
	};
	
	char buffer[4096 * 50];
	for (int i = 0; i < FuncsGot; i++)
	{
		memset(buffer, 0x00, sizeof(buffer));
		if (!callstack[i])
		{
			snprintf(buffer, sizeof(buffer), "\n -- WARNING = Function Call %d Unable To Fetch --\n", i);
			pOutString->append(buffer);
			continue;
		}

		std::string ret_disasm;
		std::string sig;
		std::string module_name;
		std::string func_name = "";
		void* pModuleStart;
		void* pModuleEnd;
		BuildSignaturex86(&sig, (unsigned char*)(callstack[i]), 20);
		DisassembleMemoryRegionx86(&ret_disasm, callstack[i], 30, 5);
		GetAddressModuleName(callstack[i], &module_name);
		GetFunctionSymbolName(&func_name, callstack[i]);
		GetModuleBounds(callstack[i], pModuleStart, pModuleEnd);

		snprintf(buffer, sizeof(buffer), "- Call %d : 0x%p (%s @ %s (0x%p -> 0x%p))\n   Sig : (%s)\n\n   Possible Params:\n%s\n   Ret Addr Disasm:\n  %s\n \n\n",
			i,
			callstack[i],
			func_name.c_str(),
			module_name.c_str(),
			pModuleStart,
			pModuleEnd,
			sig.c_str(),
			build_params_string(params[i], 5).c_str(),
			ret_disasm.c_str()
		);

		pOutString->append(buffer);
	}

	for (int i = 0; i < nCallStackMax; i++)
	{
		free(params[i]);
	}
	free(params);

	_freea(callstack);
}




void MTCALL MemoryTools::GetFunctionSymbolName(_In_ void* pString, void* pAddr)
{
	SymInitialize(GetCurrentProcess(), NULL, TRUE);
	DWORD displacement = 0;
	char name[1024] = { 0 };
	const int MaxNameLen = 255;
	IMAGEHLP_SYMBOL* pSymbol =
		(IMAGEHLP_SYMBOL*)malloc(sizeof(IMAGEHLP_SYMBOL64) + MaxNameLen * sizeof(TCHAR));
	pSymbol->MaxNameLength = MaxNameLen;

	if (SymGetSymFromAddr(GetCurrentProcess(), (ULONG)pAddr, &displacement, pSymbol))
		UnDecorateSymbolName(pSymbol->Name, (PSTR)name, 256, UNDNAME_COMPLETE);
	else
		*((std::string*)(pString)) = "!#no_symbol_avaliable#!";

	if (name[0] == 0x00)
	{
		*((std::string*)(pString)) = "!#no_symbol_avaliable#!";
		//std::string module_name;
		void* pMin = nullptr;
		void* pMax = nullptr;
		//MemoryTools::GetAddressModuleName(pAddr, &module_name);
		MemoryTools::GetModuleBounds(pAddr, pMin, pMax);

		snprintf(name, sizeof(name), " #no_symbol# [ (0x%p) + 0x%p ]", pMin, (char*)pAddr - pMin);
		((std::string*)(pString))->append(name);
	}


	*((std::string*)(pString)) = std::string(name);
}

void MTCALL MemoryTools::DumpModuleFromPEHeaderStartx86(void* pModule, const char* szModuleName)
{
	// TODO : Add Checks To See If Valid
	IMAGE_DOS_HEADER* pDOS = reinterpret_cast<IMAGE_DOS_HEADER*>(pModule);
	IMAGE_NT_HEADERS* pNt = reinterpret_cast<IMAGE_NT_HEADERS*>((char*)pModule + pDOS->e_lfanew);
	IMAGE_OPTIONAL_HEADER* pOpt = &(pNt->OptionalHeader);
	std::ofstream out_file(szModuleName, std::ios::out | std::ios::binary);
	out_file.write((const char*)pModule, pNt->OptionalHeader.SizeOfImage);
	out_file.close();
}

bool MTCALL MemoryTools::DumpModuleFromModuleHandlex86(unsigned int hModuleHandle, const char* szModuleName)
{
	MODULEINFO modInfo;
	if (K32GetModuleInformation(GetCurrentProcess(), (HMODULE)hModuleHandle, &modInfo, sizeof(modInfo)))
	{
		std::ofstream out_file(szModuleName, std::ios::out | std::ios::binary);
		out_file.write((const char*)modInfo.lpBaseOfDll,modInfo.SizeOfImage);
		out_file.close();
		return true;
	}

	return false;
}

void MTCALL MemoryTools::DumpAllLoadedModulesx86(const char* szPath)
{
	HMODULE hMods[1024];
	HANDLE hProcess;
	DWORD cbNeeded;
	int i = 0;
	hProcess = GetCurrentProcess();
	if (K32EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
	{
		for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
		{
			char buf[MAX_PATH];
			if (!GetModuleBaseNameA(GetCurrentProcess(), hMods[i], buf, ARRAYSIZE(buf)))
				return;
			std::string path_str(szPath);
			path_str.append(buf);
			DumpModuleFromModuleHandlex86((unsigned int)hMods[i], path_str.c_str());
		}
	}
}

#define ThreadQuerySetWin32StartAddress 9
void* MTCALL MemoryTools::GetThreadStartAddressx86(unsigned int hThread)
{
	NTSTATUS ntStatus;
	HANDLE hDupHandle;
	DWORD dwStartAddress;


	HANDLE hCurrentProcess = GetCurrentProcess();
	if (!DuplicateHandle(hCurrentProcess, (HANDLE)hThread, hCurrentProcess, &hDupHandle, THREAD_QUERY_INFORMATION, FALSE, 0)) {
		SetLastError(ERROR_ACCESS_DENIED);

		return 0;
	}
	
	ntStatus = NtQueryInformationThread(hDupHandle, (THREADINFOCLASS)ThreadQuerySetWin32StartAddress, &dwStartAddress, sizeof(DWORD), NULL);
	CloseHandle(hDupHandle);

	if (ntStatus != STATUS_SUCCESS)
		return 0;

	return (void*)dwStartAddress;
}

bool MTCALL MemoryTools::IsAddressWithinLoadModule(void* pAddress)
{
	HMODULE hMods[1024];
	HANDLE hProcess;
	DWORD cbNeeded;
	int i = 0;
	hProcess = GetCurrentProcess();
	if (K32EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
	{
		for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
		{
			MODULEINFO modInfo;
			if (!K32GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo)))
				continue;

			if (modInfo.lpBaseOfDll <= pAddress && pAddress <= ((char*)modInfo.lpBaseOfDll + modInfo.SizeOfImage))
				return true;

		}
	}

	return false;
}


void _suspend_all_threads()
{
	HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (h != INVALID_HANDLE_VALUE) {
		THREADENTRY32 te;
		te.dwSize = sizeof(te);
		if (Thread32First(h, &te)) {
			do {
				if (te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) +
					sizeof(te.th32OwnerProcessID)) {

					if (te.th32ThreadID == GetCurrentThreadId() || te.th32OwnerProcessID != GetCurrentProcessId())
						continue;

					HANDLE thread = ::OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);

					if (thread == GetCurrentThread())
						continue;

					SuspendThread(thread);

				}
				te.dwSize = sizeof(te);
			} while (Thread32Next(h, &te));
		}
		CloseHandle(h);
	}

}

void _resume_all_threads()
{
	HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (h != INVALID_HANDLE_VALUE) {
		THREADENTRY32 te;
		te.dwSize = sizeof(te);
		if (Thread32First(h, &te)) {
			do {
				if (te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) +
					sizeof(te.th32OwnerProcessID)) {

					if (te.th32ThreadID == GetCurrentThreadId() || te.th32OwnerProcessID != GetCurrentProcessId())
					    continue;

					HANDLE thread = ::OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);

					ResumeThread(thread);

				}
				te.dwSize = sizeof(te);
			} while (Thread32Next(h, &te));
		}
		CloseHandle(h);
	}
}

bool MTCALL MemoryTools::SearchForNonStandardMappedDLLsx86()
{
	// First Lets Go Through All Threads And See If We Can Find Weird eip Addresses
	HANDLE hProcess = GetCurrentProcess();
	DWORD dwProcessID = GetProcessId(hProcess);
	std::vector<THREADENTRY32> current_process_threads;
	std::vector<void*> suspicious_start_addresses;

	HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (h != INVALID_HANDLE_VALUE) {
		THREADENTRY32 te;
		te.dwSize = sizeof(te);
		if (Thread32First(h, &te)) {
			do {
				if (te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) +
					sizeof(te.th32OwnerProcessID)) {

					if (te.th32OwnerProcessID != dwProcessID)
						continue;

					current_process_threads.push_back(te);
				}
				te.dwSize = sizeof(te);
			} while (Thread32Next(h, &te));
		}
		
	}
	
	// Search For Start Addresses That Are Not Within Current Modules
	for (const auto thread : current_process_threads)
	{
		HANDLE hThreadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, thread.th32ThreadID);

		if (hThreadHandle == NULL && IsDebuggerPresent())
			__debugbreak();

		void* pStartAddress = GetThreadStartAddressx86((unsigned int)hThreadHandle);

		CloseHandle(hThreadHandle);

		if (IsAddressWithinLoadModule(pStartAddress))
			continue;

		suspicious_start_addresses.push_back(pStartAddress);
	}


	//return !suspicious_start_addresses.empty();


	// Now Lets Go Through Literally Every Bit Of Memory
	
	// Freeze All Threads Right Now!!!
	_suspend_all_threads();

	std::vector<MEMORY_BASIC_INFORMATION> process_memory_map_executable;
	unsigned int i = 0;
	for (; i < 0x7FFF0000; )
	{
		MEMORY_BASIC_INFORMATION meminfo;
		if (!VirtualQuery((LPCVOID)i, &meminfo, sizeof(meminfo)))
			i += 1;

		i += meminfo.RegionSize;
		

		if (meminfo.Protect & PAGE_EXECUTE || meminfo.Protect & PAGE_EXECUTE_READ || meminfo.Protect & PAGE_EXECUTE_READWRITE)
		{
			if(!IsAddressWithinLoadModule(meminfo.BaseAddress))
				process_memory_map_executable.push_back(meminfo);
		}
	
	}

	_resume_all_threads();
	return !suspicious_start_addresses.empty() || !process_memory_map_executable.empty();
}



void MTCALL MemoryTools::GetModuleBounds(_In_ void* pAddr, _Outptr_ void*& nMinAddr, _Outptr_ void*& nMaxAddr)
{
	HMODULE hHandle;
	if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)pAddr, &hHandle))
		return;

	MODULEINFO modinfo;
	if(!GetModuleInformation(
		GetCurrentProcess(),
		hHandle,
		&modinfo,
		sizeof(MODULEINFO)
	)) {
		return;
	}

	nMinAddr = modinfo.lpBaseOfDll;
	nMaxAddr = ((char*)modinfo.lpBaseOfDll + modinfo.SizeOfImage);
}


__declspec(naked) void WINAPI CaptureContext_X86ControlOnly(CONTEXT* context) {
	__asm {
		push ebp
		mov  ebp, esp
		mov  ecx, context            //ecx = [ebp + 8]
		pop  ebp                     //restore old frame
		pop  eax                     //pop return address
		pop  ecx                     //pop context as WINAPI needs. Note: ecx will stay the same
		mov[ecx]CONTEXT.ContextFlags, CONTEXT_CONTROL
		mov[ecx]CONTEXT.Ebp, ebp
		mov[ecx]CONTEXT.Eip, eax
		mov[ecx]CONTEXT.Esp, esp
		jmp  eax
	}
} //I'm writing from my memory - so step through the code above to double check.

bool IsCallOpCode(unsigned char cOpCode)
{
	switch ((int)cOpCode)
	{
	case 0xFF:
	case 0xE8:
	case 0xE9: // not a call but whatever
	case 0x9A:
		return true;
		break;
	default:
		return false;
		break;
	}
}

unsigned int MTCALL MemoryTools::GetCallStackx86(
	_In_ char** pArray,
	_In_ unsigned int nNumFuncsToFetch,
	_In_ bool bGetReturnAddressInstead /*= false*/,
	_In_ bool bAttemptPrologueFind /*= false*/,
	_In_ unsigned int** pParams /*= nullptr*/,
	_In_ unsigned int hThreadHandle/* = -1*/
)
{
	STACKFRAME sfFrame;
	CONTEXT             cxRecord;
	HANDLE hProcess;
	HANDLE hThread = (HANDLE)hThreadHandle;
	DWORD             displacement;
	hProcess = GetCurrentProcess();

	if (!hThreadHandle)
	{
		hThread = GetCurrentThread();
		CaptureContext_X86ControlOnly(&cxRecord);
	}
	else
	{
		cxRecord.ContextFlags = CONTEXT_FULL;
		if (!GetThreadContext(hThread, &cxRecord))	
			return 0;
		

	}
	//RtlCaptureContext(&cxRecord);
	memset(&sfFrame, 0, sizeof(STACKFRAME));
	//SymInitialize(hProcess, nullptr, true);

	displacement = 0;
	sfFrame.AddrPC.Offset = cxRecord.Eip;
	sfFrame.AddrPC.Mode = AddrModeFlat;
	sfFrame.AddrStack.Offset = cxRecord.Esp;
	sfFrame.AddrStack.Mode = AddrModeFlat;
	sfFrame.AddrFrame.Offset = cxRecord.Ebp;
	sfFrame.AddrFrame.Mode = AddrModeFlat;

	unsigned int nFrameCount = 0;
	for (; nFrameCount < nNumFuncsToFetch; nFrameCount++)
	{
		BOOL bRes = StackWalk
		(
			IMAGE_FILE_MACHINE_I386,
			hProcess,
			hThread,
			&sfFrame,
			&cxRecord,
			NULL,
			SymFunctionTableAccess,
			SymGetModuleBase,
			NULL
		);

		if (!bRes || !sfFrame.AddrReturn.Offset || !sfFrame.AddrPC.Offset)
			break;

		char* pFoundAddr = bGetReturnAddressInstead ? (char*)sfFrame.AddrReturn.Offset : (char*)sfFrame.AddrPC.Offset;
		if (bAttemptPrologueFind)
		{
			char* pPrologue = (char*)FindFunctionPrologueFromReturnAddressx86(pFoundAddr, 100, true);
			pFoundAddr = pPrologue != nullptr ? pPrologue : pFoundAddr;

			if (pPrologue == nullptr && bGetReturnAddressInstead)
			{
				pFoundAddr -= 5;
				unsigned char byte = *pFoundAddr;
				if (!IsCallOpCode(byte)) {
					for (int i = 0; i < 5; i++) {
						pFoundAddr++;
						if (IsCallOpCode(*pFoundAddr))
							break;
					}
				}
			}


		}
		else if (bGetReturnAddressInstead)
		{
			pFoundAddr -= 5;
			unsigned char byte = *pFoundAddr;
			if (!IsCallOpCode(byte))
			{
				for (int i = 0; i < 5; i++)
				{
					pFoundAddr++;
					if (IsCallOpCode(*pFoundAddr))
						break;
				}
			}
		}

		pArray[nFrameCount] = pFoundAddr;

		if (pParams)
			memcpy(pParams[nFrameCount], sfFrame.Params, sizeof(sfFrame.Params));
	}

	return --nFrameCount;
}


std::mutex g_DebuggingMutex;



void RemoveCallTree();
class BuildCallTree
{
public:

	struct _CallStack
	{
		enum Type {
			RETURN,
			CALL,
		};

		void* pNextAddress;
	};

	~BuildCallTree() { RemoveCallTree(); }


	void MakeExecutableWriteable(void* pAddress)
	{
		VirtualProtect(pAddress, 4000, PAGE_EXECUTE_READWRITE, &m_dwLastPageProtection);
	}

	void WriteBreakPoint(void* pAddress)
	{
		MakeExecutableWriteable(pAddress);
		m_cReplacedInstruction = *(unsigned char*)pAddress;
		*(unsigned char*)pAddress = 0xCC;
	}

	void StartCallTree()
	{
		void* pStartAddress = _ReturnAddress();
		WriteBreakPoint(pStartAddress);
	}

	bool IsCall(unsigned char cOpCode, int nLength)
	{
		switch ((int)cOpCode)
		{
		case 0xFF:
			if (nLength > 3)
				return false;
		case 0xE8:
		case 0x9A:
			return true;
			break;
		default:
			return false;
			break;
		}
	}

	bool IsRet(unsigned char cOpCode)
	{
		switch ((int)cOpCode)
		{
		case 0xC3:
		case 0xCB:
		case 0xC2:
		case 0xCA:
			return true;
			break;
		default:
			return false;
			break;
		}
	}

	bool IsJMP(unsigned char cOpCode)
	{
		switch ((int)cOpCode)
		{
		case 0xFF:
		case 0xEB:
		case 0xE9:
		case 0xEA:
			return true;
			break;
		default:
			return false;
			break;
		}
	}


	void OnStep(CONTEXT* pContextRecord)
	{
		hde32s disasm;
		hde32_disasm((const void*)pContextRecord->Eip, &disasm);

		

		//disasm.opcode == 0xE8

	}

private:
	bool bNextAddressIsCall = false;
	bool bNextAddressIsRet = false;

	void* m_pLastAddress = nullptr;
	DWORD m_dwLastPageProtection = PAGE_EXECUTE_READWRITE;
	unsigned char m_cReplacedInstruction;
};

class MemToolsExceptionHelper
{
public:

	bool bHasCallTree(){return m_CallTrees[GetCurrentThreadId()] != nullptr ? true : false;}


	BuildCallTree* GetCallTree() { return m_CallTrees[GetCurrentThreadId()]; }

	void StartCallTreeOnThread()
	{
		m_CallTrees[GetCurrentThreadId()] = new BuildCallTree();
	}

	void DeleteCallTree()
	{
		m_CallTrees[GetCurrentThreadId()] = nullptr;
	}

private:
	std::map<DWORD, BuildCallTree*> m_CallTrees;
};

MemToolsExceptionHelper g_Exceptions;


void _RemoveCallTree()
{
	g_Exceptions.DeleteCallTree();
}


EXCEPTION_DISPOSITION __cdecl MemToolsExceptionHandler(
	EXCEPTION_RECORD* pRecord,
	void* pEstablisherFrame,
	CONTEXT* pContextRecord,
	void* DispatcherContext

)
{

	if (pRecord->ExceptionInformation[0] == EXCEPTION_SINGLE_STEP)
	{
		BuildCallTree* pTree = g_Exceptions.GetCallTree();

		if (!pTree)
			return ExceptionContinueExecution;






	}
}

// todo finish
namespace WinSocksIntercept
{
	decltype(&send) osend = nullptr;
	decltype(&send) send_callback = nullptr;
	decltype(&recv) orecv = nullptr;
	decltype(&recv) recv_callback = nullptr;
	int WSAAPI send(
			_In_ SOCKET s,
			_In_reads_bytes_(len) const char FAR* buf,
			_In_ int len,
			_In_ int flags
		
	){



		return osend(s, buf, len, flags);
	}

	int WSAAPI recv(
		_In_ SOCKET s,
		_Out_writes_bytes_to_(len, return) __out_data_source(NETWORK) char FAR* buf,
		_In_ int len,
		_In_ int flags
	){

		return orecv(s, buf, len, flags);
	}

}
