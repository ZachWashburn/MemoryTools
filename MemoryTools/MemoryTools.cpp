// MemoryTools.cpp : Defines the functions for the static library.
//

#include "MemoryTools.h"
#include <cstdlib>
#include <string.h>
#include <Windows.h>
#include <Psapi.h>
#include <intsafe.h>
#include <malloc.h>
#include <winternl.h>
#include <intrin.h>
#include <list>

#include "ThirdParty/hde/hde32.h"
#include "ThirdParty/hde/hde64.h"

#ifdef THROWEXCEPTION
#include <exception>
#endif

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

_Ret_maybenull_ void* MTCALL MemoryTools::PatternScanCurrentProcess(_In_z_ const char* pszPattern)
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
	if (!MemoryTools::IsMemoryRangeReadable(ptr, sizeof(void*)))
		return nullptr;

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

_Success_(return != false) bool HookFunctionx86(_In_ void* pFunction, _In_ void* pHook, _Outptr_ void** ppOriginal)
{


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
}

_Ret_maybenull_ void* MemoryTools::GenerateIntermediaryFunctionx86(
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


_Ret_maybenull_ void* MemoryTools::FindFunctionPrologueFromReturnAddressx86(
	_In_ void* pReturnAddress,
	_In_opt_ int nMaxNumberOfBytes /* = 0*/
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
			break;	
	}

	pAddr++;

	if (*pAddr != 0x55)
		return nullptr;

	return pAddr;
}

#include <sstream>
#include <iomanip>

size_t MemoryTools::CalculateVmtLength(_In_ void* vmt) 
{
	size_t length = 0;
	MEMORY_BASIC_INFORMATION memoryInfo;
	while (VirtualQuery(LPCVOID(((uintptr_t*)vmt)[length]), &memoryInfo, sizeof(memoryInfo)) && memoryInfo.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
		++length;
	return length;
}

std::string hexStr(BYTE* data, int len)
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

std::string GetHexCharacter(uint8_t Value)
{
	std::ostringstream ss;
	ss << std::hex << std::setw(2) << std::setfill('0');
	ss << std::uppercase;
	ss << static_cast<int>(Value);
	return ss.str();
}


void MemoryTools::BuildSignaturex86(_Outptr_ void* pStrObject, _In_reads_(len) unsigned char* data, _In_ unsigned int len)
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

		if (disasm.imm.imm32 && disasm.len >= 5)
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

void MemoryTools::CreateVTableSigsx86(_In_ void* class_definition, _In_ int& nVtablesCount, _In_opt_ void* strArray)
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
		MemoryTools::BuildSignaturex86(&signature, pFunc, 20);

		//printf("Index %d : (%s) %s \n", i, buf, signature.c_str());
		((std::string*)strArray)[i] = signature;
	}

	return;
}
