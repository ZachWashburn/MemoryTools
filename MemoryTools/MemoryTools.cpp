// MemoryTools.cpp : Defines the functions for the static library.
//

#include "MemoryTools.h"
#include <cstdlib>
#include <string.h>
#include <Windows.h>
#include <Psapi.h>
#include <intsafe.h>

_Ret_maybenull_ void* MTCALL MemoryTools::PatternScanMemoryRegion(_In_reads_bytes_(nRegionSize) void* pBaseAddress, _In_ size_t nRegionSize, _In_ const char* pszPattern)
{
	size_t nPatternSize = strlen(pszPattern) - 1;

	unsigned char* s = reinterpret_cast<unsigned char*>(pBaseAddress);
	unsigned char* e = s + nRegionSize;
	unsigned char* pPatternPos = (unsigned char*)pszPattern;
	for (; s < e; s++)
	{
		if (*pPatternPos == ' ')
		{
			s--;
			pPatternPos++;
			continue;
		}

		if (*pPatternPos == '?')
		{
			pPatternPos++;
			continue;
		}

		unsigned char byte = (unsigned char)strtoul((const char*)pPatternPos, (char**)&pPatternPos, 16);

		if (byte != *s)
		{
			pPatternPos = (unsigned char*)pszPattern;
		}
		else
		{
			if (pPatternPos >= (unsigned char*)(pszPattern + nPatternSize))
				return (void*)(s - nPatternSize);
		}

	}

	return (void*)nullptr;
}

_Ret_maybenull_ void* MTCALL MemoryTools::PatternScanModuleHandle(_In_ void* hModule, _In_ const char* pszPattern)
{
	MODULEINFO modInfo;

	if (GetModuleInformation(GetCurrentProcess(), (HMODULE)hModule, &modInfo, sizeof(MODULEINFO)))
		MemoryTools::PatternScanMemoryRegion((void*)modInfo.lpBaseOfDll, modInfo.SizeOfImage, pszPattern);

	return (void*)nullptr;
}

_Ret_maybenull_ void* MTCALL MemoryTools::PatternScanModule(_In_ const char* pszModuleName, _In_ const char* pszPattern)
{
	HMODULE hModule;
	hModule = GetModuleHandleA(pszModuleName);

	if (!hModule)
		return (void*)nullptr;

	return PatternScanModuleHandle(hModule, pszPattern);
}

_Ret_maybenull_ void* MTCALL MemoryTools::PatternScanCurrentProcess(_In_ const char* pszPattern)
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


_Ret_maybenull_ void* MTCALL MemoryTools::PatternScanHeap(_In_/*PROCESS_HEAP_ENTRY*/ void* pHeapEntry, _In_ const char* pszPattern)
{
	MEMORY_BASIC_INFORMATION MemInfo;
	DWORD dwOldProtect = 0;
	PROCESS_HEAP_ENTRY* pEntry = reinterpret_cast<PROCESS_HEAP_ENTRY*>(pHeapEntry);


	if (!VirtualQueryEx(GetCurrentProcess(), pEntry, &MemInfo, sizeof(MEMORY_BASIC_INFORMATION)))
		return (void*)nullptr;

	if (MemInfo.State != MEM_COMMIT || MemInfo.Protect == PAGE_NOACCESS)
		return (void*)nullptr;

	return MemoryTools::PatternScanMemoryRegion((void*)pEntry->lpData, pEntry->cbData, pszPattern);
}


_Ret_maybenull_ void* MTCALL MemoryTools::PatternScanCurrentProcessHeaps(_In_ const char* pszPattern)
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



_Success_(return != false) bool MTCALL MemoryTools::PlaceJumpRel32x86(_Out_writes_bytes_all_(5) void* pWriteAddress, _In_ void* pJumpAddress)
{
	DWORD dwOldProtect;
	if (!VirtualProtect(pWriteAddress, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect))
		return false;
	memset(pWriteAddress, 0x90, 5);
	char* pRelativeDifference = (char*)(((char*)pJumpAddress - (char*)pWriteAddress) - 5);
	*(unsigned char*)(pWriteAddress) = 0xE9;
	*(void**)((char*)pWriteAddress + sizeof(unsigned char*)) = pRelativeDifference;
	if (!VirtualProtect(pWriteAddress, 5, dwOldProtect, &dwOldProtect))
		return false;
	return true;
}

_Success_(return != false) bool MTCALL MemoryTools::PlaceCallRel32x86(_Out_writes_bytes_all_(5) void* pWriteAddress, _In_ void* pJumpAddress)
{
	DWORD dwOldProtect;
	if (!VirtualProtect(pWriteAddress, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect))
		return false;
	memset(pWriteAddress, 0x90, 5);
	char* pRelativeDifference = (char*)(((char*)pJumpAddress - (char*)pWriteAddress) - 5);
	*(unsigned char*)(pWriteAddress) = 0xE8;
	*(void**)((char*)pWriteAddress + sizeof(unsigned char*)) = pRelativeDifference;
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

	size_t nBlockOffset = (size_t)((char*)ptr - (char*)mbi.AllocationBase);
	size_t nBlockBytesPostPtr = mbi.RegionSize - nBlockOffset;

	if (nBlockBytesPostPtr < nDataSize)
	{
		if(pnReadableAmount)
			*pnReadableAmount += mbi.RegionSize;

		bool bReturnValue = DoesMemoryHaveAttributes((char*)ptr + nBlockBytesPostPtr,
			nDataSize - nBlockBytesPostPtr, PageState, PageProtect, PageType, pnReadableAmount);

		return bReturnValue;
	}

	return true;
}

bool MTCALL MemoryTools::IsMemoryRangeReadable(_In_ void* ptr, _In_ size_t nDataSize, _Inout_opt_ size_t* pnReadableAmount /* = nullptr */)
{
	return MemoryTools::DoesMemoryHaveAttributes(ptr, nDataSize, 0xFFFFFFFF, PAGE_READONLY & PAGE_READWRITE & PAGE_EXECUTE_READWRITE, 0xFFFFFFFF, pnReadableAmount);
}

