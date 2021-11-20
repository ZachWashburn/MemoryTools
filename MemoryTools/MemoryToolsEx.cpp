#include "MemoryTools.h"
#include <cstdlib>
#include <string.h>
#include <Windows.h>
#include <Psapi.h>
#include <intsafe.h>
#include <malloc.h>
#include <winternl.h>
#include <intrin.h>

#define INRANGE(x,a,b)    (x >= a && x <= b) 
#define getBits( x )    (INRANGE((x&(~0x20)),'A','F') ? ((x&(~0x20)) - 'A' + 0xa) : (INRANGE(x,'0','9') ? x - '0' : 0))
#define getByte( x )    (getBits(x[0]) << 4 | getBits(x[1]))

_Ret_maybenull_ void* MTCALL MemoryToolsEx::PatternScanMemoryRegionEx
(
	_In_ void* hProcess,
	_In_reads_bytes_(nRegionSize) void* pBaseAddress,
	_In_ size_t nRegionSize,
	_In_z_ const char* pszPattern
)
{
	const char* pat = pszPattern;
	BYTE* firstMatch = 0;
	BYTE* rangeStart = (BYTE*)pBaseAddress;
	BYTE* rangeEnd = rangeStart + nRegionSize;
	BYTE* pLastReadLocation = nullptr;
	size_t nStepSize = min(8196, rangeEnd - rangeStart);
	BYTE* pMemoryBuffer = (BYTE*)_alloca(nStepSize);
	unsigned int nBufferPosition = 0;

	// This may possibly cause issues on huge ranges
	for (BYTE* pCur = rangeStart; pCur < rangeEnd; pCur++, nBufferPosition++)
	{
		if (!pLastReadLocation || (pLastReadLocation + nStepSize < pCur))
		{
			SIZE_T nNumBytesRead = 0;
			nStepSize = min(8196, rangeEnd - pCur);
			BOOL bRet = ReadProcessMemory(hProcess, pCur, pMemoryBuffer, nStepSize, &nNumBytesRead);

			if (!bRet || nNumBytesRead < nStepSize)
				return nullptr;

			pLastReadLocation = pCur;
			nBufferPosition = 0;
		}

		if (!*pat)
			return firstMatch;

		if (*(PBYTE)pat == '\?' || *(BYTE*)pMemoryBuffer[nBufferPosition] == getByte(pat))
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