#ifndef _H_MEMORY_TOOLS
#define _H_MEMORY_TOOLS

#pragma once

#include <stdio.h>

#define MEMTOOLS_STATIC_LIBRARY
#ifndef MEMTOOLS_STATIC_LIBRARY
#define DLLEXPORT __declspec(dllexport)
#else 
#define DLLEXPORT 
#endif

#define EXTERNCOPEN extern "C" {
#define EXTERNCCLOSE };
// Using stdcall for easier use in x86 (not needing to clean up the stack)
#define MTCALL __stdcall

namespace MemoryTools
{


	/* Definitions */

	struct StackStore_t
	{
		size_t m_nStackSize = 0;
		_Field_size_bytes_(m_nStackSize)
		void* m_pStack = nullptr;
	};


	/* Functions */

	EXTERNCOPEN
		/// <c>PatternScanMemoryRegion</c> 
		/// <summary> Find a Pattern within pBaseAddress to pBaseAddress + nRegionSize.</summary>
		/// <param name="pBaseAddress"> Base Address To Scan From.</param>
		/// <param name="nRegionSize"> Amount of bytes to scan from pBaseAddress.</param>
		/// <param name="pszPattern"> The String To Scan For in  XX XX ? XX XX  format.</param>
		/// <returns>  Address Pattern Found At Or NULL (no match).</returns>
		DLLEXPORT _Ret_maybenull_ void* MTCALL PatternScanMemoryRegion
		(
			_In_reads_bytes_(nRegionSize) void* pBaseAddress,
			_In_ size_t nRegionSize,
			_In_z_ const char* pszPattern
		);


		/// <c>PatternScanMemoryRegionReverse</c> 
		/// <summary> Find a Pattern within pBaseAddress to pBaseAddress + nRegionSize going in reverse order.</summary>
		/// <param name="pBaseAddress"> Base Address To Scan From.</param>
		/// <param name="nRegionSize"> Amount of bytes to scan from pBaseAddress.</param>
		/// <param name="pszPattern"> The String To Scan For in  XX XX ? XX XX  format, function automatically reversed code bytes </param>
		/// <returns>  Address Pattern Found At Or NULL to signify no match .</returns>
		DLLEXPORT _Ret_maybenull_ void* MTCALL PatternScanMemoryRegionReverse
		(
			_In_reads_bytes_(nRegionSize) void* pBaseAddress,
			_In_ size_t nRegionSize,
			_In_z_ const char* pszPattern
		);


		/// <c>PatternScanModule</c> 
		/// <summary> Finds a Loaded Module, and Scans its Memory For a Pattern.</summary> 
		/// <param name="pszModuleName"> String With Name Of The Module To Scan.</param>
		/// <param name="pszPattern"> The String To Scan For in  XX XX ? XX XX  format.</param>
		/// <returns> <strong> Address Pattern Found At Or NULL (no match / module not found) </strong>.</returns>
		DLLEXPORT _Ret_maybenull_ void* MTCALL PatternScanModule
		(
			_In_z_ const char* pszModuleName,
			_In_z_ const char* pszPattern
		);


		/// <c> PatternScanModuleHandle </c> 
		/// <summary> Takes a Module Handle, Scans the Modules Memory </summary>
		/// <param name="hModule"> The Handle To The Module Found </param>
		/// <param name="pszPattern"> The String To Scan For in  XX XX ? XX XX  format </param>
		/// <returns> <strong> Address Pattern Found At Or NULL (no match / module info not acquired) </strong> </returns>
		DLLEXPORT _Ret_maybenull_ void* MTCALL PatternScanModuleHandle
		(
			_In_ void* hModule,
			_In_z_ const char* pszPattern
		);

		/// <c> PatternScanCurrentProcess </c> 
		/// <summary> Scans All Process Modules For a Pattern </summary>
		/// <param name="pszPattern"> The String To Scan For in  XX XX ? XX XX  format </param>
		/// <returns> <strong> Address Pattern Found At Or NULL (no match) </strong> </returns>
		DLLEXPORT _Ret_maybenull_ void* MTCALL PatternScanCurrentProcess
		(
			_In_z_ const char* pszPattern
		);


		/// <c> PatternScanHeap </c> 
		/// <summary> Scans a Specific Memory Heap For a Pattern </summary>
		/// <param name="pHeapEntry"> A Pointer to a PROCESS_HEAP_ENTRY structure </param>
		/// <param name="pszPattern"> The String To Scan For in  XX XX ? XX XX  format </param>
		/// <returns> <strong> Address Pattern Found At Or NULL (no match) </strong> </returns>
		DLLEXPORT _Ret_maybenull_ void* MTCALL PatternScanHeap
		(
			_In_ void* pHeapEntry, /* PROCESS_HEAP_ENTRY* */
			_In_z_ const char* pszPattern
		);


		/// <c> PatternScanCurrentProcessHeaps </c> 
		/// <summary> Scans All Heaps For The Current Process For a Pattern </summary>
		/// <param name="pszPattern"> The String To Scan For in  XX XX ? XX XX  format </param>
		/// <returns> <strong> Address Pattern Found At Or NULL (no match) </strong> </returns>
		DLLEXPORT _Ret_maybenull_ void* MTCALL PatternScanCurrentProcessHeaps
		(
			_In_z_ const char* pszPattern
		);

		/// <c> PatternScanStack </c> 
		/// <summary> Scans The Stack Top To Bottom And Returns First Match </summary>
		/// <param name="pThreadHandle"> A Handle To The Thread That We Should Scan The Stack For </param>
		/// <param name="pszPattern"> The String To Scan For in XX XX ? XX XX  format </param>
		/// <returns> <strong> Address Pattern Found At Or NULL (no match) </strong> </returns>
		DLLEXPORT _Ret_maybenull_ void* MTCALL PatternScanStack
		(
			_In_ void* pThreadHandle,
			_In_z_ const char* pszPattern
		);

		/// <c> PatternScanStack </c> 
		/// <summary> Scans The Stack Top To Bottom And Returns First Match </summary>
		/// <param name="pszPattern"> The String To Scan For in XX XX ? XX XX  format </param>
		/// <returns> <strong> Address Pattern Found At Or NULL (no match) </strong> </returns>
		DLLEXPORT _Ret_maybenull_ void* MTCALL PatternScanCurrentStack
		(
			_In_z_ const char* pszPattern
		);


		/// <c> PlaceJumpRel32x86 </c> 
		/// <summary> Places a Relative Jump 32bit to pJumpAddress.</summary>
		/// <param name="pWriteAddress"> A Pointer To The Address To Place The Jump.</param>
		/// <param name="pJumpAddress"> A Pointer To The Address The Jump Points To.</param>
		/// <returns> <strong> true if the function succeeds, failure is caused do to a VirtualProtect failure.</strong> </returns>
		DLLEXPORT _Success_(return != false) bool MTCALL PlaceJumpRel32x86
		(
			_Out_writes_bytes_all_(5) void* pWriteAddress,
			_In_ void* pJumpAddress
		);


		/// <c> PlaceCallRel32x86 </c> 
		/// <summary> Places a Relative Call 32bit (0xE8) to pJumpAddress </summary>
		/// <param name="pWriteAddress"> A Pointer To The Address To Place The Call </param>
		/// <param name="pCallAddress"> A Pointer To The Address The Call Points To </param>
		/// <returns> <strong> true if the function succeeds, failure is caused do to a VirtualProtect failure </strong> </returns>
		DLLEXPORT _Success_(return != false) bool MTCALL PlaceCallRel32x86
		(
			_Out_writes_bytes_all_(5) void* pWriteAddress,
			_In_ void* pCallAddress
		);

		/// <c> WriteNOPs </c>
		/// <summary> Writes NOP (0x90) Opcodes from pWriteAddress to pWriteAddress + nDataSize </summary>
		/// <param name="pWriteAddress">  A Pointer To The Address To Place The NOP OpCodes </param>
		/// <param name="nDataSize"> Amount of Bytes to Overwrite </param>
		/// <returns> <strong> true if the function succeeds, failure is caused do to a VirtualProtect failure </strong> </returns>
		DLLEXPORT _Success_(return != false) bool MTCALL WriteNOPs
		(
			_Out_writes_bytes_all_(nDataSize) void* pWriteAddress,
			_In_ size_t nDataSize
		);


		/// <c> CreateNewExecutableStackx86 </c>
		/// <summary> Create A New Stack, StackStore_t must be static/thread_local/global var! </summary>
		/// <param name="nMinStackSize"> Minimum Size The New Stack Can Be </param>
		/// <param name="bExecutable"> Where to Mark The Page Protection As Executable </param>
		/// <param name="pStackStore"> A Pointer to a StackStore_t Object, I recommend a thread_local var (can't be on stack) </param>
		DLLEXPORT void MTCALL CreateNewStackx86
		(
			_In_ size_t nMinStackSize,
			_In_opt_ bool bExecutable,
			_In_opt_ StackStore_t * pStackStore
		);
		

		/// <c> RestoreStackx86 </c>
		/// <summary> Restore Stack From StackStore Obj </summary>
		/// <param name="pStackStore"> A Pointer to a StackStore_t Object </param>
		DLLEXPORT void MTCALL RestoreStackx86
		(
			_In_ StackStore_t * pStackStore
		);

		/// <c> DoesMemoryHaveAttributes </c> 
		/// <summary> Checks Memory Region for page characteristics *pnMatchable amount must be 0 pass, 0xFFFFFFFF for any characteristic fields you don't care for	</summary>
		/// <param name="ptr">  A Pointer To Start Memory Address </param>
		/// <param name="nDataSize"> Amount Of Bytes to Check </param>
		/// <param name="PageState"> The Page State To Check For (i.e.) MEM_COMMIT , Pass 0xFFFFFFF if it doesn't matter </param>
		/// <param name="PageProtect"> The Page Protection To Check For (i.e.) PAGE_EXECUTE, Pass 0xFFFFFFF if it doesn't matter </param>
		/// <param name="PageType"> The Page Type To Check For (i.e.) MEM_IMAGE, Pass 0xFFFFFFF if it doesn't matter </param>
		/// <param name="pnMatchableAmount"> An Optional Pointer that returns how many bytes met these requirements </param>
		/// <returns> <strong> True if all bytes checked meet the requirements passed </strong> </returns>
		DLLEXPORT bool MTCALL DoesMemoryHaveAttributes
		(
			_In_ void* ptr,
			_In_ size_t nDataSize,
			_In_ int PageState,
			_In_ int PageProtect,
			_In_ int PageType,
			_Inout_opt_ size_t* pnMatchableAmount = nullptr
		);


		/// <c> IsMemoryRangeReadable </c> 
		/// <summary> Are these bytes readable? if passing pnReadableAmount, value passed in must be 0 </summary>
		/// <param name="ptr"> A Pointer To Start Memory Address </param>
		/// <param name="nDataSize"> Amount Of Bytes to Check </param>
		/// <param name="pnReadableAmount"> An Optional Pointer that returns how many bytes were readable </param>
		/// <returns> <strong> True if all bytes checked were readable </strong> </returns>
		DLLEXPORT bool MTCALL IsMemoryRangeReadable
		(
			_In_ void* ptr,
			_In_ size_t nDataSize,
			_Inout_opt_ size_t* pnReadableAmount = nullptr
		);

		/// <c> RelativeToAbsolute </c> 
		/// <summary> Converts a Relative Address In Memory To An Absolute One </summary>
		/// <param name="ptr"> A Pointer To The Address Location In Memory </param>
		/// <returns> <strong> Absolute Value Of Address, NULL if Memory Is Not Readable </strong> </returns>
		DLLEXPORT _Ret_maybenull_ void* MTCALL RelativeToAbsolute
		(
			_In_reads_(sizeof(void*)) void** ptr
		);

		/// <c> GetThreadTEB </c> 
		/// <summary> Gets The TEB For A Running Thread </summary>
		/// <param name="hThread"> The HANDLE to the thread </param>
		/// <returns> <strong> Returns NULL Due to Error, otherwise the TEB </strong> </returns>
		DLLEXPORT _Ret_maybenull_ void* MTCALL GetThreadTEB
		(
			_In_ void* hThread
		);

		/// <c> GetCurrentTEB </c> 
		/// <summary> Gets The TEB For The Current Thread </summary>
		/// <returns> <strong> Returns NULL Due to Error, otherwise the TEB </strong> </returns>
		DLLEXPORT void* MTCALL GetCurrentTEB();

		/// <c> GetPatternReversed </c> 
		/// <summary> Reverses a Code Pattern or any string less than 8192 </summary>
		/// <param name="szPattern"> A Pointer To The String </param>
		/// <returns> <strong> Returns a allocated new string, must free using MTFree </strong> </returns>
		DLLEXPORT _Ret_maybenull_ _Null_terminated_ _Must_inspect_result_ char* MTCALL GetPatternReversed
		(
			_In_opt_z_ const char* szPattern
		);

		/// <c> MTFree </c> 
		/// <summary> Frees memory, use incase of custom allocator </summary>
		/// <param name="ptr"> A Pointer To The Allocated String </param>
		/// <returns> <strong> void (no return) </strong> </returns>
		DLLEXPORT void MTCALL MTFree
		(
			_In_opt_ void* ptr
		);

	EXTERNCCLOSE



}

namespace MemoryToolsEx {
	EXTERNCOPEN

		/// <c>PatternScanMemoryRegionEx</c> 
		/// <summary> Find a Pattern within pBaseAddress to pBaseAddress + nRegionSize. Of An External Process </summary>
		/// <param name="hProcess"> A (HANDLE) to the Process of Which We Are Scanning </param>
		/// <param name="pBaseAddress"> Base Address To Scan From.</param>
		/// <param name="nRegionSize"> Amount of bytes to scan from pBaseAddress.</param>
		/// <param name="pszPattern"> The String To Scan For.</param>
		/// <returns>  Address Pattern Found At Or NULL (no match).</returns>
		DLLEXPORT _Ret_maybenull_ void* MTCALL PatternScanMemoryRegionEx
		(
			_In_ void* hProcess,
			_In_reads_bytes_(nRegionSize) void* pBaseAddress,
			_In_ size_t nRegionSize,
			_In_z_ const char* pszPattern
		);

	EXTERNCCLOSE
}

#undef DLLEXPORT
#endif

