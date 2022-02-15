<?xml version="1.0"?><doc>
<members>
<member name="M:MemoryTools.PatternScanMemoryRegion(System.Void*,System.UInt32,System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte!System.Runtime.CompilerServices.IsConst*)" decl="true" source="C:\Users\user\source\repos\MemoryTools\MemoryTools\MemoryTools.h" line="40">
<c>PatternScanMemoryRegion</c> 
<summary> Find a Pattern within pBaseAddress to pBaseAddress + nRegionSize.</summary>
<param name="pBaseAddress"> Base Address To Scan From.</param>
<param name="nRegionSize"> Amount of bytes to scan from pBaseAddress.</param>
<param name="pszPattern"> The String To Scan For in  XX XX ? XX XX  format.</param>
<returns>  Address Pattern Found At Or NULL (no match).</returns>
</member>
<member name="M:MemoryTools.PatternScanMemoryRegionReverse(System.Void*,System.UInt32,System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte!System.Runtime.CompilerServices.IsConst*)" decl="true" source="C:\Users\user\source\repos\MemoryTools\MemoryTools\MemoryTools.h" line="54">
<c>PatternScanMemoryRegionReverse</c> 
<summary> Find a Pattern within pBaseAddress to pBaseAddress + nRegionSize going in reverse order.</summary>
<param name="pBaseAddress"> Base Address To Scan From.</param>
<param name="nRegionSize"> Amount of bytes to scan from pBaseAddress.</param>
<param name="pszPattern"> The String To Scan For in  XX XX ? XX XX  format, function automatically reversed code bytes </param>
<returns>  Address Pattern Found At Or NULL to signify no match .</returns>
</member>
<member name="M:MemoryTools.PatternScanModule(System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte!System.Runtime.CompilerServices.IsConst*,System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte!System.Runtime.CompilerServices.IsConst*)" decl="true" source="C:\Users\user\source\repos\MemoryTools\MemoryTools\MemoryTools.h" line="68">
<c>PatternScanModule</c> 
<summary> Finds a Loaded Module, and Scans its Memory For a Pattern.</summary> 
<param name="pszModuleName"> String With Name Of The Module To Scan.</param>
<param name="pszPattern"> The String To Scan For in  XX XX ? XX XX  format.</param>
<returns> <strong> Address Pattern Found At Or NULL (no match / module not found) </strong>.</returns>
</member>
<member name="M:MemoryTools.PatternScanModuleHandle(System.Void*,System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte!System.Runtime.CompilerServices.IsConst*)" decl="true" source="C:\Users\user\source\repos\MemoryTools\MemoryTools\MemoryTools.h" line="80">
<c> PatternScanModuleHandle </c> 
<summary> Takes a Module Handle, Scans the Modules Memory </summary>
<param name="hModule"> The Handle To The Module Found </param>
<param name="pszPattern"> The String To Scan For in  XX XX ? XX XX  format </param>
<returns> <strong> Address Pattern Found At Or NULL (no match / module info not acquired) </strong> </returns>
</member>
<member name="M:MemoryTools.PatternScanCurrentProcess(System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte!System.Runtime.CompilerServices.IsConst*)" decl="true" source="C:\Users\user\source\repos\MemoryTools\MemoryTools\MemoryTools.h" line="91">
<c> PatternScanCurrentProcess </c> 
<summary> Scans All Process Modules For a Pattern </summary>
<param name="pszPattern"> The String To Scan For in  XX XX ? XX XX  format </param>
<returns> <strong> Address Pattern Found At Or NULL (no match) </strong> </returns>
</member>
<member name="M:MemoryTools.PatternScanHeap(System.Void*,System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte!System.Runtime.CompilerServices.IsConst*)" decl="true" source="C:\Users\user\source\repos\MemoryTools\MemoryTools\MemoryTools.h" line="101">
<c> PatternScanHeap </c> 
<summary> Scans a Specific Memory Heap For a Pattern </summary>
<param name="pHeapEntry"> A Pointer to a PROCESS_HEAP_ENTRY structure </param>
<param name="pszPattern"> The String To Scan For in  XX XX ? XX XX  format </param>
<returns> <strong> Address Pattern Found At Or NULL (no match) </strong> </returns>
</member>
<member name="M:MemoryTools.PatternScanCurrentProcessHeaps(System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte!System.Runtime.CompilerServices.IsConst*)" decl="true" source="C:\Users\user\source\repos\MemoryTools\MemoryTools\MemoryTools.h" line="113">
<c> PatternScanCurrentProcessHeaps </c> 
<summary> Scans All Heaps For The Current Process For a Pattern </summary>
<param name="pszPattern"> The String To Scan For in  XX XX ? XX XX  format </param>
<returns> <strong> Address Pattern Found At Or NULL (no match) </strong> </returns>
</member>
<member name="M:MemoryTools.PatternScanStack(System.Void*,System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte!System.Runtime.CompilerServices.IsConst*)" decl="true" source="C:\Users\user\source\repos\MemoryTools\MemoryTools\MemoryTools.h" line="122">
<c> PatternScanStack </c> 
<summary> Scans The Stack Top To Bottom And Returns First Match </summary>
<param name="pThreadHandle"> A Handle To The Thread That We Should Scan The Stack For </param>
<param name="pszPattern"> The String To Scan For in XX XX ? XX XX  format </param>
<returns> <strong> Address Pattern Found At Or NULL (no match) </strong> </returns>
</member>
<member name="M:MemoryTools.PatternScanCurrentStack(System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte!System.Runtime.CompilerServices.IsConst*)" decl="true" source="C:\Users\user\source\repos\MemoryTools\MemoryTools\MemoryTools.h" line="133">
<c> PatternScanStack </c> 
<summary> Scans The Stack Top To Bottom And Returns First Match </summary>
<param name="pszPattern"> The String To Scan For in XX XX ? XX XX  format </param>
<returns> <strong> Address Pattern Found At Or NULL (no match) </strong> </returns>
</member>
<member name="M:MemoryTools.PlaceJumpRel32x86(System.Void*,System.Void*)" decl="true" source="C:\Users\user\source\repos\MemoryTools\MemoryTools\MemoryTools.h" line="143">
<c> PlaceJumpRel32x86 </c> 
<summary> Places a Relative Jump 32bit to pJumpAddress.</summary>
<param name="pWriteAddress"> A Pointer To The Address To Place The Jump.</param>
<param name="pJumpAddress"> A Pointer To The Address The Jump Points To.</param>
<returns> <strong> true if the function succeeds, failure is caused do to a VirtualProtect failure.</strong> </returns>
</member>
<member name="M:MemoryTools.PlaceCallRel32x86(System.Void*,System.Void*)" decl="true" source="C:\Users\user\source\repos\MemoryTools\MemoryTools\MemoryTools.h" line="155">
<c> PlaceCallRel32x86 </c> 
<summary> Places a Relative Call 32bit (0xE8) to pJumpAddress </summary>
<param name="pWriteAddress"> A Pointer To The Address To Place The Call </param>
<param name="pCallAddress"> A Pointer To The Address The Call Points To </param>
<returns> <strong> true if the function succeeds, failure is caused do to a VirtualProtect failure </strong> </returns>
</member>
<member name="M:MemoryTools.WriteNOPs(System.Void*,System.UInt32)" decl="true" source="C:\Users\user\source\repos\MemoryTools\MemoryTools\MemoryTools.h" line="166">
<c> WriteNOPs </c>
<summary> Writes NOP (0x90) Opcodes from pWriteAddress to pWriteAddress + nDataSize </summary>
<param name="pWriteAddress">  A Pointer To The Address To Place The NOP OpCodes </param>
<param name="nDataSize"> Amount of Bytes to Overwrite </param>
<returns> <strong> true if the function succeeds, failure is caused do to a VirtualProtect failure </strong> </returns>
</member>
<member name="M:MemoryTools.CreateNewStackx86(System.UInt32,System.Boolean,MemoryTools.StackStore_t*)" decl="true" source="C:\Users\user\source\repos\MemoryTools\MemoryTools\MemoryTools.h" line="178">
<c> CreateNewExecutableStackx86 </c>
<summary> Create A New Stack, StackStore_t must be static/thread_local/global var! </summary>
<param name="nMinStackSize"> Minimum Size The New Stack Can Be </param>
<param name="bExecutable"> Where to Mark The Page Protection As Executable </param>
<param name="pStackStore"> A Pointer to a StackStore_t Object, I recommend a thread_local var (can't be on stack) </param>
</member>
<member name="M:MemoryTools.RestoreStackx86(MemoryTools.StackStore_t*)" decl="true" source="C:\Users\user\source\repos\MemoryTools\MemoryTools\MemoryTools.h" line="191">
<c> RestoreStackx86 </c>
<summary> Restore Stack From StackStore Obj </summary>
<param name="pStackStore"> A Pointer to a StackStore_t Object </param>
</member>
<member name="M:MemoryTools.DoesMemoryHaveAttributes(System.Void*,System.UInt32,System.Int32,System.Int32,System.Int32,System.UInt32*)" decl="true" source="C:\Users\user\source\repos\MemoryTools\MemoryTools\MemoryTools.h" line="199">
<c> DoesMemoryHaveAttributes </c> 
<summary> Checks Memory Region for page characteristics *pnMatchable amount must be 0 pass, 0xFFFFFFFF for any characteristic fields you don't care for	</summary>
<param name="ptr">  A Pointer To Start Memory Address </param>
<param name="nDataSize"> Amount Of Bytes to Check </param>
<param name="PageState"> The Page State To Check For (i.e.) MEM_COMMIT , Pass 0xFFFFFFF if it doesn't matter </param>
<param name="PageProtect"> The Page Protection To Check For (i.e.) PAGE_EXECUTE, Pass 0xFFFFFFF if it doesn't matter </param>
<param name="PageType"> The Page Type To Check For (i.e.) MEM_IMAGE, Pass 0xFFFFFFF if it doesn't matter </param>
<param name="pnMatchableAmount"> An Optional Pointer that returns how many bytes met these requirements </param>
<returns> <strong> True if all bytes checked meet the requirements passed </strong> </returns>
</member>
<member name="M:MemoryTools.IsMemoryRangeReadable(System.Void*,System.UInt32,System.UInt32*)" decl="true" source="C:\Users\user\source\repos\MemoryTools\MemoryTools\MemoryTools.h" line="219">
<c> IsMemoryRangeReadable </c> 
<summary> Are these bytes readable? if passing pnReadableAmount, value passed in must be 0 </summary>
<param name="ptr"> A Pointer To Start Memory Address </param>
<param name="nDataSize"> Amount Of Bytes to Check </param>
<param name="pnReadableAmount"> An Optional Pointer that returns how many bytes were readable </param>
<returns> <strong> True if all bytes checked were readable </strong> </returns>
</member>
<member name="M:MemoryTools.RelativeToAbsolute(System.Void**)" decl="true" source="C:\Users\user\source\repos\MemoryTools\MemoryTools\MemoryTools.h" line="232">
<c> RelativeToAbsolute </c> 
<summary> Converts a Relative Address In Memory To An Absolute One </summary>
<param name="ptr"> A Pointer To The Address Location In Memory </param>
<returns> <strong> Absolute Value Of Address, NULL if Memory Is Not Readable </strong> </returns>
</member>
<member name="M:MemoryTools.GetThreadTEB(System.Void*)" decl="true" source="C:\Users\user\source\repos\MemoryTools\MemoryTools\MemoryTools.h" line="241">
<c> GetThreadTEB </c> 
<summary> Gets The TEB For A Running Thread </summary>
<param name="hThread"> The HANDLE to the thread </param>
<returns> <strong> Returns NULL Due to Error, otherwise the TEB </strong> </returns>
</member>
<member name="M:MemoryTools.GetCurrentTEB" decl="true" source="C:\Users\user\source\repos\MemoryTools\MemoryTools\MemoryTools.h" line="250">
<c> GetCurrentTEB </c> 
<summary> Gets The TEB For The Current Thread </summary>
<returns> <strong> Returns NULL Due to Error, otherwise the TEB </strong> </returns>
</member>
<member name="M:MemoryTools.GetPatternReversed(System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte!System.Runtime.CompilerServices.IsConst*)" decl="true" source="C:\Users\user\source\repos\MemoryTools\MemoryTools\MemoryTools.h" line="255">
<c> GetPatternReversed </c> 
<summary> Reverses a Code Pattern or any string less than 8192 </summary>
<param name="szPattern"> A Pointer To The String </param>
<returns> <strong> Returns a allocated new string, must free using MTFree </strong> </returns>
</member>
<member name="M:MemoryTools.MTFree(System.Void*)" decl="true" source="C:\Users\user\source\repos\MemoryTools\MemoryTools\MemoryTools.h" line="264">
<c> MTFree </c> 
<summary> Frees memory, use incase of custom allocator </summary>
<param name="ptr"> A Pointer To The Allocated String </param>
<returns> <strong> void (no return) </strong> </returns>
</member>
<member name="M:MemoryTools.GenerateIntermediaryFunctionx86(System.Void*)" decl="true" source="C:\Users\user\source\repos\MemoryTools\MemoryTools\MemoryTools.h" line="273">
<c> GenerateIntermediaryFunctionx86 </c> 
<summary> Generates A Function That Serves As A Jump To The Other </summary>
<param name="pFunc"> A Pointer To Desired Function </param>
<returns> <strong> void* The Generated Function </strong> </returns>
</member>
<member name="M:MemoryTools.FindFunctionPrologueFromReturnAddressx86(System.Void*,System.Int32)" decl="true" source="C:\Users\user\source\repos\MemoryTools\MemoryTools\MemoryTools.h" line="281">
<c> FindFunctionPrologueFromReturnAddressx86 </c> 
<summary> Attempts To Find The Start of a function based off the return address you have </summary>
<param name="pReturnAddress"> A Pointer To The Return Address to the function to find </param>
<param name="nMaxNumberOfBytes"> Number Of Bytes To Search </param>
<returns> <strong> void* The Function Address if found </strong> </returns>
</member>
<member name="M:MemoryTools.CalculateVmtLength(System.Void*)" decl="true" source="C:\Users\user\source\repos\MemoryTools\MemoryTools\MemoryTools.h" line="291">
<c> CalculateVmtLength </c> 
<summary> Calculates the total count of functions in a Vtable </summary>
<param name="vmt"> A Pointer To VTable </param>
<returns> <strong> size_t The Amount of Functions </strong> </returns>
</member>
<member name="M:MemoryTools.BuildSignaturex86(System.Void*,System.Byte*,System.UInt32)" decl="true" source="C:\Users\user\source\repos\MemoryTools\MemoryTools\MemoryTools.h" line="299">
<c> BuildSignaturex86 </c> 
<summary> Create A Code Pattern For A Selected Region Of Memory </summary>
<param name="pStrObject"> A Pointer To A std::string Object </param>
<param name="data"> A Pointer To The Data A Signature Will Be Created For </param>
<param name="len"> Amount Of Bytes To Use In The Pattern </param>
</member>
<member name="M:MemoryTools.CreateVTableSigsx86(System.Void*,System.Int32*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.Void*)" decl="true" source="C:\Users\user\source\repos\MemoryTools\MemoryTools\MemoryTools.h" line="310">
<c> CreateVTableSigsx86 </c> 
<summary> Create A Code Pattern For Each Function In A Vtable, returns nVtableCount is strArray is nullptr </summary>
<param name="class_definition"> A Pointer To A Virtual Class </param>
<param name="nVtablesCount"> Number Of Functions To Generate </param>
<param name="strArray"> A Array of std::string equal to nVtablesCount, if set as 0, nVtablesCount is set </param>
</member>
<member name="M:MemoryToolsEx.PatternScanMemoryRegionEx(System.Void*,System.Void*,System.UInt32,System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte!System.Runtime.CompilerServices.IsConst*)" decl="true" source="C:\Users\user\source\repos\MemoryTools\MemoryTools\MemoryTools.h" line="330">
<c>PatternScanMemoryRegionEx</c> 
<summary> Find a Pattern within pBaseAddress to pBaseAddress + nRegionSize. Of An External Process </summary>
<param name="hProcess"> A (HANDLE) to the Process of Which We Are Scanning </param>
<param name="pBaseAddress"> Base Address To Scan From.</param>
<param name="nRegionSize"> Amount of bytes to scan from pBaseAddress.</param>
<param name="pszPattern"> The String To Scan For.</param>
<returns>  Address Pattern Found At Or NULL (no match).</returns>
</member>
<member name="M:WinRebuilt.RtlCaptureImageExceptionValues(System.Void*,System.Void**,System.UInt32!System.Runtime.CompilerServices.IsLong*)" decl="true" source="C:\Users\user\source\repos\MemoryTools\MemoryTools\WindowsRebuild.h" line="13">
<summary>
Queries Exception Information Contained Within An Image 
</summary>
<param name="Base"> A Pointer To The Base Address Of The Image </param>
<param name="FunctionTable"> A Pointer That Recieves The Base Address Of The Function Table </param>
<param name="TableSize"> Pointer To ULONG That Recieves The Size Of The Function Table </param>
</member>
<member name="M:WinRebuilt.RtlImageNtHeader(System.Void*)" decl="true" source="C:\Users\user\source\repos\MemoryTools\MemoryTools\WindowsRebuild.h" line="25">
<summary>
Gets The NT Header For A Module
</summary>
<param name="Base"> Base Address Of Module </param>
<returns> Pointer To NT Header </returns>
</member>
</members>
</doc>