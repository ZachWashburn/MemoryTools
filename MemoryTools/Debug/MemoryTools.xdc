<?xml version="1.0"?><doc>
<members>
<member name="M:MemoryTools.PatternScanMemoryRegion(System.Void*,System.UInt32,System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte!System.Runtime.CompilerServices.IsConst*)" decl="true" source="C:\Users\user\source\repos\MemoryTools\MemoryTools\MemoryTools.h" line="27">
<c>PatternScanMemoryRegion</c> 
<summary> Find a Pattern within <paramref name="pBaseAddress"/> to <paramref name="pBaseAddress"/> + <paramref name="nRegionSize"/>.</summary>
<param name="pBaseAddress"> Base Address To Scan From.</param>
<param name="nRegionSize"> Amount of bytes to scan from pBaseAddress.</param>
<param name="pszPattern"> The String To Scan For in  XX XX ? XX XX  format.</param>
<returns>  Address Pattern Found At Or NULL (no match).</returns>
</member>
<member name="M:MemoryTools.PatternScanModule(System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte!System.Runtime.CompilerServices.IsConst*,System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte!System.Runtime.CompilerServices.IsConst*)" decl="true" source="C:\Users\user\source\repos\MemoryTools\MemoryTools\MemoryTools.h" line="41">
<c>PatternScanModule</c> 
<summary> Finds a Loaded Module, and Scans its Memory For a Pattern.</summary> 
<param name="pszModuleName"> String With Name Of The Module To Scan.</param>
<param name="pszPattern"> The String To Scan For in  XX XX ? XX XX  format.</param>
<returns> <strong> Address Pattern Found At Or NULL (no match / module not found) </strong>.</returns>
</member>
<member name="M:MemoryTools.PatternScanModuleHandle(System.Void*,System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte!System.Runtime.CompilerServices.IsConst*)" decl="true" source="C:\Users\user\source\repos\MemoryTools\MemoryTools\MemoryTools.h" line="54">
<c> PatternScanModuleHandle </c> 
<summary> Takes a Module Handle, Scans the Modules Memory </summary>
<param name="hModule"> The Handle To The Module Found </param>
<param name="pszPattern"> The String To Scan For in  XX XX ? XX XX  format </param>
<returns> <strong> Address Pattern Found At Or NULL (no match / module info not acquired) </strong> </returns>
</member>
<member name="M:MemoryTools.PatternScanCurrentProcess(System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte!System.Runtime.CompilerServices.IsConst*)" decl="true" source="C:\Users\user\source\repos\MemoryTools\MemoryTools\MemoryTools.h" line="66">
<c> PatternScanCurrentProcess </c> 
<summary> Scans All Process Modules For a Pattern </summary>
<param name="pszPattern"> The String To Scan For in  XX XX ? XX XX  format </param>
<returns> <strong> Address Pattern Found At Or NULL (no match) </strong> </returns>
</member>
<member name="M:MemoryTools.PatternScanHeap(System.Void*,System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte!System.Runtime.CompilerServices.IsConst*)" decl="true" source="C:\Users\user\source\repos\MemoryTools\MemoryTools\MemoryTools.h" line="77">
<c> PatternScanHeap </c> 
<summary> Scans a Specific Memory Heap For a Pattern </summary>
<param name="pHeapEntry"> A Pointer to a PROCESS_HEAP_ENTRY structure </param>
<param name="pszPattern"> The String To Scan For in  XX XX ? XX XX  format </param>
<returns> <strong> Address Pattern Found At Or NULL (no match) </strong> </returns>
</member>
<member name="M:MemoryTools.PatternScanCurrentProcessHeaps(System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte!System.Runtime.CompilerServices.IsConst*)" decl="true" source="C:\Users\user\source\repos\MemoryTools\MemoryTools\MemoryTools.h" line="90">
<c> PatternScanCurrentProcessHeaps </c> 
<summary> Scans All Heaps For The Current Process For a Pattern </summary>
<param name="pszPattern"> The String To Scan For in  XX XX ? XX XX  format </param>
<returns> <strong> Address Pattern Found At Or NULL (no match) </strong> </returns>
</member>
<member name="M:MemoryTools.PlaceJumpRel32x86(System.Void*,System.Void*)" decl="true" source="C:\Users\user\source\repos\MemoryTools\MemoryTools\MemoryTools.h" line="100">
<c> PlaceJumpRel32x86 </c> 
<summary> Places a Relative Jump 32bit to pJumpAddress.</summary>
<param name="pWriteAddress"> A Pointer To The Address To Place The Jump.</param>
<param name="pJumpAddress"> A Pointer To The Address The Jump Points To.</param>
<returns> <strong> true if the function succeeds, failure is caused do to a VirtualProtect failure.</strong> </returns>
</member>
<member name="M:MemoryTools.PlaceCallRel32x86(System.Void*,System.Void*)" decl="true" source="C:\Users\user\source\repos\MemoryTools\MemoryTools\MemoryTools.h" line="113">
<c> PlaceCallRel32x86 </c> 
<summary> Places a Relative Call 32bit (0xE8) to pJumpAddress </summary>
<param name="pWriteAddress"> A Pointer To The Address To Place The Call </param>
<param name="pCallAddress"> A Pointer To The Address The Call Points To </param>
<returns> <strong> true if the function succeeds, failure is caused do to a VirtualProtect failure </strong> </returns>
</member>
<member name="M:MemoryTools.WriteNOPs(System.Void*,System.UInt32)" decl="true" source="C:\Users\user\source\repos\MemoryTools\MemoryTools\MemoryTools.h" line="125">
<c> WriteNOPs </c>
<summary> Writes NOP (0x90) Opcodes from pWriteAddress to pWriteAddress + nDataSize </summary>
<param name="pWriteAddress">  A Pointer To The Address To Place The NOP OpCodes </param>
<param name="nDataSize"> Amount of Bytes to Overwrite </param>
<returns> <strong> true if the function succeeds, failure is caused do to a VirtualProtect failure </strong> </returns>
</member>
<member name="M:MemoryTools.DoesMemoryHaveAttributes(System.Void*,System.UInt32,System.Int32,System.Int32,System.Int32,System.UInt32*)" decl="true" source="C:\Users\user\source\repos\MemoryTools\MemoryTools\MemoryTools.h" line="138">
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
<member name="M:MemoryTools.IsMemoryRangeReadable(System.Void*,System.UInt32,System.UInt32*)" decl="true" source="C:\Users\user\source\repos\MemoryTools\MemoryTools\MemoryTools.h" line="158">
<c> IsMemoryRangeReadable </c> 
<summary> Are these bytes readable? if passing pnReadableAmount, value passed in must be 0 </summary>
<param name="ptr"> A Pointer To Start Memory Address </param>
<param name="nDataSize"> Amount Of Bytes to Check </param>
<param name="pnReadableAmount"> An Optional Pointer that returns how many bytes were readable </param>
<returns> <strong> True if all bytes checked were readable </strong> </returns>
</member>
<member name="M:MemoryTools.RelativeToAbsolute(System.Void**)" decl="true" source="C:\Users\user\source\repos\MemoryTools\MemoryTools\MemoryTools.h" line="171">
<c> RelativeToAbsolute </c> 
<summary> Converts a Relative Address In Memory To An Absolute One </summary>
<param name="ptr"> A Pointer To The Address Location In Memory </param>
<returns> <strong> Absolute Value Of Address, NULL if Memory Is Not Readable </strong> </returns>
</member>
</members>
</doc>