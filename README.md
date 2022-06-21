# MemoryTools

**A collection of tools for working with process memory (with a specification for inner-process hacking)**

<p>
I found myself re-writing a lot of a the same code over and over again, so I decided to create a library for personal
use, and release it here. 

This library contains various tools and utilities I use for inner-process hacking (i.e.) malware research, game hacking/reverse-engineering (single player only!), etc.

Currently only x86 Windows is supported, but I have plans for x64, and eventually linux compatability. 
  
All functions contain SAL annotation and XML documentation to offer better intellisense.
  
Any functions that contain a base definiton aswell as an -Ex definition, specific that the Ex version works on external processes. 
External Functions can be found in the MemoryToolsEx namespace.
 
MemoryTools now depends on Zydis for opcode disassembly 
 
</p>

# Documentation


## Pattern Scanning Functions

Tools For Scanning Process Memory For A Certain Pattern In "XX XX ? XX XX ? ? ? ? XX" Format 


<pre>
  MemoryTools::
     
     PatternScanMemoryRegion(pBaseAddress, nRegionSize, pszPattern)
            -  Find a Pattern within the region specified by pBaseAddress of region size nRegionSize 
            
     PatternScanMemoryRegionReportPartial(pBaseAddress, nRegionSize, pszPattern, bPartial)
            -  Scans A Memory Region, reports if it partially found a pattern before reaching 
            -  pBaseAddress + nRegion size cut off of memory region
            
     PatternScanMemoryRegionReverse(pBaseAddress, nRegionSize, pszPattern)
            -  Finds A Pattern Within A Region, but scans from highest address
            -  to lowest address. Pattern Is Automatically Reversed
            
     PatternScanModule(pszModuleName, pszPattern)
            -  Finds a Loaded Module, and Scans its Memory For a Pattern
             
     PatternScanModuleHandle(hModule, pszPattern)
            -   Takes a Module Handle, Scans the Modules Memory For a Pattern 
            
     PatternScanCurrentProcess(pszPattern)
            -   Scans All Process Modules For a Pattern
        
     PatternScanHeap(pHeapEntry, pszPattern)
            -   Scans a Specific Heap For A Pattern 
            -   (note pHeapEntry is of PROCESS_HEAP_ENTRY type, and refers to a specific heap)
         
     PatternScanCurrentProcessHeaps(pszPattern)
            -   Scans All Heaps For The Current Process For a Pattern
            
     PatternScanStack(void* pThreadHandle, const char* pszPattern)
            -   Scans Stack For Thread Specified by pTheadHandle for a Pattern
            -   (Top -> Bottom Scan)
            
     PatternScanCurrentStack(const char* pszPattern)
            -   Scans Current Thread Stack for a Pattern
            -   (Top -> Bottom Scan) 
            
     BuildSignaturex86(pStrObject, data, len)
            -   Creates a Code Pattern for a specified memory Region
            
     CreateVTableSigsx86(pClass, nVtablesCount, pStrArray)
            -   Creates a Code Pattern for each function in a classes vtable
            
      
    
            
  MemoryToolsEx::
  
     PatternScanMemoryRegionEx(hProcess, pBaseAddress, nRegionSize, pszPattern)
            -  Same As PatternScanMemoryRegion, but scans the process specified by
            -  hProcess instead of the local process
            
</pre>

## Code Patching Functions

Tools For Byte Patching Executable Code In A Process


<pre>
     PlaceJumpRel32x86(pWriteAddress, pJumpAddres)
            -  Place a Relative Jump at pWriteAddress to pJumpAddress (0xE9 rel/32 opcode)
            
     PlaceCallRel32x86(pWriteAddress, pCallAddres)
            -  Place a Relative Call at pWriteAddress to pJumpAddress (0xE8 rel/32 opcode)
            
     WriteNOPs(pWriteAddress, nDataSize)
            -  Fill at the Write Address an nDataSize about of nop Opcodes (0x90)
            
     GenerateIntermediaryFunctionx86(pTargetFunction)
            -  Generates a jump function that points to another
            
     HookFunctionx86(pFunction, pHook, ppOirignal)
            - Detour a function (pFunction) to a hook function (pHook)
            - Return Original in *ppOriginal
            
</pre>

## Memory Query Functions

Tools for finding information about a specified memory region

<pre>
     DoesMemoryHaveAttributes(ptr, nDataSize, PageState, PageProtect, PageType, pnMatchableAmount (optional))
            -  Queries a Specific Memory Region (ptr->ptr+nDataSize) And Checks To See If The Memory Matches 
            -  Certain Page Attributes (State, Protection, Type). The Optional Value pnMatchableAmount Will 
            -  Return The Amount Of Bytes That Match The Attributes (if not all do, this also returns false)
            
     IsMemoryRangeReadable(ptr, nDataSize, pnReadableAmount (optional))
            -  Checks To See If We Are Able to Read From a Certain Memory Range
            -  pnReadableAmount Will Return The Max Readable Bytes If Passed
</pre>

## Misc Functions
Miscellaneous Functions 

<pre>
     CreateNewStackx86(nMinStackSize, bExecutable, pStackStore (optional))
            -  Create A New Stack For The Current Thread
            -  pStackStore Can Be Passed To Store The Current Stack To Restore later
            -  Remember The Stack Is Different, I Recommend Using A thread_local Var
            -  For pStackStore (Or Static/Global If Not Using Multiple Threads)
      
     RestoreStackx86(pStackStore)
            -  Restores The Stack To A Previous Stack
            -  Usually You'll Still Have To Do Some Cleanup On Your End
            
     GetThreadTEB(hThread)
            -  Returns The Thread Execution Block of the Thread Specified By hThread
            
     GetCurrentTEB()
            -  Returns The TEB of the Current Thread
            
     FindFunctionPrologueFromReturnAddressx86(pRetAddr, nMaxSearchableBytes)
            -  Attempts to find the begining of a function from an address
            -  provided within the function body (usually a return address)
     
</pre>

## Helper Functions

Simple Helper Functions

<pre>
     RelativeToAbsolute(ptr)
            -  Converts A Relative Address To Absolute (returns NULL if memory location is not readable)
            
     GetPatternReversed(szPattern)
            -  Reverses a Pattern (or any string)
            -  Return is allocate, call MTFree(ret) to free
          
     CalculateVmtLength(pVMT)
            -  Calculates the length of a Virtual Method Table
            
     MTFree(ptr)
            - Frees Memory Allocated By MemoryTools
            
     BuildSignaturex86(pStrObject, data, len, bUseWildCards)
            - Generate a code pattern at location pointed to by data,
            - of size len, returns in a std::string object pointed to by
            - pStrObject.
            
    CreateVTableSigsx86(class_definition, nVtableCount, strArray, nSigSize, bUseWildCards)
            - Generate a signature of each function within a vtable up to nVtableCount
            - Returns by using an array of std::string objects pointed to by strarry
     
    DisassembleMemoryRegionx86(pStrObject, pMemory, nRegionSize, line_indentation)
            - Generate a formated disassembly of a memory region pointed to by pMemory
            - returns in an std::string object pointed too by pStrObject
            
    InstructionSizex86(pAddress)
            - Get the size of an instruction at address pAddress
            
    GetCallStackx86(pArray, nNumFuncsToFetch, bGetReturnAddressInstead, bAttemptPrologueFind, pParams, hThreadHandle)
            - Return the current callstack, up to nNumFuncsToFetch. 
            - Can Attempt to find the start of a function (func prolouge),
            - or simply get the address of return
            
    GetVTableFuncAddress(class_definition, nVtableOffset)
            - Get The Address of a vtable function at nVtableOffset of class type pointed to by class_definition
            
    GetAddressModuleName(pAddress, pString)
            - Return the name of the loaded module pAddress resides in
            - Returns in a std::string object pointed to by pString
            
       
    GetModuleBounds(pAddr, nMinAddr, nMaxAddr)
            - Fetch the starting and ending address of the module that pAddr 
            - is within. nMinAddr and nMaxAddr are reference cast integers
            
    GetFunctionSymbolName(pString, pAddr)
            - Fetch the functions symbol name that pAddr resides in,
            - returns in an std::string object pointed to by pString.
            
    GetDebugCallStackString(pStr, bFindFunctionProlouge, nCallStackMax, hThread)
            - Generate a large debug string about all functions currently in the callstack
            - includes patterns, disassembly, symbol and module names. 
            
    DumpModuleFromPEHeaderStartx86(pModule, szModuleName)
            - Dump a module by PE header pointed to by pModule, writes a file named szModuleName to disk
            
    DumpModuleFromModuleHandlex86(hModuleHandle, szModuleName)
            - Dump a module referenced by hModuleHandle, writes a file named szModuleName to disk
            
    DumpAllLoadedModulesx86(szPath)
            - Dump All Windows Loader-Loaded modules within a process to location
            - specified by szPath
            
    SearchForNonStandardMappedDLLsx86()
            - Attempts to scan for modules not loaded by the windows loader (manually mapped)
            - Returns true on finding
            
    GetThreadStartAddressx86(hThread)
            - Get The Start Address Of The Thread Referenced by hThread
            
    IsValidPEHeaderx86(pAddr)
            - Checks a PE header at pAddr, verifies validity
            
    IsAddressWithinLoadModule(pAddress)
            - Checks a address to verify if it resides within a module loaded by
            - the windows loader. 
         
          
</pre>


