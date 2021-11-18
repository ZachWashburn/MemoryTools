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
 
</p>

# Documentation


## Pattern Scanning Functions

Tools For Scanning Process Memory For A Certain Pattern In "XX XX ? XX XX ? ? ? ? XX" Format 


<pre>
     PatternScanMemoryRegion(pBaseAddress, nRegionSize, pszPattern)
            -  Find a Pattern within the region specified by pBaseAddress of region size nRegionSize 
            
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
