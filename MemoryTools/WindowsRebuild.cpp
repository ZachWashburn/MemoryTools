#include "WindowsRebuild.h"
#include <cstdlib>
#include <string.h>
#include <Windows.h>
#include <Psapi.h>
#include <intsafe.h>
#include <malloc.h>
#include <winternl.h>
#include <intrin.h>
#include <DbgHelp.h>
#include <winerror.h>
#include <exception>

#define STATUS_INVALID_IMAGE_FORMAT 0xC000007B
#define RTL_IMAGE_NT_HEADER_EX_FLAG_NO_RANGE_CHECK (0x00000001)


#pragma region

#define 	GDI_HANDLE_BUFFER_SIZE32   34
#define 	GDI_HANDLE_BUFFER_SIZE64   60
#define 	GDI_HANDLE_BUFFER_SIZE   GDI_HANDLE_BUFFER_SIZE32
typedef ULONG 	GDI_HANDLE_BUFFER[GDI_HANDLE_BUFFER_SIZE];

typedef struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME
{
    _RTL_ACTIVATION_CONTEXT_STACK_FRAME* Previous;
    _ACTIVATION_CONTEXT* ActivationContext;
    ULONG Flags;
} RTL_ACTIVATION_CONTEXT_STACK_FRAME, * PRTL_ACTIVATION_CONTEXT_STACK_FRAME;


typedef struct _ACTIVATION_CONTEXT_STACK
{
    PRTL_ACTIVATION_CONTEXT_STACK_FRAME ActiveFrame;
    LIST_ENTRY FrameListCache;
    ULONG Flags;
    ULONG NextCookieSequenceNumber;
    ULONG StackId;
} ACTIVATION_CONTEXT_STACK, * PACTIVATION_CONTEXT_STACK;

typedef struct _GDI_TEB_BATCH
{
    ULONG Offset;
    ULONG HDC;
    ULONG Buffer[310];
} GDI_TEB_BATCH, * PGDI_TEB_BATCH;

// https://www.nirsoft.net/kernel_struct/
// https://everything.explained.today/Win32_Thread_Information_Block/
// https://www.travismathison.com/posts/PEB_TEB_TIB-Structure-Offsets/
// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FThread%2FTEB.html
// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FThread%2FTHREAD_INFORMATION_CLASS.html
// https://guidedhacking.com/threads/undocumented-windows-functions-structures.14438/
typedef struct _HEAVEN_TEB {

    NT_TIB                  Tib;
    PVOID                   EnvironmentPointer;
    CLIENT_ID               Cid;
    PVOID                   ActiveRpcInfo;
    PVOID                   ThreadLocalStoragePointer;
    PPEB ProcessEnvironmentBlock;

    DWORD LastErrorValue;
    DWORD CountOfOwnedCriticalSections;
    DWORD CsrClientThread;
    DWORD Win32ThreadInfo;
    ULONG                   Win32ClientInfo[0x1F];
    PVOID                   WOW32Reserved;
    ULONG                   CurrentLocale;
    ULONG                   FpSoftwareStatusRegister;

    PVOID ReservedForDebuggerInstrumentation[16];
#ifdef _WIN64
    PVOID SystemReserved1[30];
#else
    PVOID SystemReserved1[26];
#endif
    CHAR PlaceholderCompatibilityMode;
    CHAR PlaceholderReserved[11];
    ULONG ProxiedProcessId;
    ACTIVATION_CONTEXT_STACK ActivationStack;

    UCHAR WorkingOnBehalfTicket[8];
    NTSTATUS ExceptionCode;

    PACTIVATION_CONTEXT_STACK ActivationContextStackPointer;
    ULONG_PTR InstrumentationCallbackSp;
    ULONG_PTR InstrumentationCallbackPreviousPc;
    ULONG_PTR InstrumentationCallbackPreviousSp;
#ifdef _WIN64
    ULONG TxFsContext;
#endif
    BOOLEAN InstrumentationCallbackDisabled;
#ifndef _WIN64
    UCHAR SpareBytes[23];
    ULONG TxFsContext;
#endif
    GDI_TEB_BATCH GdiTebBatch;
    CLIENT_ID RealClientId;
    HANDLE GdiCachedProcessHandle;
    ULONG GdiClientPID;
    ULONG GdiClientTID;
    PVOID GdiThreadLocalInfo;
    ULONG_PTR Win32ClientInfo2[62];
    PVOID glDispatchTable[233];
    ULONG_PTR glReserved1[29];
    PVOID glReserved2;
    PVOID glSectionInfo;
    PVOID glSection;
    PVOID glTable;
    PVOID glCurrentRC;
    PVOID glContext;
    NTSTATUS LastStatusValue;
    UNICODE_STRING StaticUnicodeString;
    WCHAR StaticUnicodeBuffer[261];
    PVOID DeallocationStack;
    PVOID TlsSlots[64];
    _LIST_ENTRY TlsLinks;
    DWORD Vdm;
    DWORD ReservedForNtRpc;
    DWORD DbgSsReserved[2];
    DWORD HardErrorMode;
    DWORD Instrumentation[9];
    GUID ActivityId;
    DWORD SubProcessTag;
    DWORD PerflibData;
    DWORD EtwTraceData;
    DWORD WinSockData;
    DWORD GdiBatchCount;
    DWORD ___u63;
    DWORD GuaranteedStackBytes;
    DWORD ReservedForPerf;
    PVOID ReservedForOle;  // Windows 2000 only
    DWORD WaitingOnLoaderLock;
    DWORD SavedPriorityState;
    DWORD ReservedForCodeCoverage;
    DWORD ThreadPoolData;
    PVOID TlsExpansionSlots;
    DWORD MuiGeneration;
    DWORD IsImpersonating;
    PVOID NlsCache;
    PVOID pShimData;
    PVOID HeapData;
    PVOID CurrentTransactionHandle;
    PVOID ActiveFrame;
    PVOID FlsData;
    PVOID PreferredLanguages;
    PVOID UserPrefLanguages;
    PVOID MergedPrefLanguages;
    PVOID MuiImpersonation;
    DWORD Buf;
    PVOID TxnScopeEnterCallback;
    PVOID TxnScopeExitCallback;
    PVOID TxnScopeContext;
    PVOID LockCount;
    DWORD WowTebOffset;
    PVOID ResourceRetValue;
    PVOID ReservedForWdf;
    PVOID ReservedForCrt;
    _GUID EffectiveContainerId;
} HEAVENTEB, * PHEAVENTEB;


typedef struct _HEAVEN_PEB {
    BOOLEAN                 InheritedAddressSpace;
    BOOLEAN                 ReadImageFileExecOptions;
    BYTE BeingDebugged;
    union
    {
        BOOLEAN BitField;
        struct
        {
            BOOLEAN ImageUsesLargePages : 1;
            BOOLEAN IsProtectedProcess : 1;
            BOOLEAN IsImageDynamicallyRelocated : 1;
            BOOLEAN SkipPatchingUser32Forwarders : 1;
            BOOLEAN IsPackagedProcess : 1;
            BOOLEAN IsAppContainer : 1;
            BOOLEAN IsProtectedProcessLight : 1;
            BOOLEAN IsLongPathAwareProcess : 1;
        } s1;
    } FLAGS;
    HANDLE                  Mutant;
    PVOID                   ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    PVOID                        SubSystemData;
    HANDLE                       ProcessHeap;
    PRTL_CRITICAL_SECTION        FastPebLock;
    PVOID AtlThunkSListPtr;
    PVOID IFEOKey;
    union
    {
        ULONG CrossProcessFlags;
        struct
        {
            ULONG ProcessInJob : 1;
            ULONG ProcessInitializing : 1;
            ULONG ProcessUsingVEH : 1;
            ULONG ProcessUsingVCH : 1;
            ULONG ProcessUsingFTH : 1;
            ULONG ProcessPreviouslyThrottled : 1;
            ULONG ProcessCurrentlyThrottled : 1;
            ULONG ReservedBits0 : 25;
        } s2;
    } PROCESSFLAGS;
    union
    {
        PVOID KernelCallbackTable;
        PVOID UserSharedInfoPtr;
    } KernelData;
    ULONG SystemReserved[1];
    ULONG AtlThunkSListPtr32;
    PVOID ApiSetMap;
    ULONG TlsExpansionCounter;
    PVOID TlsBitmap;
    ULONG TlsBitmapBits[2];
    PVOID ReadOnlySharedMemoryBase;
    PVOID SharedData; // HotpatchInformation
    PVOID* ReadOnlyStaticServerData;
    PVOID AnsiCodePageData; // PCPTABLEINFO
    PVOID OemCodePageData; // PCPTABLEINFO
    PVOID UnicodeCaseTableData; // PNLSTABLEINFO
    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;
    LARGE_INTEGER CriticalSectionTimeout;
    SIZE_T HeapSegmentReserve;
    SIZE_T HeapSegmentCommit;
    SIZE_T HeapDeCommitTotalFreeThreshold;
    SIZE_T HeapDeCommitFreeBlockThreshold;
    ULONG NumberOfHeaps;
    ULONG MaximumNumberOfHeaps;
    PVOID* ProcessHeaps; // PHEAP
    PVOID GdiSharedHandleTable;
    PVOID ProcessStarterHelper;
    ULONG GdiDCAttributeList;
    PRTL_CRITICAL_SECTION LoaderLock;
    ULONG OSMajorVersion;
    ULONG OSMinorVersion;
    USHORT OSBuildNumber;
    USHORT OSCSDVersion;
    ULONG OSPlatformId;
    ULONG ImageSubsystem;
    ULONG ImageSubsystemMajorVersion;
    ULONG ImageSubsystemMinorVersion;
    ULONG_PTR ActiveProcessAffinityMask;
    GDI_HANDLE_BUFFER GdiHandleBuffer;
    PVOID PostProcessInitRoutine;
    PVOID TlsExpansionBitmap;
    ULONG TlsExpansionBitmapBits[32];
    ULONG SessionId;
    ULARGE_INTEGER AppCompatFlags;
    ULARGE_INTEGER AppCompatFlagsUser;
    PVOID pShimData;
    PVOID AppCompatInfo; // APPCOMPAT_EXE_DATA
    _UNICODE_STRING CSDVersion;
    PVOID ActivationContextData; // ACTIVATION_CONTEXT_DATA
    PVOID ProcessAssemblyStorageMap; // ASSEMBLY_STORAGE_MAP
    PVOID SystemDefaultActivationContextData; // ACTIVATION_CONTEXT_DATA
    PVOID SystemAssemblyStorageMap; // ASSEMBLY_STORAGE_MAP
    SIZE_T MinimumStackCommit;
    PVOID* FlsCallback;
    LIST_ENTRY FlsListHead;
    PVOID FlsBitmap;
    ULONG FlsBitmapBits[FLS_MAXIMUM_AVAILABLE / (sizeof(ULONG) * 8)];
    ULONG FlsHighIndex;
    PVOID WerRegistrationData;
    PVOID WerShipAssertPtr;
    PVOID pUnused; // pContextData
    PVOID pImageHeaderHash;
    union
    {
        ULONG TracingFlags;
        struct
        {
            ULONG HeapTracingEnabled : 1;
            ULONG CritSecTracingEnabled : 1;
            ULONG LibLoaderTracingEnabled : 1;
            ULONG SpareTracingBits : 29;
        } s3;
    } TracingInfo;
    ULONGLONG CsrServerReadOnlySharedMemoryBase;
    PVOID TppWorkerpListLock;
    LIST_ENTRY TppWorkerpList;
    PVOID Reserved12[1];
    PVOID TelemetryCoverageHeader;
    ULONG CloudFileFlags;

} HEAVENPEB, * PHEAVENPEB;

__forceinline PHEAVENTEB FetchWindowsTEB()
{
    return reinterpret_cast<PHEAVENTEB>(NtCurrentTeb());
}

__forceinline PHEAVENPEB FetchWindowsPEB()
{
    return reinterpret_cast<PHEAVENPEB>(NtCurrentTeb()->ProcessEnvironmentBlock);
}
#pragma endregion

// TODO : Actually Reverse This and rebuilt Properly!
NTSTATUS __stdcall RtlImageNtHeaderEx(int Flags, unsigned int Base, unsigned int Size, int a4, PIMAGE_NT_HEADERS a5)
{
    PIMAGE_NT_HEADERS pNT = nullptr;
    bool bRangeCheck; // bl
    unsigned int v7; // esi
    unsigned int e_lfanew; // ecx
    int result; // eax
    IMAGE_DOS_HEADER* pDos = nullptr;

    pNT = 0;
    if (!a5)
        return STATUS_INVALID_IMAGE_FORMAT;

    memset(a5, 0, sizeof(IMAGE_NT_HEADERS));

    if ((Flags & (~RTL_IMAGE_NT_HEADER_EX_FLAG_NO_RANGE_CHECK)) != 0 || !Base || Base == -1)
        return STATUS_INVALID_IMAGE_FORMAT;


    if ((Flags & 1) != 0)
    {
        bRangeCheck = 0;
    }
    else
    {
        bRangeCheck = 1;
        if (!a4)
        {
            v7 = Size;
            if (Size < sizeof(IMAGE_SECTION_HEADER))
                return STATUS_INVALID_IMAGE_FORMAT;
            goto LABEL_8;
        }
    }
    v7 = Size;
LABEL_8:
    
    pDos = (PIMAGE_DOS_HEADER)Base;
    if (pDos->e_magic == 0x5A4D) // MZ 
    {
        e_lfanew = pDos->e_lfanew;
        if (!bRangeCheck || (a4 || e_lfanew < v7) && e_lfanew < 0xFFFFFFE7 && (a4 || e_lfanew + 24 < v7))
        {
            if (e_lfanew >= 0x10000000) 
            {
                result = STATUS_INVALID_IMAGE_FORMAT;
                pNT = 0;
            }
            else
            {
                pNT = (PIMAGE_NT_HEADERS)(Base + e_lfanew);
                if ((unsigned int)pNT < Base)
                {
                    result = STATUS_INVALID_IMAGE_FORMAT;
                }
                else if (pNT->Signature == IMAGE_NT_SIGNATURE) // PE 
                {
                    result = S_OK; 
                } 
                else
                {
                    result = STATUS_INVALID_IMAGE_FORMAT;
                }
            }
        }
        else
        {
            result = STATUS_INVALID_IMAGE_FORMAT;
            pNT = 0;
        }
    }
    else
    {
        result = STATUS_INVALID_IMAGE_FORMAT;
    }
    if (result >= 0)
        *a5 = *pNT;
    return result; 

}

PIMAGE_SECTION_HEADER RtlSectionTableFromVirtualAddress(IN PIMAGE_NT_HEADERS NtHeaders, IN PVOID Base, IN ULONG Address)
{
    ULONG i;
    PIMAGE_SECTION_HEADER NtSection;
    NtSection = IMAGE_FIRST_SECTION(NtHeaders);
    for (i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++) {
        if ((ULONG)Address >= NtSection->VirtualAddress &&
            (ULONG)Address < NtSection->VirtualAddress + NtSection->SizeOfRawData
            ) {
            return NtSection;
        }
        ++NtSection;
    }

    return NULL;
}

PVOID RtlAddressInSectionTable(_In_ PIMAGE_NT_HEADERS NtHeaders, _In_ PVOID Base, _In_ ULONG Address)
{
    PIMAGE_SECTION_HEADER NtSection;

    NtSection = RtlSectionTableFromVirtualAddress(NtHeaders, Base, Address);
    if (NtSection != NULL) {
        return(((PCHAR)Base + ((ULONG_PTR)Address - NtSection->VirtualAddress) + NtSection->PointerToRawData));
    }
    else {
        return(NULL);
    }
}

int MTCALL RtlpImageDirectoryEntryToDataEx(
    unsigned int ImageBase_1,
    char bMappedAsImage,
    unsigned __int16 DirectoryEntry,
    DWORD* Size,
    PVOID* ppData)
{
    unsigned int ImageBase; // ebx
    int result; // eax
    IMAGE_NT_HEADERS ntHeader;
    _IMAGE_NT_HEADERS* pNTHeader; // edx
    unsigned __int16 OptionalHeader; // ax
    unsigned int DirectoryAddress; // edi
    bool bNotMappedAsImage; // zf
    PVOID pData; // eax
    bool MappedAsImage; // [esp+Fh] [ebp-1h]
    ImageBase = ImageBase_1;
    MappedAsImage = bMappedAsImage;
    pNTHeader = &ntHeader;


    *ppData = 0;
    if ((ImageBase_1 & 3) != 0)
    {
        if ((ImageBase_1 & 1) != 0)
            MappedAsImage = 0;
        ImageBase = ImageBase_1 & 0xFFFFFFFC;
    }
    result = RtlImageNtHeaderEx(1, ImageBase, 0, 0, pNTHeader);

    if (!pNTHeader)
        return result;

    OptionalHeader = pNTHeader->OptionalHeader.Magic;

    if (OptionalHeader != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        if (OptionalHeader == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            throw std::exception("No 64 Bit Support For RtlpImageDirectoryEntryToDataEx");
            //return RtlpImageDirectoryEntryToData64(ImageBase, MappedAsImage, DirectoryEntry, Size, (int)pNTHeader, pOptHeader);

        return STATUS_INVALID_PARAMETER;                          // STATUS_INVALID_PARAMETER
    }

    if (DirectoryEntry >= pNTHeader->OptionalHeader.NumberOfRvaAndSizes)
        return STATUS_INVALID_PARAMETER;


    DirectoryAddress = pNTHeader->OptionalHeader.DataDirectory[DirectoryEntry].VirtualAddress;

    if (!DirectoryAddress)
        return 0xC0000002; // STATUS_CORRUPTED_IMAGE


    bNotMappedAsImage = MappedAsImage == 0;
    *Size = pNTHeader->OptionalHeader.DataDirectory[DirectoryEntry].Size;
    if (bNotMappedAsImage && DirectoryAddress >= pNTHeader->OptionalHeader.SizeOfHeaders)
    {
        pData = RtlAddressInSectionTable(pNTHeader, (PVOID)ImageBase, DirectoryAddress);
        *ppData = pData;
        if (pData)
            return S_OK;                                 // S_OK
        return STATUS_INVALID_PARAMETER;
    }
    *ppData = (PVOID)(DirectoryAddress + ImageBase);
    return 0;
}



// This isn't Really "Correct" as windows version does a lot different, but this works
// fine for our application
void* MTCALL WinRebuilt::RtlImageNtHeader(_In_ void* Base)
{
    IMAGE_DOS_HEADER* pDos = reinterpret_cast<PIMAGE_DOS_HEADER>(Base);
    return (void*)PIMAGE_NT_HEADERS(pDos->e_lfanew + (char*)Base);
}


PVOID MTCALL LdrImageDirectoryEntryToLoadConfig(void* pBase)
{
    IMAGE_NT_HEADERS Headers;

    NTSTATUS ntstat = RtlImageNtHeaderEx(1, (unsigned int)pBase, 0, 0, &Headers);
    PVOID pData;
    DWORD dwSize;
    if (pBase || (ntstat != S_OK))
        return 0;

    NTSTATUS Ret = RtlpImageDirectoryEntryToDataEx((unsigned int)pBase, 1, 0xA, &dwSize, &pData);

    if (Ret != S_OK)
        return nullptr;

    if (!pData || !dwSize || (dwSize != 0x40) && (dwSize != *(DWORD*)pData))
        return nullptr;

    DWORD dwMachine = Headers.FileHeader.Machine;
    if (dwMachine == 0x3A64)
        dwMachine = IMAGE_FILE_MACHINE_I386;

    if (dwMachine == IMAGE_FILE_MACHINE_I386)
        return pData;

    return nullptr;
}
void MTCALL WinRebuilt::RtlCaptureImageExceptionValues(
    _In_  void* pBase,
    _Outptr_ void** FunctionTable,
    _Outptr_ unsigned long* TableSize
)
{
#ifndef _WIN64
    PIMAGE_NT_HEADERS pNT;
    PIMAGE_LOAD_CONFIG_DIRECTORY32 pLoadConfig;
    ULONG LoadConfigSize;


    pNT = (PIMAGE_NT_HEADERS)RtlImageNtHeader(pBase);
    if (pNT->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH) {
        *FunctionTable = (void*)-1;
        *TableSize = -1;
        return;
    }

    pLoadConfig = (PIMAGE_LOAD_CONFIG_DIRECTORY)LdrImageDirectoryEntryToLoadConfig(pBase);

    if (!pLoadConfig || pLoadConfig->Size < 0x48 || !pLoadConfig->SEHandlerTable || !pLoadConfig->SEHandlerCount)
    {
        PVOID pEntryData;
        DWORD dwOutSize;
        RtlpImageDirectoryEntryToDataEx((unsigned int)pBase, 1, 14, &dwOutSize, &pEntryData);
        if (!pEntryData || ((*(BYTE*)((char*)pEntryData + 16) & 1) == 0))
        {
            *TableSize = -1;
            *FunctionTable = (void*)-1;
            return;
        }
    }

    *FunctionTable = (void*)pLoadConfig->SEHandlerTable;
    *TableSize = pLoadConfig->SEHandlerCount;


    if (*FunctionTable < (char*)pBase + pNT->OptionalHeader.SizeOfHeaders || (int)TableSize > ((char*)pBase + pNT->OptionalHeader.SizeOfImage - *FunctionTable) >> 2)
    {
        *TableSize = -1;
        *FunctionTable = (void*)-1;
    }
#else
    *TableSize = -1;
    *FunctionTable = (void*)-1;
#endif
    return;
}

int __fastcall RtlInsertInvertedFunctionTable(void* pBase, int a2)
{
    int v3; // esi
    unsigned long TableSize; // [esp+10h] [ebp-8h] BYREF
    void* pFunctionTable; // [esp+14h] [ebp-4h] BYREF

    // Get Exception Info 
    //WinRebuilt::RtlCaptureImageExceptionValues(pBase, &pFunctionTable, &TableSize);

    // ?????
    // what is the significance of this memory address?
    //v3 = __ROR4__(pFunctionTable ^ MEMORY[0x7FFE0330], MEMORY[0x7FFE0330] & 0x1F);

    // Get Table Lock
    //RtlAcquireSRWLockExclusive(&LdrpInvertedFunctionTableSRWLock);

    // Change Memory Protection To Allow Write
    //LdrProtectMrdata(0);


   // RtlpInsertInvertedFunctionTableEntry(v3, a2, TableSize);

    //Change Memory Protection
    //LdrProtectMrdata(1);


    // Release Lock
    //return RtlReleaseSRWLockExclusive(&LdrpInvertedFunctionTableSRWLock);
    return 0;
}

bool WINAPI RtlWow64EnableFsRedirectionEx(_In_ BOOL bNewValue, _Outptr_ BOOL* bPreviousValueReturn)
{
    struct _HEAVEN_TEB* TEB; // eax
    char* pWowTEB = nullptr;
    DWORD WowTebOffset; // ecx
    void* defaultSlot; // eax
    char* TEB_1; // eax
    int WowTebOffset_1; // ecx
    BOOL bOldValue; // [esp+14h] [ebp-1Ch]

    TEB = (_HEAVEN_TEB*)NtCurrentTeb();
    WowTebOffset = TEB->WowTebOffset;
    if (WowTebOffset < 0)
        pWowTEB = ((char*)TEB + WowTebOffset);
    if (pWowTEB == (char*)TEB->Tib.Self)
        defaultSlot = *(void**)(TEB + 3632);
    else
        defaultSlot = *(void**)(TEB + 5312);
    bOldValue = (bool)defaultSlot;
    TEB_1 = (char*)NtCurrentTeb();
    WowTebOffset_1 = ((HEAVENTEB*)TEB_1)->WowTebOffset;
    if (WowTebOffset_1 < 0)
        TEB_1 = ((char*)TEB_1 + WowTebOffset_1);
    if (TEB_1 == (char*)((HEAVENTEB*)TEB_1)->Tib.Self)
    {
        *(DWORD*)(TEB_1 + 3632) = bNewValue;
    }
    else
    {
        *(DWORD*)(TEB_1 + 5312) = bNewValue;
        *(DWORD*)(TEB_1 + 5316) = 0;
    }
    *bPreviousValueReturn = bOldValue;
    return 0;
}