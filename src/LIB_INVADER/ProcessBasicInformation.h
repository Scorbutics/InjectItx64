#ifndef PROCESSBASICINFORMATION_H
#define PROCESSBASICINFORMATION_H

#include "_RTL_BALANCED_NODE.h"
#include "_LDR_DLL_LOAD_REASON.h"
#include "_PEB_LDR_DATA.h"

#include "PPVOID.h"
#include "UnicodeString.h"

#define FLS_MAXIMUM_AVAILABLE   128

// 32-bit definitions
//#define WOW64_POINTER(Type) ULONG








//module name : ntdll
struct _LDR_DATA_TABLE_ENTRY
{	/* +0x000 */ 	LIST_ENTRY InLoadOrderLinks ;
    /* +0x010 */ 	LIST_ENTRY InMemoryOrderLinks ;
    union
    {
        /* +0x020 */ 	LIST_ENTRY InInitializationOrderLinks ;
        /* +0x020 */ 	LIST_ENTRY InProgressLinks ;
    };
    /* +0x030 */ 	PVOID /* Ptr64 Void */ DllBase ;
    /* +0x038 */ 	PVOID /* Ptr64 Void */ EntryPoint ;
    /* +0x040 */ 	ULONG SizeOfImage ;
    /* +0x048 */ 	UNICODE_STRING FullDllName ;
    /* +0x058 */ 	UNICODE_STRING BaseDllName ;

    union
    {
        /* +0x068 */ 	BYTE FlagGroup [4];
        /* +0x068 */ 	ULONG Flags ;
        struct
        {
            /* +0x068 */ 	ULONG PackagedBinary :1;
            /* +0x068 */ 	ULONG MarkedForRemoval :1;
            /* +0x068 */ 	ULONG ImageDll :1;
            /* +0x068 */ 	ULONG LoadNotificationsSent :1;
            /* +0x068 */ 	ULONG TelemetryEntryProcessed :1;
            /* +0x068 */ 	ULONG ProcessStaticImport :1;
            /* +0x068 */ 	ULONG InLegacyLists :1;
            /* +0x068 */ 	ULONG InIndexes :1;
            /* +0x068 */ 	ULONG ShimDll :1;
            /* +0x068 */ 	ULONG InExceptionTable :1;
            /* +0x068 */ 	ULONG ReservedFlags1 :2;
            /* +0x068 */ 	ULONG LoadInProgress :1;
            /* +0x068 */ 	ULONG ReservedFlags2 :1;
            /* +0x068 */ 	ULONG EntryProcessed :1;
            /* +0x068 */ 	ULONG ReservedFlags3 :3;
            /* +0x068 */ 	ULONG DontCallForThreads :1;
            /* +0x068 */ 	ULONG ProcessAttachCalled :1;
            /* +0x068 */ 	ULONG ProcessAttachFailed :1;
            /* +0x068 */ 	ULONG CorDeferredValidate :1;
            /* +0x068 */ 	ULONG CorImage :1;
            /* +0x068 */ 	ULONG DontRelocate :1;
            /* +0x068 */ 	ULONG CorILOnly :1;
            /* +0x068 */ 	ULONG ReservedFlags5 :3;
            /* +0x068 */ 	ULONG Redirected :1;
            /* +0x068 */ 	ULONG ReservedFlags6 :2;
            /* +0x068 */ 	ULONG CompatDatabaseProcessed :1;
        };
    };

    /* +0x06c */ 	USHORT ObsoleteLoadCount ;
    /* +0x06e */ 	USHORT TlsIndex ;
    /* +0x070 */ 	LIST_ENTRY HashLinks ;
    /* +0x080 */ 	ULONG TimeDateStamp ;
    /* +0x088 */ 	PVOID /* Ptr64 _ACTIVATION_CONTEXT */ EntryPointActivationContext ;
    /* +0x090 */ 	PVOID /* Ptr64 Void */ Spare ;
    /* +0x098 */ 	PVOID /* Ptr64 _LDR_DDAG_NODE */ DdagNode ;
    /* +0x0a0 */ 	LIST_ENTRY NodeModuleLink ;
    /* +0x0b0 */ 	PVOID /* Ptr64 _LDRP_DLL_SNAP_CONTEXT */ SnapContext ;
    /* +0x0b8 */ 	PVOID /* Ptr64 Void */ ParentDllBase ;
    /* +0x0c0 */ 	PVOID /* Ptr64 Void */ SwitchBackContext ;
    /* +0x0c8 */ 	RTL_BALANCED_NODE BaseAddressIndexNode ;
    /* +0x0e0 */ 	RTL_BALANCED_NODE MappingInfoIndexNode ;
    /* +0x0f8 */ 	ULONGLONG OriginalBase ;
    /* +0x100 */ 	LARGE_INTEGER LoadTime ;
    /* +0x108 */ 	ULONG BaseNameHashValue ;
    /* +0x10c */ 	LDR_DLL_LOAD_REASON LoadReason ;
    /* +0x110 */ 	ULONG ImplicitPathOptions ;

};
typedef struct _LDR_DATA_TABLE_ENTRY LDR_DATA_TABLE_ENTRY;

typedef struct _STRING
{
     USHORT Length;
     USHORT MaximumLength;
     CHAR * Buffer;
} STRING, *PSTRING;

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
     USHORT Flags;
     USHORT Length;
     ULONG TimeStamp;
     STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;


typedef struct _CURDIR
{
     UNICODE_STRING DosPath;
     PVOID Handle;
} CURDIR, *PCURDIR;


#define RTL_MAX_DRIVE_LETTERS 32

//module name : ntdll
struct _RTL_USER_PROCESS_PARAMETERS
{	/* +0x000 */ 	ULONG MaximumLength ;
    /* +0x004 */ 	ULONG Length ;
    /* +0x008 */ 	ULONG Flags ;
    /* +0x00c */ 	ULONG DebugFlags ;
    /* +0x010 */ 	PVOID /* Ptr64 Void */ ConsoleHandle ;
    /* +0x018 */ 	ULONG ConsoleFlags ;
    /* +0x020 */ 	PVOID /* Ptr64 Void */ StandardInput ;
    /* +0x028 */ 	PVOID /* Ptr64 Void */ StandardOutput ;
    /* +0x030 */ 	PVOID /* Ptr64 Void */ StandardError ;
    /* +0x038 */ 	CURDIR CurrentDirectory ;
    /* +0x050 */ 	UNICODE_STRING DllPath ;
    /* +0x060 */ 	UNICODE_STRING ImagePathName ;
    /* +0x070 */ 	UNICODE_STRING CommandLine ;
    /* +0x080 */ 	PVOID /* Ptr64 Void */ Environment ;
    /* +0x088 */ 	ULONG StartingX ;
    /* +0x08c */ 	ULONG StartingY ;
    /* +0x090 */ 	ULONG CountX ;
    /* +0x094 */ 	ULONG CountY ;
    /* +0x098 */ 	ULONG CountCharsX ;
    /* +0x09c */ 	ULONG CountCharsY ;
    /* +0x0a0 */ 	ULONG FillAttribute ;
    /* +0x0a4 */ 	ULONG WindowFlags ;
    /* +0x0a8 */ 	ULONG ShowWindowFlags ;
    /* +0x0b0 */ 	UNICODE_STRING WindowTitle ;
    /* +0x0c0 */ 	UNICODE_STRING DesktopInfo ;
    /* +0x0d0 */ 	UNICODE_STRING ShellInfo ;
    /* +0x0e0 */ 	UNICODE_STRING RuntimeData ;
    /* +0x0f0 */ 	RTL_DRIVE_LETTER_CURDIR CurrentDirectories [32];
    /* +0x3f0 */ 	ULONGLONG EnvironmentSize ;
    /* +0x3f8 */ 	ULONGLONG EnvironmentVersion ;
    /* +0x400 */ 	PVOID /* Ptr64 Void */ PackageDependencyData ;
    /* +0x408 */ 	ULONG ProcessGroupId ;

};
typedef struct _RTL_USER_PROCESS_PARAMETERS RTL_USER_PROCESS_PARAMETERS;
typedef struct _RTL_USER_PROCESS_PARAMETERS *PRTL_USER_PROCESS_PARAMETERS;


//module name : ntdll
struct _PEB_32
{	/* +0x000 */ 	BYTE InheritedAddressSpace ;
    /* +0x001 */ 	BYTE ReadImageFileExecOptions ;
    /* +0x002 */ 	BYTE BeingDebugged ;
    union
    {
    /* +0x003 */ 	BYTE BitField ;
    struct
    {
    /* +0x003 */ 	BYTE ImageUsesLargePages :1;
    /* +0x003 */ 	BYTE IsProtectedProcess :1;
    /* +0x003 */ 	BYTE IsImageDynamicallyRelocated :1;
    /* +0x003 */ 	BYTE SkipPatchingUser32Forwarders :1;
    /* +0x003 */ 	BYTE IsPackagedProcess :1;
    /* +0x003 */ 	BYTE IsAppContainer :1;
    /* +0x003 */ 	BYTE IsProtectedProcessLight :1;
    /* +0x003 */ 	BYTE SpareBits :1;
    };
    };

    /* +0x004 */ 	BYTE Padding0 [4];
    /* +0x008 */ 	PVOID /* Ptr64 Void */ Mutant ;
    /* +0x010 */ 	PVOID /* Ptr64 Void */ ImageBaseAddress ;
    /* +0x018 */ 	PPEB_LDR_DATA /* Ptr64 _PEB_LDR_DATA */ Ldr ;
    /* +0x020 */ 	PRTL_USER_PROCESS_PARAMETERS /* Ptr64 _RTL_USER_PROCESS_PARAMETERS */ ProcessParameters ;
    /* +0x028 */ 	PVOID /* Ptr64 Void */ SubSystemData ;
    /* +0x030 */ 	PVOID /* Ptr64 Void */ ProcessHeap ;
    /* +0x038 */ 	PRTL_CRITICAL_SECTION /* Ptr64 _RTL_CRITICAL_SECTION */ FastPebLock ;
    /* +0x040 */ 	PVOID /* Ptr64 Void */ AtlThunkSListPtr ;
    /* +0x048 */ 	PVOID /* Ptr64 Void */ IFEOKey ;
    union
    {
    /* +0x050 */ 	ULONG CrossProcessFlags ;
    struct
    {
    /* +0x050 */ 	ULONG ProcessInJob :1;
    /* +0x050 */ 	ULONG ProcessInitializing :1;
    /* +0x050 */ 	ULONG ProcessUsingVEH :1;
    /* +0x050 */ 	ULONG ProcessUsingVCH :1;
    /* +0x050 */ 	ULONG ProcessUsingFTH :1;
    /* +0x050 */ 	ULONG ReservedBits0 :27;
    };
    };

    /* +0x054 */ 	BYTE Padding1 [4];
    union
    {
    /* +0x058 */ 	PVOID /* Ptr64 Void */ KernelCallbackTable ;
    /* +0x058 */ 	PVOID /* Ptr64 Void */ UserSharedInfoPtr ;
    };
    /* +0x060 */ 	ULONG SystemReserved [1];
    /* +0x064 */ 	ULONG AtlThunkSListPtr32 ;
    /* +0x068 */ 	PVOID /* Ptr64 Void */ ApiSetMap ;
    /* +0x070 */ 	ULONG TlsExpansionCounter ;
    /* +0x074 */ 	BYTE Padding2 [4];
    /* +0x078 */ 	PVOID /* Ptr64 Void */ TlsBitmap ;
    /* +0x080 */ 	ULONG TlsBitmapBits [2];
    /* +0x088 */ 	PVOID /* Ptr64 Void */ ReadOnlySharedMemoryBase ;
    /* +0x090 */ 	PVOID /* Ptr64 Void */ SparePvoid0 ;
    /* +0x098 */ 	PPVOID /* Ptr64 Ptr64 Void */ ReadOnlyStaticServerData ;
    /* +0x0a0 */ 	PVOID /* Ptr64 Void */ AnsiCodePageData ;
    /* +0x0a8 */ 	PVOID /* Ptr64 Void */ OemCodePageData ;
    /* +0x0b0 */ 	PVOID /* Ptr64 Void */ UnicodeCaseTableData ;
    /* +0x0b8 */ 	ULONG NumberOfProcessors ;
    /* +0x0bc */ 	ULONG NtGlobalFlag ;
    /* +0x0c0 */ 	LARGE_INTEGER CriticalSectionTimeout ;
    /* +0x0c8 */ 	ULONGLONG HeapSegmentReserve ;
    /* +0x0d0 */ 	ULONGLONG HeapSegmentCommit ;
    /* +0x0d8 */ 	ULONGLONG HeapDeCommitTotalFreeThreshold ;
    /* +0x0e0 */ 	ULONGLONG HeapDeCommitFreeBlockThreshold ;
    /* +0x0e8 */ 	ULONG NumberOfHeaps ;
    /* +0x0ec */ 	ULONG MaximumNumberOfHeaps ;
    /* +0x0f0 */ 	PPVOID /* Ptr64 Ptr64 Void */ ProcessHeaps ;
    /* +0x0f8 */ 	PVOID /* Ptr64 Void */ GdiSharedHandleTable ;
    /* +0x100 */ 	PVOID /* Ptr64 Void */ ProcessStarterHelper ;
    /* +0x108 */ 	ULONG GdiDCAttributeList ;
    /* +0x10c */ 	BYTE Padding3 [4];
    /* +0x110 */ 	PRTL_CRITICAL_SECTION /* Ptr64 _RTL_CRITICAL_SECTION */ LoaderLock ;
    /* +0x118 */ 	ULONG OSMajorVersion ;
    /* +0x11c */ 	ULONG OSMinorVersion ;
    /* +0x120 */ 	USHORT OSBuildNumber ;
    /* +0x122 */ 	USHORT OSCSDVersion ;
    /* +0x124 */ 	ULONG OSPlatformId ;
    /* +0x128 */ 	ULONG ImageSubsystem ;
    /* +0x12c */ 	ULONG ImageSubsystemMajorVersion ;
    /* +0x130 */ 	ULONG ImageSubsystemMinorVersion ;
    /* +0x134 */ 	BYTE Padding4 [4];
    /* +0x138 */ 	ULONGLONG ActiveProcessAffinityMask ;
    /* +0x140 */ 	ULONG GdiHandleBuffer [60];
    /* +0x230 */ 	PVOID  /* Ptr64     void  */ PostProcessInitRoutine ;
    /* +0x238 */ 	PVOID /* Ptr64 Void */ TlsExpansionBitmap ;
    /* +0x240 */ 	ULONG TlsExpansionBitmapBits [32];
    /* +0x2c0 */ 	ULONG SessionId ;
    /* +0x2c4 */ 	BYTE Padding5 [4];
    /* +0x2c8 */ 	ULARGE_INTEGER AppCompatFlags ;
    /* +0x2d0 */ 	ULARGE_INTEGER AppCompatFlagsUser ;
    /* +0x2d8 */ 	PVOID /* Ptr64 Void */ pShimData ;
    /* +0x2e0 */ 	PVOID /* Ptr64 Void */ AppCompatInfo ;
    /* +0x2e8 */ 	UNICODE_STRING CSDVersion ;
    /* +0x2f8 */ 	PVOID /* Ptr64 _ACTIVATION_CONTEXT_DATA */ ActivationContextData ;
    /* +0x300 */ 	PVOID/* Ptr64 _ASSEMBLY_STORAGE_MAP */ ProcessAssemblyStorageMap ;
    /* +0x308 */ 	PVOID/* Ptr64 _ACTIVATION_CONTEXT_DATA */ SystemDefaultActivationContextData ;
    /* +0x310 */ 	PVOID/* Ptr64 _ASSEMBLY_STORAGE_MAP */ SystemAssemblyStorageMap ;
    /* +0x318 */ 	ULONGLONG MinimumStackCommit ;
    /* +0x320 */ 	PVOID/* Ptr64 _FLS_CALLBACK_INFO */ FlsCallback ;
    /* +0x328 */ 	LIST_ENTRY FlsListHead ;
    /* +0x338 */ 	PVOID /* Ptr64 Void */ FlsBitmap ;
    /* +0x340 */ 	ULONG FlsBitmapBits [4];
    /* +0x350 */ 	ULONG FlsHighIndex ;
    /* +0x358 */ 	PVOID /* Ptr64 Void */ WerRegistrationData ;
    /* +0x360 */ 	PVOID /* Ptr64 Void */ WerShipAssertPtr ;
    /* +0x368 */ 	PVOID /* Ptr64 Void */ pUnused ;
    /* +0x370 */ 	PVOID /* Ptr64 Void */ pImageHeaderHash ;
    union
    {
    /* +0x378 */ 	ULONG TracingFlags ;
    struct
    {
    /* +0x378 */ 	ULONG HeapTracingEnabled :1;
    /* +0x378 */ 	ULONG CritSecTracingEnabled :1;
    /* +0x378 */ 	ULONG LibLoaderTracingEnabled :1;
    /* +0x378 */ 	ULONG SpareTracingBits :29;
    };
    };

    /* +0x37c */ 	BYTE Padding6 [4];
    /* +0x380 */ 	ULONGLONG CsrServerReadOnlySharedMemoryBase ;

};
typedef struct _PEB_32 PEB;
typedef PEB *PPEB;

typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID ExitStatus;
    PPEB PebBaseAddress;
    PVOID AffinityMask;
    PVOID BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;

#endif // PROCESSBASICINFORMATION_H
