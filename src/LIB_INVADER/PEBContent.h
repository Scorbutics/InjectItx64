#ifndef PEBCONTENT_H
#define PEBCONTENT_H

#include "AnsiString.h"
#include "ProcessModule.h"


struct CurdirContent
{
     ANSI_STRING DosPath;
     void* Handle;
};
typedef struct CurdirContent CurdirContent;

struct RtlDriveLetterCurdirContent
{
     unsigned short Flags;
     unsigned short Length;
     unsigned long TimeStamp;
     ANSI_STRING DosPath;
};
typedef struct RtlDriveLetterCurdirContent RtlDriveLetterCurdirContent;

struct RtlUserProcessParametersContent
{
    unsigned long MaximumLength ;
    unsigned long Length ;
    unsigned long Flags ;
    unsigned long DebugFlags ;
    void* ConsoleHandle ;
    unsigned long ConsoleFlags ;
    void* StandardInput ;
    void* StandardOutput ;
    void* StandardError ;
    CurdirContent CurrentDirectory ;
    ANSI_STRING DllPath ;
    ANSI_STRING ImagePathName ;
    ANSI_STRING CommandLine ;
    void* Environment ;
    unsigned long StartingX ;
    unsigned long StartingY ;
    unsigned long CountX ;
    unsigned long CountY ;
    unsigned long CountCharsX ;
    unsigned long CountCharsY ;
    unsigned long FillAttribute ;
    unsigned long WindowFlags ;
    unsigned long ShowWindowFlags ;
    ANSI_STRING WindowTitle ;
    ANSI_STRING DesktopInfo ;
    ANSI_STRING ShellInfo ;
    ANSI_STRING RuntimeData ;
    RtlDriveLetterCurdirContent CurrentDirectories [32];
    unsigned long long EnvironmentSize ;
    unsigned long long EnvironmentVersion ;
    void* PackageDependencyData ;
    unsigned long ProcessGroupId ;

};
typedef struct RtlUserProcessParametersContent RtlUserProcessParametersContent;

struct PEBLdrDataContent
{
    unsigned long Length ;
    char Initialized ;
    HANDLE SsHandle ;
    LIST_ENTRY InLoadOrderModuleList ;
    LIST_ENTRY InMemoryOrderModuleList ;
    LIST_ENTRY InInitializationOrderModuleList ;
    void* EntryInProgress ;
    char ShutdownInProgress ;
    HANDLE ShutdownThreadId ;

    //Added
    ProcessModule* moduleList;

};
typedef struct PEBLdrDataContent PEBLdrDataContent;


struct PEBContent {

    char InheritedAddressSpace ;
    char ReadImageFileExecOptions ;
    char BeingDebugged ;

    union
    {
        char BitField ;
        struct
        {

            char ImageUsesLargePages :1;
            char IsProtectedProcess :1;
            char IsImageDynamicallyRelocated :1;
            char SkipPatchingUser32Forwarders :1;
            char IsPackagedProcess :1;
            char IsAppContainer :1;
            char IsProtectedProcessLight :1;
            char SpareBits :1;
        };
    };

    void* Mutant ;
    void* ImageBaseAddress ;
    PEBLdrDataContent* /* Ptr64 _PEB_LDR_DATA */ Ldr ;
    RtlUserProcessParametersContent* /* Ptr64 _RTL_USER_PROCESS_PARAMETERS */ ProcessParameters ;
    void* SubSystemData ;
    void* ProcessHeap ;
    void* /* Ptr64 _RTL_CRITICAL_SECTION */ FastPebLock ;
    void* AtlThunkSListPtr ;
    void* IFEOKey ;

    union
    {
        unsigned long CrossProcessFlags ;
        struct
        {
            unsigned long ProcessInJob :1;
            unsigned long ProcessInitializing :1;
            unsigned long ProcessUsingVEH :1;
            unsigned long ProcessUsingVCH :1;
            unsigned long ProcessUsingFTH :1;
            unsigned long ReservedBits0 :27;
        };
    };

    union
    {
        void* KernelCallbackTable ;
        void* UserSharedInfoPtr ;
    };

    unsigned long SystemReserved [1];
    unsigned long AtlThunkSListPtr32 ;
    void* ApiSetMap ;
    unsigned long TlsExpansionCounter ;
    void* TlsBitmap ;
    unsigned long TlsBitmapBits [2];
    void* ReadOnlySharedMemoryBase ;
    void* SparePvoid0 ;
    void** ReadOnlyStaticServerData ;
    void* AnsiCodePageData ;
    void* OemCodePageData ;
    void* UnicodeCaseTableData ;
    unsigned long NumberOfProcessors ;
    unsigned long NtGlobalFlag ;
    unsigned long long CriticalSectionTimeout ;
    unsigned long long HeapSegmentReserve ;
    unsigned long long HeapSegmentCommit ;
    unsigned long long HeapDeCommitTotalFreeThreshold ;
    unsigned long long HeapDeCommitFreeBlockThreshold ;
    unsigned long NumberOfHeaps ;
    unsigned long MaximumNumberOfHeaps ;
    void** ProcessHeaps ;
    void* GdiSharedHandleTable ;
    void* ProcessStarterHelper ;
    unsigned long GdiDCAttributeList ;
    void* LoaderLock ;
    unsigned long OSMajorVersion ;
    unsigned long OSMinorVersion ;
    unsigned short OSBuildNumber ;
    unsigned short OSCSDVersion ;
    unsigned long OSPlatformId ;
    unsigned long ImageSubsystem ;
    unsigned long ImageSubsystemMajorVersion ;
    unsigned long ImageSubsystemMinorVersion ;
    unsigned long long ActiveProcessAffinityMask ;
    unsigned long GdiHandleBuffer [60];
    void*  PostProcessInitRoutine ;
    void* TlsExpansionBitmap ;
    unsigned long TlsExpansionBitmapBits [32];
    unsigned long SessionId ;
    unsigned long long AppCompatFlags ;
    unsigned long long AppCompatFlagsUser ;
    void* pShimData ;
    void* AppCompatInfo ;
    ANSI_STRING CSDVersion ;
    void* ActivationContextData ;
    void* ProcessAssemblyStorageMap ;
    void* SystemDefaultActivationContextData ;
    void* SystemAssemblyStorageMap ;
    unsigned long long MinimumStackCommit ;
    void* FlsCallback ;
    LIST_ENTRY FlsListHead ;
    void* FlsBitmap ;
    unsigned long FlsBitmapBits [4];
    unsigned long FlsHighIndex ;
    void* WerRegistrationData ;
    void* WerShipAssertPtr ;
    void* pUnused ;
    void* pImageHeaderHash ;
    union
    {
        unsigned long TracingFlags ;
        struct
        {
            unsigned long HeapTracingEnabled :1;
            unsigned long CritSecTracingEnabled :1;
            unsigned long LibLoaderTracingEnabled :1;
            unsigned long SpareTracingBits :29;
        };
     };

    unsigned long long CsrServerReadOnlySharedMemoryBase ;

};
typedef struct PEBContent PEBContent;


PEBContent* CreatePEBContent();
void DisplayPEBContent(PEBContent* peb);
void DisplayModuleListHashTableListMethod(unsigned long pid);
void FreePEBContent(PEBContent* peb);

#endif // PEBCONTENT_H
