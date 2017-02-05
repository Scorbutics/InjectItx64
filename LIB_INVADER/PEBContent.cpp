#include <windows.h>
#include <stdlib.h>
#include <stdio.h>

#include "AnsiString.h"
#include "ProcessBasicInformation.h"
#include "PEBContent.h"
#include "ProcessInformation.h"
#include "GetProcessInformation.h"
#include "ErrorUtils.h"
#include "ProcessModule.h"

#define LDRP_HASH_TABLE_SIZE 32
#define LDRP_HASH_MASK       (LDRP_HASH_TABLE_SIZE-1)
#define LDRP_COMPUTE_HASH_INDEX(wch) ( (RtlUpcaseUnicodeChar((wch)) - (WCHAR)'A') & LDRP_HASH_MASK )

void ZeroRtlUserProcessParametersContent(RtlUserProcessParametersContent* rtl)
{
    memset(rtl, 0, sizeof(RtlUserProcessParametersContent));
}

RtlUserProcessParametersContent* CreateRtlUserProcessParametersContent()
{
    RtlUserProcessParametersContent* result = (RtlUserProcessParametersContent*) malloc(sizeof(RtlUserProcessParametersContent));
    ZeroRtlUserProcessParametersContent(result);
    return result;
}


void FreeRtlUserProcessParametersContent(RtlUserProcessParametersContent* rtl)
{
    unsigned int i;

    //ANSI_STRINGs
    free(rtl->CommandLine.Buffer);
    free(rtl->WindowTitle.Buffer);
    free(rtl->DllPath.Buffer);
    free(rtl->DesktopInfo.Buffer);
    free(rtl->ImagePathName.Buffer);
    free(rtl->RuntimeData.Buffer);
    free(rtl->ShellInfo.Buffer);

    //Pointers
//    free(rtl->ConsoleHandle);
    free(rtl->Environment);

    for(i = 0; i < 32; i++)
        free(rtl->CurrentDirectories[i].DosPath.Buffer);

    free(rtl->CurrentDirectory.DosPath.Buffer);
//    free(rtl->PackageDependencyData);
//    free(rtl->StandardError);
//    free(rtl->StandardInput);
    free(rtl);
}

void ZeroPEBLdrDataContent(PEBLdrDataContent* ldr)
{
    memset(ldr, 0, sizeof(PEBLdrDataContent));
}


PEBLdrDataContent* CreatePEBLdrDataContent()
{
    PEBLdrDataContent* result = (PEBLdrDataContent*) malloc(sizeof(PEBLdrDataContent));
    ZeroPEBLdrDataContent(result);
    return result;
}

void FreePEBLdrDataContent(PEBLdrDataContent* ldr)
{
    free(ldr->EntryInProgress);
    FreeProcessModuleList(ldr->moduleList);
    free(ldr);
}

void ZeroPEBContent(PEBContent* peb)
{
    memset(peb, 0, sizeof(PEBContent));
}

PEBContent* CreatePEBContent()
{
    PEBContent* result = (PEBContent*) malloc(sizeof(PEBContent));
    ZeroPEBContent(result);

    result->Ldr = CreatePEBLdrDataContent();
    result->ProcessParameters = CreateRtlUserProcessParametersContent();

    return result;
}


void DisplayPEBContent(PEBContent* peb)
{
    RtlUserProcessParametersContent* procParam = peb->ProcessParameters;
    PEBLdrDataContent* ldr = peb->Ldr;
    unsigned int i;

    puts("");
    printf("Activation Context Data : %p\n", peb->ActivationContextData);
    printf("ActiveProcessAffinityMask : %I64d\n", peb->ActiveProcessAffinityMask);
    printf("Ansi Code Page Data : %p\n", peb->AnsiCodePageData);
    printf("Api Set Map : %p\n", peb->ApiSetMap);
    printf("App Compat Flags : %I64d\n", peb->AppCompatFlags);
    printf("App Compat Flags User : %I64d\n", peb->AppCompatFlagsUser);
    printf("App Compat Info : %p\n", peb->AppCompatInfo);
    printf("AtlThunkSListPtr : %p\n", peb->AtlThunkSListPtr);
    printf("AtlThunkSListPtr32 : %lu\n", peb->AtlThunkSListPtr32);
    printf("Being Debugged : %s\n", peb->BeingDebugged ? "TRUE" : "FALSE");
    printf("Critical Section Timeout : %I64d\n", peb->CriticalSectionTimeout);
    printf("CSD Version : %s\n", peb->CSDVersion.Buffer);
    printf("CsrServerReadOnlySharedMemoryBase : %I64d\n", peb->CsrServerReadOnlySharedMemoryBase);
    printf("Fast PEB Lock : %p\n", peb->FastPebLock);
    printf("Fls Bitmap : %p\n", peb->FlsBitmap);

    printf("Fls Bitmap Bits :\n");
    for(i = 0; i < 4; i++)
        printf("\t[%u] = %lu\n", i, peb->FlsBitmapBits[i]);

    printf("Fls Callback : %p\n", peb->FlsCallback);
    printf("Fls High Index : %lu\n", peb->FlsHighIndex);
    printf("Fls List Head Flink : %p\n", peb->FlsListHead.Flink);
    printf("GdiDC Attribute List : %lu\n", peb->GdiDCAttributeList);

    printf("Gdi Handle Buffers : \n");
    for(i = 0; i < 60; i++)
        printf("\t[%u] = %lu\n", i, peb->GdiHandleBuffer[i]);

    printf("GdiSharedHandleTable : %p\n", peb->GdiSharedHandleTable);
    printf("HeapDeCommitFreeBlockThreshold : %I64d\n", peb->HeapDeCommitFreeBlockThreshold);
    printf("HeapDeCommitTotalFreeThreshold : %I64d\n", peb->HeapDeCommitTotalFreeThreshold);
    printf("HeapSegmentCommit : %I64d\n", peb->HeapSegmentCommit);
    printf("HeapSegmentReserve : %I64d\n", peb->HeapSegmentReserve);
    printf("IFEOKey : %p\n", peb->IFEOKey);
    printf("Image Base Address : %p\n", peb->ImageBaseAddress);
    printf("Image Subsystem : %lu\n", peb->ImageSubsystem);
    printf("Image Subsystem Major Version : %lu\n", peb->ImageSubsystemMajorVersion);
    printf("Image Subsystem Minor Version : %lu\n", peb->ImageSubsystemMinorVersion);
    printf("Inherited Address Space : %d\n", peb->InheritedAddressSpace);

    if(ldr != NULL)
    {
        printf("\tEntry In Progress : %p\n", ldr->EntryInProgress);
        printf("\tIn Initialization Order Module List : \n");
        printf("\tInitialized : %i\n", ldr->Initialized);
        printf("\tIn Load Order Module List Flink : %p\n", ldr->InLoadOrderModuleList.Flink);
        printf("\tLength : %lu\n", ldr->Length);
        printf("\tIn Memory Order Module List Flink : %p\n", ldr->InMemoryOrderModuleList.Flink);
        printf("\tShutdown In Progress : %i\n", ldr->ShutdownInProgress);
        printf("\tShutdown Thread Id : %p\n", ldr->ShutdownThreadId);
        printf("\tSsHandle : %p\n", ldr->SsHandle);
    }

    printf("Loader Lock : %p\n", peb->LoaderLock);
    printf("Maximum Number Of Heaps : %lu\n", peb->MaximumNumberOfHeaps);
    printf("Minimum Stack Commit : %I64d\n", peb->MinimumStackCommit);
    printf("Mutant : %p\n", peb->Mutant);
    printf("Nt Global Flag : %lu\n", peb->NtGlobalFlag);
    printf("Number Of Heaps : %lu\n", peb->NumberOfHeaps);
    printf("Oem Code Page Data : %p\n", peb->OemCodePageData);
    printf("OS Build Number : %u\n", (unsigned int)peb->OSBuildNumber);
    printf("OS CSDVersion : %u\n", (unsigned int)peb->OSCSDVersion);
    printf("OS Major Version OS : %lu\n", peb->OSMajorVersion);
    printf("OS Minor Version OS : %lu\n", peb->OSMinorVersion);
    printf("OS Platform Id : %lu\n", peb->OSPlatformId);
    printf("pImageHeaderHash : %p\n", peb->pImageHeaderHash);
    printf("Post Process Init Routine : %p\n", peb->PostProcessInitRoutine);
    printf("Process Assembly Storage Map : %p\n", peb->ProcessAssemblyStorageMap);
    printf("Process Heap : %p\n", peb->ProcessHeap);
    printf("Process Heaps : %p\n", peb->ProcessHeaps);

    printf("Process Parameters :\n");
    if(procParam != NULL)
    {
        printf("\tCommand Line : %s\n", procParam->CommandLine.Buffer);
        printf("\tWindow Title : %s\n", procParam->WindowTitle.Buffer);
        printf("\tImage Path Name : %s\n", procParam->ImagePathName.Buffer);
        printf("\tDLL Path : %s\n", procParam->DllPath.Buffer);
        printf("\tShell Info : %s\n", procParam->ShellInfo.Buffer);
        printf("\tDesktop Info : %s\n", procParam->DesktopInfo.Buffer);
        printf("\tConsole Flags : %lu\n", procParam->ConsoleFlags);
        printf("\tConsole Handle : %p\n", procParam->ConsoleHandle);
        printf("\tCount Chars X : %lu\n", procParam->CountCharsX);
        printf("\tCount Chars Y : %lu\n", procParam->CountCharsY);
        printf("\tCount X : %lu\n", procParam->CountX);
        printf("\tCount Y : %lu\n", procParam->CountY);
        printf("\tEnvironment Strings :\n");
        puts((const char*)procParam->Environment);

        printf("\tCurrent directories : \n");
        for(i = 0; i < 32; i++)
            printf("\t\t[%u] = %s\n", i, procParam->CurrentDirectories[i].DosPath.Buffer);

        printf("\tCurrent Directory : %s\n", procParam->CurrentDirectory.DosPath.Buffer);
        printf("\tDebug Flags : %lu\n", procParam->DebugFlags);
        printf("\tEnvironment : %p\n", procParam->Environment);
        printf("\tEnvironment Size : %I64d\n", procParam->EnvironmentSize);
        printf("\tEnvironment Version : %I64d\n", procParam->EnvironmentVersion);
        printf("\tFill Attribute : %lu\n", procParam->FillAttribute);
        printf("\tFlags : %lu\n", procParam->Flags);
        printf("\tLength : %lu\n", procParam->Length);
        printf("\tMaximum Length : %lu\n", procParam->MaximumLength);
        printf("\tPackage Dependency Data : %p\n", procParam->PackageDependencyData);
        printf("\tProcess Group Id : %lu\n", procParam->ProcessGroupId);
        printf("\tRuntime Data : %s\n", procParam->RuntimeData.Buffer);
        printf("\tShow Window Flags : %lu\n", procParam->ShowWindowFlags);
        printf("\tStandard Error : %p\n", procParam->StandardError);
        printf("\tStandard Input : %p\n", procParam->StandardInput);
        printf("\tStandard Output : %p\n", procParam->StandardOutput);
        printf("\tStarting X : %lu\n", procParam->StartingX);
        printf("\tStarting Y : %lu\n", procParam->StartingY);
        printf("\tWindow Flags : %lu\n", procParam->WindowFlags);

    }

    printf("Process Starter Helper : %p\n", peb->ProcessStarterHelper);
    printf("pShimData : %p\n", peb->pShimData);
    printf("pUnused : %p\n", peb->pUnused);
    printf("Read Image File Exec Options : %i\n", peb->ReadImageFileExecOptions);
    printf("Read Only Shared Memory Base : %p\n", peb->ReadOnlySharedMemoryBase);
    printf("Read Only Static Server Data : %p\n", peb->ReadOnlyStaticServerData);
    printf("Session Id : %lu\n", peb->SessionId);
    printf("SparePvoid0 : %p\n", peb->SparePvoid0);
    printf("Sub System Data : %p\n", peb->SubSystemData);
    printf("System Assembly Storage Map : %p\n", peb->SystemAssemblyStorageMap);
    printf("System Default Activation Context Data : %p\n", peb->SystemDefaultActivationContextData);

    for(i = 0; i < 1; i++)
        printf("System Reserved : %lu\n", peb->SystemReserved[i]);

    printf("Tls Bitmap : %p\n", peb->TlsBitmap);

    printf("Tls Bitmap Bits : \n");
    for(i = 0; i < 2; i++)
        printf("\t[%u] = %lu\n", i, peb->TlsBitmapBits[i]);

    printf("Tls Expansion Bitmap : %p\n", peb->TlsExpansionBitmap);

    printf("Tls Expansion Bitmap Bits : \n");
    for(i = 0; i < 32; i++)
        printf("\t[%u] = %lu\n", i, peb->TlsExpansionBitmapBits[i]);

    printf("Tls Expansion Counter : %lu\n", peb->TlsExpansionCounter);
    printf("Unicode Case Table Data : %p\n", peb->UnicodeCaseTableData);
    printf("Wer Registration Data : %p\n", peb->WerRegistrationData);
    printf("Wer Ship Assert Ptr : %p\n", peb->WerShipAssertPtr);

    puts("");
}

void FreePEBContent(PEBContent* peb)
{
//    free(peb->ActivationContextData);
//    free(peb->AnsiCodePageData);
//    free(peb->ApiSetMap);
//    free(peb->AppCompatInfo);
//    free(peb->AtlThunkSListPtr);
//    free(peb->FastPebLock);
//    free(peb->FlsBitmap);
//    free(peb->FlsCallback);
//    free(peb->GdiSharedHandleTable);
//    free(peb->IFEOKey);
//    free(peb->ImageBaseAddress);

    FreePEBLdrDataContent(peb->Ldr);

//    free(peb->LoaderLock);
//    free(peb->Mutant);
//    free(peb->OemCodePageData);
//    free(peb->pImageHeaderHash);
//    free(peb->PostProcessInitRoutine);
//    free(peb->ProcessAssemblyStorageMap);
//    free(peb->ProcessHeap);
//    free(peb->ProcessHeaps);

    FreeRtlUserProcessParametersContent(peb->ProcessParameters);

//    free(peb->ProcessStarterHelper);
//    free(peb->pShimData);
//    free(peb->pUnused);
//    free(peb->ReadOnlySharedMemoryBase);
//    free(peb->ReadOnlyStaticServerData);
//    free(peb->SparePvoid0);
//    free(peb->SubSystemData);
//    free(peb->SystemAssemblyStorageMap);
//    free(peb->SystemDefaultActivationContextData);
//    free(peb->TlsBitmap);
//    free(peb->TlsExpansionBitmap);
//    free(peb->UnicodeCaseTableData);
//    free(peb->WerRegistrationData);
//    free(peb->WerShipAssertPtr);

    free(peb);
}






/*
void DisplayModuleListHashTableListMethod(unsigned long pid)
{
    WCHAR tmpData[2048] = {'\0'};
    LIST_ENTRY nextModule = {0};
    LDR_DATA_TABLE_ENTRY dataTable;
    SIZE_T read = 0;
    PEBContent* peb = CreatePEBContentFromPid(pid);
    LIST_ENTRY* pLoadOrderModuleList = peb->Ldr->InLoadOrderModuleList.Flink;
    HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);


    if(!ReadProcessMemory(processHandle,
                     pLoadOrderModuleList,
                     &dataTable,
                     sizeof(dataTable),
                     &read))
    {
        printf("Byte read : %lu\n", (unsigned long) read);
        DisplayLastError();
        return;
    }


    LIST_ENTRY* moduleStart = dataTable.HashLinks.Flink;
    LIST_ENTRY* currentModule = moduleStart;




    if(processHandle)
    {
        do
        {
            printf("Reading %p\n", currentModule);

            if(!ReadProcessMemory(processHandle,
                              currentModule,
                              &nextModule,
                              sizeof(currentModule),
                              &read))
            {
                printf("Byte read : %lu\n", (unsigned long) read);
                DisplayLastError();
                break;
            }

            printf("OK1\n");
            if(!ReadProcessMemory(processHandle,
                             currentModule,
                             &dataTable,
                             sizeof(dataTable),
                             &read))
            {
                printf("Byte read : %lu\n", (unsigned long) read);
                DisplayLastError();
                break;
            }

            printf("OK2 : %p\n", dataTable.FullDllName.Buffer);

            if(!ReadProcessMemory(processHandle,
                                  dataTable.FullDllName.Buffer,
                                  tmpData,
                                  dataTable.FullDllName.Length,
                                  &read))
            {
                printf("Byte read : %lu\n", (unsigned long) read);
                DisplayLastError();
                break;
            }

            ANSI_STRING tmpStr = CreateAnsiStringDataFromUnicode(tmpData, read);
            printf("DLL Full Name : %s\n", tmpStr.Buffer);
            free(tmpStr.Buffer);

            memset(tmpData, 0, dataTable.FullDllName.Length * sizeof(WCHAR));

            currentModule = nextModule.Flink;
        }while(currentModule != moduleStart);
    }

    CloseHandle(processHandle);
    FreePEBContent(peb);
}
*/
