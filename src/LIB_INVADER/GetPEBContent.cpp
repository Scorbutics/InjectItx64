#include <windows.h>
#include <stdio.h>
#include "ProcessBasicInformation.h"
#include "PEBContent.h"
#include "GetPEBContent.h"

#include "ErrorUtils.h"

#include "ProcessInformation.h"
#include "GetProcessInformation.h"

void FillLdrPEB(PPEB_LDR_DATA pLdr, PEBContent* output)
{
    PEBLdrDataContent* ldr = output->Ldr;

    ldr->Initialized = pLdr->Initialized;
    ldr->Length = pLdr->Length;
    ldr->ShutdownInProgress = pLdr->ShutdownInProgress;

    ldr->InInitializationOrderModuleList = pLdr->InInitializationOrderModuleList;
    ldr->InLoadOrderModuleList = pLdr->InLoadOrderModuleList;
    ldr->InMemoryOrderModuleList = pLdr->InMemoryOrderModuleList;

}

void FillProcessParametersPEB(PRTL_USER_PROCESS_PARAMETERS pProcParam, PEBContent* output)
{
    RtlUserProcessParametersContent* procParam = output->ProcessParameters;

    procParam->ConsoleFlags = pProcParam->ConsoleFlags;
    procParam->CountCharsX = pProcParam->CountCharsX;
    procParam->CountCharsY = pProcParam->CountCharsY;
    procParam->CountX = pProcParam->CountX;
    procParam->CountY = pProcParam->CountY;
    procParam->DebugFlags = pProcParam->DebugFlags;
    procParam->EnvironmentSize = pProcParam->EnvironmentSize;
    procParam->EnvironmentVersion = pProcParam->EnvironmentVersion;
    procParam->FillAttribute = pProcParam->FillAttribute;
    procParam->Flags = pProcParam->Flags;
    procParam->Length = pProcParam->Length;
    procParam->MaximumLength = pProcParam->MaximumLength;
    procParam->ProcessGroupId = pProcParam->ProcessGroupId;
    procParam->ShowWindowFlags = pProcParam->ShowWindowFlags;
    procParam->StartingX = pProcParam->StartingX;
    procParam->StartingY = pProcParam->StartingY;
    procParam->WindowFlags = pProcParam->WindowFlags;

    //Pointers
    procParam->ConsoleHandle = pProcParam->ConsoleHandle;
    procParam->PackageDependencyData = pProcParam->PackageDependencyData;
    procParam->StandardError = pProcParam->StandardError;
    procParam->StandardInput = pProcParam->StandardInput;
    procParam->StandardOutput = pProcParam->StandardOutput;

}

void FillMainPEB(PEB* peb, PEBContent* output)
{
    unsigned int i;

    output->ActiveProcessAffinityMask = peb->ActiveProcessAffinityMask;
    output->AppCompatFlags = peb->AppCompatFlags.QuadPart;
    output->AppCompatFlagsUser = peb->AppCompatFlagsUser.QuadPart;
    output->AtlThunkSListPtr32 = peb->AtlThunkSListPtr32;
    output->BeingDebugged = peb->BeingDebugged;
    output->CriticalSectionTimeout = peb->CriticalSectionTimeout.QuadPart;
    output->CsrServerReadOnlySharedMemoryBase = peb->CsrServerReadOnlySharedMemoryBase;

    for(i = 0; i < 4; i++)
        output->FlsBitmapBits[i] = peb->FlsBitmapBits[i];

    output->FlsHighIndex = peb->FlsHighIndex;
    output->GdiDCAttributeList = peb->GdiDCAttributeList;

    for(i = 0; i < 60; i++)
        output->GdiHandleBuffer[i] = peb->GdiHandleBuffer[i];

    output->HeapDeCommitFreeBlockThreshold = peb->HeapDeCommitFreeBlockThreshold;
    output->HeapDeCommitTotalFreeThreshold = peb->HeapDeCommitTotalFreeThreshold;
    output->HeapSegmentCommit = peb->HeapSegmentCommit;
    output->HeapSegmentReserve = peb->HeapSegmentReserve;
    output->ImageSubsystem = peb->ImageSubsystem;
    output->ImageSubsystemMajorVersion = peb->ImageSubsystemMajorVersion;
    output->ImageSubsystemMinorVersion = peb->ImageSubsystemMinorVersion;
    output->InheritedAddressSpace = peb->InheritedAddressSpace;
    output->MaximumNumberOfHeaps = peb->MaximumNumberOfHeaps;
    output->MinimumStackCommit = peb->MinimumStackCommit;
    output->NtGlobalFlag = peb->NtGlobalFlag;
    output->NumberOfHeaps = peb->NumberOfHeaps;
    output->NumberOfProcessors = peb->NumberOfProcessors;
    output->OSBuildNumber = peb->OSBuildNumber;
    output->OSCSDVersion = peb->OSCSDVersion;
    output->OSMajorVersion = peb->OSMajorVersion;
    output->OSMinorVersion = peb->OSMinorVersion;
    output->OSPlatformId = peb->OSPlatformId;
    output->ReadImageFileExecOptions = peb->ReadImageFileExecOptions;
    output->SessionId = peb->SessionId;

    for(i = 0; i < 1; i++)
        output->SystemReserved[i] = peb->SystemReserved[i];

    for(i = 0; i < 2; i++)
        output->TlsBitmapBits[i] = peb->TlsBitmapBits[i];

    for(i = 0; i < 32; i++)
        output->TlsExpansionBitmapBits[i] = peb->TlsExpansionBitmapBits[i];

    output->TlsExpansionCounter = peb->TlsExpansionCounter;


    //Pointers
    output->ActivationContextData = peb->ActivationContextData;
    output->AnsiCodePageData = peb->AnsiCodePageData;
    output->ApiSetMap = peb->ApiSetMap;
    output->AppCompatInfo = peb->AppCompatInfo;
    output->AtlThunkSListPtr = peb->AtlThunkSListPtr;
    output->FastPebLock = peb->FastPebLock;
    output->FlsBitmap = peb->FlsBitmap;
    output->FlsCallback = peb->FlsCallback;
    output->GdiSharedHandleTable = peb->GdiSharedHandleTable;
    output->IFEOKey = peb->IFEOKey;
    output->ImageBaseAddress = peb->ImageBaseAddress;
    output->LoaderLock = peb->LoaderLock;
    output->Mutant = peb->Mutant;
    output->OemCodePageData = peb->OemCodePageData;
    output->pImageHeaderHash = peb->pImageHeaderHash;
    output->PostProcessInitRoutine = peb->PostProcessInitRoutine;
    output->ProcessAssemblyStorageMap = peb->ProcessAssemblyStorageMap;
    output->ProcessHeap = peb->ProcessHeap;
    output->ProcessHeaps = peb->ProcessHeaps;
    output->ProcessStarterHelper = peb->ProcessStarterHelper;
    output->pShimData = peb->pShimData;
    output->pUnused = peb->pUnused;
    output->ReadOnlySharedMemoryBase = peb->ReadOnlySharedMemoryBase;
    output->ReadOnlyStaticServerData = peb->ReadOnlyStaticServerData;
    output->SparePvoid0 = peb->SparePvoid0;
    output->SubSystemData = peb->SubSystemData;
    output->SystemAssemblyStorageMap = peb->SystemAssemblyStorageMap;
    output->SystemDefaultActivationContextData = peb->SystemDefaultActivationContextData;
    output->TlsBitmap = peb->TlsBitmap;
    output->TlsExpansionBitmap = peb->TlsExpansionBitmap;
    output->UnicodeCaseTableData = peb->UnicodeCaseTableData;
    output->WerRegistrationData = peb->WerRegistrationData;
    output->WerShipAssertPtr = peb->WerShipAssertPtr;
}



ProcessModule* GetModuleListListEntryMethod(PEBContent* peb, unsigned int pid)
{
    LDR_DATA_TABLE_ENTRY dataTable;
    LIST_ENTRY* moduleStart = peb->Ldr->InLoadOrderModuleList.Flink;
    LIST_ENTRY* currentModule = moduleStart;
    LIST_ENTRY nextModule = {0};
    HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    WCHAR tmpData[2048] = {'\0'};
    SIZE_T read = 0;

    ProcessModule* head = NULL;

    if(processHandle)
    {
        do
        {

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

            ANSI_STRING tmpStrFullName = CreateAnsiStringDataFromUnicode(tmpData, read);
            dataTable.FullDllName.Buffer = (PWSTR) tmpStrFullName.Buffer;

            memset(tmpData, 0, dataTable.FullDllName.Length * sizeof(WCHAR));

            if(!ReadProcessMemory(processHandle,
                                  dataTable.BaseDllName.Buffer,
                                  tmpData,
                                  dataTable.BaseDllName.Length,
                                  &read))
            {
                printf("Byte read : %lu\n", (unsigned long) read);
                DisplayLastError();
                break;
            }

            ANSI_STRING tmpStrDllName = CreateAnsiStringDataFromUnicode(tmpData, read);
            dataTable.BaseDllName.Buffer = (PWSTR) tmpStrDllName.Buffer;

            AddHeadProcessModule(&head, CreateSingleProcessModuleFromDataTable(&dataTable));

            memset(tmpData, 0, dataTable.BaseDllName.Length * sizeof(WCHAR));

            currentModule = nextModule.Flink;
        }while(currentModule != moduleStart);
    }

    CloseHandle(processHandle);

    return head;
}




PEBContent* GetPEBContentFromPid(unsigned long pid)
{

    PEBContent* result = CreatePEBContent();

    SIZE_T read;
    BOOL isWow64 = TRUE;
    HANDLE processHandle;
    PEB peb;
    RTL_USER_PROCESS_PARAMETERS procParam;
    PEB_LDR_DATA pLdrData;
    WCHAR tmpData[8192] = {'\0'};

    PROCESS_BASIC_INFORMATION* pInfo;

    processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);

    if(!processHandle)
    {
        printf("INFO : Impossible d'obtenir un handle sur ce processus.\n");
        DisplayLastError();
        return result;
    }

    IsWow64Process(processHandle, &isWow64);

    pInfo = QueryProcessBasicInformation(NULL, pid);
    if(pInfo != NULL)
    {


        //PEB MAIN//
        if(!ReadProcessMemory(processHandle,
                              pInfo->PebBaseAddress,
                              &peb,
                              sizeof(peb),
                              &read))
        {
            printf("Byte read : %lu\n", (unsigned long) read);
            DisplayLastError();
            return result;
        }

        FillMainPEB(&peb, result);

        //PEB LDR//
        if(!ReadProcessMemory(processHandle,
                          peb.Ldr,
                          &pLdrData,
                          sizeof(pLdrData),
                          &read))
        {
            printf("Byte read : %lu\n", (unsigned long) read);
            DisplayLastError();
            return result;
        }

        FillLdrPEB(&pLdrData, result);


        //PEB PROCESS PARAMETERS//
        if(!ReadProcessMemory(processHandle,
                          peb.ProcessParameters,
                          &procParam,
                          sizeof(RTL_USER_PROCESS_PARAMETERS),
                          &read))
        {
            printf("Byte read : %lu\n", (unsigned long) read);
            DisplayLastError();
            return result;
        }

        FillProcessParametersPEB(&procParam, result);

        char* environmentStringsBuf = (char*) calloc(procParam.EnvironmentSize, sizeof(char));
        char* formattedEnvironmentStrings = (char*) calloc(procParam.EnvironmentSize, sizeof(char));

        //PEB PROCESS PARAMETERS ENVIRONMENT STRINGS//
        if(!ReadProcessMemory(processHandle,
                              procParam.Environment,
                              environmentStringsBuf,
                              procParam.EnvironmentSize,
                              &read))
        {
            printf("Byte read : %lu\n", (unsigned long) read);
            DisplayLastError();
            return result;
        }

        char currentChar;
        unsigned int index = 0;
        puts("");
        do
        {

            currentChar = environmentStringsBuf[index];

            if(currentChar != '\0')
                sprintf(formattedEnvironmentStrings+index/2, "%c", currentChar);
            else
                sprintf(formattedEnvironmentStrings+index/2, "\n");

            index += 2;
        }while(index < procParam.EnvironmentSize);

        free(environmentStringsBuf);
        result->ProcessParameters->Environment = formattedEnvironmentStrings;


        //PEB PROCESS PARAMETERS CURRENT DIRECTORIES//
        unsigned int i = 0;
        do
        {
            if(!ReadProcessMemory(processHandle,
                                  procParam.CurrentDirectories[i].DosPath.Buffer,
                                  tmpData,
                                  procParam.CurrentDirectories[i].DosPath.Length,
                                  &read))
            {
                printf("Byte read : %lu\n", (unsigned long) read);
                DisplayLastError();
                return result;
            }

            result->ProcessParameters->CurrentDirectories[i].DosPath = CreateAnsiStringDataFromUnicode(tmpData, read);
            memset(tmpData, 0, procParam.CurrentDirectories[i].DosPath.Length * sizeof(WCHAR));

            i++;
        }while(i < 32);


        //PEB PROCESS PARAMETERS CURRENT DIRECTORIES//
        if(!ReadProcessMemory(processHandle,
                              procParam.CurrentDirectory.DosPath.Buffer,
                              tmpData,
                              procParam.CurrentDirectory.DosPath.Length,
                              &read))
        {
            printf("Byte read : %lu\n", (unsigned long) read);
            DisplayLastError();
            return result;
        }
        result->ProcessParameters->CurrentDirectory.DosPath = CreateAnsiStringDataFromUnicode(tmpData, read);
        memset(tmpData, 0, procParam.CurrentDirectory.DosPath.Length * sizeof(WCHAR));

        //PEB PROCESS PARAMETERS COMMAND LINE//
        if(!ReadProcessMemory(processHandle,
                         procParam.CommandLine.Buffer,
                         tmpData,
                         procParam.CommandLine.Length,
                         &read))
        {
            printf("Byte read : %lu\n", (unsigned long) read);
            DisplayLastError();
            return result;
        }
        result->ProcessParameters->CommandLine = CreateAnsiStringDataFromUnicode(tmpData, read);
//        printf("process handle (%p) : %s (%u octets)\n", processHandle, result->ProcessParameters->CommandLine.Buffer, result->ProcessParameters->CommandLine.Length);

        if(procParam.CommandLine.Length != 0)
            memset(tmpData, 0, procParam.CommandLine.Length * sizeof(WCHAR));

        //PEB PROCESS PARAMETERS WINDOW TITLE//
        if(!ReadProcessMemory(processHandle,
                         procParam.WindowTitle.Buffer,
                         tmpData,
                         procParam.WindowTitle.Length,
                         &read))
        {
            printf("Byte read : %lu\n", (unsigned long) read);
            DisplayLastError();
            return result;
        }
        result->ProcessParameters->WindowTitle = CreateAnsiStringDataFromUnicode(tmpData, read);

        if(procParam.WindowTitle.Length != 0)
            memset(tmpData, 0, procParam.WindowTitle.Length * sizeof(WCHAR));

        //PEB PROCESS PARAMETERS DLL PATH//
        if(!ReadProcessMemory(processHandle,
                         procParam.DllPath.Buffer,
                         tmpData,
                         procParam.DllPath.Length,
                         &read))
        {
            printf("Byte read : %lu\n", (unsigned long) read);
            DisplayLastError();
            return result;
        }
        result->ProcessParameters->DllPath = CreateAnsiStringDataFromUnicode(tmpData, read);

        if(procParam.DllPath.Length != 0)
            memset(tmpData, 0, procParam.DllPath.Length * sizeof(WCHAR));

        //PEB PROCESS PARAMETERS IMAGE PATH//
        if(!ReadProcessMemory(processHandle,
                         procParam.ImagePathName.Buffer,
                         tmpData,
                         procParam.ImagePathName.Length,
                         &read))
        {
            printf("Byte read : %lu\n", (unsigned long) read);
            DisplayLastError();
            return result;
        }
        result->ProcessParameters->ImagePathName = CreateAnsiStringDataFromUnicode(tmpData, read);

        if(procParam.ImagePathName.Length != 0)
            memset(tmpData, 0, procParam.ImagePathName.Length * sizeof(WCHAR));

        //PEB PROCESS PARAMETERS DESKTOP INFO//
        if(!ReadProcessMemory(processHandle,
                         procParam.DesktopInfo.Buffer,
                         tmpData,
                         procParam.DesktopInfo.Length,
                         &read))
        {
            printf("Byte read : %lu\n", (unsigned long) read);
            DisplayLastError();
            return result;
        }
        result->ProcessParameters->DesktopInfo = CreateAnsiStringDataFromUnicode(tmpData, read);

        if(procParam.DesktopInfo.Length != 0)
            memset(tmpData, 0, procParam.DesktopInfo.Length * sizeof(WCHAR));

        //PEB PROCESS PARAMETERS SHELL INFO//
        if(!ReadProcessMemory(processHandle,
                         procParam.ShellInfo.Buffer,
                         tmpData,
                         procParam.ShellInfo.Length,
                         &read))
        {
            printf("Byte read : %lu\n", (unsigned long) read);
            DisplayLastError();
            return result;
        }
        result->ProcessParameters->ShellInfo = CreateAnsiStringDataFromUnicode(tmpData, read);

        if(procParam.ShellInfo.Length != 0)
            memset(tmpData, 0, procParam.ShellInfo.Length * sizeof(WCHAR));

        //PEB LDR MODULE LIST//
        result->Ldr->moduleList = GetModuleListListEntryMethod(result, pid);

    }

    free(pInfo);
    CloseHandle(processHandle);

    return result;
}

