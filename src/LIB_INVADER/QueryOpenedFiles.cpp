#include <windows.h>
#include <stdio.h>

#include "ErrorUtils.h"

#include "NTStatus.h"
#include "SystemInformationClass.h"
#include "UnicodeString.h"
#include "ProcessInformation.h"
#include "GetOpenedHandles.h"
#include "PoolType.h"
#include "ObjectTypeInformation.h"
#include "ObjectNameInformation.h"
#include "GetProcessInformation.h"

#define ObjectBasicInformation 0
#define ObjectNameInformation 1
#define ObjectTypeInformation 2

//Booléen permettant de désactiver la protection anti-hang de NtQueryObject
#define ACCESS_MASK_ALL_ALLOWED 1

typedef NTSTATUS (NTAPI *_NtDuplicateObject)(
    HANDLE SourceProcessHandle,
    HANDLE SourceHandle,
    HANDLE TargetProcessHandle,
    PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess,
    ULONG Attributes,
    ULONG Options
    );

typedef NTSTATUS (NTAPI *_NtQueryObject)(
    HANDLE ObjectHandle,
    ULONG ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength
    );

typedef NTSTATUS (__stdcall *NtQuerySystemInformation)(
      SYSTEM_INFORMATION_CLASS SystemInformationClass,
      PVOID SystemInformation,
      ULONG SystemInformationLength,
      PULONG ReturnLength
    );


/**
* NB : malloc sur la valeur retournée (liste chaînée outputList)
*/
HandleProcessInformation* GetOpenedHandles(HMODULE dll, unsigned int pid, char* filterOnType, int silent)
{
    HandleProcessInformation* iteratorList = CreateHandleProcessInformation();
    HandleProcessInformation* outputList = iteratorList;
    int lazyLoad = 0;
    if(dll == NULL)
    {
        dll = LoadLibrary(TEXT("ntdll.dll"));
        lazyLoad = 1;
    }

    if(dll != NULL)
    {

        NtQuerySystemInformation func = (NtQuerySystemInformation) GetProcAddress(dll, "NtQuerySystemInformation");
        if(func != NULL)
        {
            ULONG handleInfoSize = 0x10000;
            PSYSTEM_HANDLE_INFORMATION handleInfo = (SYSTEM_HANDLE_INFORMATION*) malloc(sizeof(SYSTEM_HANDLE_INFORMATION) * handleInfoSize);
            NTSTATUS ns;

            /* NtQuerySystemInformation won't give us the correct buffer size, so we guess by doubling the buffer size. */
            while ((ns = func(SystemHandleInformation, handleInfo, handleInfoSize, NULL)) == STATUS_INFO_LENGTH_MISMATCH)
            {
                handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2);
            }

            //Si on échoue
            if(ns < 0)
            {
                if(!silent)
                {
                    DisplayLastError();
                }
                return outputList;
            }

            if(handleInfo != NULL)
            {
                func(SystemHandleInformation, (PVOID)handleInfo, handleInfoSize, NULL);
                ProcessInformation procInfo = GetProcessInformationsFromPID(dll, pid);
                HandleProcessInformation* endList = SystemHandleInformationHandler(dll, handleInfo, pid, procInfo.name, filterOnType, iteratorList, silent);

                iteratorList = endList;

                free(handleInfo);
                handleInfo = NULL;
            }

        }

        if(lazyLoad)
        {
            FreeLibrary(dll);
        }
    }

    return outputList;
}


ProcessWithHandlesList* GetProcessWithAttachedHandle(char* attachedHandleName)
{
    if(attachedHandleName == NULL)
    {
        return NULL;
    }


    ProcessWithHandlesList* pListFiltered = (ProcessWithHandlesList*)malloc(sizeof(ProcessWithHandlesList));
    ProcessInformationList* pWholeList = GetProcessList(NULL);
    ProcessWithHandlesList* itResult = pListFiltered;
    ProcessWithHandlesList* lastItResult = NULL;
    unsigned int i;

    for(i = 0; i < pWholeList->length; i++)
    {
        ProcessInformation proc = pWholeList->data[i];

        HandleProcessInformation* handleList = GetOpenedHandles(NULL, proc.pid, NULL, 1);
        HandleProcessInformation* handleIt;
        unsigned int counter = 0;

//        printf("lol\n");
        for(handleIt = handleList; handleIt != NULL; handleIt = handleIt->next)
        {
//            if(handleIt != NULL && handleIt->name != NULL)
//            {
                //printf("%s handleIt->name : %s\n", attachedHandleName, handleIt->name);
                //printf(".");
//            }
            if(handleIt != NULL && handleIt->name != NULL && strstr(handleIt->name, attachedHandleName) != NULL)
            {
                //printf("test\n");
                itResult->dataProcess.handleCount = proc.handleCount;
                itResult->dataProcess.threadCount = proc.threadCount;
                strcpy(itResult->dataProcess.name, proc.name);
                itResult->dataProcess.pid = proc.pid;
                itResult->next = (ProcessWithHandlesList*)malloc(sizeof(ProcessWithHandlesList));
                strcpy(itResult->fullHandleName, handleIt->name);
                strcpy(itResult->handleType, handleIt->type);
                lastItResult = itResult;
                itResult = itResult->next;

                itResult->dataProcess.pid = -1;
                itResult->dataProcess.name[0] = '\0';
                counter++;
            }
        }

        FreeHandleProcessInformation(handleList);
    }


    itResult->next = NULL;
    if(lastItResult != NULL)
    {
        free(lastItResult->next);
        lastItResult->next = NULL;
    }
    free(pWholeList->data);
    free(pWholeList);

    return pListFiltered;
}


HANDLE GetDuplicatedProcessHandle(unsigned int pid, char* processName, int silent)
{
    HANDLE processHandle;
    if (!(processHandle = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid)))
    {
        if(!silent)
        {
            printf("Could not open PID %d  \t(%s) \t\t (Don't try to open a system process)\n", pid, processName);
        }
        return NULL;
    }
    else if(!silent)
    {
        printf("PID %u \t (%s) \t\t opened with success.\n", pid, processName);
    }

    return processHandle;
}

/* Skip handles with the following access codes as the next call
   to NtDuplicateObject() or NtQueryObject() might hang forever. */
int GrantAccessWontHang(ACCESS_MASK accessMask)
{
    return (ACCESS_MASK_ALL_ALLOWED ||!((accessMask == 0x0012019f)
        || (accessMask == 0x001a019f)
        || (accessMask == 0x00120189)
        || (accessMask == 0x00100000)));
}

NTSTATUS QueryNameObject(HMODULE ntdllLoaded, char* outputName, unsigned int outputMaxLength, HANDLE detachedHandle)
{
    _NtQueryObject NtQueryObject = (_NtQueryObject) GetProcAddress(ntdllLoaded, "NtQueryObject");
    POBJECT_NAME_INFORMATION objectNameInfo = (POBJECT_NAME_INFORMATION)malloc(0x1000);
    ULONG returnLength;

    NTSTATUS ns = NtQueryObject(detachedHandle, ObjectNameInformation, objectNameInfo, 0x1000, &returnLength);
    if (ns == STATUS_INFO_LENGTH_MISMATCH && returnLength > 0)
    {
        /* Reallocate the buffer and try again. */
        objectNameInfo = (POBJECT_NAME_INFORMATION)realloc(objectNameInfo, returnLength);
        ns = NtQueryObject(detachedHandle, ObjectNameInformation, objectNameInfo, returnLength, NULL);
    }

    if(ns == STATUS_SUCCESS)
    {
        ConvertToCharArrayFromUnicodeString(objectNameInfo->Name, outputName, outputMaxLength);
    }

    free(objectNameInfo);
    return ns;
}

NTSTATUS QueryTypeObject(HMODULE ntdllLoaded, char* outputName, unsigned int outputMaxLength, HANDLE detachedHandle)
{
    _NtQueryObject NtQueryObject = (_NtQueryObject) GetProcAddress(ntdllLoaded, "NtQueryObject");
    POBJECT_TYPE_INFORMATION objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x1000);

    NTSTATUS ns = NtQueryObject(detachedHandle, ObjectTypeInformation, objectTypeInfo, 0x1000, NULL);
    if(ns == STATUS_SUCCESS)
    {
        ConvertToCharArrayFromUnicodeString(objectTypeInfo->Name, outputName, outputMaxLength);
    }

    free(objectTypeInfo);
    return ns;
}

NTSTATUS DuplicateObject(HMODULE ntdllLoaded, HANDLE processHandle, PVOID handle, PHANDLE dupHandle)
{
    _NtDuplicateObject NtDuplicateObject = (_NtDuplicateObject) GetProcAddress(ntdllLoaded, "NtDuplicateObject");
    return NtDuplicateObject(processHandle, handle, GetCurrentProcess(), dupHandle, 0, 0, 0);
}


void DisplayAllOpenedHandles(HMODULE ntdll, char* filterOnType)
{
    ProcessInformationList* pList = GetProcessList(ntdll);
    unsigned int i;
    for(i = 0; i < pList->length; i++)
    {
        HandleProcessInformation* pHandlePInfo = GetOpenedHandles(ntdll, pList->data[i].pid, filterOnType, 1);
        HandleProcessInformation* pIt;
        for(pIt = pHandlePInfo; pIt != NULL; pIt = pIt->next)
        {
            if(pIt->name[0] != '\0')
            {
                printf("%s (%lu) : %s\n", pList->data[i].name, pList->data[i].pid, pIt->name);
            }
        }
        FreeHandleProcessInformation(pHandlePInfo);
    }
    free(pList->data);
    free(pList);
}

HandleProcessInformation* SystemHandleInformationHandler(HMODULE dllLoaded, PSYSTEM_HANDLE_INFORMATION handleInfo, unsigned int pid, char* processName, char* filterOnType, HandleProcessInformation* existantList, int silent)
{
    HandleProcessInformation* iteratorHandle = existantList;
    HANDLE processHandle;
    processHandle = GetDuplicatedProcessHandle(pid, processName, silent);
    if(processHandle == NULL)
    {
        return existantList;
    }

    unsigned int i;
    for(i = 0; i < handleInfo->HandleCount; i++)
    {
        SYSTEM_HANDLE handle = handleInfo->Handles[i];
        HANDLE dupHandle = NULL;

        if(GrantAccessWontHang(handle.GrantedAccess))
        {
            //Pour chacun des handle stockés dans le système, on regarde si le processus contenant ce handle est le processus cherché
            //On fait donc la vérification sur le PID
            if(handle.ProcessId == pid)
            {
                /* Duplicate the handle so we can query it. */
                if(DuplicateObject(dllLoaded, processHandle, (PVOID)(intptr_t)handle.Handle, &dupHandle) == STATUS_SUCCESS)
                {
                    QueryTypeObject(dllLoaded, iteratorHandle->type, 256, dupHandle);
                    if(filterOnType == NULL || !strcmp(filterOnType, iteratorHandle->type))
                    {
                        QueryNameObject(dllLoaded, iteratorHandle->name, 512, dupHandle);
                        iteratorHandle->next = CreateHandleProcessInformation();
                        strcpy(iteratorHandle->processName, processName);
                        iteratorHandle->processPid = pid;
                        iteratorHandle = iteratorHandle->next;
                    }

                    CloseHandle(dupHandle);
                }
            }
        }

    }
    CloseHandle(processHandle);
    return iteratorHandle;
}
