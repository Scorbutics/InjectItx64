#include <stdio.h>
#include <stdarg.h>     /* va_list, va_start, va_arg, va_end */
#include <windows.h>
#include "NTStatus.h"

//Ci-dessous, includes pour NtQuerySystemInformation avec le type SystemProcessInformation
#include "SystemInformationClass.h"
#include "UnicodeString.h"
#include "SystemProcessInformation.h"
#include "ProcessInformation.h"
#include "ErrorUtils.h"
#include "PROCESSINFOCLASS.h"

#include "GetProcessInformation.h"

#define NT_PROCESS_LIST 5
#define ProcessBasicInformation 0
#define ProcessWow64Information 26

//Correspond à 8 (bloc de 1octet):
#define BLOCK_SIZE 0x1000


NTSTATUS QuerySystemInformation(HMODULE ntdllLoaded, SYSTEM_INFORMATION_CLASS systemInfoClass, BYTE **pBuff)
{
    NTSTATUS ntResult = 0;

    //On défini le prototype de la fonction à récupérer dans "ntdll" et on le nomme "NtQuerySystemInformation"
    typedef NTSTATUS (__stdcall *NtQuerySystemInformation)(
          SYSTEM_INFORMATION_CLASS SystemInformationClass,
          PVOID SystemInformation,
          ULONG SystemInformationLength,
          PULONG ReturnLength
        );


    //On récupère la fonction souhaitée "NtQuerySystemInformation", "castée" par le prototype qu'on a déclaré au dessus
    NtQuerySystemInformation ntQuerySystemInformation = (NtQuerySystemInformation)  GetProcAddress(ntdllLoaded, "NtQuerySystemInformation");

    if (ntQuerySystemInformation != NULL)
    {

        ULONG cbNeeded = 0;

        //Récupération de la taille nécessaire
        ntResult = ntQuerySystemInformation(NT_PROCESS_LIST, NULL, cbNeeded, &cbNeeded);
        if((ntResult == STATUS_INFO_LENGTH_MISMATCH) && (cbNeeded > 0))
        {
            *pBuff = (BYTE*) malloc(sizeof(BYTE) * cbNeeded);
            if(*pBuff != NULL)
            {
                //fill the buffer with actual information.
                ntResult = ntQuerySystemInformation(systemInfoClass, *pBuff, cbNeeded, &cbNeeded);
            }
            else
            {
                printf("Erreur lors d'une allocation memoire\n");
            }
        }
    }
    else
    {
        printf("Erreur : Impossible de recuperer NtQuerySystemInformation dans ntdll.dll\n");
    }

    return ntResult;
}

/**
*   NB : malloc sur ProcessInformationList
*
*   Params :
*   ntdllLibrary : la bibliothèque ntdll.dll chargée, ou NULL
*/
void* GetProcessListNoWrap(HMODULE ntdllLoaded, va_list vlist)
{
    ProcessInformation* processList;
    ProcessInformationList* processListContainer = (ProcessInformationList*) malloc(sizeof(ProcessInformationList));
    processListContainer->length = 0;
    processListContainer->data = NULL;

    SYSTEM_PROCESS_INFORMATION *psys = NULL;

    ULONG offset = 0;
    BYTE* pBuff = NULL;

    (void)vlist;

    //Récupération d'un pBuff alloué
    QuerySystemInformation(ntdllLoaded, NT_PROCESS_LIST, &pBuff);

    if(pBuff != NULL)
    {

        BYTE* pIt = pBuff;
        //char nameProcess[256];
        unsigned int processListSize = 0;
        unsigned int i;

        do
        {
            psys = (SYSTEM_PROCESS_INFORMATION*)pIt;

            //get the offset for next entry.
            offset = psys->NextEntryOffset;
            //point to the next entry.
            pIt += offset;


            processListSize++;
        }while(offset > 0);


        processList = (ProcessInformation*) malloc(sizeof(ProcessInformation)*(processListSize));
        for(i = 0, pIt = pBuff; i < processListSize; i++, pIt += psys->NextEntryOffset)
        {
            psys = (SYSTEM_PROCESS_INFORMATION*)pIt;

            UNICODE_STRING uniStr = psys->ImageName;
            ConvertToCharArrayFromUnicodeString(uniStr, processList[i].name, 512);
            processList[i].handleCount = psys->HandleCount;
            processList[i].pid = (unsigned long)(intptr_t)psys->ProcessId;
            processList[i].threadCount= psys->NumberOfThreads;

        }
        processListContainer->length = processListSize;
        processListContainer->data = processList;

        free(pBuff);
    }

    return (void*) processListContainer;
}

void* WrapWithNtdllLazyLoading(void* (*needingNtdll)(HMODULE ntdllLoaded, va_list vlist), HMODULE ntdllLibraryLazy, ...)
{
    int lazyLoad = 0;
    void * result = NULL;

    HMODULE resultDll = ntdllLibraryLazy;
    if(resultDll == NULL)
    {
        resultDll = LoadLibrary(TEXT("ntdll.dll"));
        lazyLoad = 1;
    }

    if(resultDll)
    {
        va_list vl;
        va_start(vl, ntdllLibraryLazy);
        result = needingNtdll(resultDll, vl);
        va_end(vl);
    }
    else
    {
        printf("Erreur lors du chargement de ntdll.dll\n");
    }

    if(lazyLoad)
    {
        FreeLibrary(resultDll);
    }
    return result;
}

ProcessInformationList* GetProcessList(HMODULE ntdllLibrary)
{
    return ((ProcessInformationList*)WrapWithNtdllLazyLoading(GetProcessListNoWrap, ntdllLibrary));
}

void CopyProcessInformation(ProcessInformation* dst, ProcessInformation* src)
{
    dst->handleCount = src->handleCount;
    strcpy(dst->name, src->name);
    dst->threadCount = src->threadCount;
    dst->pid = src->pid;
}

ProcessInformation GetProcessInformationsFromPID(HMODULE ntdllLibrary, unsigned long pid)
{
    ProcessInformationList* pList = GetProcessList(ntdllLibrary);
    ProcessInformation result;

    result.pid = pid;
    result.name[0] = '\0';

    unsigned int i;
    for(i = 0; i < pList->length; i++)
    {
        if(pid == pList->data[i].pid)
        {
            CopyProcessInformation(&result, pList->data + i);
            break;
        }
    }

    free(pList->data);
    free(pList);
    return result;
}

void* QueryProcessBasicInformationNoWrap(HMODULE ntdllLoaded, va_list vlist)
{
    NTSTATUS ntResult = 0;
    ULONG cbNeeded = 0;
    unsigned long pid;
    PROCESS_BASIC_INFORMATION * result = NULL;

    typedef NTSTATUS (__stdcall *NtQueryInformationProcess)(
        HANDLE ProcessHandle,
        PROCESSINFOCLASS ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength,
        PULONG ReturnLength
        );

    NtQueryInformationProcess ntQueryInformationProcess = (NtQueryInformationProcess)  GetProcAddress(ntdllLoaded, "ZwQueryInformationProcess");
    if(ntQueryInformationProcess)
    {
        pid = va_arg(vlist, unsigned long);
//        printf("Entered PID : %lu\n", pid);

        HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, FALSE, pid);
        if(processHandle != NULL)
        {
            result = (PROCESS_BASIC_INFORMATION*) calloc(1, sizeof(PROCESS_BASIC_INFORMATION));
            ntResult = ntQueryInformationProcess(processHandle, ProcessBasicInformation, result, sizeof(PROCESS_BASIC_INFORMATION), &cbNeeded);

            if(ntResult != STATUS_SUCCESS)
            {
                DisplayErrorWithCode(L"%1", ntResult);
            }

            CloseHandle(processHandle);
        }
        else
        {
            printf("ERREUR OUVERTURE PROCESS\n");
            DisplayLastError();
        }
    }

    return result;
}

PROCESS_BASIC_INFORMATION* QueryProcessBasicInformation(HMODULE ntdll, unsigned long pid)
{
	return (PROCESS_BASIC_INFORMATION*)WrapWithNtdllLazyLoading(QueryProcessBasicInformationNoWrap, ntdll, pid);
}

ProcessInformationList* GetProcessInformationsFromName(HMODULE ntdllLibrary, char* processPathName)
{
    ProcessInformationList* pResult;
    ProcessInformationList* pList = GetProcessList(ntdllLibrary);

    unsigned int i;

    pResult = (ProcessInformationList*) malloc(sizeof(ProcessInformationList));
    pResult->length = 0;
    pResult->data = NULL;

    ProcessInformation* pIt = pList->data;

    for(i = 0; i < pList->length; i++)
    {
        //printf("%u Name %s\n", pList->data[i].pid, pList->data[i].name);
        if(strstr(pList->data[i].name, processPathName) != NULL)
        {
            pResult->length++;
        }
    }

    pResult->data = (ProcessInformation*) malloc(sizeof(ProcessInformation) * pResult->length);
    pIt = pList->data;
//    printf("Recherche de : %s\n", processPathName);

    unsigned int count;
    for(i = 0, count = 0; i < pList->length; i++, pIt++)
    {
//        printf("%u Name %s\n", pIt->pid, pIt->name);
        if(strstr(pIt->name, processPathName) != NULL)
        {
            CopyProcessInformation(pResult->data + count, pIt);
            count++;
        }
    }

    free(pList->data);
    free(pList);

    return pResult;
}



void DisplayProcessList(HMODULE ntdllLibrary)
{
    ProcessInformationList* pList = GetProcessList(ntdllLibrary);
    ProcessInformation* pIt = pList->data;
    unsigned int i = 0;

    while(i < pList->length)
    {
        printf("PID : %lu \t HandleCount : %lu \t Name : %s \t Number of threads : %u\n", pIt->pid, pIt->handleCount, pIt->name, pIt->threadCount);
        pIt++;
        i++;
    }
    free(pList->data);
    free(pList);
}

