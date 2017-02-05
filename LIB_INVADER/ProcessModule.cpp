#include <windows.h>
#include <stdio.h>
#include "ProcessBasicInformation.h"
#include "ProcessModule.h"
#include "AnsiString.h"

ProcessModule* CreateSingleProcessModuleFromDataTable(LDR_DATA_TABLE_ENTRY* dataTable)
{
    ProcessModule* result = (ProcessModule*) calloc(1, sizeof(ProcessModule));

    result->BaseDllName.Buffer = (char*) dataTable->BaseDllName.Buffer;
    result->FullDllName.Buffer = (char*) dataTable->FullDllName.Buffer;

    result->BaseNameHashValue = dataTable->BaseNameHashValue;
    result->DdagNode = dataTable->DdagNode;
    result->DllBase = dataTable->DllBase;
    result->EntryPoint = dataTable->EntryPoint;
    result->EntryPointActivationContext = dataTable->EntryPointActivationContext;
    result->HashLinks = dataTable->HashLinks.Flink;
    result->ImplicitPathOptions = dataTable->ImplicitPathOptions;
    result->InLoadOrderLinks = dataTable->InLoadOrderLinks.Flink;
    result->InMemoryOrderLinks = dataTable->InMemoryOrderLinks.Flink;
    result->LoadReason = dataTable->LoadReason;
    result->LoadTime = dataTable->LoadTime.QuadPart;
    result->NodeModuleLink = dataTable->NodeModuleLink.Flink;
    result->ObsoleteLoadCount = dataTable->ObsoleteLoadCount;
    result->OriginalBase = dataTable->OriginalBase;
    result->ParentDllBase = dataTable->ParentDllBase;
    result->SizeOfImage = dataTable->SizeOfImage;
    result->SnapContext = dataTable->SnapContext;
    result->Spare = dataTable->Spare;
    result->SwitchBackContext = dataTable->SwitchBackContext;
    result->TimeDateStamp = dataTable->TimeDateStamp;
    result->TlsIndex = dataTable->TlsIndex;

    return result;
}

void DisplayProcessModule(ProcessModule* list)
{
    for(; list != NULL; list = (ProcessModule*) list->next)
    {
        printf("(%p) %s\n", list->FullDllName.Buffer, list->FullDllName.Buffer);
        printf("HashLinks : %p\n", list->HashLinks);
    }
}

void AddQueueProcessModule(ProcessModule* head, ProcessModule* toAdd)
{
    ProcessModule* list;
    for(list = head; list->next; list = (ProcessModule*) list->next);

    list->next = toAdd;
}


void AddHeadProcessModule(ProcessModule** head, ProcessModule* toAdd)
{
    toAdd->next = *head;
    *head = toAdd;
}

void FreeProcessModuleList(ProcessModule* list)
{
    if(list)
    {
        free(list->BaseDllName.Buffer);
        free(list->FullDllName.Buffer);
    }
}
