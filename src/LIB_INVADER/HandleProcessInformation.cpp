#include <windows.h>
#include <stdio.h>

#include "ProcessInformation.h"


HandleProcessInformation* CreateHandleProcessInformation()
{
    HandleProcessInformation* result = (HandleProcessInformation*) malloc(sizeof(HandleProcessInformation));
    if(result != NULL)
    {
        result->next = NULL;
        result->processName[0] = '\0';
        result->name[0] = '\0';
        result->type[0] = '\0';
        result->processPid = -1;

    }
    return result;
}


void FreeHandleProcessInformation(HandleProcessInformation* handle)
{
    HandleProcessInformation** next = &handle->next;
    while(handle != NULL)
    {
        free(handle);
        handle = *next;
        *next = NULL;
    }
}

void DisplayHandleProcessInformation(HandleProcessInformation* handle)
{
    HandleProcessInformation* it;
    for(it = handle; it != NULL; it = it->next)
    {
        if(it != NULL && !(it->processName[0] == '\0' && it->name[0] == '\0' && it->type[0] == '\0'))
        {
            puts("");
            printf("%s\n", it->name);
            printf("\tType : \t\t%s\n", it->type);
            printf("\tPossesseur : \t\t%s\n", it->processName);
            printf("\tPID possesseur : \t\t%ld\n", it->processPid);
        }
    }

}
