#ifndef DEF_QUERYOPENEDFILES
#define DEF_QUERYOPENEDFILES

#define SystemHandleInformation 16

/* The following structure is actually called SYSTEM_HANDLE_TABLE_ENTRY_INFO, but SYSTEM_HANDLE is shorter. */
typedef struct _SYSTEM_HANDLE
{
    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG HandleCount; /* Or NumberOfHandles if you prefer. */
    SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;


HANDLE GetDuplicatedProcessHandle(unsigned int pid, char* processName, int silent);
HandleProcessInformation* SystemHandleInformationHandler(HMODULE dllLoaded, PSYSTEM_HANDLE_INFORMATION handleInfo, unsigned int pid, char* processName, char* filterOnType, HandleProcessInformation* existantList, int silent);
HandleProcessInformation* GetOpenedHandles(HMODULE dll, unsigned int pid, char* filterOnType, int silent);
ProcessWithHandlesList* GetProcessWithAttachedHandle(char* attachedHandleName);
void DisplayAllOpenedHandles(HMODULE ntdll, char* filterOnType);
#endif
