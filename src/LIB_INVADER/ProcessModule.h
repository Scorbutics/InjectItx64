#ifndef PROCESSMODULE_H
#define PROCESSMODULE_H

#include "AnsiString.h"

struct _ProcessModule {
    /* +0x000 */ 	void* InLoadOrderLinks ;
    /* +0x010 */ 	void* InMemoryOrderLinks ;
    union
    {
        /* +0x020 */ 	void* InInitializationOrderLinks ;
        /* +0x020 */ 	void* InProgressLinks ;
    };
    /* +0x030 */ 	void* /* Ptr64 Void */ DllBase ;
    /* +0x038 */ 	void* /* Ptr64 Void */ EntryPoint ;
    /* +0x040 */ 	unsigned long SizeOfImage ;
    /* +0x048 */ 	ANSI_STRING FullDllName ;
    /* +0x058 */ 	ANSI_STRING BaseDllName ;

    union
    {
        /* +0x068 */ 	char FlagGroup [4];
        /* +0x068 */ 	unsigned int Flags ;
        struct
        {
            /* +0x068 */ 	unsigned int PackagedBinary :1;
            /* +0x068 */ 	unsigned int MarkedForRemoval :1;
            /* +0x068 */ 	unsigned int ImageDll :1;
            /* +0x068 */ 	unsigned int LoadNotificationsSent :1;
            /* +0x068 */ 	unsigned int TelemetryEntryProcessed :1;
            /* +0x068 */ 	unsigned int ProcessStaticImport :1;
            /* +0x068 */ 	unsigned int InLegacyLists :1;
            /* +0x068 */ 	unsigned int InIndexes :1;
            /* +0x068 */ 	unsigned int ShimDll :1;
            /* +0x068 */ 	unsigned int InExceptionTable :1;
            /* +0x068 */ 	unsigned int ReservedFlags1 :2;
            /* +0x068 */ 	unsigned int LoadInProgress :1;
            /* +0x068 */ 	unsigned int ReservedFlags2 :1;
            /* +0x068 */ 	unsigned int EntryProcessed :1;
            /* +0x068 */ 	unsigned int ReservedFlags3 :3;
            /* +0x068 */ 	unsigned int DontCallForThreads :1;
            /* +0x068 */ 	unsigned int ProcessAttachCalled :1;
            /* +0x068 */ 	unsigned int ProcessAttachFailed :1;
            /* +0x068 */ 	unsigned int CorDeferredValidate :1;
            /* +0x068 */ 	unsigned int CorImage :1;
            /* +0x068 */ 	unsigned int DontRelocate :1;
            /* +0x068 */ 	unsigned int CorILOnly :1;
            /* +0x068 */ 	unsigned int ReservedFlags5 :3;
            /* +0x068 */ 	unsigned int Redirected :1;
            /* +0x068 */ 	unsigned int ReservedFlags6 :2;
            /* +0x068 */ 	unsigned int CompatDatabaseProcessed :1;
        };
    };

    /* +0x06c */ 	unsigned short ObsoleteLoadCount ;
    /* +0x06e */ 	unsigned short TlsIndex ;
    /* +0x070 */ 	void* HashLinks ;
    /* +0x080 */ 	unsigned int TimeDateStamp ;
    /* +0x088 */ 	void* /* Ptr64 _ACTIVATION_CONTEXT */ EntryPointActivationContext ;
    /* +0x090 */ 	void* /* Ptr64 Void */ Spare ;
    /* +0x098 */ 	void* /* Ptr64 _LDR_DDAG_NODE */ DdagNode ;
    /* +0x0a0 */ 	void* NodeModuleLink ;
    /* +0x0b0 */ 	void* /* Ptr64 _LDRP_DLL_SNAP_CONTEXT */ SnapContext ;
    /* +0x0b8 */ 	void* /* Ptr64 Void */ ParentDllBase ;
    /* +0x0c0 */ 	void* /* Ptr64 Void */ SwitchBackContext ;
//    /* +0x0c8 */ 	RTL_BALANCED_NODE BaseAddressIndexNode ;
//    /* +0x0e0 */ 	RTL_BALANCED_NODE MappingInfoIndexNode ;
    /* +0x0f8 */ 	unsigned long long OriginalBase ;
    /* +0x100 */ 	unsigned long long LoadTime ;
    /* +0x108 */ 	unsigned long BaseNameHashValue ;
    /* +0x10c */ 	LDR_DLL_LOAD_REASON LoadReason ;
    /* +0x110 */ 	unsigned long ImplicitPathOptions ;

    struct _ProcessModule* next;
};
typedef struct _ProcessModule ProcessModule;

ProcessModule* CreateSingleProcessModuleFromDataTable(LDR_DATA_TABLE_ENTRY* dataTable);
void DisplayProcessModule(ProcessModule* list);
void AddQueueProcessModule(ProcessModule* list, ProcessModule* toAdd);
void AddHeadProcessModule(ProcessModule** head, ProcessModule* toAdd);
void FreeProcessModuleList(ProcessModule* list);

#endif // PROCESSMODULE_H
