#ifndef _PEB_LDR_DATA_H
#define _PEB_LDR_DATA_H

//module name : ntdll
struct _PEB_LDR_DATA
{	/* +0x000 */ 	ULONG Length ;
    /* +0x004 */ 	BOOLEAN Initialized ;
    /* +0x008 */ 	HANDLE /* Ptr64 Void */ SsHandle ;
    /* +0x010 */ 	LIST_ENTRY InLoadOrderModuleList ;
    /* +0x020 */ 	LIST_ENTRY InMemoryOrderModuleList ;
    /* +0x030 */ 	LIST_ENTRY InInitializationOrderModuleList ;

    //InMemoryOrderModuleList
    //The head of a doubly-linked list that contains the loaded modules for the process. Each item in the list is a pointer to an LDR_DATA_TABLE_ENTRY structure.
    //For more information, see Remarks.

    /* +0x040 */ 	PVOID /* Ptr64 Void */ EntryInProgress ;
    /* +0x048 */ 	BOOLEAN ShutdownInProgress ;
    /* +0x050 */ 	HANDLE /* Ptr64 Void */ ShutdownThreadId ;

};
typedef struct _PEB_LDR_DATA PEB_LDR_DATA;
typedef PEB_LDR_DATA *PPEB_LDR_DATA;

#endif // _PEB_LDR_DATA_H
