#ifndef _RTL_BALANCED_NODE_H
#define _RTL_BALANCED_NODE_H

//module name : ntdll
struct _RTL_BALANCED_NODE
{	union
    {
        /* +0x000 */ 	struct _RTL_BALANCED_NODE* /* Ptr64 _RTL_BALANCED_NODE */ Children [2];
        struct {
        /* +0x000 */ 	struct _RTL_BALANCED_NODE* /* Ptr64 _RTL_BALANCED_NODE */ Left ;
        /* +0x008 */ 	struct _RTL_BALANCED_NODE* /* Ptr64 _RTL_BALANCED_NODE */ Right ;
        };
    };

    union
    {
        /* +0x010 */ 	ULONG_PTR /* Ptr64 _RTL_BALANCED_NODE */ Red :1;
        /* +0x010 */ 	ULONG_PTR /* Ptr64 _RTL_BALANCED_NODE */ Balance :2;
        /* +0x010 */ 	ULONG_PTR ParentValue ;
    };

};
typedef struct _RTL_BALANCED_NODE RTL_BALANCED_NODE;

#endif // _RTL_BALANCED_NODE_H
