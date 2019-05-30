#ifndef DEF_PROCESSINFORMATION
#define DEF_PROCESSINFORMATION

struct ProcessInformation {
    unsigned long pid, handleCount;
    unsigned int threadCount;
    char name[1024];
};
typedef struct ProcessInformation ProcessInformation;

struct ProcessInformationList {
    ProcessInformation* data;
    unsigned int length;
};
typedef struct ProcessInformationList ProcessInformationList;

struct ProcessWithHandlesList {
    ProcessInformation dataProcess;
    char fullHandleName[512];
    char handleType[256];
    struct ProcessWithHandlesList* next;
};
typedef struct ProcessWithHandlesList ProcessWithHandlesList;

struct HandleProcessInformation {
    unsigned long processPid;
    char name[1024], type[256], processName[256];
    struct HandleProcessInformation* next;
};
typedef struct HandleProcessInformation HandleProcessInformation;

void FreeHandleProcessInformation(HandleProcessInformation* handle);
HandleProcessInformation* CreateHandleProcessInformation();
void DisplayHandleProcessInformation(HandleProcessInformation* handle);

#endif // DEF_PROCESSINFORMATION
