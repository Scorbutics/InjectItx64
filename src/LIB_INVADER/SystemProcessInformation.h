#ifndef SYSTEMPROCESSINFORMATION_H_INCLUDED
#define SYSTEMPROCESSINFORMATION_H_INCLUDED

typedef DWORD KPRIORITY; // Thread priority

typedef enum _KWAIT_REASON
{
         Executive = 0,
         FreePage = 1,
         PageIn = 2,
         PoolAllocation = 3,
         DelayExecution = 4,
         Suspended = 5,
         UserRequest = 6,
         WrExecutive = 7,
         WrFreePage = 8,
         WrPageIn = 9,
         WrPoolAllocation = 10,
         WrDelayExecution = 11,
         WrSuspended = 12,
         WrUserRequest = 13,
         WrEventPair = 14,
         WrQueue = 15,
         WrLpcReceive = 16,
         WrLpcReply = 17,
         WrVirtualMemory = 18,
         WrPageOut = 19,
         WrRendezvous = 20,
         Spare2 = 21,
         Spare3 = 22,
         Spare4 = 23,
         Spare5 = 24,
         WrCalloutStack = 25,
         WrKernel = 26,
         WrResource = 27,
         WrPushLock = 28,
         WrMutex = 29,
         WrQuantumEnd = 30,
         WrDispatchInt = 31,
         WrPreempted = 32,
         WrYieldExecution = 33,
         WrFastMutex = 34,
         WrGuardedMutex = 35,
         WrRundown = 36,
         MaximumWaitReason = 37
} KWAIT_REASON;

typedef struct _CLIENT_ID {
    DWORD          UniqueProcess;
    DWORD          UniqueThread;
} CLIENT_ID;

typedef struct _VM_COUNTERS {
#ifdef _WIN64
    SIZE_T		   PeakVirtualSize;
    SIZE_T         PageFaultCount;
    SIZE_T         PeakWorkingSetSize;
    SIZE_T         WorkingSetSize;
    SIZE_T         QuotaPeakPagedPoolUsage;
    SIZE_T         QuotaPagedPoolUsage;
    SIZE_T         QuotaPeakNonPagedPoolUsage;
    SIZE_T         QuotaNonPagedPoolUsage;
    SIZE_T         PagefileUsage;
    SIZE_T         PeakPagefileUsage;
    SIZE_T         VirtualSize;
#else
    SIZE_T         PeakVirtualSize;
    SIZE_T         VirtualSize;
    ULONG          PageFaultCount;
    SIZE_T         PeakWorkingSetSize;
    SIZE_T         WorkingSetSize;
    SIZE_T         QuotaPeakPagedPoolUsage;
    SIZE_T         QuotaPagedPoolUsage;
    SIZE_T         QuotaPeakNonPagedPoolUsage;
    SIZE_T         QuotaNonPagedPoolUsage;
    SIZE_T         PagefileUsage;
    SIZE_T         PeakPagefileUsage;
#endif
} VM_COUNTERS;

typedef struct _SYSTEM_THREAD_INFORMATION {
  LARGE_INTEGER           KernelTime;
  LARGE_INTEGER           UserTime;
  LARGE_INTEGER           CreateTime;
  ULONG                   WaitTime;
  PVOID                   StartAddress;
  CLIENT_ID               ClientId;
  KPRIORITY               Priority;
  LONG                    BasePriority;
  ULONG                   ContextSwitchCount;
  ULONG                   State;
  ULONG                   WaitReason;   //KWAIT_REASON

} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;


typedef struct _SYSTEM_PROCESS_INFORMATION {                           /* x86/x64 */
    ULONG                               NextEntryOffset;                /* 00/00 */
    ULONG                               NumberOfThreads;                /* 04/04 */
    LARGE_INTEGER                       WorkingSetPrivateSize;          /* 08/08 */
    ULONG                               HardFaultCount;                 /* 12/12 */
    ULONG                               NumberOfThreadsHighWatermark;   /* 16/16 */
    ULONGLONG                           CycleTime;                      /* 1A/1A */
    LARGE_INTEGER                       CreateTime;                     /* 20/20 */
    LARGE_INTEGER                       UserTime;                       /* 28/28 */
    LARGE_INTEGER                       KernelTime;                     /* 30/30 */
    UNICODE_STRING                      ImageName;                      /* 38/38 */
    KPRIORITY                           BasePriority;                   /* 40/48 */
    HANDLE                              ProcessId;                      /* 44/50 */
    HANDLE                              InheritedFromProcessId;         /* 48/58 */
    ULONG                               HandleCount;                    /* 4C/60 */
    DWORD                               Reserved2[2];                   /* 50/64 */
    //ULONG                             PrivatePageCount;
    VM_COUNTERS                         VirtualMemoryCounters;          /* 58/70 */
    IO_COUNTERS                         IoCounters;                     /* 88/D0 */
    SYSTEM_THREAD_INFORMATION           Threads[1];                     /* B8/100 */
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;




#endif // SYSTEMPROCESSINFORMATION_H_INCLUDED
