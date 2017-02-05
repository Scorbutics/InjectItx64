#ifndef DEF_QUERYPROCESSINFORMATION
#define DEF_QUERYPROCESSINFORMATION

#include "ProcessBasicInformation.h"

#define PTR_ADD_OFFSET(Pointer, Offset) ((PVOID)((ULONG_PTR)(Pointer) + (ULONG_PTR)(Offset)))

void DisplayProcessList(HMODULE ntdllLibrary);
ProcessInformationList* GetProcessList(HMODULE ntdllLibrary);
ProcessInformation GetProcessInformationsFromPID(HMODULE ntdllLibrary, unsigned long pid);
PROCESS_BASIC_INFORMATION* QueryProcessBasicInformation(HMODULE ntdll, unsigned long pid);
ProcessInformationList* GetProcessInformationsFromName(HMODULE ntdllLibrary, char* processPathName);

#endif // DEF_QUERYPROCESSINFORMATION
