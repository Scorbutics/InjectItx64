#ifndef INJECTOR_H
#define INJECTOR_H

#define INJECTION_METHOD_NT 2
#define INJECTION_METHOD_RTL 1
#define INJECTION_METHOD_CreateRemoteThread 0

DWORD GetExportDllOffset(UINT_PTR uiBaseAddress, char* dllPathName);
PVOID GetRVAFromFilename(char* pathFileName, DWORD* outputFileSize);
int InjectDllCreatingSuspendedProcess(const char* processPathName, const char* cmdLine, const char* dllPathName, int method);
int InjectDllRemoteThread(DWORD pid, const char* dllPathName, int ntMethodBool);
int ReleaseDllRemoteThread(DWORD pid, const char* dllPathName, int ntMethodBool);


#endif // INJECTOR_H
