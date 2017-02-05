#ifndef NTCREATETHREAD_H
#define NTCREATETHREAD_H


HANDLE NtCreateRemoteThread(HANDLE hHandle, LPVOID pRoutine, LPVOID parameters);
HANDLE RtlCreateUserThread(HANDLE hProcess, LPVOID lpBaseAddress, LPVOID lpSpace);

#endif // NTCREATETHREAD_H
