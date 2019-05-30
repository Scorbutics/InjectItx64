#include <windows.h>
#include <stdio.h>

#include "NtCreateThread.h"
#include "ErrorUtils.h"

struct NtCreateThreadExBuffer {
	ULONG Size;
	ULONG Unknown1;
	ULONG Unknown2;
	PULONG Unknown3;
	ULONG Unknown4;
	ULONG Unknown5;
	ULONG Unknown6;
	PULONG Unknown7;
	ULONG Unknown8;
};
typedef struct NtCreateThreadExBuffer NtCreateThreadExBuffer;


typedef NTSTATUS(WINAPI *LPFUN_NtCreateThreadEx) (
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN LPVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN LPTHREAD_START_ROUTINE lpStartAddress,
	IN LPVOID lpParameter,
	IN BOOL CreateSuspended,
	IN ULONG StackZeroBits,
	IN ULONG SizeOfStackCommit,
	IN ULONG SizeOfStackReserve,
	OUT LPVOID lpBytesBuffer
	);

HANDLE RtlCreateUserThread(HANDLE hProcess, LPVOID lpBaseAddress, LPVOID lpArgs) {

	typedef DWORD(WINAPI * tRtlCreateUserThread)(
		HANDLE 					ProcessHandle,
		PSECURITY_DESCRIPTOR 	SecurityDescriptor,
		BOOL 					CreateSuspended,
		ULONG					StackZeroBits,
		PULONG					StackReserved,
		PULONG					StackCommit,
		LPVOID					StartAddress,
		LPVOID					StartParameter,
		HANDLE 					ThreadHandle,
		LPVOID					ClientID);


	HANDLE hRemoteThread = NULL;
	HMODULE hNtDllModule = GetModuleHandleA("ntdll.dll");
	if (hNtDllModule == NULL) {
		DisplayLastError();
		return NULL;
	}

	tRtlCreateUserThread RtlCreateUserThread = (tRtlCreateUserThread)GetProcAddress(hNtDllModule, "RtlCreateUserThread");

	if (!RtlCreateUserThread) {
		DisplayLastError();
		return NULL;
	}

	RtlCreateUserThread(hProcess, NULL, 0, 0, 0, 0, lpBaseAddress, lpArgs, &hRemoteThread, NULL);

	return hRemoteThread;

}


HANDLE NtCreateRemoteThread(HANDLE hHandle, LPVOID pRoutine, LPVOID parameters) {

	HANDLE hRemoteThread = NULL;

	LPVOID ntCreateThreadExAddr = NULL;
	NtCreateThreadExBuffer ntbuffer;
	DWORD temp1 = 0;
	DWORD temp2 = 0;
	HMODULE ntdllModule = GetModuleHandle(TEXT("ntdll.dll"));

	ntCreateThreadExAddr = GetProcAddress(ntdllModule, "NtCreateThreadEx");

	if (ntCreateThreadExAddr) {
		memset(&ntbuffer, 0, sizeof(NtCreateThreadExBuffer));
		ntbuffer.Size = sizeof(struct NtCreateThreadExBuffer);
		ntbuffer.Unknown1 = 0x10003;
		ntbuffer.Unknown2 = 0x8;
		ntbuffer.Unknown3 = &temp2;
		ntbuffer.Unknown4 = 0;
		ntbuffer.Unknown5 = 0x10004;
		ntbuffer.Unknown6 = 4;
		ntbuffer.Unknown7 = &temp1;
		ntbuffer.Unknown8 = 0;

		LPFUN_NtCreateThreadEx funNtCreateThreadEx = (LPFUN_NtCreateThreadEx)ntCreateThreadExAddr;
		NTSTATUS status = funNtCreateThreadEx(
			&hRemoteThread,
			0x1FFFFF,								//All accesses
			NULL,
			hHandle,
			(LPTHREAD_START_ROUTINE)pRoutine,
			parameters,
			FALSE,
			0,
			0,
			0,
			//NULL
			&ntbuffer
			);

		if (hRemoteThread == NULL) {
			printf("Error : NtCreateThreadEx Failed (returned status %08x)\n", (unsigned int)status);
			DisplayLastError();
		}
		else {
			return hRemoteThread;
		}

	}
	else {
		printf("Error : unable to find \"NtCreateThreadEx\" in ntdll.dll\n");
	}

	return NULL;
}
