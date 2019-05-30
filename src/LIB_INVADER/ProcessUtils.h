#ifndef PROCESSUTILS_H
#define PROCESSUTILS_H

struct tagOSVersion {
	DWORD osMajorVersion;
	DWORD osMinorVersion;
};

typedef struct tagOSVersion OSVersion;

int Is64Process(DWORD pid);
BOOL Is64Os();
DWORD GetFirstProcessIdFromProcessName(const char* processName);

#endif // PROCESSUTILS_H
