#include <windows.h>
#include <stdio.h>
#include <Psapi.h>
#include <iostream>
#include <memory>

#include "ProcessUtils.h"

#pragma comment(lib, "version.lib" )

typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);

LPFN_ISWOW64PROCESS fnIsWow64Process;

int IsWow64ProcessCaller(HANDLE hProcess)
{
    BOOL bIsWow64 = FALSE;

    fnIsWow64Process = (LPFN_ISWOW64PROCESS) GetProcAddress(
        GetModuleHandle(TEXT("kernel32")),"IsWow64Process");

    if(fnIsWow64Process != NULL)
    {
        if (!fnIsWow64Process(hProcess,&bIsWow64))
        {
            printf("Erreur lors du test de profondeur de bits du processus\n");
            //Erreur : par défaut on choisi 32 bits
            return -1;
        }
    }
    else
    {
        //IsWow64Process introuvable : OS 32 bits
        return 2;
    }

    //Si bisWow64 == 1, OS 64 bits sinon impossible de savoir
    return bIsWow64 ? 1 : 0;
}

bool GetOSVersionString(OSVersion* version)
{
	WCHAR path[_MAX_PATH];
	if (!GetSystemDirectoryW(path, _MAX_PATH))
		return false;

	wcscat_s(path, L"\\kernel32.dll");

	//
	// Based on example code from this article
	// http://support.microsoft.com/kb/167597
	//

	DWORD handle;
#if (_WIN32_WINNT >= _WIN32_WINNT_VISTA)
	DWORD len = GetFileVersionInfoSizeExW(FILE_VER_GET_NEUTRAL, path, &handle);
#else
	DWORD len = GetFileVersionInfoSizeW(path, &handle);
#endif
	if (!len)
		return false;

	std::unique_ptr<uint8_t> buff(new (std::nothrow) uint8_t[len]);
	if (!buff)
		return false;

#if (_WIN32_WINNT >= _WIN32_WINNT_VISTA)
	if (!GetFileVersionInfoExW(FILE_VER_GET_NEUTRAL, path, 0, len, buff.get()))
#else
	if (!GetFileVersionInfoW(path, 0, len, buff.get()))
#endif
		return false;

	VS_FIXEDFILEINFO *vInfo = nullptr;
	UINT infoSize;

	if (!VerQueryValueW(buff.get(), L"\\", reinterpret_cast<LPVOID*>(&vInfo), &infoSize))
		return false;

	if (!infoSize)
		return false;
	
	version->osMajorVersion = HIWORD(vInfo->dwFileVersionMS);
	version->osMinorVersion = LOWORD(vInfo->dwFileVersionMS);

	return true;
}

int Is64Process(DWORD pid)
{
	DWORD dwVersion, dwMajorVersion, dwMinorVersion = 2;
	OSVersion osVersion;
	GetOSVersionString(&osVersion);	

	dwMajorVersion = osVersion.osMajorVersion;
	dwMinorVersion = osVersion.osMinorVersion;

    if((dwMajorVersion < 5 || (dwMajorVersion == 5 && dwMinorVersion == 1)))
    {
        return 2;
    }
    else
    {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
		if (hProcess == NULL) {
			printf("Erreur : impossible d'ouvrir le processus de pid %u\n", pid);
		} else {
			int wow64 = IsWow64ProcessCaller(hProcess);
			CloseHandle(hProcess);
			return !wow64;
		}
		return 0;
    }
}


BOOL Is64Os()
{
//    printf("int* = %u\n", sizeof(int*));
    return (sizeof(int*) == 8) || (Is64Process(GetCurrentProcessId()) == 0);
}

DWORD GetFirstProcessIdFromProcessName(const char* processName)
{
    DWORD aProcesses[1024], cbNeeded, cProcesses;
    unsigned int i;

    if ( !EnumProcesses( aProcesses, sizeof(aProcesses), &cbNeeded ) )
    {
        printf("Erreur lors de l'enumeration des processus\n");
        return -1;
    }

    cProcesses = cbNeeded / sizeof(DWORD);

    for ( i = 0; i < cProcesses; i++ )
    {
        if( aProcesses[i] != 0 )
        {
            HANDLE hProcess = OpenProcess( PROCESS_QUERY_INFORMATION |
                                               PROCESS_VM_READ,
                                               FALSE, aProcesses[i] );
            if(hProcess != NULL)
            {
                char name[2048] = {'\0'};
                GetModuleBaseNameA(hProcess, NULL, name, sizeof(name) - 1);
                printf("name = %s\npid = %u\n", name, (unsigned int) aProcesses[i]);
                if(strstr(name, processName) != NULL)
                {
                    //printf("name = %s\npid = %u\n", name, aProcesses[i]);
                    return aProcesses[i];
                }
            }
            CloseHandle(hProcess);
        }
    }
    printf("Erreur : impossible de trouver le processus correspondant a \"%s\"\n", processName);
    return -1;
}
