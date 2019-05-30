#include <stdio.h>
#include <string.h>
#include <windows.h>

#include "LIB_INVADER/Injector.h"
#include "LIB_INVADER/ProcessInformation.h"
#include "LIB_INVADER/GetProcessInformation.h"
#include "LIB_INVADER/DebugPrivileges.h"

#include "LIB_INVADER/ArgUtils.h"

const char* usageRules = "Utilisation : commandes\n"
" -i : inject the dll to the process\n"
" -pid <integer> : use a process id instead of providing a name\n"
" -f : free the dll from the process\n"
"Exemple : injectit.exe calc.exe -i injectdll.dll \n"
"injecte un module \"injectdll.dll\" dans la calculatrice Windows\n";

void ProcessPidInjection(unsigned int pid, const char* nameInjected, const char* dllPathName, const char* argv[], int argc)
{
	if (pid != 0)
	{
		if (FileExists(dllPathName))
		{
			
			if (FindArg((const char**)argv, argc, "-iNt") != NULL)
			{
				printf("Injecting %s with %s... (using NtCreateThreadEx)\n", nameInjected, dllPathName);
				if (!InjectDllRemoteThread(pid, (char*)dllPathName, INJECTION_METHOD_NT))
				{
					printf("Injection Failed\n");
				} else {
					system("cls");
				}
			}
			else if (FindArg((const char**)argv, argc, "-iRtl") != NULL)
			{
				printf("Injecting %s with %s... (using RtlCreateUserThread)\n", nameInjected, dllPathName);
				if (!InjectDllRemoteThread(pid, (char*)dllPathName, INJECTION_METHOD_RTL))
				{
					printf("Injection Failed\n");
				} else {
					system("cls");
				}
			}
			else if (FindArg((const char**)argv, argc, "-i") != NULL)
			{
				printf("Injecting %s with %s... (using CreateRemoteThread)\n", nameInjected, dllPathName);
				if (!InjectDllRemoteThread(pid, (char*)dllPathName, INJECTION_METHOD_CreateRemoteThread))
				{
					printf("Injection Failed\n");
				} else {
					system("cls");
				}
			}
			else if (FindArg((const char**)argv, argc, "-fNt") != NULL)
			{
				printf("Releasing %s in %s... (using NtCreateThreadEx)\n", dllPathName, nameInjected);
				ReleaseDllRemoteThread(pid, (char*)dllPathName, INJECTION_METHOD_NT);
			}
			else if (FindArg((const char**)argv, argc, "-fRtl") != NULL)
			{
				printf("Releasing %s in %s... (using RtlCreateUserThread)\n", dllPathName, nameInjected);
				ReleaseDllRemoteThread(pid, (char*)dllPathName, INJECTION_METHOD_RTL);
			}
			else if (FindArg((const char**)argv, argc, "-f") != NULL)
			{
				printf("Releasing %s in %s... (using CreateRemoteThread)\n", dllPathName, nameInjected);
				ReleaseDllRemoteThread(pid, (char*)dllPathName, INJECTION_METHOD_CreateRemoteThread);
			}
			else
			{
				puts(usageRules);
			}
		}
		else
		{
			printf("Erreur : impossible de trouver la dll specifiee (%s)\n", dllPathName);
		}
	}
	else
	{
		printf("Erreur : processus introuvable ou non valide\n");
	}
}

int main(int argc, char* argv[])
{
	if (argc < 3)
	{
		puts(usageRules);
		return 1;
	}

	unsigned int pid = 0;
	const char *processPathName = FindExtensionPathName((const char **)argv, argc, ".exe");
	const char *dllPathName = FindExtensionPathName((const char **)argv, argc, ".dll");
	const char *pidPathName = FindPidPathName((const char **)argv, argc);
	const char *injectNtCS = FindArg((const char**)argv, argc, "-iNtCS");
	const char *injectRtlCS = FindArg((const char**)argv, argc, "-iRtlCS");
	const char *injectCS = FindArg((const char**)argv, argc, "-iCS");

	BOOL mustBeActiveProcess = !injectNtCS && !injectRtlCS && !injectCS;

	if (dllPathName == NULL)
	{
		printf("Erreur : impossible de determiner quelle est la dll a injecter\n");
		return 1;
	}

	EnableDebugPrivilege(TRUE);

	if ((pidPathName == NULL && processPathName == NULL) && mustBeActiveProcess)
	{
		printf("Erreur : impossible de determiner quel est le processus a subir l'injection\n");
		return 1;
	} else if (!mustBeActiveProcess) {
		if (processPathName == NULL) {
			printf("Erreur : impossible de determiner quel est le processus a lancer et a subir l'injection\n");
			return 1;
		}

		if (injectNtCS) {
			if (!InjectDllCreatingSuspendedProcess(processPathName, FindNextArg((const char **)argv, argc, "-cmdLine"), dllPathName, INJECTION_METHOD_NT)) {
				printf("Injection Failed\n");
				return 1;
			}
		} else if (injectRtlCS) {
			if (!InjectDllCreatingSuspendedProcess(processPathName, FindNextArg((const char **)argv, argc, "-cmdLine"), dllPathName, INJECTION_METHOD_RTL)) {
				printf("Injection Failed\n");
				return 1;
			}
		} else if (injectCS) {
			if (!InjectDllCreatingSuspendedProcess(processPathName, FindNextArg((const char **)argv, argc, "-cmdLine"), dllPathName, INJECTION_METHOD_CreateRemoteThread)) {
				printf("Injection Failed\n");
				return 1;
			}
		}
	} else {

		if (pidPathName == NULL)
		{
			ProcessInformationList *pList = GetProcessInformationsFromName(NULL, (char*)processPathName);
			unsigned int i;
			printf("Processes found :\n");
			for (i = 0; i < pList->length; i++)
			{
				printf("\tPID : %u\n\tName : %s\n", (unsigned int)pList->data[i].pid, pList->data[i].name);
				ProcessPidInjection(pList->data[i].pid, pList->data[i].name, dllPathName, (const char **)argv, argc);
			}

			free(pList->data);
			free(pList);
		}
		else
		{
			pid = atoi(pidPathName);
			ProcessPidInjection(pid, pidPathName, dllPathName, (const char **)argv, argc);
		}

	}


	return 0;
}







