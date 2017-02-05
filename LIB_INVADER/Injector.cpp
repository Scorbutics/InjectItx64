#include <stdio.h>
#include <windows.h>

#include "NtCreateThread.h"
#include "ASMUtils.h"
#include "ProcessUtils.h"
#include "ErrorUtils.h"
#include "Injector.h"


#define DLL_METASPLOIT_ATTACH	4
#define DLL_METASPLOIT_DETACH	5
#define DLL_QUERY_HMODULE		6

#define DEREF( name )*(UINT_PTR *)(name)
#define DEREF_64( name )*(DWORD64 *)(name)
#define DEREF_32( name )*(DWORD *)(name)
#define DEREF_16( name )*(WORD *)(name)
#define DEREF_8( name )*(BYTE *)(name)

#define ERROR_CODE_NOT_VALID_WIN32_APP 193
#define ERROR_CODE_FILE_NOT_FOUND 2

/*
typedef struct _IMAGE_DOS_HEADER
{

    WORD e_magic;       // Magic number
    WORD e_cblp;        // Bytes on last page of file
    WORD e_cp;          // Pages in file
    WORD e_crlc;        // Relocations
    WORD e_cparhdr;     // Size of header in paragraphs
    WORD e_minalloc;    // Minimum extra paragraphs needed
    WORD e_maxalloc;    // Maximum extra paragraphs needed
    WORD e_ss;          // Initial (relative) SS value
    WORD e_sp;          // Initial SP value
    WORD e_csum;        // Checksum
    WORD e_ip;          // Initial IP value
    WORD e_cs;          // Initial (relative) CS value
    WORD e_lfarlc;      // File address of relocation table
    WORD e_ovno;        // Overlay number
    WORD e_res[4];      // Reserved words
    WORD e_oemid;       // OEM identifier (for e_oeminfo)
    WORD e_oeminfo;     // OEM information; e_oemid specific
    WORD e_res2[10];    // Reserved words
    LONG e_lfanew;      // File address of new exe header

} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
*/

PVOID AllocWriteStrInTarget(HANDLE hTarget, const char* str) {
	PVOID loc = VirtualAllocEx(hTarget, NULL, strlen(str) + 1, MEM_COMMIT, PAGE_READWRITE);
	WriteProcessMemory(hTarget, loc, str, strlen(str) + 1, NULL);
	return loc;
}

DWORD GetFileOffsetFromRVA(DWORD pRva, UINT_PTR pBaseAddress)
{
    WORD index;

    //Pointe vers l'adresse réelle du header des nouveaux fichiers exécutables (et non les exécutables DOS)
    // = Récupération du pointeur vers le header du fichier
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(pBaseAddress + ((PIMAGE_DOS_HEADER)pBaseAddress)->e_lfanew);

    //Pointe vers la première section du header, se situant après le header optionnel (à ADDR_OPT_HEADER + SIZE_OPT_HEADER)
    // = Récupération du pointeur vers la 1ère section du header
    //Equivalent à IMAGE_FIRST_SECTION(pNtHeaders);
    PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&pNtHeaders->OptionalHeader) + pNtHeaders->FileHeader.SizeOfOptionalHeader);

    //Si le pointeur fourni est hors des sections du header, on le retourne lui-même : il ne figure pas dans les sections.
    if(pRva < pSectionHeader[0].PointerToRawData)
        return pRva;

    for(index = 0; index < pNtHeaders->FileHeader.NumberOfSections; index++)
    {
        PIMAGE_SECTION_HEADER pCurSection = pSectionHeader + index;
        //Si le pointeur de RVA est dans la section pointée courante (entre "son adresse de base" et "son adresse de base + taille de la section")
        if(pRva >= pCurSection->VirtualAddress && pRva < pCurSection->VirtualAddress + pCurSection->SizeOfRawData)
        {

            //Maintenant que nous sommes sûrs que la RVA appartient bien à la section courante,
            //la "formule magique" pour obtenir le file offset pointant vers cette adresse est :
            // pRva - pVa + pSection
            DWORD fileOffset = pRva - pCurSection->VirtualAddress;
            fileOffset += pCurSection->PointerToRawData;
            return fileOffset;
        }
    }
    return 0;
}

//Les PE files peuvent être à la fois de 64 bits ou de 32 bits.
//Cette fonction renvoie "true" lorsqu'un PE de 32 bits tourne sur une machine de 32 bits,
//ou un PE de 64 bits sur une machine de 64 bits
int IsValidCurrentPEBArchitecture(PVOID baseAddress)
{
    DWORD currentArch;

#ifdef WIN_X64
    currentArch = 2;
#else
    currentArch = 1;
    //Toute archi sauf x64 (WIN RT et WIN32)
#endif

    DWORD osVersion = ((PIMAGE_NT_HEADERS)baseAddress)->OptionalHeader.Magic;

    if(
        (osVersion == IMAGE_NT_OPTIONAL_HDR32_MAGIC && currentArch != 1) // PE32, x64 running
            ||
        (osVersion == IMAGE_NT_OPTIONAL_HDR64_MAGIC && currentArch != 2) // PE64, x86 running
      )
    {
            return 0;
    }
    return 1;
}



/*
 *typedef struct _IMAGE_EXPORT_DIRECTORY
{
    DWORD Characteristics;
    DWORD TimeDateStamp;
    WORD MajorVersion;
    WORD MinorVersion;
    DWORD Name;
    DWORD Base;
    DWORD NumberOfFunctions;        //Le nombre de fonctions exportées par le module
    DWORD NumberOfNames;            //Le nombre de noms de fonctions
    DWORD AddressOfFunctions;       //Un pointeur (PDWORD*) de pointeurs vers les adresses des fonctions
    DWORD AddressOfNames;           //Pointeur (DWORD*) sur la première case d'un tableau de
                                    //pointeurs vers la chaîne de caractères du nom de la fonction
                                    //(en quelque sorte, un String**)
    DWORD AddressOfNameOrdinals;    //Pointeur (WORD*) vers un tableau d'index pour convertir un ordinal
                                    //vers son index correspondant dans AddressOfFUnctions
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
*/


DWORD GetExportDllOffset(UINT_PTR uiBaseAddress, char* dllPathName)
{
    UINT_PTR uiExportDir     = 0;
    UINT_PTR uiNameArray     = 0;
    UINT_PTR uiAddressArray  = 0;
    UINT_PTR uiNameOrdinals  = 0;
    DWORD dwCounter          = 0;

    DWORD pExportDllResult = 0;

    if(!IsValidCurrentPEBArchitecture((PVOID)uiBaseAddress))
    {
        printf("Error : Invalid PEB version\n");
        return 0;
    }

    printf("Base address : %p\n", (PVOID)uiBaseAddress);

    //Adresses RVA
    uiExportDir = uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew;


    if(((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size != 0)
    {
        uiNameArray = (UINT_PTR)&((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];
        printf("Export dir RVA : %p\n", (PVOID)uiExportDir);
        printf("Export Name Array RVA : %p\n", (PVOID)uiNameArray);

        //Adresses basées sur l'offset par rapport au fichier
        uiExportDir = uiBaseAddress + GetFileOffsetFromRVA( ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress, uiBaseAddress );
        uiNameArray = uiBaseAddress + GetFileOffsetFromRVA( ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfNames, uiBaseAddress );
        uiAddressArray = uiBaseAddress + GetFileOffsetFromRVA( ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfFunctions, uiBaseAddress );
        uiNameOrdinals = uiBaseAddress + GetFileOffsetFromRVA( ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfNameOrdinals, uiBaseAddress );

        printf("Export Dir FILE OFFSET : %p\n", (PVOID)uiExportDir);
        printf("Export Name Array FILE OFFSET : %p\n", (PVOID)uiNameArray);
        printf("Export Address Array FILE OFFSET : %p\n", (PVOID)uiAddressArray);
        printf("Export Name Ordinals FILE OFFSET : %p\n", (PVOID)uiNameOrdinals);

        //Nombre de fonctions exportées dans la dll
        dwCounter = ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->NumberOfNames;

        printf("Number of Names : %u\n", (unsigned int) dwCounter);

        LPSTR libname[256];
        size_t i = 0;

        while(dwCounter--)
        {
            printf("Library Name   :");

            //Get the name of each DLL
            libname[i] = (PCHAR)((DWORD_PTR)uiBaseAddress + GetFileOffsetFromRVA(DEREF_32(uiNameArray), uiBaseAddress));
            printf("%s\n", libname[i]);

            if(dllPathName != NULL && strstr(libname[i], dllPathName) != NULL )
            {
                uiAddressArray = uiBaseAddress + GetFileOffsetFromRVA( ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfFunctions, uiBaseAddress );

                // use the functions name ordinal as an index into the array of name pointers
                uiAddressArray += (DEREF_16( uiNameOrdinals ) * sizeof(DWORD) );
                pExportDllResult = GetFileOffsetFromRVA(DEREF_32(uiAddressArray), uiBaseAddress);
            }

            // get the next exported function name
            uiNameArray += sizeof(DWORD);

            // get the next exported function name ordinal
            uiNameOrdinals += sizeof(WORD);
            i++;
        }

    }
    else
    {
        printf("No Export Table!\n");
    }

    return pExportDllResult;
}

/*
 * ATTENTION, NE PAS OUBLIER L'APPEL à
 *
    VirtualFree(uiBaseAddress, fileSize, MEM_DECOMMIT);

    après avoir utilisé cette fonction.
*/
PVOID GetRVAFromFilename(char* pathFileName, DWORD* outputFileSize)
{
    HANDLE handle = CreateFile((LPCTSTR)pathFileName, GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    DWORD byteRead;

    if(handle)
    {
        *outputFileSize = GetFileSize(handle, NULL);
        PVOID vPFile = VirtualAlloc(NULL, *outputFileSize, MEM_COMMIT, PAGE_READWRITE);
        ReadFile(handle, vPFile, *outputFileSize, &byteRead, NULL);
        CloseHandle(handle);

        return vPFile;
    }
    return (PVOID)NULL;
}

DWORD WaitReturnValueFromThread(HANDLE pHandle, PDWORD exitCode) {
	DWORD result = WaitForSingleObject(pHandle, INFINITE);

    if (result == WAIT_OBJECT_0) {
        BOOL rc = GetExitCodeThread( pHandle, exitCode);
        if (rc != NULL) {
			return *exitCode;
        }
        DisplayLastError();
    }

    return -1;
}


DWORD Queryx86ProcAddress(LPWSTR moduleName, LPWSTR procName) {
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	WCHAR cmdLine[2048] = { 0 };
	DWORD result;
	wsprintf(cmdLine, L"Getx86Proc.exe %s %s", moduleName, procName);

	if (!CreateProcess(
		NULL,
		cmdLine,
		NULL,           // Process handle not inheritable
		NULL,           // Thread handle not inheritable
		FALSE,          // Set handle inheritance to FALSE
		0,              // No creation flags
		NULL,           // Use parent's environment block
		NULL,           // Use parent's starting directory 
		&si,            // Pointer to STARTUPINFO structure
		&pi))
	{
		printf("CreateProcess (on Getx86Proc.exe) failed : ");
		DWORD lastErrorCode = GetLastError();
		if (lastErrorCode != ERROR_CODE_FILE_NOT_FOUND) {
			DisplayErrorWithCode(NULL, lastErrorCode);
		}
		else {
			printf(" unable to find Getx86Proc.exe. Please put it next to Injectx64 and rewrite your command.\n");
		}

		return NULL;
	}

	// Wait until child process exits.
	WaitForSingleObject(pi.hProcess, INFINITE);

	GetExitCodeProcess(pi.hProcess, &result);

	// Close process and thread handles. 
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	return result;
}

PVOID InjectLoadLibraryInMem(HANDLE pHandle, const char* fullDllPath, PVOID dllFullPathNameLoc, bool injectx64, unsigned int *outputCodeSize) {
	BYTE* gCode;
	unsigned int codeSize;

	/*
	* "Strictly speaking, this is not guaranteed to work because the address of LoadLibraryA in your process is not necessarily the same as LoadLibraryA in the other process.
	* However, in practice it does work because system DLLs like kernel32 (where LoadLibraryA resides) are mapped to the same address in all processes,
	* so LoadLibraryA also has the same address in both processes."
	(Igor Skochinsky)
	Quoted from StackOverflow

	=> In fact ASLR is only started once at startup and then, each Win32 Dll have the same address in any process
	*/


	if (injectx64) {
#ifdef _WIN64
		PVOID outputCurrentDir = VirtualAllocEx(pHandle, NULL, 2048 + 1, MEM_COMMIT, PAGE_READWRITE);
		char * dllCurrentDirectory = (char*) malloc(strlen(fullDllPath) + 1);
		strcpy(dllCurrentDirectory, fullDllPath);

		bool firstSlash = false;
		
		for (int i = strlen(fullDllPath) + 1; i >= 0; i--) {
			if (fullDllPath[i] == '\\') {
				if (!firstSlash) {
					firstSlash = true;
					dllCurrentDirectory[i] = '\0';
					continue;
				}
			} else if (!firstSlash) {
				continue;
			}

			dllCurrentDirectory[i] = fullDllPath[i];
		}
		
		PVOID dllCurDirLoc = AllocWriteStrInTarget(pHandle, dllCurrentDirectory);
		free(dllCurrentDirectory);

		PVOID loadLibAProc = (PVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
		PVOID setCurrentDirectoryA = (PVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "SetCurrentDirectoryA");
		PVOID getCurrentDirectoryA = (PVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetCurrentDirectoryA");
		PVOID getLastErrorProc = (PVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetLastError");

		if (loadLibAProc == NULL) {
			printf("Error occured while finding LoadLibraryA address : address = 0x%p\n", loadLibAProc);
			DisplayLastError();
			return NULL;
		}

		if (getLastErrorProc == NULL) {
			printf("Error occured while finding GetLastError address : address = 0x%p\n", getLastErrorProc);
			DisplayLastError();
			return NULL;
		}

		BYTE code[] = {
			0x51, 0x52, 0x57,								//PUSH RCX, PUSH RDX, PUSH RDI
			0x48, 0x81, 0xEC, 0x80, 0x00, 0x00, 0x00,		//SUB RSP, 0x80
			
			//GetCurrentDirectoryA
			0x48, 0xB8,										//MOV RAX,
			0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE, //getCurrentDirectoryA
			0x48, 0xC7, 0xC1,								//MOV RCX, 2048
			0x00, 0x08, 0x00, 0x00,
			0x48, 0xBA,										//MOV RDX,
			0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE, //outputCurDir
			0xFF, 0xD0,										//CALL RAX
			
			//SetCurrentDirectoryA
			0x48, 0xB8,										//MOV RAX,
			0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE, //setCurrentDirectoryA
			0x48, 0xB9, 									//MOV RCX,
			0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE, //dllDirectory
			0xFF, 0xD0,										//CALL RAX
			
			//LoadLibraryA
			0x48, 0xB8,										//MOV RAX, 
			0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE, //loadLibAProc
			0x48, 0xB9,										//MOV RCX, 
			0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE, //dllFullPathNameLoc
			0xFF, 0xD0,										//CALL RAX
			0x48, 0x85, 0xC0,								//TEST RAX, RAX
			0x74, 0x05,										//JE <ERROR>
			0x48, 0x31, 0xC0,								//XOR RAX, RAX
			0xEB, 0x0C,										//JMP <END>
			//<ERROR>:
			0x48, 0xb8,										//MOV RAX,
			0xef, 0xbe, 0xad, 0xde, 0xef, 0xbe, 0xad, 0xde, //getLastErrorProc
			0xff, 0xd0,										//CALL RAX
			//<END>:

			//SetCurrentDirectoryA
			0x48, 0x89, 0xC7,								//MOV RDI, RAX
			0x48, 0xB8,										//MOV RAX,
			0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE, //setCurrentDirectoryA
			0x48, 0xB9, 									//MOV RCX,
			0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE, //outputCurDir
			0xFF, 0xD0,										//CALL RAX
			0x48, 0x89, 0xF8,								//MOV RAX, RDI
			
			0x48, 0x81, 0xc4, 0x80, 0x00, 0x00, 0x00,		//ADD RSP, 0x80
			0x5F, 0x5A, 0x59,								//POP RDI, POP RDX, POP RCX
			0xC3 };											//RET


		ASMUtils::reverseAddressx64((DWORD64)getCurrentDirectoryA, code + 9 + 3);
		ASMUtils::reverseAddressx64((DWORD64)outputCurrentDir, code + 26 + 3);
		ASMUtils::reverseAddressx64((DWORD64)setCurrentDirectoryA, code + 38 + 3);
		ASMUtils::reverseAddressx64((DWORD64)dllCurDirLoc, code + 48 + 3);
		ASMUtils::reverseAddressx64((DWORD64)loadLibAProc, code + 60 + 3);
		ASMUtils::reverseAddressx64((DWORD64)dllFullPathNameLoc, code + 70 + 3);
		ASMUtils::reverseAddressx64((DWORD64)getLastErrorProc, code + 92 + 3);
		ASMUtils::reverseAddressx64((DWORD64)setCurrentDirectoryA, code + 105 + 5);
		ASMUtils::reverseAddressx64((DWORD64)outputCurrentDir, code + 115 + 5);

		//ASMUtils::printCode(code, sizeof(code));

		gCode = code;
		codeSize = sizeof(code);
#else
		printf("Erreur : l'injection a partir d'un injecteur 32 bits dans un processus 64 bits n'est pas supportee dans cette version\nMerci d'utiliser la version 64 bits\n");
		return NULL;
#endif
	} else {
#ifdef _WIN64
		DWORD loadLibAProc = Queryx86ProcAddress(L"kernel32.dll", L"LoadLibraryA");
		DWORD setCurrentDirectoryA = Queryx86ProcAddress(L"kernel32.dll", L"SetCurrentDirectoryA");
		DWORD getCurrentDirectoryA = Queryx86ProcAddress(L"kernel32.dll", L"GetCurrentDirectoryA");
		DWORD getLastErrorProc = Queryx86ProcAddress(L"kernel32.dll", L"GetLastError");
#else 
		DWORD loadLibAProc = (DWORD)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
		DWORD setCurrentDirectoryA = (DWORD)GetProcAddress(GetModuleHandleA("kernel32.dll"), "SetCurrentDirectoryA");
		DWORD getCurrentDirectoryA = (DWORD)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetCurrentDirectoryA");
		DWORD getLastErrorProc = (DWORD)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetLastError");
#endif
		if (loadLibAProc == NULL) {
			printf("Error occured while finding LoadLibraryA address : address = 0x%08x\n", loadLibAProc);
			return NULL;
		}

		if (getLastErrorProc == NULL) {
			printf("Error occured while finding GetLastError address : address = 0x%08x\n", getLastErrorProc);
			return NULL;
		}

		BYTE code[] = {
			0x57,										//PUSH EDI
			0x83, 0xEC, 0x40,							//SUB ESP, 0x40
			0xB8,										//MOV EAX,
			0xEF, 0xBE, 0xAD, 0xDE,						//loadLibAProc
			0x68,										//PUSH
			0xEF, 0xBE, 0xAD, 0xDE,						//dllFullPathNameLoc
			0xFF, 0xD0,									//CALL EAX
			0x85, 0xC0,									//TEST EAX, EAX
			0x74, 0x04,									//JE <ERROR>
			0x31, 0xC0,									//XOR EAX, EAX
			0xEB, 0x07,									//JMP <END>
			//<ERROR>:
			0xB8,										//MOV EAX,
			0xEF, 0xBE, 0xAD, 0xDE,						//getLastErrorProc
			0xFF, 0xD0,									//CALL EAX
			//<END>:
			0x83, 0xC4, 0x40,							//ADD ESP, 0x40
			0x5F,										//POP EDI
			0xC3 };										//RET



		DWORD dllLoc = (DWORD)dllFullPathNameLoc;

		ASMUtils::reverseAddressx86((DWORD)loadLibAProc, code + 5);
		ASMUtils::reverseAddressx86(dllLoc, code + 10);
		ASMUtils::reverseAddressx86((DWORD)getLastErrorProc, code + 25);

		gCode = code;
		codeSize = sizeof(code);
	}
	*outputCodeSize = codeSize;
	return ASMUtils::writeAssembly(pHandle, gCode, codeSize);
}

DWORD64 GetExecutionPointer(PCONTEXT ctx) {
	/* We cheat here : we convert every address to a 64 bits size variable in order 
	   to have enough place to stock both a 32 bits value or a 64 bits one */
#ifdef _WIN64
	DWORD64 executionPointer = ctx->Rip;
#else
	DWORD64 executionPointer = (DWORD64)ctx->Eip;
#endif
	return executionPointer;
}

void SetExecutionPointer(PCONTEXT ctx, DWORD64 ep) {
#ifdef _WIN64
	ctx->Rip = ep;
#else
	ctx->Eip = (DWORD) ep;
#endif
}

PVOID InjectInfiniteLoop(HANDLE pHandle, SIZE_T* bytesWritten) {
	BYTE code[] = { 0xEB, 0xFE };
	*bytesWritten = sizeof(code);
	return ASMUtils::writeAssembly(pHandle, code, sizeof(code));
}

int InjectDllCreatingSuspendedProcess(const char* processPathName, const char* cmdLine, const char* dllPathName, int method) {
	char fullCmdLine[4096];
	if (cmdLine != NULL) {
		sprintf(fullCmdLine, "%s %s", processPathName, cmdLine);
	} else {
		strcpy(fullCmdLine, processPathName);
	}
	
	CONTEXT ctx;
	PROCESS_INFORMATION pi;
	STARTUPINFOA startup;
	ZeroMemory(&startup, sizeof(startup));
	ZeroMemory(&pi, sizeof(pi));
	
	printf("Creating suspended process \"%s\"\n", fullCmdLine);
	if (!CreateProcessA(NULL, fullCmdLine, NULL, NULL, NULL, CREATE_SUSPENDED, NULL, NULL, &startup, &pi)) {
		DisplayLastError();
		return 0;
	}
	
	ctx.ContextFlags = CONTEXT_CONTROL;
	GetThreadContext(pi.hThread, &ctx);
	
	/* We save current thread execution pointer in order to move it, execute some code (infinite loop) and restore it */
	DWORD64 lastEPointer = GetExecutionPointer(&ctx);

	//printf("Thread Execution Pointer : 0x%p\n", lastEPointer);

	/* We write the infinite loop */
	SIZE_T bytesWritten;
	PVOID infiniteLoopCode = InjectInfiniteLoop(pi.hProcess, &bytesWritten);
	SetExecutionPointer(&ctx, (DWORD64)infiniteLoopCode);
	ctx.ContextFlags = CONTEXT_CONTROL;
	SetThreadContext(pi.hThread, &ctx);
	
	ResumeThread(pi.hThread);
	printf("Process resumed in infinite loop, now injecting Dll\n");

	int result = InjectDllRemoteThread(GetProcessId(pi.hProcess), dllPathName, method);

	printf("Injection terminated. Restoring EIP/RIP\n");

	SuspendThread(pi.hThread);

	ctx.ContextFlags = CONTEXT_CONTROL;
	GetThreadContext(pi.hThread, &ctx);
	SetExecutionPointer(&ctx, lastEPointer);
	SetThreadContext(pi.hThread, &ctx);

	VirtualFreeEx(pi.hProcess, infiniteLoopCode, bytesWritten, MEM_RELEASE);

	ResumeThread(pi.hThread);
	
	return result;
}

int InjectDllRemoteThread(DWORD pid, const char * dllPathName, int method) {
	HANDLE pHandle;
	HANDLE threadHandle;
	LPVOID dllFullPathNameLoc;
	int result = 1;

	char fullDllPath[1024] = { 0 };

	pHandle = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (pHandle == NULL) {
		DisplayLastError();
		return 0;
	}

	if (GetFullPathNameA(dllPathName, sizeof(fullDllPath), fullDllPath, NULL) == 0) {
		DisplayLastError();
		CloseHandle(pHandle);
		return 0;
	}

	printf("Full Dll path name : %s\n", fullDllPath);

	dllFullPathNameLoc = AllocWriteStrInTarget(pHandle, fullDllPath);

	/* x64 mode : LoadLibrary returns a QWORD (8 bits address to the module loaded) while an exit code only accepts 4 bits (DWORD)
	That's why I created a small assembly code that call GetLastError and returns the error code when LoadLibrary fails in x64 mode*/
	PVOID remoteProcedure;
	bool isTargetx64;

	if (isTargetx64 = Is64Process(GetProcessId(pHandle))) {
		printf("Target process is in x64 mode\n");
	}
	else {
		printf("Target process is in x86 mode\n");
	}

	unsigned int procedureSize;
	remoteProcedure = InjectLoadLibraryInMem(pHandle, fullDllPath, dllFullPathNameLoc, isTargetx64, &procedureSize);

	if (remoteProcedure == NULL) {
		return 0;
	}

	switch (method) {
	case INJECTION_METHOD_NT:
		threadHandle = NtCreateRemoteThread(pHandle, (LPTHREAD_START_ROUTINE)remoteProcedure, (LPVOID)NULL);
		break;

	case INJECTION_METHOD_RTL:
		threadHandle = RtlCreateUserThread(pHandle, remoteProcedure, NULL);
		break;

	default:
		threadHandle = CreateRemoteThread(pHandle, NULL, 0, (LPTHREAD_START_ROUTINE)remoteProcedure, (LPVOID)NULL, 0, NULL);
		break;
	}

	DWORD exitCode = 0;
	if (threadHandle == NULL) {
		DWORD lastErrorCode = GetLastError();
		DisplayErrorWithCode(NULL, lastErrorCode);
		SetLastError(lastErrorCode);
	}
	else {
		WaitReturnValueFromThread(threadHandle, &exitCode);

		if (exitCode == 0) {
			printf("\nLoadLibraryA OK : returned 0\n");
		}
		else {
			printf("\nLoadLibraryA FAILED (%ld) : ", exitCode);
			DisplayErrorWithCode(NULL, exitCode);
			if (exitCode == ERROR_CODE_NOT_VALID_WIN32_APP) {
				if (!isTargetx64) {
					printf("REM : it might failed cause you want to load a x64 dll into a x86 process\n");
				}
				else {
					printf("REM : it might failed cause you want to load a x86 dll into a x64 process\n");
				}

			}
			result = 0;
		}
		SetLastError(exitCode);
	}

	CloseHandle(pHandle);
	VirtualFreeEx(pHandle, (LPVOID)dllFullPathNameLoc, 0, MEM_DECOMMIT);
	VirtualFreeEx(pHandle, remoteProcedure, procedureSize, MEM_RELEASE);
	return result;
}


int ReleaseDllRemoteThread (DWORD pid, const char* dllPathName, int ntMethodBool)
{
    HMODULE hKernel32 = LoadLibrary (L"kernel32.dll");
    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid);
    LPVOID lpHandle = 0;

    SIZE_T dwWritten;

    if (hProcess == NULL)
    {
        DisplayLastError();
        return 1;
    }

    //Récupération de la taille du nom du chemin vers la dll en bytes
    SIZE_T sizeDllPathName = (SIZE_T) strlen(dllPathName);

    //On réserve de la mémoire dans le processus cible, puis on y stocke le nom du chemin vers la dll
    LPVOID lpBuf = VirtualAllocEx (hProcess, NULL, sizeDllPathName, MEM_COMMIT, PAGE_READWRITE);

    printf("Dll path name written at \t0x%p ...\n", lpBuf);

    if (! WriteProcessMemory (hProcess, lpBuf, (LPVOID) dllPathName, sizeDllPathName, &dwWritten))
    {
        DisplayLastError();
        VirtualFreeEx (hProcess, lpBuf, sizeDllPathName, MEM_DECOMMIT);
        CloseHandle (hProcess);
        return 1;
    }

    //On effectue ensuite un appel vers GetModuleHandleA pour obtenir un handle vers le module de la dll par le biais d'un thread
    HANDLE hThread;
    if(ntMethodBool)
    {
        hThread = NtCreateRemoteThread(hProcess, (LPTHREAD_START_ROUTINE)GetProcAddress (hKernel32, "GetModuleHandleA"), lpBuf);
    }
    else
    {
        hThread = CreateRemoteThread (hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)GetProcAddress (hKernel32, "GetModuleHandleA"), lpBuf, 0, NULL);
    }

    if (hThread == NULL)
    {
        DisplayLastError();
        CloseHandle (hProcess);
        return 1;
    }

    WaitForSingleObject (hThread, INFINITE);

    //On récupère le module handle dans dwHandle
    GetExitCodeThread (hThread, (LPDWORD)&lpHandle);

    printf("Module handle %s (image base) : \t0x%p\n", dllPathName, (void*)lpHandle);

    //On fini par effacer la mémoire écrite pour le nom du chemin de la dll
    printf("Free-ing memory on module handle...\n");
    VirtualFreeEx (hProcess, lpBuf, sizeDllPathName, MEM_DECOMMIT);
    printf("Closing GetModuleHandleA thread...\n");
    CloseHandle (hThread);

    HANDLE ht;
    if(ntMethodBool)
    {
        ht = NtCreateRemoteThread(hProcess, (LPTHREAD_START_ROUTINE) GetProcAddress (hKernel32, "FreeLibrary"), (LPVOID) lpHandle);
    }
    else
    {
        ht = CreateRemoteThread (hProcess, 0, 0, (LPTHREAD_START_ROUTINE) GetProcAddress (hKernel32, "FreeLibrary"), (LPVOID) lpHandle, 0, NULL);
    }

//    printf("Thread \"FreeLibrary\" handle \t0x%p ...\n", hThread);

    if (ht == NULL)
    {
        DisplayLastError();
        FreeLibrary (hKernel32);
        CloseHandle (hProcess);
        return 1;
    }

    switch (WaitForSingleObject (ht, 2000))
    {
        case WAIT_OBJECT_0:
        printf("Releasing OK\n");
        break;

        default:
        DisplayLastError();
        break;
    }

    printf("Closing FreeLibrary thread...\n");
    // Closes the remote thread handle
    CloseHandle(ht);

    // Free up the kernel32.dll
    if (hKernel32 != NULL)
    {
        FreeLibrary (hKernel32);
    }

    // Close the process handle
    CloseHandle (hProcess);

    return 0;

}


