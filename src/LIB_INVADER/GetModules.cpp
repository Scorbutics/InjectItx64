#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <Psapi.h>

int PrintModules( unsigned long processID )
{
//    HMODULE hMods[1024];
//    HANDLE hProcess;
//    DWORD cbNeeded;
//    unsigned int i;

//    // Print the process identifier.

//    printf( "\nProcess ID: %u\n", processID );

//    // Get a handle to the process.

//    hProcess = OpenProcess( PROCESS_QUERY_INFORMATION |
//                            PROCESS_VM_READ,
//                            FALSE, processID );
//    if (NULL == hProcess)
//        return 1;

//   // Get a list of all the modules in this process.

//    if(EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL))
//    {
//        for ( i = 0; i < (cbNeeded / sizeof(HMODULE)); i++ )
//        {
//            TCHAR szModName[MAX_PATH];

//            // Get the full path to the module's file.

//            if ( GetModuleFileName( hProcess, hMods[i], szModName,
//                                      sizeof(szModName) / sizeof(TCHAR)))
//            {
//                // Print the module name and handle value.

//                printf("\t%s (0x%08X)\n", szModName, hMods[i] );
//            }
//        }
//    }

//    // Release the handle to the process.

//    CloseHandle( hProcess );

    return 0;
}
