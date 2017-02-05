#include <windows.h>
#include <stdio.h>
#include "DebugPrivileges.h"
#include "ErrorUtils.h"

BOOL SetPrivilege(
    HANDLE hToken,          // access token handle
    LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
    BOOL bEnablePrivilege   // to enable or disable privilege
    )
{
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if ( !LookupPrivilegeValue(
            NULL,            // lookup privilege on local system
            lpszPrivilege,   // privilege to lookup
            &luid ) )        // receives LUID of privilege
    {
        printf("LookupPrivilegeValue error: %u\n", (unsigned int) GetLastError() );
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;

    // Enable the privilege or disable all privileges.

    if ( !AdjustTokenPrivileges(
           hToken,
           FALSE,
           &tp,
           sizeof(TOKEN_PRIVILEGES),
           (PTOKEN_PRIVILEGES) NULL,
           (PDWORD) NULL) )
    {
          printf("AdjustTokenPrivileges error: %u\n", (unsigned int) GetLastError() );
          return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

    {
          printf("The token does not have the specified privilege. \n");
          return FALSE;
    }

    return TRUE;
}

void MyPrivilegeCheck()
{
    LPCTSTR lpszPrivilege = SE_DEBUG_NAME;
    BOOL bEnablePrivilege = TRUE;
    HANDLE token;
    PRIVILEGE_SET privset;
    BOOL bResult;

    printf("Setting SeDebugPrivilege\r\n");

    privset.PrivilegeCount = 1;
    //privset.Control = PRIVILEGE_SET_ALL_NECESSARY;
    privset.Privilege[0].Attributes = 0;

    if (!LookupPrivilegeValue(NULL, lpszPrivilege, &privset.Privilege[0].Luid))
    ErrorExit("LookupPrivilegeValue");

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &token))
    ErrorExit("OpenProcessToken");

    if (!PrivilegeCheck(token, &privset, &bResult))
    ErrorExit("PrivilegeCheck");

    if (bResult)
    printf(" We have debug privileges for the system\r\n");
    else
    printf(" Nope, Try again. Attempting to get it...\r\n");

    if(!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token))
    {
        DisplayLastError();
    return;
    }
    printf("SetPrivilege() return value: %d\n\n", SetPrivilege(token, lpszPrivilege, bEnablePrivilege));

}

BOOL EnableDebugPrivilege(BOOL bEnable)
{
    HANDLE hToken = NULL;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) return FALSE;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) { CloseHandle(hToken); return FALSE; }

    TOKEN_PRIVILEGES tokenPriv;
    tokenPriv.PrivilegeCount = 1;
    tokenPriv.Privileges[0].Luid = luid;
    tokenPriv.Privileges[0].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tokenPriv, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) { CloseHandle(hToken); return FALSE; }

    return TRUE;
}
