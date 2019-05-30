#include <windows.h>
#include <stdio.h>
#include "UnicodeString.h"
#include "ErrorUtils.h"

void str_replace_char(char * str, char character, char charToReplace)
{
    char* strSearched = NULL;
    while((strSearched = strchr(str, character)))
    {
        strSearched[0] = charToReplace;
    }
}

void str_delete_char(char * str, char character)
{
    char result[1024] = {0};
    unsigned int absIndex = 0, outputIndex = 0;
    unsigned int itNum = 1;

    char* strSearched = str;

    while((strSearched = strchr(str + absIndex, character)))
    {
        unsigned int index = strSearched - str;
        //Copie du contenu intermédiaire
        memcpy(result + outputIndex, str + absIndex, index - absIndex );
        absIndex = index + 1;
        outputIndex = strlen(result);
        itNum++;
    }

    //Copie de fin de chaîne
    memcpy(result + outputIndex, str + absIndex, strlen(str) - absIndex);

    strcpy(str, result);
}

void ErrorExit(const char* msg)
{
    puts(msg);
    DisplayLastError();
    exit(EXIT_FAILURE);
}

void DisplayErrorWithCode(LPWSTR pMessage, long code)
{
    LPVOID pBuffer = NULL;
	WCHAR finalMessage[2048] = { 0 };

    FormatMessageW(
                FORMAT_MESSAGE_ALLOCATE_BUFFER |
                FORMAT_MESSAGE_FROM_SYSTEM |
                FORMAT_MESSAGE_IGNORE_INSERTS,
                pMessage,
                code,
                0, // Default language
                (LPWSTR) &pBuffer,
                0,
                NULL
                ) ;

	
#ifdef UNICODE
	wsprintf(finalMessage, L"Erreur [0x%08x] : %s\n", (unsigned int)code, (LPCWSTR)pBuffer);
	WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), finalMessage, lstrlenW(finalMessage), NULL, NULL);
#else
	printf("Erreur [0x%08x] : %s\n", (unsigned int)code, (LPCTSTR)pBuffer);
#endif

    LocalFree(pBuffer);
}

void DisplayLastError()
{
    DisplayErrorWithCode(NULL, (DWORD_PTR)GetLastError());
}
