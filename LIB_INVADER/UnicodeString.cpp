#include <windows.h>
#include "UnicodeString.h"

void ConvertToCharArrayFromUnicodeString(UNICODE_STRING str, char* output, unsigned int maxLength)
{
    unsigned int i;
    for(i = 0; i < str.Length && i < (maxLength-1); i++)
    {
        output[i] = str.Buffer[i];
    }
    output[i] = '\0';
}

void utf8_encode(LPCTSTR wstr, unsigned int size, char* output, unsigned int outputMaxLength)
{
    if(outputMaxLength == 0)
        return;

    WideCharToMultiByte(CP_UTF8, 0, wstr, size, output, outputMaxLength, NULL, NULL);
    output[outputMaxLength-1] = '\0';
}

