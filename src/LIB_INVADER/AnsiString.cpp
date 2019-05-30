#include <stdlib.h>
#include "AnsiString.h"
#include "UnicodeString.h"

/*
  * malloc sur ANSI_STRING.Buffer
*/

ANSI_STRING CreateAnsiStringData(unsigned int size)
{
    ANSI_STRING result;
    result.Buffer = (char*) calloc(size, sizeof(char));
    result.Length = size;

    return result;
}

void ZeroAnsiString(ANSI_STRING *str)
{
    memset(str, 0, sizeof(ANSI_STRING));
}

ANSI_STRING CreateAnsiStringDataFromUnicodeString(UNICODE_STRING uni)
{
    return CreateAnsiStringDataFromUnicode(uni.Buffer, uni.MaximumLength);
}

ANSI_STRING CreateAnsiStringDataFromUnicode(WCHAR* str, unsigned int size)
{
    ANSI_STRING result = CreateAnsiStringData(size);
    utf8_encode(reinterpret_cast<LPCTSTR>(str), size, result.Buffer, size);

    return result;
}
