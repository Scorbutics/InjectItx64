#ifndef ANSISTRING_H
#define ANSISTRING_H
#include "UnicodeString.h"

struct ANSI_STRING {
    unsigned int Length;
    char* Buffer;
};
typedef struct ANSI_STRING ANSI_STRING;

ANSI_STRING CreateAnsiStringDataFromUnicode(WCHAR* str, unsigned int size);
ANSI_STRING CreateAnsiStringDataFromUnicodeString(UNICODE_STRING uni);

#endif // ANSISTRING_H
