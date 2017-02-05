#ifndef UNICODESTRING_H_INCLUDED
#define UNICODESTRING_H_INCLUDED

#include <windows.h>

typedef struct _LSA_UNICODE_STRING {
 /* +0x000 */ USHORT Length;
 /* +0x002 */ USHORT MaximumLength;
 /* +0x008 */ PWSTR  Buffer;
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING, UNICODE_STRING, *PUNICODE_STRING;


void ConvertToCharArrayFromUnicodeString(UNICODE_STRING str, char* output, unsigned int maxLength);
void utf8_encode(LPCTSTR wstr, unsigned int size, char* output, unsigned int outputMaxLength);
#endif
