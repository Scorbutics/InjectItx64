#ifndef DEF_KEYNAMEINFORMATION
#define DEF_KEYNAMEINFORMATION

//The KEY_NAME_INFORMATION structure holds the name and name length of the key.
typedef struct _KEY_NAME_INFORMATION {
  ULONG NameLength;
  WCHAR Name[1];
} KEY_NAME_INFORMATION, *PKEY_NAME_INFORMATION;
/*
NameLength

    The size, in bytes, of the key name string in the Name array.
Name

    An array of wide characters that contains the name of the key. This character string is not null-terminated.
    Only the first element in this array is included in the KEY_NAME_INFORMATION structure definition.
    The storage for the remaining elements in the array immediately follows this element.

*/

#endif
