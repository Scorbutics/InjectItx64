#ifndef IMAGE_NT_HEADERS_H
#define IMAGE_NT_HEADERS_H

typedef struct _IMAGE_NT_HEADERS {
  DWORD                 Signature;
  IMAGE_FILE_HEADER     FileHeader;
  IMAGE_OPTIONAL_HEADER OptionalHeader;
} IMAGE_NT_HEADERS, *PIMAGE_NT_HEADERS;

#endif // IMAGE_NT_HEADERS_H
