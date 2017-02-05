#ifndef DEF_ERRORUTILS
#define DEF_ERRORUTILS

void ErrorExit(char const* msg);
void DisplayLastError();
void DisplayErrorWithCode(LPWSTR pMessage, long code);

#endif // DEF_ERRORUTILS
