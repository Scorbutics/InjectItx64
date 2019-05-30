#ifndef DEF_REGUTILS
#define DEF_REGUTILS

void DisplayValuesInKey(HKEY key);
void GetKeyPathFromHKEY(HMODULE dll, HKEY key, TCHAR* keyPath);
HKEY OpenKeySoftwaresStartup();

#endif
