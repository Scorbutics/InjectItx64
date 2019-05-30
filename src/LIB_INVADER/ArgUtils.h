#ifndef ARGUTILS_H
#define ARGUTILS_H

int FileExists(const char* pathFileName);
const char* FindArg(const char* argStr[], unsigned int argc, const char* arg);
const char* FindNextArg(const char* argStr[], unsigned int argc, const char* arg);
const char* FindExtensionPathName(const char* argStr[], unsigned int argc, const char* ext);
const char* FindPidPathName(const char* argStr[], unsigned int argc);

#endif // ARGUTILS_H
