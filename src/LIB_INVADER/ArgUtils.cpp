#include <string.h>
#include <stdio.h>

int FileExists(const char* pathFileName)
{
    FILE * file = fopen(pathFileName, "r");
    int result = file != NULL;
    fclose(file);

    return result;
}

const char* FindArg(const char* argStr[], unsigned int argc, const char* arg)
{
    unsigned int i;
    for(i = 1; i < argc; i++)
    {
        if(strstr(argStr[i], arg) == argStr[i])
        {
            return argStr[i];
        }
    }

    return NULL;
}

const char* FindExtensionPathName(const char* argStr[], unsigned int argc, const char* ext)
{
    unsigned int i;
    for(i = 1; i < argc; i++)
    {
        if(strstr(argStr[i], ext) == (argStr[i] + strlen(argStr[i]) - strlen(ext)))
        {
            return argStr[i];
        }
    }
    return NULL;
}

const char* FindNextArg(const char* argStr[], unsigned int argc, const char* arg) {
	unsigned int i;
	for (i = 1; i < argc; i++)
	{
		if (!strcmp(argStr[i], arg))
		{
			return (i + 1 < argc) ? argStr[i + 1] : NULL;
		}
	}
	return NULL;
}

const char* FindPidPathName(const char* argStr[], unsigned int argc)
{
	return FindNextArg(argStr, argc, "-pid");
}

