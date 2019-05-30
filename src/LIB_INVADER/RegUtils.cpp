#include <windows.h>
#include <stdio.h>

#include "NTStatus.h"
#include "KeyNameInformation.h"
#include "ErrorUtils.h"

#define KEY_VALUE_MAX_LENGTH 16383
/*
#define KEY_WOW64_32KEY 0x0200
#define KEY_WOW64_64KEY 0x0100
*/

#include "RegUtils.h"

HKEY OpenKeySoftwaresStartup()
{
    HKEY hkResult;
    LPTSTR subKeyPath = TEXT("Software\\Microsoft\\Windows\\CurrentVersion\\Run\\");
    DWORD retCode;

    if((retCode = RegOpenKeyEx(HKEY_LOCAL_MACHINE, subKeyPath, 0, KEY_READ | KEY_WOW64_64KEY, &hkResult)) != ERROR_SUCCESS)
    {
        printf("Erreur (OpenKeySoftwaresStartup) : Impossible d'ouvrir le chemin \"HKEY_LOCAL_MACHINE\\%s\"\n", (char*)subKeyPath);
        DisplayErrorWithCode(L"%1", retCode);
    }

    return hkResult;
}

void DisplayValuesInKey(HKEY key)
{
    TCHAR    buf[KEY_VALUE_MAX_LENGTH];
    DWORD    bufferLength = KEY_VALUE_MAX_LENGTH;
    TCHAR data[512];
    DWORD dataSize = 512;

    //TCHAR    achKey[KEY_VALUE_MAX_LENGTH];   // buffer for subkey name
    //DWORD    cbName;                   // size of name string
    TCHAR    achClass[256] = TEXT("");  // buffer for class name
    DWORD    cchClassName = 256;  // size of class string
    DWORD    cSubKeys=0;               // number of subkeys
    DWORD    cbMaxSubKey;              // longest subkey size
    DWORD    cchMaxClass;              // longest class string
    DWORD    cValues;              // number of values for key
    DWORD    cchMaxValue;          // longest value name
    DWORD    cbMaxValueData;       // longest value data
    DWORD    cbSecurityDescriptor; // size of security descriptor
    FILETIME ftLastWriteTime;      // last write time
    DWORD i, retCode;


    // Get the class name and the value count.
    retCode = RegQueryInfoKey(
        key,                    // key handle
        achClass,                // buffer for class name
        &cchClassName,           // size of class string
        NULL,                    // reserved
        &cSubKeys,               // number of subkeys
        &cbMaxSubKey,            // longest subkey size
        &cchMaxClass,            // longest class string
        &cValues,                // number of values for this key
        &cchMaxValue,            // longest value name
        &cbMaxValueData,         // longest value data
        &cbSecurityDescriptor,   // security descriptor
        &ftLastWriteTime);       // last write time

    if(retCode != ERROR_SUCCESS)
    {
        DisplayErrorWithCode(L"%1", retCode);
        return;
    }

    TCHAR keyPath[512];
    GetKeyPathFromHKEY(NULL, key, keyPath);
    printf("Affichage des valeurs dans %s:\n", (char*)keyPath);
    for(i = 0; i < cValues; i++)
    {
        RegEnumValue(key, i, buf, &bufferLength, NULL, NULL, (LPBYTE)&data, &dataSize);
        puts("");
        printf("%s\n\t%s\n", (char*)buf, (char*)data);
    }

}


void GetKeyPathFromHKEY(HMODULE dll, HKEY key, TCHAR* keyPath)
{

    int lazyLoad = 0;

    if (key != NULL)
    {
        //Premièrement, nous allons récupérer une fonction de "ntdll.dll", on a donc besoin d'un LoadLibrary
        if(dll == NULL)
        {
            dll = LoadLibraryW(L"ntdll.dll");
            lazyLoad = 1;
        }

        ULONG size = 0;
        DWORD result = 0;
        KEY_NAME_INFORMATION* keyInfoName;
        //static const int MAXLEN = 512;

        if (dll != NULL) {

            //On défini le prototype de la fonction à récupérer dans "ntdll" et on le nomme "NtQueryKeyType"
            typedef DWORD (__stdcall *NtQueryKeyType)(
                HANDLE  KeyHandle,
                int KeyInformationClass,
                PVOID  KeyInformation,
                ULONG  Length,
                PULONG  ResultLength);

            //On récupère la fonction souhaitée "NtQueryKey", "castée" par le prototype qu'on a déclaré au dessus
            NtQueryKeyType func = (NtQueryKeyType)  GetProcAddress(dll, "NtQueryKey");

            if (func != NULL)
            {
                //Premier appel à la fonction, dans le but de récupérer la taille de buffer requise pour stocker le nom de la clé.
                result = func(key, 3, NULL, size, &size);
                if (result == ((DWORD)STATUS_BUFFER_TOO_SMALL))
                {
                    //Evidemment, étant donné que size = 0, la fonction échoue avec pour code retour "STATUS_BUFFER_TOO_SMALL"

                    //L'allocation du buffer de bytes qui contiendra le résultat. Le résultat est sous forme d'un KEY_NAME_INFORMATION
                    //suivi d'un tableau de bytes contenant le nom de la clef en entier, sans son 1er caractère (voir la structure d'une KEY_NAME_INFORMATION pour comprendre).
                    //D'où le "sizeof(KEY_NAME_INFORMATION) + (size-1)*sizeof(char)" nécessaire
                    char* buffer = (char*) malloc(sizeof(KEY_NAME_INFORMATION) + (size-1)*sizeof(char));
                    if (buffer != NULL)
                    {
                        //On refait ensuite un appel à la fonction avec cette fois un buffer de bytes (char) assez grand pour contenir le résultat
                        result = func(key, 3, buffer, size, &size);
                        if (result == STATUS_SUCCESS)
                        {
                            //La zone mémoire récupérée contient tout d'abord le KEY_NAME_INFORMATION, on le cast donc explicitement.
                            keyInfoName = (KEY_NAME_INFORMATION*)buffer;

                            //On récupère ensuite le nom de la clef
                            WCHAR* wname = keyInfoName->Name;
                            char* rvtemp = (char*) calloc(size, sizeof(char));
                            if(rvtemp != NULL)
                            {
                                char* rvtempPtr = rvtemp;

                                //On finit par copier le tout dans une chaine résultat et l'insérer dans "keyPath"
                                do{
                                    *rvtempPtr++ = (char)*wname++;
                                } while(rvtempPtr[-1]);

                                strcpy((char*)keyPath, rvtemp);

                                free(rvtemp);
                            }
                        }

                        free(buffer);
                    }
                }
            }

            if(lazyLoad)
            {
                //On décharge "ntdll"
                FreeLibrary(dll);
            }
        }
    }
}

