#include <windows.h>
#include <stdio.h>

int main()
{
    HMODULE hKernel32 = LoadLibrary("Kernel32.dll");

    if (hKernel32 == NULL)
    {
        printf("Error: Unable to load Kernel32.dll.\n");
        return 1;
    }

    FARPROC pCreateFileA = GetProcAddress(hKernel32, "CreateFileA");
    FARPROC pWriteFile = GetProcAddress(hKernel32, "WriteFile");
    FARPROC pCloseHandle = GetProcAddress(hKernel32, "CloseHandle");
    FARPROC pWinExec = GetProcAddress(hKernel32, "WinExec");


    if (pCreateFileA == NULL)
    {
        printf("Error: Unable to find CreateFileA function.\n");
        return 1;
    }
    if (pCloseHandle == NULL)
    {
        printf("Error: Unable to find CloseHandle function.\n");
        return 1;
    }
    if (pWriteFile == NULL)
    {
        printf("Error: Unable to find WriteFile function.\n");
        return 1;
    }
    if (pWinExec == NULL) {
        printf("Error: Unable to find WinExec function.\n");
        return 1;
    }

    printf("Address of CreateFileA function: %p\n", pCreateFileA);
    printf("Address of CloseHandle function: %p\n", pCloseHandle);
    printf("Address of WriteFile function: %p\n", pWriteFile);
    printf("Address of WinExec function: %p\n", pWinExec);

    FreeLibrary(hKernel32);

    return 0;
}