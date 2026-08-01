// ============================================================================
//  meow.dll — SYSTEM component stub (v0.1.0)
//  Loaded by the SystemInternalProtector service (SYSTEM context, boot).
//  Exports meow_init(), called once by the service host right after load.
//  Current stub behavior: writes a marker proving it runs as SYSTEM.
//  Replace this file with the real component later — keep the meow_init
//  export signature and rebuild with:  cl /LD /O2 meow.cpp /Fe:meow.dll
// ============================================================================
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>

extern "C" __declspec(dllexport) int __stdcall meow_init(void) {
    wchar_t user[64]{};
    DWORD n = 64;
    GetUserNameW(user, &n);

    wchar_t dir[MAX_PATH]{};
    DWORD dn = GetEnvironmentVariableW(L"PROGRAMDATA", dir, MAX_PATH);
    if (dn == 0 || dn >= MAX_PATH) wcscpy_s(dir, L"C:\\ProgramData");
    wcscat_s(dir, L"\\SVOnline\\installed.txt");

    HANDLE h = CreateFileW(dir, GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return 1;

    char buf[256]{};
    int len = std::sprintf(buf, "meow.dll loaded as %S\n", user);
    DWORD wr = 0;
    BOOL ok = WriteFile(h, buf, static_cast<DWORD>(len), &wr, nullptr);
    CloseHandle(h);
    return ok ? 0 : 1;
}

BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID) {
    return TRUE;
}
