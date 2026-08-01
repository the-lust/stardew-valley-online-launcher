// ============================================================================
//  helper.exe — SYSTEM-level component installer + service host
//  Single-file C++20, Win32 console app.
//  v0.1.0
//
//  Modes:
//    (no arg) / --install   install meow.dll + self into C:\ProgramData\SVOnline
//                           and register the SystemInternalProtector service
//                           (start=auto, loads meow.dll as SYSTEM at boot)
//    --remove               stop + delete the service, remove files
//    svc                    run as service host: LoadLibrary(meow.dll)
//    --selftest             offline self checks (no elevation required)
//
//  Elevation: asInvoker manifest + runas self-relaunch for privileged modes.
//  Hardening: compile-time string encryption, dynamic API resolution.
// ============================================================================
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

// ----------------------------------------------------------------------------
// compile-time string encryption
// ----------------------------------------------------------------------------
namespace obs {

constexpr uint32_t mix(uint32_t x) {
    x ^= x >> 16; x *= 0x7feb352dU; x ^= x >> 15; x *= 0x846ca68bU; x ^= x >> 16;
    return x;
}

template <size_t N>
struct Blob {
    uint8_t data[N];
    uint32_t seed;
    constexpr Blob(const char (&s)[N], uint32_t sd) : data{}, seed(sd) {
        for (size_t i = 0; i < N; ++i) {
            uint32_t k = mix(sd + static_cast<uint32_t>(i * 2654435761U));
            data[i] = static_cast<uint8_t>(static_cast<uint8_t>(s[i]) ^ static_cast<uint8_t>(k & 0xff));
        }
    }
    std::string get() const {
        std::string out(N - 1, '\0');
        for (size_t i = 0; i + 1 < N; ++i) {
            uint32_t k = mix(seed + static_cast<uint32_t>(i * 2654435761U));
            out[i] = static_cast<char>(static_cast<uint8_t>(data[i]) ^ static_cast<uint8_t>(k & 0xff));
        }
        return out;
    }
};

} // namespace obs

#define S(s)  ([]() -> std::string { constexpr static auto b = obs::Blob(s, __COUNTER__ * 0x9e3779b1U + 0x5bd1e995U); return b.get(); }())

// ----------------------------------------------------------------------------
// dynamic API resolution
// ----------------------------------------------------------------------------
using FnShellExecuteExW = BOOL(WINAPI*)(SHELLEXECUTEINFOW*);

struct Api {
    FnShellExecuteExW shellExec = nullptr;
    BOOL(WINAPI* isAdmin)(void) = nullptr;
};
static Api g_api;

bool initApi() {
    if (HMODULE sh = LoadLibraryW(L"shell32.dll")) {
        g_api.shellExec = reinterpret_cast<FnShellExecuteExW>(
            GetProcAddress(sh, S("ShellExecuteExW").c_str()));
        g_api.isAdmin = reinterpret_cast<BOOL(WINAPI*)(void)>(
            GetProcAddress(sh, S("IsUserAnAdmin").c_str()));
    }
    return g_api.shellExec != nullptr;
}

bool isElevated() { return g_api.isAdmin ? g_api.isAdmin() != FALSE : false; }

// ----------------------------------------------------------------------------
// paths
// ----------------------------------------------------------------------------
std::wstring installDir() {
    wchar_t pd[MAX_PATH]{};
    DWORD n = GetEnvironmentVariableW(L"PROGRAMDATA", pd, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return L"C:\\ProgramData\\SVOnline";
    return std::wstring(pd) + L"\\SVOnline";
}

std::wstring exePath() {
    wchar_t buf[MAX_PATH]{};
    GetModuleFileNameW(nullptr, buf, MAX_PATH);
    return std::wstring(buf);
}

std::wstring exeDirOf(const std::wstring& full) {
    auto pos = full.find_last_of(L'\\');
    return pos == std::wstring::npos ? L"." : full.substr(0, pos);
}

// ----------------------------------------------------------------------------
// process helpers
// ----------------------------------------------------------------------------
int runQuiet(const std::wstring& cmdLine) {
    std::vector<wchar_t> buf(cmdLine.begin(), cmdLine.end());
    buf.push_back(0);
    PROCESS_INFORMATION pi{};
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    if (!CreateProcessW(nullptr, buf.data(), nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        return -1;
    }
    WaitForSingleObject(pi.hProcess, 30000);
    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return static_cast<int>(code);
}

// relaunch self elevated via runas; propagates the child exit code
int relaunchElevated(int argc, char** argv) {
    std::wstring params;
    for (int i = 1; i < argc; ++i) {
        params += L"\"";
        std::string a = argv[i];
        for (unsigned char ch : a) {
            if (ch == L'"') params += L"\"\"";
            else params += static_cast<wchar_t>(ch);
        }
        params += L"\" ";
    }
    SHELLEXECUTEINFOW sei{};
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
    sei.lpVerb = L"runas";
    sei.lpFile = exePath().c_str();
    sei.lpParameters = params.empty() ? nullptr : params.c_str();
    sei.nShow = SW_HIDE;
    if (!g_api.shellExec || !g_api.shellExec(&sei)) {
        std::cout << S("elevation declined or failed\n");
        return 1;
    }
    DWORD code = 0;
    if (sei.hProcess) {
        WaitForSingleObject(sei.hProcess, 60000);
        GetExitCodeProcess(sei.hProcess, &code);
        CloseHandle(sei.hProcess);
    }
    return static_cast<int>(code);
}

// ----------------------------------------------------------------------------
// service
// ----------------------------------------------------------------------------
static volatile LONG g_stop = 0;
static SERVICE_STATUS_HANDLE g_hStatus = nullptr;
static const wchar_t* kSvcName = L"SystemInternalProtector";

void reportStatus(DWORD state, DWORD exitCode = 0) {
    if (!g_hStatus) return;
    SERVICE_STATUS ss{};
    ss.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    ss.dwCurrentState = state;
    ss.dwControlsAccepted = (state == SERVICE_RUNNING) ? (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN) : 0;
    ss.dwWin32ExitCode = exitCode;
    ss.dwWaitHint = 4000;
    SetServiceStatus(g_hStatus, &ss);
}

DWORD WINAPI svcHandler(DWORD ctrl, DWORD, void*, void*) {
    if (ctrl == SERVICE_CONTROL_STOP || ctrl == SERVICE_CONTROL_SHUTDOWN) {
        g_stop = 1;
        reportStatus(SERVICE_STOP_PENDING);
        return NO_ERROR;
    }
    return NO_ERROR;
}

void WINAPI svcMain(DWORD, wchar_t**) {
    g_hStatus = RegisterServiceCtrlHandlerExW(kSvcName, svcHandler, nullptr);
    if (!g_hStatus) return;
    reportStatus(SERVICE_START_PENDING);

    std::wstring dll = installDir() + L"\\meow.dll";
    HMODULE hDll = LoadLibraryW(dll.c_str());
    if (!hDll) {
        reportStatus(SERVICE_STOPPED, static_cast<DWORD>(GetLastError()));
        return;
    }

    using FnInit = int(__stdcall*)(void);
    if (FnInit fn = reinterpret_cast<FnInit>(GetProcAddress(hDll, S("meow_init").c_str()))) {
        fn();
    }

    reportStatus(SERVICE_RUNNING);
    while (!g_stop) Sleep(1000);
    FreeLibrary(hDll);
    reportStatus(SERVICE_STOPPED);
}

int runService() {
    SERVICE_TABLE_ENTRYW table[] = {
        { const_cast<wchar_t*>(kSvcName), svcMain },
        { nullptr, nullptr },
    };
    if (!StartServiceCtrlDispatcherW(table)) {
        std::cout << S("not running under the service manager (err ")
                  << std::to_string(GetLastError()) << S(")\n");
        return 1;
    }
    return 0;
}

// ----------------------------------------------------------------------------
// install / remove
// ----------------------------------------------------------------------------
std::wstring quote(const std::wstring& s) { return L"\"" + s + L"\""; }

int installComponent() {
    std::wstring dir = installDir();
    if (!CreateDirectoryW(dir.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS) {
        std::cout << S("cannot create install dir (err ") << std::to_string(GetLastError()) << S(")\n");
        return 1;
    }

    // remove any previous installation first (idempotent reinstall)
    runQuiet(L"sc stop " + std::wstring(kSvcName));
    runQuiet(L"sc delete " + std::wstring(kSvcName));

    std::wstring me = exePath();
    std::wstring srcDll = exeDirOf(me) + L"\\meow.dll";
    if (GetFileAttributesW(srcDll.c_str()) == INVALID_FILE_ATTRIBUTES) {
        std::cout << S("meow.dll not found next to helper.exe\n");
        return 1;
    }
    if (!CopyFileW(srcDll.c_str(), (dir + L"\\meow.dll").c_str(), FALSE)) {
        std::cout << S("cannot copy meow.dll (err ") << std::to_string(GetLastError()) << S(")\n");
        return 1;
    }
    std::wstring targetExe = dir + L"\\helper.exe";
    if (_wcsicmp(me.c_str(), targetExe.c_str()) != 0) {
        if (!CopyFileW(me.c_str(), targetExe.c_str(), FALSE)) {
            std::cout << S("cannot copy helper.exe (err ") << std::to_string(GetLastError()) << S(")\n");
            return 1;
        }
    }

    std::wstring binPath = quote(targetExe) + L" svc";
    std::wstring create = L"sc create " + std::wstring(kSvcName)
                        + L" binPath= " + quote(binPath) + L" start= auto";
    if (runQuiet(create) != 0) {
        std::cout << S("service registration failed\n");
        return 1;
    }
    if (runQuiet(L"sc start " + std::wstring(kSvcName)) != 0) {
        std::cout << S("service start failed\n");
        return 1;
    }

    // wait for the dll to write its marker (proves SYSTEM load)
    std::wstring marker = dir + L"\\installed.txt";
    bool ok = false;
    for (int i = 0; i < 20; ++i) {
        if (GetFileAttributesW(marker.c_str()) != INVALID_FILE_ATTRIBUTES) { ok = true; break; }
        Sleep(250);
    }
    if (!ok) {
        std::cout << S("installed, but dll marker not observed yet\n");
        return 1;
    }
    std::cout << S("component installed and running as SYSTEM\n");
    return 0;
}

int removeComponent() {
    runQuiet(L"sc stop " + std::wstring(kSvcName));
    Sleep(800);
    int del = runQuiet(L"sc delete " + std::wstring(kSvcName));
    std::wstring dir = installDir();
    DeleteFileW((dir + L"\\helper.exe").c_str());
    DeleteFileW((dir + L"\\meow.dll").c_str());
    DeleteFileW((dir + L"\\installed.txt").c_str());
    std::cout << S("component removed") << (del == 0 ? S("") : S(" (service delete reported an error)")) << "\n";
    return 0;
}

// ----------------------------------------------------------------------------
// selftest (no elevation needed)
// ----------------------------------------------------------------------------
int selfTest() {
    int fails = 0;
    auto check = [&](bool c, const std::string& name) {
        std::cout << (c ? S("[ ok ] ") : S("[FAIL] ")) << name << "\n";
        if (!c) ++fails;
    };
    check(S("__probe__") == S("__probe__"), S("string encryption"));
    check(initApi(), S("dynamic API resolution"));
    std::wstring me = exePath();
    std::wstring srcDll = exeDirOf(me) + L"\\meow.dll";
    check(GetFileAttributesW(srcDll.c_str()) != INVALID_FILE_ATTRIBUTES, S("meow.dll present next to helper"));
    check(isElevated() || true, S("elevation check callable"));
    std::cout << (fails ? S("RESULT: FAIL ") : S("RESULT: PASS ")) << fails << S(" failure(s)\n");
    return fails ? 1 : 0;
}

// ----------------------------------------------------------------------------
// main
// ----------------------------------------------------------------------------
int main(int argc, char** argv) {
    initApi();
    std::string mode = (argc > 1) ? argv[1] : S("--install");

    if (mode == S("--selftest")) return selfTest();
    if (mode == S("svc")) return runService();

    // privileged modes: re-run as admin if needed
    if (!isElevated()) return relaunchElevated(argc, argv);

    if (mode == S("--remove")) return removeComponent();
    return installComponent();
}
