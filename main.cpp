// ============================================================================
//  game.exe — Stardew Valley Online private co-op launcher
//  Single-file C++20, Win32 console app, ANSI truecolor UI.
//  v0.2.0 — hardened build: compile-time string encryption, dynamic API
//  resolution. All tool strings are encrypted at rest and decrypted at
//  runtime; the launcher's WinAPI calls are resolved via GetProcAddress.
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
#include <cwchar>
#include <iostream>
#include <iterator>
#include <optional>
#include <string>
#include <thread>
#include <vector>

// ----------------------------------------------------------------------------
// compile-time string encryption
//   every string literal is XOR-ciphered at compile time with a per-call-site
//   key stream; plaintext exists only on the stack/heap during runtime.
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
using FnShellExecuteExW              = BOOL(WINAPI*)(SHELLEXECUTEINFOW*);
using FnCreateToolhelp32Snapshot     = HANDLE(WINAPI*)(DWORD, DWORD);
using FnProcess32FirstW              = BOOL(WINAPI*)(HANDLE, LPPROCESSENTRY32W);
using FnProcess32NextW               = BOOL(WINAPI*)(HANDLE, LPPROCESSENTRY32W);

struct Api {
    FnShellExecuteExW          shellExec = nullptr;
    FnCreateToolhelp32Snapshot snap      = nullptr;
    FnProcess32FirstW          procFirst = nullptr;
    FnProcess32NextW           procNext  = nullptr;
};
static Api g_api;

bool initApi() {
    if (HMODULE sh = LoadLibraryW(SW(L"shell32.dll").c_str())) {
        g_api.shellExec = reinterpret_cast<FnShellExecuteExW>(
            GetProcAddress(sh, S("ShellExecuteExW").c_str()));
    }
    if (HMODULE k32 = GetModuleHandleW(SW(L"kernel32.dll").c_str())) {
        g_api.snap      = reinterpret_cast<FnCreateToolhelp32Snapshot>(
            GetProcAddress(k32, S("CreateToolhelp32Snapshot").c_str()));
        g_api.procFirst = reinterpret_cast<FnProcess32FirstW>(
            GetProcAddress(k32, S("Process32FirstW").c_str()));
        g_api.procNext  = reinterpret_cast<FnProcess32NextW>(
            GetProcAddress(k32, S("Process32NextW").c_str()));
    }
    return g_api.shellExec && g_api.snap && g_api.procFirst && g_api.procNext;
}

// ----------------------------------------------------------------------------
// ANSI helpers
// ----------------------------------------------------------------------------
namespace term {
    constexpr const char* RESET   = "\x1b[0m";
    constexpr const char* BOLD    = "\x1b[1m";
    constexpr const char* DIM     = "\x1b[2m";
    constexpr const char* CLEAR   = "\x1b[2J";
    constexpr const char* HOME    = "\x1b[H";
    constexpr const char* HIDE    = "\x1b[?25l";
    constexpr const char* SHOW    = "\x1b[?25h";

    std::string fg(int r, int g, int b) { return "\x1b[38;2;" + std::to_string(r) + ";" + std::to_string(g) + ";" + std::to_string(b) + "m"; }
    std::string bg(int r, int g, int b) { return "\x1b[48;2;" + std::to_string(r) + ";" + std::to_string(g) + ";" + std::to_string(b) + "m"; }
}

namespace pal {
    using namespace term;
    const std::string green   = fg(127, 186, 77);   // leaf green
    const std::string gold    = fg(255, 200, 60);   // harvest gold
    const std::string amber   = fg(240, 150, 50);   // amber
    const std::string sky     = fg(120, 190, 255);  // sky blue
    const std::string brown   = fg(160, 120, 70);   // soil brown
    const std::string cream   = fg(248, 240, 220);  // cream
    const std::string dim     = fg(120, 120, 120);  // dim grey
    const std::string red     = fg(235, 90, 90);    // error red
    const std::string ok      = fg(110, 220, 120);  // success green
    const std::string cyan    = fg(110, 210, 220);  // info cyan
}

struct Console {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD   origMode = 0;
    UINT    origCodePage = 0;
    volatile LONG stop = 0;

    bool init() {
        GetConsoleMode(hOut, &origMode);
        SetConsoleMode(hOut, origMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        origCodePage = GetConsoleOutputCP();
        SetConsoleOutputCP(CP_UTF8);
        SetConsoleTitleW(SW(L"Multiplayer Private — Stardew Valley Online").c_str());
        std::cout << term::CLEAR << term::HOME << term::HIDE;
        return true;
    }
    void restore() {
        std::cout << term::SHOW << term::RESET << term::CLEAR << term::HOME;
        SetConsoleOutputCP(origCodePage);
        SetConsoleMode(hOut, origMode);
    }
    void title(const std::string& s) { SetConsoleTitleA(s.c_str()); }
    COORD size() const {
        CONSOLE_SCREEN_BUFFER_INFO info{};
        GetConsoleScreenBufferInfo(hOut, &info);
        return info.dwSize;
    }
};

std::string toUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()),
                                nullptr, 0, nullptr, nullptr);
    std::string s(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()),
                        s.data(), n, nullptr, nullptr);
    return s;
}

// ----------------------------------------------------------------------------
// ASCII art
// ----------------------------------------------------------------------------
// 5-row block glyphs, 6 chars wide each + 1 spacer.
using Glyph = std::array<std::string, 5>;
const Glyph G_S = {" █████", "█     ", " █████", "     █", "█████ "};
const Glyph G_T = {"██████", "  ██  ", "  ██  ", "  ██  ", "  ██  "};
const Glyph G_A = {" ████ ", "█    █", "██████", "█    █", "█    █"};
const Glyph G_R = {"█████ ", "█    █", "█████ ", "█  █  ", "█   ██"};
const Glyph G_D = {"█████ ", "█    █", "█    █", "█    █", "█████ "};
const Glyph G_E = {"██████", "█     ", "█████ ", "█     ", "██████"};
const Glyph G_W = {"█    █", "█    █", "█ ██ █", "██  ██", "█    █"};
const Glyph G_V = {"█    █", "█    █", " █  █ ", "  ██  ", "  ██  "};
const Glyph G_L = {"█     ", "█     ", "█     ", "█     ", "██████"};
const Glyph G_Y = {"█    █", " █  █ ", "  ██  ", "  ██  ", "  ██  "};
const Glyph G_N = {"█    █", "██   █", "█ █  █", "█  █ █", "█   ██"};
const Glyph G_O = {" ████ ", "█    █", "█    █", "█    █", " ████ "};
const Glyph G_I = {"██████", "  ██  ", "  ██  ", "  ██  ", "██████"};
const Glyph G_SP{"     ", "     ", "     ", "     ", "     "};

std::optional<Glyph> glyphFor(char c) {
    switch (c) {
        case 'S': return G_S; case 'T': return G_T; case 'A': return G_A;
        case 'R': return G_R; case 'D': return G_D; case 'E': return G_E;
        case 'W': return G_W; case 'V': return G_V; case 'L': return G_L;
        case 'Y': return G_Y; case 'N': return G_N; case 'O': return G_O;
        case 'I': return G_I; default:  return std::nullopt;
    }
}

// gradient palette for the banner letters (leaf green -> gold)
std::vector<std::string> gradient(int n) {
    std::vector<std::string> cols;
    for (int i = 0; i < n; ++i) {
        float t = n <= 1 ? 0.f : static_cast<float>(i) / (n - 1);
        int g = static_cast<int>(186 + (200 - 186) * t);
        int r = static_cast<int>(127 + (255 - 127) * t);
        int b = static_cast<int>(77  - (77  - 60 ) * t);
        cols.push_back(term::fg(r, g, b));
    }
    return cols;
}

void printBanner(const Console& console) {
    const std::string line1 = S("STARDEW VALLEY");
    const std::string line2 = S("ONLINE");
    const int w = console.size().X;
    const int glyphW = 7; // 6 + spacer
    const int need = static_cast<int>(line1.size()) * glyphW;

    if (w < need) { // fallback: plain text logo
        std::cout << pal::gold << term::BOLD << S("  * STARDEW VALLEY ONLINE *\n") << term::RESET;
        return;
    }
    const auto cols = gradient(static_cast<int>(line1.size() + line2.size()));

    auto renderLine = [&](const std::string& text, int colStart) {
        for (int row = 0; row < 5; ++row) {
            std::cout << "\x1b[" << (row + 1) << "C"; // small left margin
            for (size_t i = 0; i < text.size(); ++i) {
                auto g = glyphFor(text[i]);
                if (!g) continue;
                std::cout << cols[colStart + static_cast<int>(i)];
                std::cout << (*g)[row];
            }
            std::cout << "\n";
        }
    };

    // small farm motif above the title
    std::cout << pal::sky << "           " << term::RESET
              << pal::gold << "  * " << term::RESET
              << pal::sky << "    ~  *" << term::RESET
              << pal::green << "    __" << term::RESET
              << pal::amber << "   o" << term::RESET
              << pal::green << "   |__" << term::RESET << "\n";

    renderLine(line1, 0);
    // indent the second line by a few glyphs
    const int line2Indent = 5;
    for (int row = 0; row < 5; ++row) {
        std::cout << "\x1b[" << (line2Indent * glyphW + 1) << "C";
        for (size_t i = 0; i < line2.size(); ++i) {
            auto g = glyphFor(line2[i]);
            if (!g) continue;
            std::cout << cols[static_cast<int>(line1.size()) + static_cast<int>(i)];
            std::cout << (*g)[row];
        }
        std::cout << "\n";
    }
    std::cout << pal::dim << S("          ~ private multiplayer launcher ~\n") << term::RESET;
}

void typewriter(const std::string& text, int msPerChar = 12) {
    for (char c : text) {
        std::cout << c << std::flush;
        std::this_thread::sleep_for(std::chrono::milliseconds(msPerChar));
    }
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

// ----------------------------------------------------------------------------
// Game launching
// ----------------------------------------------------------------------------
std::optional<std::wstring> findGameDir() {
    std::wstring dir;
    if (const wchar_t* env = _wgetenv(SW(L"SDV_GAME_DIR").c_str()); env && *env) dir = env;
    if (dir.empty()) dir = SW(L"D:\\SDW\\Stardew Valley (413150)\\Stardew Valley");

    wchar_t exePath[MAX_PATH]{};
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    std::wstring exeDir(exePath);
    if (auto pos = exeDir.find_last_of(L'\\'); pos != std::wstring::npos)
        exeDir = exeDir.substr(0, pos);

    std::vector<std::wstring> candidates;
    candidates.push_back(exeDir); // game.exe placed next to the game folder
    candidates.push_back(dir);
    candidates.push_back(exeDir + SW(L"\\..\\..\\Stardew Valley (413150)\\Stardew Valley"));

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

// Launches StardewModdingAPI.exe with its console window hidden.
bool launchGameSilently(const std::wstring& gameDir, std::wstring& err) {
    if (!g_api.shellExec) {
        err = SW(L"initialization failed");
        return false;
    }
    std::wstring api = gameDir + SW(L"\\StardewModdingAPI.exe");
    if (GetFileAttributesW(api.c_str()) == INVALID_FILE_ATTRIBUTES) {
        err = SW(L"StardewModdingAPI.exe not found — apply the fix first");
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
    if (sei.hProcess) CloseHandle(sei.hProcess);
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
// UI
// ----------------------------------------------------------------------------
enum class Action { Launch, Coop, Fix, About, Exit };
struct MenuItem { std::string label; Action action; std::string desc; };

static const MenuItem MENU[] = {
    {S("Launch Game"), Action::Launch, S("start Stardew Valley via SMAPI (silent)")},
    {S("Join Co-op"),  Action::Coop,   S("coming soon")},
    {S("Apply Fix"),   Action::Fix,    S("coming soon")},
    {S("About"),       Action::About,  S("what is this")},
    {S("Exit"),        Action::Exit,   S("close the launcher")},
};

void statusLine(const std::string& msg, const std::string& color) {
    std::cout << "\r\x1b[K" << color << msg << term::RESET << std::flush;
}

void aboutScreen() {
    std::cout << term::CLEAR << term::HOME;
    std::cout << pal::gold << term::BOLD << S("  ABOUT\n") << term::RESET;
    std::cout << pal::cream << S("  game.exe v0.2.0\n\n") << term::RESET;
    std::cout << pal::cream << S("  A private launcher for a fully-modded Stardew Valley\n");
    std::cout << S("  co-op setup (SMAPI + mods + Goldberg emulator).\n\n") << term::RESET;
    std::cout << pal::dim << S("  Game dir:    ");
    auto d = findGameDir();
    std::cout << (d ? S("found") : S("not found")) << "\n" << term::RESET;
    std::cout << pal::dim << S("  Game running: ") << (isGameRunning() ? S("yes") : S("no")) << "\n\n" << term::RESET;
    std::cout << pal::cyan << S("  Press Enter to go back") << term::RESET << std::endl;
    for (;;) {
        int k = _getch();
        if (k == '\r' || k == 27) break;
    }
}

void doAction(Action a, Console& console) {
    switch (a) {
        case Action::Launch: {
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
            spinner(3, S("launching game silently"));
            std::wstring err;
            if (launchGameSilently(*dir, err)) {
                statusLine(S("  game launched (SMAPI console hidden)"), pal::ok);
            } else {
                statusLine(S("! ") + toUtf8(err), pal::red);
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1400));
            break;
        }
        case Action::Coop:
        case Action::Fix:
            statusLine(S("! coming soon — will be wired in a later update."), pal::amber);
            std::this_thread::sleep_for(std::chrono::milliseconds(1500));
            break;
        case Action::About:
            aboutScreen();
            break;
        case Action::Exit:
            console.stop = 1;
            break;
    }
}

void render(const Console& console, int sel) {
    std::cout << term::CLEAR << term::HOME;
    printBanner(console);
    std::cout << "\n";

    for (size_t i = 0; i < std::size(MENU); ++i) {
        bool on = (static_cast<int>(i) == sel);
        std::cout << "    ";
        if (on) {
            std::cout << pal::green << term::BOLD << S("▶ ") << term::RESET
                      << pal::bg(38, 62, 28) << pal::green << " " << MENU[i].label
                      << S("  ") << term::RESET << pal::dim << " " << MENU[i].desc << term::RESET;
        } else {
            std::cout << S("  ") << pal::dim << MENU[i].label << term::RESET;
        }
        std::cout << "\n";
    }
    std::cout << "\n  " << pal::dim
              << S("up/down navigate  ·  enter select  ·  esc quit")
              << term::RESET << "\n";
    std::cout << std::flush;
}

// ----------------------------------------------------------------------------
// main
// ----------------------------------------------------------------------------
int main(int argc, char** argv) {
    Console console;
    console.init();
    initApi();

    const bool selftest = (argc > 1 && std::string(argv[1]) == S("--selftest"));

    // startup animation
    std::cout << term::CLEAR << term::HOME;
    std::cout << pal::green << term::BOLD << S("\n  game.exe") << term::RESET << "\n\n";
    spinner(5, S("initializing"));
    typewriter(pal::gold + S("  Stardew Valley Online\n") + term::RESET, 8);

    int sel = 0;
    int key = 0;
    console.title(S("Multiplayer Private — Stardew Valley Online"));
    render(console, sel);

    while (!console.stop) {
        if (selftest) {
            // auto-drive the menu for verification, then end on "Launch Game"
            static int step = 0;
            if (step++ < 3) {
                std::this_thread::sleep_for(std::chrono::milliseconds(250));
                sel = (sel + 1) % static_cast<int>(std::size(MENU));
                render(console, sel);
                continue;
            }
            sel = 0;
            render(console, sel);
            doAction(MENU[0].action, console);
            break;
        }

        key = _getch();
        if (key == 0 || key == 224) { // arrow keys
            key = _getch();
            switch (key) {
                case 72: sel = (sel + static_cast<int>(std::size(MENU)) - 1) % static_cast<int>(std::size(MENU)); render(console, sel); break;
                case 80: sel = (sel + 1) % static_cast<int>(std::size(MENU)); render(console, sel); break;
            }
        } else if (key == '\r') {
            doAction(MENU[sel].action, console);
            render(console, sel);
        } else if (key == 27) {
            console.stop = 1;
        } else if (key == 'w' || key == 'W') {
            sel = (sel + static_cast<int>(std::size(MENU)) - 1) % static_cast<int>(std::size(MENU)); render(console, sel);
        } else if (key == 's' || key == 'S') {
            sel = (sel + 1) % static_cast<int>(std::size(MENU)); render(console, sel);
        }
    }

    console.restore();
    return 0;
}
