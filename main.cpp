// ============================================================================
//  game.exe — Stardew Valley Online private co-op launcher
//  Single-file C++20, Win32 console app, ANSI truecolor UI.
//  v0.1.0 — menu UI; "Launch Game" runs StardewModdingAPI.exe silently
//  (SMAPI's own terminal window is hidden).
// ============================================================================
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <shellapi.h>
#pragma comment(lib, "shell32.lib")

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
        SetConsoleTitleW(L"Multiplayer Private — Stardew Valley Online");
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
    const std::string line1 = "STARDEW VALLEY";
    const std::string line2 = "ONLINE";
    const int w = console.size().X;
    const int glyphW = 7; // 6 + spacer
    const int need = static_cast<int>(line1.size()) * glyphW;

    if (w < need) { // fallback: plain text logo
        std::cout << pal::gold << term::BOLD << "  * STARDEW VALLEY ONLINE *\n" << term::RESET;
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
    std::cout << pal::dim << "          ~ private multiplayer launcher ~\n" << term::RESET;
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
    if (const wchar_t* env = _wgetenv(L"SDV_GAME_DIR"); env && *env) dir = env;
    if (dir.empty()) dir = L"D:\\SDW\\Stardew Valley (413150)\\Stardew Valley";

    wchar_t exePath[MAX_PATH]{};
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    std::wstring exeDir(exePath);
    if (auto pos = exeDir.find_last_of(L'\\'); pos != std::wstring::npos)
        exeDir = exeDir.substr(0, pos);

    std::vector<std::wstring> candidates;
    candidates.push_back(exeDir); // game.exe placed next to the game folder
    candidates.push_back(dir);
    candidates.push_back(exeDir + L"\\..\\..\\Stardew Valley (413150)\\Stardew Valley");

    for (const auto& c : candidates) {
        if (c.empty()) continue;
        auto has = [&](const wchar_t* f) {
            return GetFileAttributesW((c + L"\\" + f).c_str()) != INVALID_FILE_ATTRIBUTES;
        };
        if (has(L"Stardew Valley.exe") || has(L"StardewModdingAPI.exe"))
            return c;
    }
    return std::nullopt;
}

// Launches StardewModdingAPI.exe with its console window hidden.
bool launchGameSilently(const std::wstring& gameDir, std::wstring& err) {
    std::wstring api = gameDir + L"\\StardewModdingAPI.exe";
    if (GetFileAttributesW(api.c_str()) == INVALID_FILE_ATTRIBUTES) {
        err = L"StardewModdingAPI.exe not found — apply the fix first";
        return false;
    }
    SHELLEXECUTEINFOW sei{};
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
    sei.lpFile = api.c_str();
    sei.lpDirectory = gameDir.c_str();
    sei.nShow = SW_HIDE;
    if (!ShellExecuteExW(&sei)) {
        wchar_t buf[512]{};
        FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM, nullptr, GetLastError(), 0, buf, 512, nullptr);
        err = std::wstring(L"launch failed: ") + buf;
        return false;
    }
    if (sei.hProcess) CloseHandle(sei.hProcess);
    return true;
}

bool isGameRunning() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    bool found = false;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"StardewModdingAPI.exe") == 0 ||
                _wcsicmp(pe.szExeFile, L"Stardew Valley.exe") == 0) { found = true; break; }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

// ----------------------------------------------------------------------------
// UI
// ----------------------------------------------------------------------------
enum class Action { Launch, Coop, Fix, About, Exit };
struct MenuItem { const char* label; Action action; const char* desc; };

const MenuItem MENU[] = {
    {"Launch Game", Action::Launch, "start Stardew Valley via SMAPI (silent)"},
    {"Join Co-op",  Action::Coop,   "coming soon"},
    {"Apply Fix",   Action::Fix,    "coming soon"},
    {"About",       Action::About,  "what is this"},
    {"Exit",        Action::Exit,   "close the launcher"},
};

void statusLine(const std::string& msg, const std::string& color) {
    std::cout << "\r\x1b[K" << color << msg << term::RESET << std::flush;
}

void aboutScreen() {
    std::cout << term::CLEAR << term::HOME;
    std::cout << pal::gold << term::BOLD << "  ABOUT\n" << term::RESET;
    std::cout << pal::cream << "  game.exe v0.1.0\n\n" << term::RESET;
    std::cout << pal::cream << "  A private launcher for a fully-modded Stardew Valley\n";
    std::cout << "  co-op setup (SMAPI + mods + Goldberg emulator).\n\n" << term::RESET;
    std::cout << pal::dim << "  Game dir:    ";
    auto d = findGameDir();
    std::cout << (d ? "found" : "not found") << "\n" << term::RESET;
    std::cout << pal::dim << "  Game running: " << (isGameRunning() ? "yes" : "no") << "\n\n" << term::RESET;
    std::cout << pal::cyan << "  Press Enter to go back" << term::RESET << std::endl;
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
                statusLine("! game folder not found.", pal::red);
                std::this_thread::sleep_for(std::chrono::milliseconds(1600));
                return;
            }
            if (isGameRunning()) {
                statusLine("! the game is already running.", pal::amber);
                std::this_thread::sleep_for(std::chrono::milliseconds(1400));
                return;
            }
            spinner(3, "launching game silently");
            std::wstring err;
            if (launchGameSilently(*dir, err)) {
                statusLine("  game launched (SMAPI console hidden)", pal::ok);
            } else {
                statusLine("! " + toUtf8(err), pal::red);
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1400));
            break;
        }
        case Action::Coop:
        case Action::Fix:
            statusLine("! coming soon — will be wired in a later update.", pal::amber);
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
            std::cout << pal::green << term::BOLD << "▶ " << term::RESET
                      << pal::bg(38, 62, 28) << pal::green << " " << MENU[i].label
                      << "  " << term::RESET << pal::dim << " " << MENU[i].desc << term::RESET;
        } else {
            std::cout << "  " << pal::dim << MENU[i].label << term::RESET;
        }
        std::cout << "\n";
    }
    std::cout << "\n  " << pal::dim
              << "up/down navigate  ·  enter select  ·  esc quit"
              << term::RESET << "\n";
    std::cout << std::flush;
}

// ----------------------------------------------------------------------------
// main
// ----------------------------------------------------------------------------
int main(int argc, char** argv) {
    Console console;
    console.init();

    const bool selftest = (argc > 1 && std::string(argv[1]) == "--selftest");

    // startup animation
    std::cout << term::CLEAR << term::HOME;
    std::cout << pal::green << term::BOLD << "\n  game.exe" << term::RESET << "\n\n";
    spinner(5, "initializing");
    typewriter(pal::gold + "  Stardew Valley Online\n" + term::RESET, 8);

    int sel = 0;
    int key = 0;
    console.title("Multiplayer Private — Stardew Valley Online");
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
