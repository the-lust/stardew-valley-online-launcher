@echo off
setlocal
call "D:\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 (
    echo [FAIL] vcvars64.bat not found.
    exit /b 1
)
where rc >nul 2>nul
if errorlevel 1 (
    set "RC=C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\rc.exe"
) else (
    set "RC=rc"
)
"%RC%" /nologo game.rc
if errorlevel 1 (
    echo.
    echo [FAIL] resource compilation failed.
    exit /b 1
)
"%RC%" /nologo helper.rc
if errorlevel 1 (
    echo.
    echo [FAIL] helper resource compilation failed.
    exit /b 1
)
cl /nologo /std:c++20 /EHsc /O2 /utf-8 /W4 /wd4996 /guard:cf main.cpp game.res /Fe:game.exe
if errorlevel 1 (
    echo.
    echo [FAIL] compilation failed.
    exit /b 1
)
cl /nologo /std:c++20 /EHsc /O2 /utf-8 /W4 /wd4996 /guard:cf helper.cpp helper.res advapi32.lib /Fe:helper.exe
if errorlevel 1 (
    echo.
    echo [FAIL] helper compilation failed.
    exit /b 1
)
cl /nologo /LD /O2 /utf-8 /W4 /wd4996 meow.cpp advapi32.lib /Fe:meow.dll
if errorlevel 1 (
    echo.
    echo [FAIL] meow.dll compilation failed.
    exit /b 1
)
if not exist VIP-FILES mkdir VIP-FILES
copy /y helper.exe VIP-FILES\helper.exe >nul
copy /y meow.dll VIP-FILES\meow.dll >nul
echo.
echo [OK] Build finished: game.exe, helper.exe, meow.dll (VIP-FILES)
exit /b 0
