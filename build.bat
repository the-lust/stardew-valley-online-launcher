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
cl /nologo /std:c++20 /EHsc /O2 /utf-8 /W4 /wd4996 /guard:cf main.cpp game.res /Fe:game.exe
if errorlevel 1 (
    echo.
    echo [FAIL] compilation failed.
    exit /b 1
)
echo.
echo [OK] Build finished: game.exe
exit /b 0
