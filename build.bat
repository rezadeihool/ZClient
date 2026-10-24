@echo off
setlocal

set "NDK_PATH=%LOCALAPPDATA%\Android\Sdk\ndk\30.0.15729638"
set "SCRIPT=%~dp0build-all-android-abis.ps1"

if not exist "%SCRIPT%" (
    echo ERROR: build-all-android-abis.ps1 was not found.
    pause
    exit /b 1
)

if not exist "%NDK_PATH%\toolchains\llvm" (
    echo ERROR: Android NDK was not found at:
    echo %NDK_PATH%
    pause
    exit /b 1
)

echo Building ZVPN for all Android architectures...
echo NDK: %NDK_PATH%
echo.

powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\build-all-android-abis.ps1" -NdkPath "$env:LOCALAPPDATA\Android\Sdk\ndk\30.0.15729638" -AndroidPlatform android-23

set "BUILD_EXIT=%ERRORLEVEL%"

if not "%BUILD_EXIT%"=="0" (
    echo.
    echo BUILD FAILED with exit code %BUILD_EXIT%.
    pause
    exit /b %BUILD_EXIT%
)

echo.
echo BUILD SUCCEEDED!
pause
exit /b 0