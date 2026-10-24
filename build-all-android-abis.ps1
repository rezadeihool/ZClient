param(
    [Parameter(Mandatory = $true)]
    [string] $NdkPath,

    [string] $AndroidPlatform = "android-23",

    # Resolve this after param binding. In some PowerShell launch contexts,
    # $PSScriptRoot is empty while default parameter expressions are evaluated.
    [string] $OutputDir
)

$ErrorActionPreference = "Stop"

$ScriptRoot = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($ScriptRoot)) {
    $ScriptPath = $MyInvocation.MyCommand.Path
    if (-not [string]::IsNullOrWhiteSpace($ScriptPath)) {
        $ScriptRoot = Split-Path -Parent $ScriptPath
    } else {
        $ScriptRoot = (Get-Location).Path
    }
}
if ([string]::IsNullOrWhiteSpace($ScriptRoot)) {
    throw "Could not determine the script directory. Save and run this as a .ps1 file."
}

if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $OutputDir = Join-Path $ScriptRoot "out\jniLibs"
} elseif (-not [System.IO.Path]::IsPathRooted($OutputDir)) {
    $OutputDir = Join-Path $ScriptRoot $OutputDir
}

if (-not (Test-Path -LiteralPath $NdkPath -PathType Container)) {
    throw "Android NDK directory not found: $NdkPath"
}
$NdkPath = (Resolve-Path -LiteralPath $NdkPath).Path
$Toolchain = Join-Path $NdkPath "build\cmake\android.toolchain.cmake"
if (-not (Test-Path $Toolchain)) {
    throw "Android NDK CMake toolchain was not found: $Toolchain"
}
if (-not (Test-Path (Join-Path $ScriptRoot "zvpn_jni.c"))) {
    throw "zvpn_jni.c must be in the same folder as this script: $ScriptRoot"
}
if (-not (Test-Path (Join-Path $ScriptRoot "zstd\build\cmake\CMakeLists.txt"))) {
    throw "Expected the Zstandard source at .\zstd\build\cmake\CMakeLists.txt"
}

$Abis = @("arm64-v8a", "armeabi-v7a", "x86_64", "x86")
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

foreach ($Abi in $Abis) {
    Write-Host "`n===== Building vpnengine for $Abi ($AndroidPlatform) =====" -ForegroundColor Cyan
    $BuildDir = Join-Path $ScriptRoot "build-android-$Abi"

    & cmake `
        -S $ScriptRoot `
        -B $BuildDir `
        -G Ninja `
        "-DCMAKE_TOOLCHAIN_FILE=$Toolchain" `
        "-DANDROID_ABI=$Abi" `
        "-DANDROID_PLATFORM=$AndroidPlatform" `
        "-DCMAKE_BUILD_TYPE=Release" `
        "-DZSTD_BUILD_PROGRAMS=OFF" `
        "-DZSTD_BUILD_TESTS=OFF" `
        "-DZSTD_BUILD_CONTRIB=OFF" `
        "-DZSTD_BUILD_SHARED=OFF" `
        "-DZSTD_BUILD_STATIC=ON" `
        "-DZSTD_MULTITHREAD_SUPPORT=OFF"
    if ($LASTEXITCODE -ne 0) { throw "CMake configure failed for $Abi (exit $LASTEXITCODE)." }

    & cmake --build $BuildDir --config Release --target vpnengine --parallel
    if ($LASTEXITCODE -ne 0) { throw "Compilation failed for $Abi (exit $LASTEXITCODE)." }

    $BuiltLibrary = Join-Path $BuildDir "libvpnengine.so"
    if (-not (Test-Path $BuiltLibrary)) {
        throw "Build succeeded but output library was not found: $BuiltLibrary"
    }

    $AbiOutput = Join-Path $OutputDir $Abi
    New-Item -ItemType Directory -Force -Path $AbiOutput | Out-Null
    Copy-Item $BuiltLibrary (Join-Path $AbiOutput "libvpnengine.so") -Force
    Write-Host "Output: $(Join-Path $AbiOutput 'libvpnengine.so')" -ForegroundColor Green
}

Write-Host "`nAll ABI builds completed. Copy the four ABI folders into your Android app's jniLibs directory." -ForegroundColor Green
