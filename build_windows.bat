
@echo off
REM =========================================================================
REM v3 Core Windows Build Script
REM 
REM 用法:
REM   build_windows.bat [release|debug|clean|help]
REM
REM 要求:
REM   - Visual Studio 2019/2022 或 MinGW-w64
REM   - CMake 3.16+
REM =========================================================================

setlocal EnableDelayedExpansion

REM --- 配置 ---
set PROJECT_NAME=v3_core
set BUILD_DIR=build
set OUTPUT_DIR=output

REM --- 颜色定义（Windows 10+）---
set "GREEN=[92m"
set "RED=[91m"
set "YELLOW=[93m"
set "BLUE=[94m"
set "RESET=[0m"

REM --- 横幅 ---
echo.
echo %BLUE%╔═══════════════════════════════════════════════════════════════╗%RESET%
echo %BLUE%║              v3 Core Windows Build Script                     ║%RESET%
echo %BLUE%╚═══════════════════════════════════════════════════════════════╝%RESET%
echo.

REM --- 参数解析 ---
set BUILD_TYPE=release
set USE_CMAKE=1
set USE_MSVC=0
set CLEAN_BUILD=0

if "%1"=="" goto :detect_tools
if /i "%1"=="release" set BUILD_TYPE=release & goto :detect_tools
if /i "%1"=="debug" set BUILD_TYPE=debug & goto :detect_tools
if /i "%1"=="clean" goto :clean
if /i "%1"=="msvc" set USE_MSVC=1 & goto :detect_tools
if /i "%1"=="mingw" set USE_MSVC=0 & goto :detect_tools
if /i "%1"=="help" goto :help
if /i "%1"=="-h" goto :help
if /i "%1"=="--help" goto :help

echo %RED%[ERROR]%RESET% Unknown option: %1
goto :help

REM =========================================================================
REM 检测工具
REM =========================================================================
:detect_tools
echo %YELLOW%[INFO]%RESET% Detecting build tools...

REM 检测 CMake
where cmake >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo %RED%[ERROR]%RESET% CMake not found!
    echo        Please install CMake 3.16+ and add to PATH
    goto :error
)
for /f "tokens=3" %%v in ('cmake --version ^| findstr /i "cmake version"') do set CMAKE_VERSION=%%v
echo   CMake: %CMAKE_VERSION%

REM 检测 Visual Studio
set VS_FOUND=0
if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" (
    set "VS_PATH=%ProgramFiles%\Microsoft Visual Studio\2022\Community"
    set VS_YEAR=2022
    set VS_FOUND=1
)
if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvarsall.bat" (
    set "VS_PATH=%ProgramFiles%\Microsoft Visual Studio\2022\Professional"
    set VS_YEAR=2022
    set VS_FOUND=1
)
if exist "%ProgramFiles%\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat" (
    set "VS_PATH=%ProgramFiles%\Microsoft Visual Studio\2019\Community"
    set VS_YEAR=2019
    set VS_FOUND=1
)
if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat" (
    set "VS_PATH=%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Community"
    set VS_YEAR=2019
    set VS_FOUND=1
)

if %VS_FOUND%==1 (
    echo   Visual Studio: %VS_YEAR%
)

REM 检测 MinGW
where gcc >nul 2>&1
if %ERRORLEVEL% equ 0 (
    for /f "tokens=3" %%v in ('gcc --version ^| findstr /i "gcc"') do set GCC_VERSION=%%v
    echo   MinGW GCC: !GCC_VERSION!
    set MINGW_FOUND=1
) else (
    set MINGW_FOUND=0
)

REM 决定使用哪个编译器
if %USE_MSVC%==1 (
    if %VS_FOUND%==0 (
        echo %RED%[ERROR]%RESET% Visual Studio not found!
        goto :error
    )
    set CMAKE_GENERATOR="Visual Studio 17 2022"
    if "%VS_YEAR%"=="2019" set CMAKE_GENERATOR="Visual Studio 16 2019"
    echo   Using: Visual Studio %VS_YEAR%
) else (
    if %MINGW_FOUND%==0 (
        echo %RED%[ERROR]%RESET% MinGW-w64 not found!
        echo        Please install MinGW-w64 and add to PATH
        goto :error
    )
    set CMAKE_GENERATOR="MinGW Makefiles"
    echo   Using: MinGW-w64
)

echo.

REM =========================================================================
REM 创建构建目录
REM =========================================================================
:prepare_build
echo %YELLOW%[INFO]%RESET% Preparing build directory...

if not exist %BUILD_DIR% mkdir %BUILD_DIR%
if not exist %OUTPUT_DIR% mkdir %OUTPUT_DIR%

cd %BUILD_DIR%

REM =========================================================================
REM CMake 配置
REM =========================================================================
:cmake_configure
echo.
echo %YELLOW%[INFO]%RESET% Configuring with CMake...
echo.

set CMAKE_OPTIONS=-DCMAKE_BUILD_TYPE=%BUILD_TYPE%
set CMAKE_OPTIONS=%CMAKE_OPTIONS% -DV3_ENABLE_FEC=ON
set CMAKE_OPTIONS=%CMAKE_OPTIONS% -DV3_ENABLE_PACING=ON
set CMAKE_OPTIONS=%CMAKE_OPTIONS% -DV3_ENABLE_GUARD=ON
set CMAKE_OPTIONS=%CMAKE_OPTIONS% -DV3_STATIC_LINK=ON

if /i "%BUILD_TYPE%"=="debug" (
    set CMAKE_OPTIONS=%CMAKE_OPTIONS% -DV3_BUILD_TESTS=ON
)

cmake -G %CMAKE_GENERATOR% %CMAKE_OPTIONS% ..
if %ERRORLEVEL% neq 0 (
    echo %RED%[ERROR]%RESET% CMake configuration failed!
    cd ..
    goto :error
)

REM =========================================================================
REM 编译
REM =========================================================================
:build
echo.
echo %YELLOW%[INFO]%RESET% Building %BUILD_TYPE% configuration...
echo.

cmake --build . --config %BUILD_TYPE% --parallel
if %ERRORLEVEL% neq 0 (
    echo %RED%[ERROR]%RESET% Build failed!
    cd ..
    goto :error
)

cd ..

REM =========================================================================
REM 复制输出
REM =========================================================================
:copy_output
echo.
echo %YELLOW%[INFO]%RESET% Copying output files...

if %USE_MSVC%==1 (
    if exist "%BUILD_DIR%\bin\%BUILD_TYPE%\%PROJECT_NAME%.exe" (
        copy "%BUILD_DIR%\bin\%BUILD_TYPE%\%PROJECT_NAME%.exe" "%OUTPUT_DIR%\" >nul
    )
) else (
    if exist "%BUILD_DIR%\bin\%PROJECT_NAME%.exe" (
        copy "%BUILD_DIR%\bin\%PROJECT_NAME%.exe" "%OUTPUT_DIR%\" >nul
    )
)

if not exist "%OUTPUT_DIR%\%PROJECT_NAME%.exe" (
    echo %YELLOW%[WARN]%RESET% Output binary not found, checking alternate locations...
    
    REM 尝试其他可能的位置
    for /r "%BUILD_DIR%" %%f in (%PROJECT_NAME%.exe) do (
        echo   Found: %%f
        copy "%%f" "%OUTPUT_DIR%\" >nul
        goto :success
    )
    
    echo %RED%[ERROR]%RESET% Could not find built binary!
    goto :error
)

REM =========================================================================
REM 成功
REM =========================================================================
:success
echo.
echo %GREEN%╔═══════════════════════════════════════════════════════════════╗%RESET%
echo %GREEN%║                    Build Successful!                          ║%RESET%
echo %GREEN%╠═══════════════════════════════════════════════════════════════╣%RESET%
echo %GREEN%║  Output: %OUTPUT_DIR%\%PROJECT_NAME%.exe%RESET%
echo %GREEN%║  Type:   %BUILD_TYPE%%RESET%
echo %GREEN%╚═══════════════════════════════════════════════════════════════╝%RESET%
echo.

REM 显示文件信息
for %%f in (%OUTPUT_DIR%\%PROJECT_NAME%.exe) do (
    echo   Size: %%~zf bytes
    echo   Date: %%~tf
)
echo.

goto :end

REM =========================================================================
REM 清理
REM =========================================================================
:clean
echo %YELLOW%[INFO]%RESET% Cleaning build artifacts...

if exist %BUILD_DIR% (
    rmdir /S /Q %BUILD_DIR%
    echo   Removed: %BUILD_DIR%
)
if exist %OUTPUT_DIR% (
    rmdir /S /Q %OUTPUT_DIR%
    echo   Removed: %OUTPUT_DIR%
)

echo %GREEN%[OK]%RESET% Clean complete.
goto :end

REM =========================================================================
REM 帮助
REM =========================================================================
:help
echo.
echo Usage: %~nx0 [command] [options]
echo.
echo Commands:
echo   release     Build optimized release binary (default)
echo   debug       Build debug binary with symbols
echo   clean       Remove all build artifacts
echo   help        Show this help
echo.
echo Options:
echo   msvc        Force Visual Studio compiler
echo   mingw       Force MinGW-w64 compiler
echo.
echo Examples:
echo   %~nx0                    Build release with auto-detected compiler
echo   %~nx0 debug              Build debug version
echo   %~nx0 release msvc       Build release with Visual Studio
echo   %~nx0 clean              Clean build files
echo.
goto :end

REM =========================================================================
REM 错误处理
REM =========================================================================
:error
echo.
echo %RED%Build failed!%RESET%
echo.
exit /b 1

REM =========================================================================
REM 结束
REM =========================================================================
:end
endlocal
exit /b 0



