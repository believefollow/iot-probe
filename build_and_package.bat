@echo off
setlocal
title IoTProbe build / deploy / package

REM ============================================================
REM  IoTProbe one-shot: build -> deploy (backup old exe) -> dist zips
REM  Usage (arg = dist variant):
REM    build_and_package.bat               build + deploy + clean/full zips
REM    build_and_package.bat clean         build + deploy + clean zip only
REM    build_and_package.bat full          build + deploy + full zip only
REM    build_and_package.bat deploy-only   build + deploy, no packaging
REM    build_and_package.bat package-only  skip build, deploy + package
REM  Deploy convention: back up old D:\dev\tools\iotprobe.exe as
REM  .bak-YYYYMMDD (same-day backups become .bak2-/.bak3-...), then replace.
REM  NOTE: keep this file ASCII-only. A UTF-8 Chinese .bat with "chcp 65001"
REM  is mis-parsed by cmd.exe (lines get split at multi-byte boundaries),
REM  which is exactly why the old Chinese version failed when double-clicked.
REM ============================================================

set VARIANT=%1
if "%VARIANT%"=="" set VARIANT=both
set DO_BUILD=1
set DO_PACKAGE=1
if /i "%VARIANT%"=="deploy-only" set DO_PACKAGE=0
if /i "%VARIANT%"=="package-only" set DO_BUILD=0

REM This script lives in iot-probe\ = Cargo workspace root (Cargo.toml here).
REM The old "%~dp0.." jumped one level up, so cargo could not find the workspace.
cd /d "%~dp0"

if "%DO_BUILD%"=="0" goto deploy

echo.
echo ==== [1/4] build release: iotprobe / batch_runner / iotprobe-mcp ====
cargo build --release -p iotprobe -p iotprobe-core -p iotprobe-aimcp
if errorlevel 1 (
    echo [ERROR] build failed
    pause
    exit /b 1
)

echo.
echo ==== [2/4] build 32-bit legacy VCI bridge (optional) ====
rustup target list --installed 2>nul | findstr /C:"i686-pc-windows-msvc" >nul
if errorlevel 1 (
    echo [SKIP] i686 target not installed - legacy VCI bridge not built
    goto deploy
)
REM package name is "vci-bridge" (hyphenated); old script used -p vcibridge and silently failed
cargo build --release --target i686-pc-windows-msvc -p vci-bridge
if errorlevel 1 echo [WARN] 32-bit bridge build failed, everything else unaffected

:deploy
echo.
echo ==== [3/4] deploy main exe to D:\dev\tools (backup old first) ====
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; $src='target\release\iotprobe.exe'; $dst='D:\dev\tools\iotprobe.exe'; if(-not (Test-Path $src)){ Write-Host '[ERROR] missing target\release\iotprobe.exe'; exit 1 }; if((Get-FileHash $src).Hash -eq (Get-FileHash $dst).Hash){ Write-Host '  already up to date, skip deploy'; exit 0 }; $d=Get-Date -Format yyyyMMdd; $base='D:\dev\tools\iotprobe.exe.bak'; if(Test-Path $dst){ $b=$base+'-'+$d; if(-not (Test-Path $b)){ Copy-Item $dst $b; Write-Host ('  backup -> iotprobe.exe.bak-'+$d) } else { $done=$false; foreach($i in 2..9){ $b=$base+$i+'-'+$d; if(-not (Test-Path $b)){ Copy-Item $dst $b; Write-Host ('  backup -> iotprobe.exe.bak'+$i+'-'+$d); $done=$true; break } }; if(-not $done){ Write-Host '[ERROR] backup slots full (.bak2~.bak9), clean up and retry'; exit 1 } } }; Copy-Item $src $dst -Force; Write-Host ('  replaced D:\dev\tools\iotprobe.exe ('+((Get-Item $dst).Length)+' bytes)')
if errorlevel 1 (
    echo [ERROR] deploy failed - common cause: iotprobe.exe is running, close it first
    pause
    exit /b 1
)

if "%DO_PACKAGE%"=="0" goto done

echo.
echo ==== [4/4] assemble dist packages (zip under dist\) ====
python scripts\package_release.py --variant %VARIANT%
if errorlevel 1 (
    echo [ERROR] packaging failed
    pause
    exit /b 1
)

:done
echo.
echo ==== done ====
dir /b dist\IoTProbe-v*-win64-*.zip 2>nul
pause
exit /b 0
