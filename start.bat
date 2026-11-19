
@echo off
chcp 65001 >nul
setlocal

title Password Authentication - Launcher

echo ========================================
echo   Password Authentication System
echo ========================================
echo.

:: Корневая папка проекта
set "ROOT=%~dp0"

:: Пути к решению и Release EXE
set "SOLUTION=%ROOT%Server\Server.sln"
set "EXE=%ROOT%Server\x64\Release\Server.exe"

:: Поиск MSBuild
echo [1/4] Поиск MSBuild...

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
set "VSINSTALL="

if not exist "%VSWHERE%" (
    echo [ОШИБКА] Не найден vswhere.exe!
    pause
    exit /b 1
)

for /f "usebackq tokens=*" %%I in (`"%VSWHERE%" -latest -products * -requires Microsoft.Component.MSBuild -property installationPath`) do (
    set "VSINSTALL=%%I"
)

if not defined VSINSTALL (
    echo [ОШИБКА] Visual Studio с MSBuild не найдена!
    pause
    exit /b 1
)

set "MSBUILD=%VSINSTALL%\MSBuild\Current\Bin\MSBuild.exe"

if not exist "%MSBUILD%" (
    echo [ОШИБКА] MSBuild.exe не найден!
    pause
    exit /b 1
)

if not exist "%SOLUTION%" (
    echo [ОШИБКА] Server.sln не найден!
    pause
    exit /b 1
)

:: Сборка Release x64
echo.
echo [2/4] Сборка проекта Release x64...
echo.


set "BUILD_LOG=%TEMP%\PasswordAuthentication-build.log"

"%MSBUILD%" "%SOLUTION%" /t:Build /p:Configuration=Release /p:Platform=x64 /restore /m /verbosity:minimal > "%BUILD_LOG%" 2>&1

if errorlevel 1 (
    echo.
    echo [ОШИБКА] Сборка завершилась неудачно!
    echo.
    echo Подробный журнал:
    echo %BUILD_LOG%
    echo.
    type "%BUILD_LOG%"
    echo.
    echo Сервер не будет запущен.
    pause
    exit /b 1
)

echo [OK] Сборка успешно завершена!

echo.
echo Проверка предупреждений...

findstr /i /c:"warning " "%BUILD_LOG%"

echo.


:: Запуск сервера из корня проекта
echo.
echo [3/4] Запуск сервера...
echo.

start "Auth Server" /D "%ROOT%" "%EXE%"

:: Небольшая задержка
timeout /t 2 /nobreak >nul

:: Открытие сайта
echo [4/4] Открытие сайта в браузере...

start "" "http://localhost:8080/index.html"

echo.
echo ========================================
echo   Сервер запущен!
echo   Сайт открыт в браузере.
echo.
echo   Для остановки закройте окно Auth Server.
echo ========================================
echo.

pause
