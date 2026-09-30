@echo off
chcp 65001 >nul
title Password Authentication - Launcher

echo ========================================
echo   Password Authentication System
echo ========================================
echo.

if not exist "server.exe" (
    echo [ОШИБКА] Файл server.exe не найден!
    echo Убедитесь, что server.exe лежит в одной папке со start.bat
    echo.
    pause
    exit /b 1
)

echo [1/2] Запуск сервера...
start "Auth Server" cmd /k server.exe

timeout /t 2 /nobreak >nul

echo [2/2] Открытие сайта в браузере...
start "" "Website\index.html"

echo.
echo ========================================
echo   Сервер запущен!
echo   Сайт открыт в браузере.
echo.
echo   Чтобы остановить сервер:
echo   закройте окно "Auth Server".
echo ========================================
echo.
pause