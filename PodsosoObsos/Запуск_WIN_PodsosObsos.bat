@echo off
chcp 65001 >nul
title PodsosoObsos — All-in-One Antigravity & agy CLI Patcher
cd /d "%~dp0"

:: 1. Поиск интерпретатора Python в PATH
where python >nul 2>nul
if %ERRORLEVEL% equ 0 (
    python "%~dp0common\podsoso_obsos.py" %*
    goto :check_exit
)

where py >nul 2>nul
if %ERRORLEVEL% equ 0 (
    py -3 "%~dp0common\podsoso_obsos.py" %*
    goto :check_exit
)

where python3 >nul 2>nul
if %ERRORLEVEL% equ 0 (
    python3 "%~dp0common\podsoso_obsos.py" %*
    goto :check_exit
)

:: 2. Поиск Python в стандартных каталогах пользователей и системы
for /d %%D in ("%LOCALAPPDATA%\Programs\Python\Python*") do (
    if exist "%%D\python.exe" (
        "%%D\python.exe" "%~dp0common\podsoso_obsos.py" %*
        goto :check_exit
    )
)
for /d %%D in ("%ProgramFiles%\Python*") do (
    if exist "%%D\python.exe" (
        "%%D\python.exe" "%~dp0common\podsoso_obsos.py" %*
        goto :check_exit
    )
)
for /d %%U in ("C:\Users\*") do (
    for /d %%D in ("%%U\AppData\Local\Programs\Python\Python*") do (
        if exist "%%D\python.exe" (
            "%%D\python.exe" "%~dp0common\podsoso_obsos.py" %*
            goto :check_exit
        )
    )
)

echo.
echo ============================================================
echo  [ОШИБКА] Python 3 не найден в системе Windows!
echo ============================================================
echo.
echo Для работы PodsosoObsos необходим Python 3:
echo   1. Скачайте Python с официального сайта:
echo      https://www.python.org/downloads/
echo   2. При установке ОБЯЗАТЕЛЬНО отметьте галочку:
echo      "[x] Add python.exe to PATH"
echo.
pause
exit /b 1

:check_exit
if %ERRORLEVEL% neq 0 (
    echo.
    echo [!] Программа завершилась с ошибкой: %ERRORLEVEL%
    pause
)
