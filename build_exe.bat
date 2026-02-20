@echo off
cls
echo.
echo ========================================
echo     COM Sniffer - Build EXE
echo ========================================
echo.

cd /d "%~dp0"

REM Активирам виртуалния環境
call .venv\Scripts\activate.bat

REM Изтривам старите файлове
echo Изтривам старите build файлове...
rmdir /s /q build 2>nul
rmdir /s /q dist 2>nul
del *.spec 2>nul

echo.
echo Компилирам приложението (това ще отнеме 2-3 минути)...
echo.

REM Правя exe
pyinstaller --onefile --windowed com_sniffer.py

if %errorlevel% equ 0 (
    echo.
    echo ========================================
    echo       BUILD УСПЕШЕН!
    echo ========================================
    echo.
    echo EXE файлът е готов в: dist\com_sniffer.exe
    echo.
    echo Преместете го където искате и го стартирайте.
    echo.
    REM pause
) else (
    echo.
    echo ГРЕШКА при компилация!
    echo.
    REM pause
)
