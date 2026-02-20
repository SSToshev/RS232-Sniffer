@echo off
REM COM Sniffer - Starter script

echo.
echo ========================================
echo       COM Sniffer Launcher
echo ========================================
echo.

REM Проверка дали Python е инсталиран
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python не е инсталиран или не е в PATH!
    echo Моля, инсталирайте Python 3.7+ от https://www.python.org/
    pause
    exit /b 1
)

echo [OK] Python намерен
echo.

REM Проверка за requirements
echo Проверка на необходимите библиотеки...
python -c "import PyQt5" >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] PyQt5 не е инсталиран
    echo Инсталиране на PyQt5...
    pip install PyQt5
)

python -c "import serial" >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] pyserial не е инсталиран
    echo Инсталиране на pyserial...
    pip install pyserial
)

echo.
echo [OK] Всички зависимости са налични
echo.
echo Стартиране на COM Sniffer...
echo.

REM Стартиране на приложението
python com_sniffer.py

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Приложението се затвори с грешка!
    pause
)
