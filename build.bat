@echo off
cls
echo ========================================
echo   NATIVE - EXE Builder
echo   Phishing Email Detection System
echo ========================================
echo.

echo Building NATIVE.exe...
echo Please wait (1-2 minutes)...
echo.

python -m pip install pyinstaller reportlab --quiet
python -m PyInstaller --onefile --windowed --name NATIVE native.py

if exist dist\NATIVE.exe (
    echo.
    echo ========================================
    echo   SUCCESS!
    echo ========================================
    echo.
    echo NATIVE.exe created in: dist\
    echo.
    explorer dist
) else (
    echo.
    echo ERROR: Build failed!
)

pause