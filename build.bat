@echo off
REM Windows build script for HackingGPT Desktop Application
REM This script automates the entire build process

echo ============================================
echo HackingGPT Desktop Application Builder
echo ============================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.8+ and try again
    pause
    exit /b 1
)

echo Python found: 
python --version
echo.

REM Create virtual environment
echo Creating virtual environment...
if not exist "venv" (
    python -m venv venv
    if errorlevel 1 (
        echo ERROR: Failed to create virtual environment
        pause
        exit /b 1
    )
) else (
    echo Virtual environment already exists
)

REM Activate virtual environment
echo Activating virtual environment...
call venv\Scripts\activate.bat
if errorlevel 1 (
    echo ERROR: Failed to activate virtual environment
    pause
    exit /b 1
)

REM Upgrade pip
echo Upgrading pip...
python -m pip install --upgrade pip

REM Install dependencies
echo Installing dependencies...
pip install -r requirements_webview.txt
if errorlevel 1 (
    echo ERROR: Failed to install dependencies
    pause
    exit /b 1
)

REM Install PyInstaller
echo Installing PyInstaller...
pip install pyinstaller==6.2.0
if errorlevel 1 (
    echo ERROR: Failed to install PyInstaller
    pause
    exit /b 1
)

REM Create assets directory and placeholder icon
if not exist "assets" mkdir assets
if not exist "assets\icon.ico" (
    echo Creating placeholder icon...
    echo. > assets\icon.ico
)

REM Check if required files exist
if not exist "webview_app.py" (
    echo ERROR: webview_app.py not found!
    echo Please make sure all required files are in the current directory
    pause
    exit /b 1
)

if not exist "app.py" (
    echo ERROR: app.py not found!
    echo Please make sure the Flask application file is present
    pause
    exit /b 1
)

if not exist "templates" (
    echo ERROR: templates directory not found!
    echo Please make sure the templates directory exists
    pause
    exit /b 1
)

REM Run the build script
echo Starting build process...
python build_executable.py
if errorlevel 1 (
    echo ERROR: Build process failed
    pause
    exit /b 1
)

echo.
echo ============================================
echo BUILD COMPLETED SUCCESSFULLY!
echo ============================================
echo.
echo Executable location: dist\HackingGPT.exe
echo Installer script: HackingGPT_installer.nsi
echo.
echo To create Windows installer:
echo 1. Install NSIS (Nullsoft Scriptable Install System)
echo 2. Right-click on HackingGPT_installer.nsi
echo 3. Select "Compile NSIS Script"
echo.
echo To test the application:
echo 1. Navigate to dist\ folder
echo 2. Run HackingGPT.exe
echo.

REM Deactivate virtual environment
deactivate

echo Press any key to exit...
pause >nul