#!/usr/bin/env python3
"""
Build script for creating HackingGPT executable using PyInstaller
Supports Windows, macOS, and Linux
"""

import os
import sys
import shutil
import subprocess
import platform
from pathlib import Path

# Configuration
APP_NAME = "HackingGPT"
SCRIPT_NAME = "webview_app.py"
ICON_PATH = "assets/icon.ico"  # Windows
ICON_PATH_MAC = "assets/icon.icns"  # macOS
ICON_PATH_LINUX = "assets/icon.png"  # Linux

def get_platform_info():
    """Get platform-specific information"""
    system = platform.system().lower()
    return {
        'system': system,
        'is_windows': system == 'windows',
        'is_macos': system == 'darwin',
        'is_linux': system == 'linux',
        'arch': platform.machine()
    }

def create_directories():
    """Create necessary directories"""
    directories = ['dist', 'build', 'assets', 'templates', 'static']
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
        print(f"Created directory: {directory}")

def create_icon_files():
    """Create placeholder icon files if they don't exist"""
    platform_info = get_platform_info()
    
    # Create assets directory
    Path("assets").mkdir(exist_ok=True)
    
    # Create basic icon files (you should replace these with actual icons)
    icon_files = []
    
    if platform_info['is_windows']:
        icon_files.append(("assets/icon.ico", "Windows ICO file"))
    elif platform_info['is_macos']:
        icon_files.append(("assets/icon.icns", "macOS ICNS file"))
    else:
        icon_files.append(("assets/icon.png", "Linux PNG file"))
    
    for icon_file, description in icon_files:
        if not Path(icon_file).exists():
            print(f"Warning: {icon_file} not found. Creating placeholder.")
            # Create empty file as placeholder
            Path(icon_file).touch()

def get_pyinstaller_command():
    """Generate PyInstaller command based on platform"""
    platform_info = get_platform_info()
    
    base_command = [
        'pyinstaller',
        '--name', APP_NAME,
        '--onefile',  # Single executable file
        '--windowed',  # No console window
        '--clean',
        '--noconfirm',
        
        # Add app data
        '--add-data', 'templates;templates',
        '--add-data', 'static;static',
        
        # Hidden imports for Flask and WebView
        '--hidden-import', 'flask',
        '--hidden-import', 'flask_socketio',
        '--hidden-import', 'webview',
        '--hidden-import', 'sqlite3',
        '--hidden-import', 'json',
        '--hidden-import', 'threading',
        '--hidden-import', 'requests',
        '--hidden-import', 'werkzeug.security',
        '--hidden-import', 'cryptography',
        '--hidden-import', 'celery',
        '--hidden-import', 'redis',
        '--hidden-import', 'markdown',
        '--hidden-import', 'bleach',
        
        # Exclude unnecessary modules to reduce size
        '--exclude-module', 'tkinter',
        '--exclude-module', 'matplotlib',
        '--exclude-module', 'PIL',
        '--exclude-module', 'numpy',
        '--exclude-module', 'pandas',
    ]
    
    # Platform-specific configurations
    if platform_info['is_windows']:
        if Path(ICON_PATH).exists():
            base_command.extend(['--icon', ICON_PATH])
        base_command.extend([
            '--version-file', 'version_info.txt',  # Will create this
            '--add-data', 'app.py;.',
        ])
        
    elif platform_info['is_macos']:
        if Path(ICON_PATH_MAC).exists():
            base_command.extend(['--icon', ICON_PATH_MAC])
        base_command.extend([
            '--add-data', 'app.py:.',
            '--osx-bundle-identifier', 'com.hackinggpt.desktop',
        ])
        
    else:  # Linux
        if Path(ICON_PATH_LINUX).exists():
            base_command.extend(['--icon', ICON_PATH_LINUX])
        base_command.extend([
            '--add-data', 'app.py:.',
        ])
    
    # Add the main script
    base_command.append(SCRIPT_NAME)
    
    return base_command

def create_version_file():
    """Create version file for Windows executable"""
    version_content = '''# UTF-8
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=(1, 0, 0, 0),
    prodvers=(1, 0, 0, 0),
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
  ),
  kids=[
    StringFileInfo(
      [
      StringTable(
        u'040904B0',
        [StringStruct(u'CompanyName', u'HackingGPT'),
        StringStruct(u'FileDescription', u'HackingGPT Desktop Application'),
        StringStruct(u'FileVersion', u'1.0.0'),
        StringStruct(u'InternalName', u'HackingGPT'),
        StringStruct(u'LegalCopyright', u'Copyright (c) 2024'),
        StringStruct(u'OriginalFilename', u'HackingGPT.exe'),
        StringStruct(u'ProductName', u'HackingGPT'),
        StringStruct(u'ProductVersion', u'1.0.0')])
      ]), 
    VarFileInfo([VarStruct(u'Translation', [1033, 1200])])
  ]
)'''
    
    with open('version_info.txt', 'w', encoding='utf-8') as f:
        f.write(version_content)
    print("Created version_info.txt")

def create_spec_file():
    """Create a .spec file for advanced configuration"""
    platform_info = get_platform_info()
    
    spec_content = f'''# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['{SCRIPT_NAME}'],
    pathex=[],
    binaries=[],
    datas=[
        ('templates', 'templates'),
        ('static', 'static'),
        ('app.py', '.'),
    ],
    hiddenimports=[
        'flask',
        'flask_socketio',
        'webview',
        'sqlite3',
        'json',
        'threading',
        'requests',
        'werkzeug.security',
        'cryptography',
        'celery',
        'redis',
        'markdown',
        'bleach',
    ],
    hookspath=[],
    hooksconfig={{}},
    runtime_hooks=[],
    excludes=[
        'tkinter',
        'matplotlib',
        'PIL',
        'numpy',
        'pandas',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='{APP_NAME}',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
'''

    # Platform-specific icon configuration
    if platform_info['is_windows'] and Path(ICON_PATH).exists():
        spec_content += f"    icon='{ICON_PATH}',\n"
    elif platform_info['is_macos'] and Path(ICON_PATH_MAC).exists():
        spec_content += f"    icon='{ICON_PATH_MAC}',\n"
    elif platform_info['is_linux'] and Path(ICON_PATH_LINUX).exists():
        spec_content += f"    icon='{ICON_PATH_LINUX}',\n"
    
    spec_content += ")\n"
    
    # macOS app bundle configuration
    if platform_info['is_macos']:
        spec_content += f'''
app = BUNDLE(
    exe,
    name='{APP_NAME}.app',
    icon='{ICON_PATH_MAC if Path(ICON_PATH_MAC).exists() else None}',
    bundle_identifier='com.hackinggpt.desktop',
)
'''
    
    with open(f'{APP_NAME}.spec', 'w', encoding='utf-8') as f:
        f.write(spec_content)
    print(f"Created {APP_NAME}.spec")

def install_dependencies():
    """Install required dependencies"""
    print("Installing dependencies...")
    
    try:
        subprocess.check_call([
            sys.executable, '-m', 'pip', 'install', '-r', 'requirements_webview.txt'
        ])
        
        # Install PyInstaller
        subprocess.check_call([
            sys.executable, '-m', 'pip', 'install', 'pyinstaller==6.10.0'
        ])
        
        print("Dependencies installed successfully")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"Error installing dependencies: {e}")
        return False

def build_executable():
    """Build the executable using PyInstaller"""
    print("Building executable...")
    
    try:
        # Use spec file for build
        command = ['pyinstaller', f'{APP_NAME}.spec']
        
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        print("Build completed successfully!")
        print(result.stdout)
        
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"Build failed: {e}")
        print(f"Error output: {e.stderr}")
        return False

def create_installer_script():
    """Create installer script for the application"""
    platform_info = get_platform_info()
    
    if platform_info['is_windows']:
        # Create NSIS installer script for Windows
        nsis_content = f'''!define APPNAME "{APP_NAME}"
!define COMPANYNAME "HackingGPT"
!define DESCRIPTION "Advanced Cybersecurity Assistant"
!define VERSIONMAJOR 1
!define VERSIONMINOR 0
!define VERSIONBUILD 0

!define INSTALLSIZE 50000  # Estimated size in KB

RequestExecutionLevel admin
InstallDir "$PROGRAMFILES\\${{COMPANYNAME}}\\${{APPNAME}}"

Page directory
Page instfiles

Section "install"
    SetOutPath $INSTDIR
    File "dist\\{APP_NAME}.exe"
    
    # Create uninstaller
    WriteUninstaller "$INSTDIR\\uninstall.exe"
    
    # Create start menu shortcut
    CreateDirectory "$SMPROGRAMS\\${{COMPANYNAME}}"
    CreateShortCut "$SMPROGRAMS\\${{COMPANYNAME}}\\${{APPNAME}}.lnk" "$INSTDIR\\{APP_NAME}.exe"
    
    # Create desktop shortcut
    CreateShortCut "$DESKTOP\\${{APPNAME}}.lnk" "$INSTDIR\\{APP_NAME}.exe"
    
    # Registry information for add/remove programs
    WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${{COMPANYNAME}} ${{APPNAME}}" "DisplayName" "${{APPNAME}}"
    WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${{COMPANYNAME}} ${{APPNAME}}" "UninstallString" "$\\"$INSTDIR\\uninstall.exe$\\""
    WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${{COMPANYNAME}} ${{APPNAME}}" "QuietUninstallString" "$\\"$INSTDIR\\uninstall.exe$\\" /S"
    WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${{COMPANYNAME}} ${{APPNAME}}" "InstallLocation" "$\\"$INSTDIR$\\""
    WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${{COMPANYNAME}} ${{APPNAME}}" "DisplayIcon" "$\\"$INSTDIR\\{APP_NAME}.exe$\\""
    WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${{COMPANYNAME}} ${{APPNAME}}" "Publisher" "${{COMPANYNAME}}"
    WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${{COMPANYNAME}} ${{APPNAME}}" "HelpLink" "https://github.com/hackinggpt"
    WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${{COMPANYNAME}} ${{APPNAME}}" "URLUpdateInfo" "https://github.com/hackinggpt"
    WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${{COMPANYNAME}} ${{APPNAME}}" "URLInfoAbout" "https://github.com/hackinggpt"
    WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${{COMPANYNAME}} ${{APPNAME}}" "DisplayVersion" "${{VERSIONMAJOR}}.${{VERSIONMINOR}}.${{VERSIONBUILD}}"
    WriteRegDWORD HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${{COMPANYNAME}} ${{APPNAME}}" "VersionMajor" ${{VERSIONMAJOR}}
    WriteRegDWORD HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${{COMPANYNAME}} ${{APPNAME}}" "VersionMinor" ${{VERSIONMINOR}}
    WriteRegDWORD HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${{COMPANYNAME}} ${{APPNAME}}" "NoModify" 1
    WriteRegDWORD HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${{COMPANYNAME}} ${{APPNAME}}" "NoRepair" 1
    WriteRegDWORD HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${{COMPANYNAME}} ${{APPNAME}}" "EstimatedSize" ${{INSTALLSIZE}}
SectionEnd

Section "uninstall"
    Delete "$INSTDIR\\{APP_NAME}.exe"
    Delete "$INSTDIR\\uninstall.exe"
    RMDir "$INSTDIR"
    
    Delete "$SMPROGRAMS\\${{COMPANYNAME}}\\${{APPNAME}}.lnk"
    RMDir "$SMPROGRAMS\\${{COMPANYNAME}}"
    Delete "$DESKTOP\\${{APPNAME}}.lnk"
    
    DeleteRegKey HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${{COMPANYNAME}} ${{APPNAME}}"
SectionEnd
'''
        
        with open(f'{APP_NAME}_installer.nsi', 'w', encoding='utf-8') as f:
            f.write(nsis_content)
        print(f"Created {APP_NAME}_installer.nsi")
    
    elif platform_info['is_macos']:
        # Create macOS installer script
        mac_installer = f'''#!/bin/bash
# macOS installer script for {APP_NAME}

APP_NAME="{APP_NAME}"
APP_PATH="dist/$APP_NAME.app"
INSTALL_PATH="/Applications/$APP_NAME.app"

echo "Installing $APP_NAME..."

# Check if app exists
if [ ! -d "$APP_PATH" ]; then
    echo "Error: $APP_PATH not found"
    exit 1
fi

# Copy to Applications
sudo cp -R "$APP_PATH" "$INSTALL_PATH"

# Set permissions
sudo chmod -R 755 "$INSTALL_PATH"

echo "$APP_NAME installed successfully!"
echo "You can find it in your Applications folder."
'''
        
        with open(f'install_{APP_NAME.lower()}.sh', 'w', encoding='utf-8') as f:
            f.write(mac_installer)
        os.chmod(f'install_{APP_NAME.lower()}.sh', 0o755)
        print(f"Created install_{APP_NAME.lower()}.sh")
    
    else:  # Linux
        # Create Linux installer script
        linux_installer = f'''#!/bin/bash
# Linux installer script for {APP_NAME}

APP_NAME="{APP_NAME}"
EXEC_PATH="dist/$APP_NAME"
INSTALL_DIR="/opt/$APP_NAME"
DESKTOP_FILE="/usr/share/applications/$APP_NAME.desktop"

echo "Installing $APP_NAME..."

# Check if executable exists
if [ ! -f "$EXEC_PATH" ]; then
    echo "Error: $EXEC_PATH not found"
    exit 1
fi

# Create install directory
sudo mkdir -p "$INSTALL_DIR"

# Copy executable
sudo cp "$EXEC_PATH" "$INSTALL_DIR/"
sudo chmod +x "$INSTALL_DIR/$APP_NAME"

# Create desktop entry
sudo tee "$DESKTOP_FILE" > /dev/null <<EOF
[Desktop Entry]
Version=1.0
Type=Application
Name={APP_NAME}
Comment=Advanced Cybersecurity Assistant
Exec=$INSTALL_DIR/$APP_NAME
Icon=$INSTALL_DIR/icon.png
Terminal=false
StartupNotify=true
Categories=Development;Security;
EOF

# Copy icon if exists
if [ -f "assets/icon.png" ]; then
    sudo cp "assets/icon.png" "$INSTALL_DIR/"
fi

# Create symlink in /usr/local/bin
sudo ln -sf "$INSTALL_DIR/$APP_NAME" "/usr/local/bin/$APP_NAME"

echo "$APP_NAME installed successfully!"
echo "You can run it by typing '$APP_NAME' in terminal or find it in your applications menu."
'''
        
        with open(f'install_{APP_NAME.lower()}.sh', 'w', encoding='utf-8') as f:
            f.write(linux_installer)
        os.chmod(f'install_{APP_NAME.lower()}.sh', 0o755)
        print(f"Created install_{APP_NAME.lower()}.sh")

def create_build_info():
    """Create build information file"""
    platform_info = get_platform_info()
    
    build_info = {
        'app_name': APP_NAME,
        'version': '1.0.0',
        'build_platform': platform_info['system'],
        'build_arch': platform_info['arch'],
        'python_version': sys.version,
        'build_date': str(subprocess.check_output(['date'], text=True).strip()) if platform_info['is_linux'] or platform_info['is_macos'] else 'N/A'
    }
    
    with open('build_info.json', 'w', encoding='utf-8') as f:
        import json
        json.dump(build_info, f, indent=2)
    print("Created build_info.json")

def main():
    """Main build process"""
    print(f"Building {APP_NAME} executable...")
    print(f"Platform: {platform.system()} {platform.machine()}")
    
    # Check if main script exists
    if not Path(SCRIPT_NAME).exists():
        print(f"Error: {SCRIPT_NAME} not found!")
        return False
    
    # Check if Flask app exists
    if not Path("app.py").exists():
        print("Error: app.py not found!")
        print("Make sure the Flask application file is in the same directory.")
        return False
    
    try:
        # Create directories
        create_directories()
        
        # Create icon files
        create_icon_files()
        
        # Install dependencies
        if not install_dependencies():
            return False
        
        # Create version file (Windows)
        if get_platform_info()['is_windows']:
            create_version_file()
        
        # Create spec file
        create_spec_file()
        
        # Build executable
        if not build_executable():
            return False
        
        # Create installer script
        create_installer_script()
        
        # Create build info
        create_build_info()
        
        print(f"\n{'='*50}")
        print("BUILD COMPLETED SUCCESSFULLY!")
        print(f"{'='*50}")
        print(f"Executable location: dist/{APP_NAME}")
        print(f"Platform: {platform.system()}")
        
        # Platform-specific instructions
        platform_info = get_platform_info()
        if platform_info['is_windows']:
            print(f"Windows executable: dist/{APP_NAME}.exe")
            print(f"Installer script: {APP_NAME}_installer.nsi")
            print("To create installer, install NSIS and compile the .nsi file")
        elif platform_info['is_macos']:
            print(f"macOS app bundle: dist/{APP_NAME}.app")
            print(f"Installer script: install_{APP_NAME.lower()}.sh")
        else:
            print(f"Linux executable: dist/{APP_NAME}")
            print(f"Installer script: install_{APP_NAME.lower()}.sh")
        
        print("\nNext steps:")
        print("1. Test the executable by running it")
        print("2. Use the installer script to install system-wide")
        print("3. Distribute the executable or create an installer package")
        
        return True
        
    except Exception as e:
        print(f"Build failed with error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)