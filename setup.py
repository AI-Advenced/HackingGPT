#!/usr/bin/env python3
"""
Setup script for HackingGPT Desktop Application
Alternative to PyInstaller using cx_Freeze
"""

import sys
import os
from cx_Freeze import setup, Executable

# Dependencies are automatically detected, but some modules that are imported 
# dynamically need to be explicitly included
build_exe_options = {
    "packages": [
        "flask",
        "flask_socketio",
        "webview",
        "sqlite3",
        "json",
        "threading",
        "requests",
        "werkzeug",
        "cryptography",
        "celery",
        "redis",
        "markdown",
        "bleach",
        "os",
        "sys",
        "time",
        "pathlib",
        "webbrowser",
        "subprocess",
        "signal",
        "atexit"
    ],
    "excludes": [
        "tkinter",
        "matplotlib",
        "PIL",
        "numpy",
        "pandas",
        "scipy",
        "IPython",
        "jupyter"
    ],
    "include_files": [
        ("templates/", "templates/"),
        ("static/", "static/"),
        ("app.py", "app.py"),
        ("hackinggpt.db", "hackinggpt.db") if os.path.exists("hackinggpt.db") else None,
    ],
    "optimize": 2,
    "include_msvcrt": True if sys.platform == "win32" else False,
}

# Remove None values from include_files
build_exe_options["include_files"] = [f for f in build_exe_options["include_files"] if f is not None]

# Base for GUI applications on Windows
base = None
if sys.platform == "win32":
    base = "Win32GUI"

# Executable configuration
executable = Executable(
    script="webview_app.py",
    base=base,
    target_name="HackingGPT",
    icon="assets/icon.ico" if os.path.exists("assets/icon.ico") else None,
    shortcut_name="HackingGPT",
    shortcut_dir="DesktopFolder",
)

setup(
    name="HackingGPT",
    version="1.0.0",
    description="Advanced Cybersecurity Assistant Desktop Application",
    author="Douglas Rodrigues Aguiar de Oliveira",
    options={"build_exe": build_exe_options},
    executables=[executable],
)