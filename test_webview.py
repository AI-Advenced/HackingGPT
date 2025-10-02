#!/usr/bin/env python3
"""
Test script to verify WebView installation and functionality
Run this before building to ensure everything works
"""

import sys
import os
import subprocess
import importlib
import platform
import time
import threading
import json

def test_python_version():
    """Test Python version compatibility"""
    print("🐍 Testing Python Version...")
    version = sys.version_info
    
    if version.major == 3 and version.minor >= 8:
        print(f"   ✅ Python {version.major}.{version.minor}.{version.micro} - Compatible")
        return True
    else:
        print(f"   ❌ Python {version.major}.{version.minor}.{version.micro} - Requires Python 3.8+")
        return False

def test_module_import(module_name, package_name=None, optional=False):
    """Test if a module can be imported"""
    try:
        importlib.import_module(module_name)
        print(f"   ✅ {module_name} - Available")
        return True
    except ImportError as e:
        status = "⚠️" if optional else "❌"
        install_cmd = f"pip install {package_name or module_name}"
        print(f"   {status} {module_name} - Not available")
        if not optional:
            print(f"      Install with: {install_cmd}")
        return False

def test_dependencies():
    """Test all required dependencies"""
    print("\n📦 Testing Dependencies...")
    
    required_modules = [
        ("flask", "flask"),
        ("flask_socketio", "flask-socketio"),
        ("werkzeug", "werkzeug"),
        ("requests", "requests"),
        ("sqlite3", None),  # Built-in
        ("json", None),     # Built-in
        ("threading", None), # Built-in
        ("pathlib", None),  # Built-in
        ("cryptography", "cryptography"),
        ("markdown", "markdown"),
        ("bleach", "bleach"),
    ]
    
    optional_modules = [
        ("webview", "pywebview"),
        ("celery", "celery"),
        ("redis", "redis"),
        ("PyQt5", "PyQt5"),
        ("wx", "wxPython"),
        ("tkinter", None),  # Usually built-in
    ]
    
    required_available = 0
    for module, package in required_modules:
        if test_module_import(module, package, optional=False):
            required_available += 1
    
    optional_available = 0
    for module, package in optional_modules:
        if test_module_import(module, package, optional=True):
            optional_available += 1
    
    print(f"\n   📊 Required modules: {required_available}/{len(required_modules)}")
    print(f"   📊 Optional modules: {optional_available}/{len(optional_modules)}")
    
    return required_available == len(required_modules)

def test_webview_backends():
    """Test available WebView backends"""
    print("\n🖥️  Testing WebView Backends...")
    
    backends = []
    
    # Test pywebview
    try:
        import webview
        backends.append("pywebview")
        print("   ✅ pywebview - Available")
    except ImportError:
        print("   ❌ pywebview - Not available (pip install pywebview)")
    
    # Test PyQt5
    try:
        from PyQt5.QtWidgets import QApplication
        from PyQt5.QtWebEngineWidgets import QWebEngineView
        backends.append("PyQt5")
        print("   ✅ PyQt5 WebEngine - Available")
    except ImportError:
        print("   ⚠️  PyQt5 WebEngine - Not available (pip install PyQt5 PyQtWebEngine)")
    
    # Test wxPython
    try:
        import wx
        import wx.html2
        backends.append("wxPython")
        print("   ✅ wxPython WebView - Available")
    except ImportError:
        print("   ⚠️  wxPython WebView - Not available (pip install wxPython)")
    
    # Test Tkinter
    try:
        import tkinter as tk
        backends.append("tkinter")
        print("   ✅ Tkinter - Available (GUI fallback)")
    except ImportError:
        print("   ⚠️  Tkinter - Not available")
    
    print(f"\n   📊 Available backends: {len(backends)}")
    
    if not backends:
        print("   ❌ No GUI backends available! Install at least one:")
        print("      pip install pywebview")
        print("      pip install PyQt5 PyQtWebEngine")
        print("      pip install wxPython")
        return False
    else:
        print(f"   ✅ Can use: {', '.join(backends)}")
        return True

def test_flask_app():
    """Test if Flask app can be imported and started"""
    print("\n🌐 Testing Flask Application...")
    
    # Check if app.py exists
    if not os.path.exists("app.py"):
        print("   ❌ app.py not found")
        print("      Make sure the Flask application file is present")
        return False
    
    print("   ✅ app.py found")
    
    # Check templates directory
    if not os.path.exists("templates"):
        print("   ❌ templates directory not found")
        return False
    
    print("   ✅ templates directory found")
    
    # Test Flask app import
    try:
        sys.path.insert(0, '.')
        import app
        print("   ✅ Flask app imports successfully")
        
        # Test if Flask app has required attributes
        if hasattr(app, 'app'):
            print("   ✅ Flask app object found")
        else:
            print("   ❌ Flask app object not found")
            return False
            
        return True
        
    except ImportError as e:
        print(f"   ❌ Cannot import Flask app: {e}")
        return False
    except Exception as e:
        print(f"   ❌ Error testing Flask app: {e}")
        return False

def test_server_startup():
    """Test if server can start up"""
    print("\n🚀 Testing Server Startup...")
    
    try:
        # Import required modules
        import requests
        from flask import Flask
        
        # Create test server
        test_app = Flask(__name__)
        
        @test_app.route('/')
        def test_route():
            return "Test successful"
        
        # Start server in thread
        server_thread = None
        
        def run_server():
            test_app.run(host='127.0.0.1', port=5001, debug=False, use_reloader=False)
        
        server_thread = threading.Thread(target=run_server, daemon=True)
        server_thread.start()
        
        # Wait for server to start
        time.sleep(2)
        
        # Test connection
        response = requests.get('http://127.0.0.1:5001', timeout=5)
        if response.status_code == 200:
            print("   ✅ Test server started successfully")
            print("   ✅ HTTP requests working")
            return True
        else:
            print(f"   ❌ Server responded with status {response.status_code}")
            return False
            
    except Exception as e:
        print(f"   ❌ Server startup test failed: {e}")
        return False

def test_pyinstaller():
    """Test PyInstaller availability"""
    print("\n📦 Testing PyInstaller...")
    
    try:
        result = subprocess.run(['pyinstaller', '--version'], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            version = result.stdout.strip()
            print(f"   ✅ PyInstaller {version} - Available")
            return True
        else:
            print("   ❌ PyInstaller not working properly")
            return False
    except FileNotFoundError:
        print("   ❌ PyInstaller not installed")
        print("      Install with: pip install pyinstaller")
        return False
    except subprocess.TimeoutExpired:
        print("   ❌ PyInstaller timeout")
        return False

def test_system_requirements():
    """Test system-specific requirements"""
    print(f"\n🖥️  Testing System Requirements ({platform.system()})...")
    
    system = platform.system().lower()
    
    if system == "linux":
        # Test GTK libraries
        try:
            result = subprocess.run(['pkg-config', '--exists', 'gtk+-3.0'], 
                                  capture_output=True)
            if result.returncode == 0:
                print("   ✅ GTK3 development libraries - Available")
            else:
                print("   ❌ GTK3 development libraries - Missing")
                print("      Install with: sudo apt-get install libgtk-3-dev")
        except FileNotFoundError:
            print("   ⚠️  pkg-config not found - cannot verify GTK3")
        
        # Test WebKit2GTK
        try:
            result = subprocess.run(['pkg-config', '--exists', 'webkit2gtk-4.0'], 
                                  capture_output=True)
            if result.returncode == 0:
                print("   ✅ WebKit2GTK - Available")
            else:
                print("   ❌ WebKit2GTK - Missing")
                print("      Install with: sudo apt-get install libwebkit2gtk-4.0-dev")
        except FileNotFoundError:
            pass
    
    elif system == "darwin":  # macOS
        # Test Xcode Command Line Tools
        try:
            result = subprocess.run(['xcode-select', '--print-path'], 
                                  capture_output=True)
            if result.returncode == 0:
                print("   ✅ Xcode Command Line Tools - Available")
            else:
                print("   ❌ Xcode Command Line Tools - Missing")
                print("      Install with: xcode-select --install")
        except FileNotFoundError:
            print("   ❌ Xcode Command Line Tools - Missing")
    
    elif system == "windows":
        # Test Visual C++ Build Tools
        try:
            result = subprocess.run(['where', 'cl'], capture_output=True)
            if result.returncode == 0:
                print("   ✅ Visual C++ Build Tools - Available")
            else:
                print("   ⚠️  Visual C++ Build Tools - May be missing")
                print("      Install Visual Studio Build Tools if build fails")
        except FileNotFoundError:
            print("   ⚠️  Cannot verify Visual C++ Build Tools")
    
    return True

def test_file_structure():
    """Test required file structure"""
    print("\n📁 Testing File Structure...")
    
    required_files = [
        "webview_app.py",
        "app.py",
        "requirements_webview.txt",
        "build_executable.py"
    ]
    
    required_dirs = [
        "templates"
    ]
    
    optional_files = [
        "static",
        "assets"  
    ]
    
    all_good = True
    
    for file in required_files:
        if os.path.exists(file):
            print(f"   ✅ {file} - Found")
        else:
            print(f"   ❌ {file} - Missing (Required)")
            all_good = False
    
    for dir in required_dirs:
        if os.path.isdir(dir):
            print(f"   ✅ {dir}/ - Found")
        else:
            print(f"   ❌ {dir}/ - Missing (Required)")
            all_good = False
    
    for item in optional_files:
        if os.path.exists(item):
            print(f"   ✅ {item} - Found")
        else:
            print(f"   ⚠️  {item} - Missing (Optional)")
    
    return all_good

def generate_report():
    """Generate test report"""
    print("\n" + "="*60)
    print("🧪 WEBVIEW BUILD TEST REPORT")
    print("="*60)
    
    tests = [
        ("Python Version", test_python_version),
        ("Dependencies", test_dependencies),
        ("WebView Backends", test_webview_backends),
        ("Flask Application", test_flask_app),
        ("Server Startup", test_server_startup),
        ("PyInstaller", test_pyinstaller),
        ("System Requirements", test_system_requirements),
        ("File Structure", test_file_structure)
    ]
    
    results = {}
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        try:
            result = test_func()
            results[test_name] = result
            if result:
                passed += 1
        except Exception as e:
            print(f"\n❌ {test_name} test failed with exception: {e}")
            results[test_name] = False
    
    print(f"\n📊 SUMMARY:")
    print(f"   Passed: {passed}/{total}")
    print(f"   Failed: {total - passed}/{total}")
    
    if passed == total:
        print("\n🎉 ALL TESTS PASSED!")
        print("   Your system is ready to build the WebView executable.")
        print("\n🚀 Next steps:")
        print("   1. Run: python build_executable.py")
        print("   2. Or run: ./build.sh (Linux/macOS) or build.bat (Windows)")
        return True
    else:
        print(f"\n⚠️  {total - passed} TESTS FAILED!")
        print("   Please fix the issues above before building.")
        
        print("\n🔧 Quick fixes:")
        if not results.get("Dependencies", True):
            print("   - Install dependencies: pip install -r requirements_webview.txt")
        if not results.get("WebView Backends", True):
            print("   - Install WebView: pip install pywebview")
        if not results.get("PyInstaller", True):
            print("   - Install PyInstaller: pip install pyinstaller")
        
        return False

def main():
    """Main test function"""
    print("🧪 HackingGPT WebView Build Test")
    print("Testing your system for WebView executable build readiness...\n")
    
    # Change to script directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)
    
    success = generate_report()
    
    if success:
        # Offer to run build
        print("\n❓ Would you like to start the build process now? (y/n): ", end="")
        try:
            choice = input().lower().strip()
            if choice in ['y', 'yes']:
                print("\n🚀 Starting build process...")
                try:
                    if platform.system().lower() == "windows":
                        subprocess.run(["python", "build_executable.py"], check=True)
                    else:
                        subprocess.run(["python3", "build_executable.py"], check=True)
                except subprocess.CalledProcessError:
                    print("❌ Build process failed. Check the output above for details.")
                    return False
                except FileNotFoundError:
                    print("❌ build_executable.py not found")
                    return False
        except KeyboardInterrupt:
            print("\n\n👋 Test cancelled by user")
            return False
    
    return success

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)