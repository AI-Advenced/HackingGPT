#!/usr/bin/env python3
"""
Alternative WebView launcher using different backends
Provides fallback options if pywebview doesn't work
"""

import sys
import os
import webbrowser
import threading
import time
import subprocess
import platform
from pathlib import Path

# Try different WebView backends
try:
    import webview
    WEBVIEW_AVAILABLE = True
except ImportError:
    WEBVIEW_AVAILABLE = False

try:
    import tkinter as tk
    from tkinter import messagebox
    import tkinter.ttk as ttk
    TKINTER_AVAILABLE = True
except ImportError:
    TKINTER_AVAILABLE = False

try:
    from PyQt5.QtWidgets import QApplication, QMainWindow
    from PyQt5.QtWebEngineWidgets import QWebEngineView
    from PyQt5.QtCore import QUrl
    PYQT5_AVAILABLE = True
except ImportError:
    PYQT5_AVAILABLE = False

try:
    import wx
    import wx.html2
    WXPYTHON_AVAILABLE = True
except ImportError:
    WXPYTHON_AVAILABLE = False

class FlaskServerManager:
    """Manages Flask server startup and shutdown"""
    
    def __init__(self, port=5000):
        self.port = port
        self.flask_thread = None
        self.server_url = f"http://localhost:{port}"
        
    def start_server(self):
        """Start Flask server in background thread"""
        def run_flask():
            try:
                from app import app, socketio
                socketio.run(app, debug=False, port=self.port, 
                           host='127.0.0.1', use_reloader=False)
            except ImportError:
                print("Error: Flask app not found. Make sure app.py is available.")
                sys.exit(1)
            except Exception as e:
                print(f"Error starting Flask server: {e}")
                sys.exit(1)
        
        self.flask_thread = threading.Thread(target=run_flask, daemon=True)
        self.flask_thread.start()
        
        # Wait for server to start
        for _ in range(30):  # 30 second timeout
            try:
                import requests
                response = requests.get(self.server_url, timeout=1)
                if response.status_code == 200:
                    return True
            except:
                time.sleep(1)
        
        return False


class PyWebViewLauncher:
    """PyWebView implementation"""
    
    def __init__(self, url, title="HackingGPT"):
        self.url = url
        self.title = title
    
    def launch(self):
        """Launch using pywebview"""
        if not WEBVIEW_AVAILABLE:
            return False
        
        try:
            window = webview.create_window(
                title=self.title,
                url=self.url,
                width=1400,
                height=900,
                min_size=(800, 600),
                resizable=True,
                shadow=True
            )
            
            webview.start(debug=False)
            return True
            
        except Exception as e:
            print(f"PyWebView failed: {e}")
            return False


class PyQt5Launcher:
    """PyQt5 WebEngine implementation"""
    
    def __init__(self, url, title="HackingGPT"):
        self.url = url
        self.title = title
    
    def launch(self):
        """Launch using PyQt5"""
        if not PYQT5_AVAILABLE:
            return False
        
        try:
            app = QApplication(sys.argv)
            
            # Create main window
            window = QMainWindow()
            window.setWindowTitle(self.title)
            window.setGeometry(100, 100, 1400, 900)
            
            # Create web view
            web_view = QWebEngineView()
            web_view.load(QUrl(self.url))
            
            window.setCentralWidget(web_view)
            window.show()
            
            sys.exit(app.exec_())
            
        except Exception as e:
            print(f"PyQt5 failed: {e}")
            return False


class WxPythonLauncher:
    """wxPython WebView implementation"""
    
    def __init__(self, url, title="HackingGPT"):
        self.url = url
        self.title = title
    
    def launch(self):
        """Launch using wxPython"""
        if not WXPYTHON_AVAILABLE:
            return False
        
        try:
            app = wx.App()
            
            # Create frame
            frame = wx.Frame(None, title=self.title, size=(1400, 900))
            
            # Create web view
            web_view = wx.html2.WebView.New(frame)
            web_view.LoadURL(self.url)
            
            # Layout
            sizer = wx.BoxSizer(wx.VERTICAL)
            sizer.Add(web_view, 1, wx.EXPAND)
            frame.SetSizer(sizer)
            
            frame.Show()
            app.MainLoop()
            
            return True
            
        except Exception as e:
            print(f"wxPython failed: {e}")
            return False


class TkinterLauncher:
    """Tkinter-based launcher with browser integration"""
    
    def __init__(self, url, title="HackingGPT"):
        self.url = url
        self.title = title
    
    def launch(self):
        """Launch using Tkinter GUI"""
        if not TKINTER_AVAILABLE:
            return False
        
        try:
            root = tk.Tk()
            root.title(self.title)
            root.geometry("400x300")
            root.configure(bg='#0a0a0a')
            
            # Style configuration
            style = ttk.Style()
            style.theme_use('clam')
            
            # Header
            header_label = tk.Label(
                root, 
                text="HackingGPT", 
                font=("Courier", 24, "bold"),
                fg="#00d4ff",
                bg="#0a0a0a"
            )
            header_label.pack(pady=20)
            
            subtitle_label = tk.Label(
                root,
                text="Advanced Cybersecurity Assistant",
                font=("Courier", 12),
                fg="#cccccc",
                bg="#0a0a0a"
            )
            subtitle_label.pack(pady=5)
            
            # Launch button
            def open_browser():
                webbrowser.open(self.url)
                messagebox.showinfo(
                    "Browser Opened",
                    f"{self.title} has been opened in your default browser.\n\n"
                    f"URL: {self.url}\n\n"
                    "You can close this window now."
                )
            
            launch_button = tk.Button(
                root,
                text="Launch in Browser",
                command=open_browser,
                font=("Courier", 14, "bold"),
                bg="#00d4ff",
                fg="white",
                relief="raised",
                bd=3,
                padx=20,
                pady=10
            )
            launch_button.pack(pady=30)
            
            # Info text
            info_text = tk.Text(
                root,
                height=6,
                width=50,
                font=("Courier", 10),
                bg="#1a1a1a",
                fg="#cccccc",
                relief="sunken",
                bd=2
            )
            info_text.pack(pady=10, padx=20, fill=tk.BOTH, expand=True)
            
            info_content = f"""Server running at: {self.url}

This launcher will open HackingGPT in your 
default web browser. The Flask server is 
running in the background.

Platform: {platform.system()}
Python: {sys.version.split()[0]}"""
            
            info_text.insert(tk.END, info_content)
            info_text.config(state=tk.DISABLED)
            
            root.mainloop()
            return True
            
        except Exception as e:
            print(f"Tkinter launcher failed: {e}")
            return False


class BrowserLauncher:
    """Fallback browser launcher"""
    
    def __init__(self, url, title="HackingGPT"):
        self.url = url
        self.title = title
    
    def launch(self):
        """Launch in default browser"""
        try:
            print(f"\n{self.title} Server Started!")
            print(f"URL: {self.url}")
            print("\nOpening in your default browser...")
            
            webbrowser.open(self.url)
            
            print("\nServer is running. Press Ctrl+C to stop.")
            
            # Keep the server running
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\nShutting down server...")
                return True
                
        except Exception as e:
            print(f"Browser launcher failed: {e}")
            return False


class MultiLauncher:
    """Main launcher class that tries different backends"""
    
    def __init__(self, port=5000, title="HackingGPT"):
        self.port = port
        self.title = title
        self.server_manager = FlaskServerManager(port)
        
    def get_available_launchers(self):
        """Get list of available launchers"""
        launchers = []
        
        if WEBVIEW_AVAILABLE:
            launchers.append(("PyWebView", "Best - Native WebView"))
        if PYQT5_AVAILABLE:
            launchers.append(("PyQt5", "Good - Qt WebEngine"))
        if WXPYTHON_AVAILABLE:
            launchers.append(("wxPython", "Good - wx WebView"))
        if TKINTER_AVAILABLE:
            launchers.append(("Tkinter", "Basic - GUI + Browser"))
        
        launchers.append(("Browser", "Fallback - Default Browser"))
        
        return launchers
    
    def launch(self, preferred_launcher=None):
        """Launch the application"""
        print(f"Starting {self.title}...")
        
        # Start Flask server
        print("Starting Flask server...")
        if not self.server_manager.start_server():
            print("Failed to start Flask server!")
            return False
        
        print(f"Server started at {self.server_manager.server_url}")
        
        # Get available launchers
        available_launchers = self.get_available_launchers()
        
        if not available_launchers:
            print("No GUI libraries available!")
            return False
        
        print("\nAvailable launchers:")
        for i, (name, desc) in enumerate(available_launchers):
            print(f"{i+1}. {name} - {desc}")
        
        # Auto-select or ask user
        if preferred_launcher and preferred_launcher.lower() in [name.lower() for name, _ in available_launchers]:
            selected_launcher = preferred_launcher.lower()
        else:
            # Try in order of preference
            launcher_order = ["pywebview", "pyqt5", "wxpython", "tkinter", "browser"]
            selected_launcher = None
            
            for launcher in launcher_order:
                if launcher in [name.lower() for name, _ in available_launchers]:
                    selected_launcher = launcher
                    break
        
        if not selected_launcher:
            selected_launcher = "browser"
        
        print(f"\nUsing launcher: {selected_launcher}")
        
        # Launch with selected method
        url = self.server_manager.server_url
        
        try:
            if selected_launcher == "pywebview":
                launcher = PyWebViewLauncher(url, self.title)
            elif selected_launcher == "pyqt5":
                launcher = PyQt5Launcher(url, self.title)
            elif selected_launcher == "wxpython":
                launcher = WxPythonLauncher(url, self.title)
            elif selected_launcher == "tkinter":
                launcher = TkinterLauncher(url, self.title)
            else:
                launcher = BrowserLauncher(url, self.title)
            
            return launcher.launch()
            
        except Exception as e:
            print(f"Launcher failed with error: {e}")
            print("Falling back to browser launcher...")
            
            fallback_launcher = BrowserLauncher(url, self.title)
            return fallback_launcher.launch()


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="HackingGPT Desktop Launcher")
    parser.add_argument("--port", type=int, default=5000, help="Flask server port")
    parser.add_argument("--launcher", type=str, help="Preferred launcher (pywebview, pyqt5, wxpython, tkinter, browser)")
    parser.add_argument("--list-launchers", action="store_true", help="List available launchers")
    
    args = parser.parse_args()
    
    launcher = MultiLauncher(port=args.port)
    
    if args.list_launchers:
        print("Available launchers:")
        for name, desc in launcher.get_available_launchers():
            print(f"  {name}: {desc}")
        return
    
    try:
        success = launcher.launch(args.launcher)
        if success:
            print("Application closed successfully")
        else:
            print("Application failed to start")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\nApplication interrupted by user")
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()