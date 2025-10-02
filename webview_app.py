#!/usr/bin/env python3
"""
HackingGPT WebView Desktop Application
Creates a desktop application wrapper for the HackingGPT web interface
"""

import webview
import threading
import time
import os
import sys
import json
import requests
from pathlib import Path
import webbrowser
import subprocess
import signal
import atexit
from flask import Flask

# Configuration
APP_NAME = "HackingGPT"
APP_VERSION = "1.0.0"
WINDOW_WIDTH = 1400
WINDOW_HEIGHT = 900
FLASK_PORT = 5000
DEBUG_MODE = False

class HackingGPTApp:
    """Main application class for HackingGPT Desktop"""
    
    def __init__(self):
        self.flask_process = None
        self.flask_thread = None
        self.window = None
        self.api_base_url = f"http://localhost:{FLASK_PORT}"
        
    def check_flask_server(self, timeout=30):
        """Check if Flask server is running"""
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                response = requests.get(f"{self.api_base_url}/", timeout=2)
                if response.status_code == 200:
                    return True
            except requests.exceptions.RequestException:
                pass
            time.sleep(1)
        return False
    
    def start_flask_server(self):
        """Start Flask server in a separate thread"""
        def run_server():
            try:
                # Import and run the Flask app
                from app import app, socketio
                socketio.run(app, debug=DEBUG_MODE, port=FLASK_PORT, 
                           host='127.0.0.1', use_reloader=False)
            except ImportError:
                print("Error: Flask app not found. Make sure app.py is in the same directory.")
                sys.exit(1)
            except Exception as e:
                print(f"Error starting Flask server: {e}")
                sys.exit(1)
        
        self.flask_thread = threading.Thread(target=run_server, daemon=True)
        self.flask_thread.start()
        
        # Wait for server to start
        if not self.check_flask_server():
            print("Failed to start Flask server")
            sys.exit(1)
    
    def on_window_closed(self):
        """Handle window close event"""
        print("Application closing...")
        # Cleanup will be handled by atexit
        
    def create_window(self):
        """Create and configure the webview window"""
        self.window = webview.create_window(
            title=APP_NAME,
            url=self.api_base_url,
            width=WINDOW_WIDTH,
            height=WINDOW_HEIGHT,
            min_size=(800, 600),
            resizable=True,
            fullscreen=False,
            minimized=False,
            on_top=False,
            text_select=True
        )
        
        return self.window
    
    def run(self):
        """Run the application"""
        print(f"Starting {APP_NAME} v{APP_VERSION}...")
        
        # Start Flask server
        print("Starting Flask server...")
        self.start_flask_server()
        
        # Create window
        print("Creating application window...")
        window = self.create_window()
        
        # Register cleanup
        atexit.register(self.cleanup)
        
        # Start webview
        print(f"Application ready! Opening {APP_NAME}...")
        webview.start(
            debug=DEBUG_MODE,
            http_server=False  # We're using our own Flask server
        )
    
    def cleanup(self):
        """Cleanup resources"""
        print("Cleaning up...")
        # Flask thread will be terminated when main process exits


class API:
    """API class for webview integration"""
    
    def __init__(self):
        self.app_version = APP_VERSION
    
    def get_app_info(self):
        """Get application information"""
        return {
            'name': APP_NAME,
            'version': APP_VERSION,
            'platform': sys.platform
        }
    
    def open_external_link(self, url):
        """Open link in external browser"""
        webbrowser.open(url)
    
    def show_save_dialog(self):
        """Show save file dialog"""
        return webview.windows[0].create_file_dialog(
            webview.SAVE_DIALOG,
            allow_multiple=False,
            file_types=('Text files (*.txt)', 'All files (*.*)')
        )
    
    def show_open_dialog(self):
        """Show open file dialog"""
        return webview.windows[0].create_file_dialog(
            webview.OPEN_DIALOG,
            allow_multiple=False,
            file_types=('Text files (*.txt)', 'JSON files (*.json)', 'All files (*.*)')
        )


def main():
    """Main entry point"""
    try:
        app = HackingGPTApp()
        app.run()
    except KeyboardInterrupt:
        print("\nApplication interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()