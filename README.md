# HackingGPT - Advanced Cybersecurity Assistant

![HackingGPT Banner](https://img.shields.io/badge/HackingGPT-Advanced%20Terminal-00ff88?style=for-the-badge&logo=terminal)

**HackingGPT** is an advanced AI-powered cybersecurity assistant designed for penetration testing, bug bounty hunting, and security analysis. It combines cutting-edge GPT models with practical security tools in both web and desktop interfaces.

![HackingGPT](https://github.com/user-attachments/assets/12f2e976-93f8-43ee-9eec-e3dfa8cc7744)

<img width="1367" height="848" alt="image" src="https://github.com/user-attachments/assets/2d3c4cb1-1922-4d2f-a04c-c2e5ee5b1312" />

<img width="1517" height="641" alt="image" src="https://github.com/user-attachments/assets/c3315e1d-b03c-48f8-a966-0e652f2f474a" />



## 🚀 Features

### 🤖 AI-Powered Analysis
- **Multiple AI Models**: GPT-4, GPT-4 Mini, DeepSeek Chat, DeepSeek Reasoner
- **Specialized Prompts**: Optimized for cybersecurity and penetration testing
- **Real-time Chat**: WebSocket-based communication for instant responses

### 🛡️ Security Tools Integration
- **Network Scanning**: Nmap, Nikto, Dirb, Gobuster
- **Web Application Testing**: SQLMap, Burp Suite integration
- **Vulnerability Assessment**: Automated scanning with detailed reports
- **Command Execution**: Safe, monitored execution of security tools

### 💻 Dual Interface
- **Web Application**: Full-featured Flask-based web interface
- **Desktop Application**: Standalone executable with webview wrapper
- **Real-time Updates**: Live command execution and results streaming

### 🔒 Security Features
- **User Authentication**: Secure login system with encryption
- **Rate Limiting**: API protection against abuse
- **Command Validation**: Safety checks for dangerous commands
- **Audit Logging**: Comprehensive security event tracking

## 📋 Prerequisites

### System Requirements
- **Operating System**: Windows 10/11, macOS 10.14+, or Linux
- **Python**: 3.8 or higher
- **RAM**: Minimum 4GB, Recommended 8GB+
- **Storage**: 2GB free space

### Required API Keys
```bash
# Environment Variables (create .env file)
OPENAI_API_KEY=your_openai_api_key_here
DEEPSEEK_API_KEY=your_deepseek_api_key_here
SECRET_KEY=your_secret_key_here
REDIS_URL=redis://localhost:6379/0  # Optional
```

## 🔧 Installation

### Method 1: Development Setup

1. **Clone the Repository**
```bash
git clone https://github.com/AI-Advenced/HackingGPT/hackinggpt.git
cd hackinggpt
```

2. **Create Virtual Environment**
```bash
python -m venv venv
# Windows
venv\Scripts\activate
# macOS/Linux
source venv/bin/activate
```

3. **Install Dependencies**
```bash
pip install -r requirements.txt
```

4. **Set Environment Variables**
```bash
# Windows
copy .env.example .env
# macOS/Linux
cp .env.example .env
```
Edit `.env` file with your API keys.

5. **Initialize Database**
```bash
python app.py
or
python webview_app.py
```

### Method 2: Executable Installation

Download the latest release from the [Releases](https://github.com/yourusername/hackinggpt/releases) page and run the executable.

## 🏗️ Building Executable with PyInstaller

### Step 1: Install PyInstaller
```bash
pip install pyinstaller
```

### Step 2: Create Build Script

Create `build.py`:
```python
#!/usr/bin/env python3
"""
Build script for HackingGPT executable
"""
import PyInstaller.__main__
import os
import sys
import shutil

def build_executable():
    """Build HackingGPT executable"""
    
    # Clean previous builds
    if os.path.exists('dist'):
        shutil.rmtree('dist')
    if os.path.exists('build'):
        shutil.rmtree('build')
    
    # PyInstaller arguments
    args = [
        'webview_app.py',
        '--name=HackingGPT',
        '--onefile',
        '--windowed',
        '--icon=assets/icon.ico',  # Add your icon file
        '--add-data=templates;templates',
        '--add-data=static;static',
        '--add-data=.env;.',
        '--hidden-import=app',
        '--hidden-import=flask',
        '--hidden-import=flask_socketio',
        '--hidden-import=webview',
        '--hidden-import=requests',
        '--hidden-import=sqlite3',
        '--hidden-import=cryptography',
        '--hidden-import=celery',
        '--hidden-import=redis',
        '--collect-all=flask',
        '--collect-all=flask_socketio',
        '--collect-all=jinja2',
        '--collect-all=werkzeug',
        '--noconfirm'
    ]
    
    # Platform-specific args
    if sys.platform == 'win32':
        args.extend([
            '--version-file=version_info.txt',
            '--uac-admin'  # Request admin privileges on Windows
        ])
    
    PyInstaller.__main__.run(args)
    
    print("Build completed successfully!")
    print(f"Executable location: {os.path.abspath('dist/HackingGPT.exe' if sys.platform == 'win32' else 'dist/HackingGPT')}")

if __name__ == "__main__":
    build_executable()
```

### Step 3: Create Requirements File

Create `requirements.txt`:
```txt
# Core Flask Dependencies
Flask==2.3.3
Flask-SocketIO==5.3.6
Werkzeug==2.3.7
Jinja2==3.1.2

# WebView for Desktop App
pywebview==4.4.1

# HTTP Requests
requests==2.31.0
urllib3==2.0.7

# Database
sqlite3  # Built-in

# Cryptography & Security
cryptography==41.0.7
Fernet==3.7
werkzeug-security==0.1

# Rate Limiting
Flask-Limiter==3.5.0
redis==5.0.1

# Background Tasks
celery==5.3.4

# Markdown & Text Processing
markdown==3.5.1
bleach==6.1.0

# Build Tools
PyInstaller==6.2.0
auto-py-to-exe==2.40.0  # Optional GUI builder

# Development
python-dotenv==1.0.0
```

### Step 4: Create Version Info (Windows Only)

Create `version_info.txt`:
```txt
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=(1, 0, 0, 0),
    prodvers=(1, 0, 0, 0),
    mask=0x3f,
    flags=0x0,
    OS=0x4,
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
        StringStruct(u'FileDescription', u'Advanced Cybersecurity Assistant'),
        StringStruct(u'FileVersion', u'1.0.0.0'),
        StringStruct(u'InternalName', u'HackingGPT'),
        StringStruct(u'LegalCopyright', u'Copyright (C) 2024 Douglas Rodrigues'),
        StringStruct(u'OriginalFilename', u'HackingGPT.exe'),
        StringStruct(u'ProductName', u'HackingGPT'),
        StringStruct(u'ProductVersion', u'1.0.0.0')])
      ]), 
    VarFileInfo([VarStruct(u'Translation', [1033, 1200])])
  ]
)
```

### Step 5: Build Commands

#### Option A: Using Build Script
```bash
python build.py
```

#### Option B: Direct PyInstaller Command
```bash
# Basic build
pyinstaller --onefile --windowed --name=HackingGPT webview_app.py

# Advanced build with all dependencies
pyinstaller --onefile --windowed --name=HackingGPT \
  --add-data="templates:templates" \
  --add-data="static:static" \
  --hidden-import=app \
  --hidden-import=flask \
  --hidden-import=flask_socketio \
  --icon=assets/icon.ico \
  webview_app.py
```

#### Option C: Using Spec File
```bash
# Generate spec file first
pyi-makespec --onefile --windowed --name=HackingGPT webview_app.py

# Edit HackingGPT.spec file as needed, then build
pyinstaller HackingGPT.spec
```

### Step 6: Advanced Build Configuration

Create `HackingGPT.spec`:
```python
# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['webview_app.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('templates', 'templates'),
        ('static', 'static'),
        ('.env', '.'),
        ('assets', 'assets')
    ],
    hiddenimports=[
        'app',
        'flask',
        'flask_socketio',
        'webview',
        'requests',
        'sqlite3',
        'cryptography',
        'celery',
        'redis',
        'werkzeug',
        'jinja2',
        'markdown',
        'bleach'
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
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
    name='HackingGPT',
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
    version='version_info.txt',
    icon='assets/icon.ico'
)
```

## 🚀 Usage

### Web Interface
1. **Start the Application**
```bash
python app.py
```

2. **Access the Interface**
   - Open browser to `http://localhost:5000`
   - Create account or login
   - Start chatting with HackingGPT

### Desktop Application
1. **Run the Executable**
```bash
# Development
python webview_app.py

# Production
./dist/HackingGPT.exe  # Windows
./dist/HackingGPT       # macOS/Linux
```

### Basic Commands

#### Network Scanning
```bash
# Port scan
nmap -sS -T4 target.com

# Service detection
nmap -sV target.com

# Vulnerability scan
nmap --script vuln target.com
```

#### Web Application Testing
```bash
# Directory enumeration
dirb http://target.com/

# SQL injection testing
sqlmap -u "http://target.com/page.php?id=1" --dbs

# Web vulnerability scan
nikto -h target.com
```

## 📁 Project Structure

```
hackinggpt/
├── app.py                 # Main Flask application
├── webview_app.py        # Desktop wrapper
├── requirements.txt      # Python dependencies
├── build.py             # Build script
├── HackingGPT.spec      # PyInstaller spec file
├── version_info.txt     # Windows version info
├── .env.example         # Environment variables template
├── README.md           # This file
├── templates/          # HTML templates
│   ├── base.html
│   ├── index.html
│   ├── dashboard.html
│   ├── chat.html
│   ├── auth/
│   │   ├── login.html
│   │   └── register.html
│   └── errors/
├── static/            # CSS, JS, images
│   ├── css/
│   ├── js/
│   └── images/
├── assets/           # Application assets
│   └── icon.ico
├── logs/            # Application logs
├── uploads/         # File uploads
└── dist/           # Built executables
```

## 🛠️ Configuration

### Environment Variables
```bash
# API Keys
OPENAI_API_KEY=sk-...
DEEPSEEK_API_KEY=sk-...

# Security
SECRET_KEY=your-secret-key-here
ENCRYPTION_KEY=your-encryption-key-here

# Database
DATABASE_URL=sqlite:///hackinggpt.db

# Redis (Optional)
REDIS_URL=redis://localhost:6379/0

# Application Settings
DEBUG=False
FLASK_ENV=production
FLASK_PORT=5000
```

### Database Configuration
The application uses SQLite by default. For production, consider PostgreSQL:
```bash
pip install psycopg2-binary
DATABASE_URL=postgresql://user:password@localhost/hackinggpt
```

## 🔧 Troubleshooting

### Common Build Issues

#### Missing Dependencies
```bash
# Install all dependencies
pip install -r requirements.txt

# Update pip and setuptools
pip install --upgrade pip setuptools
```

#### WebView Issues
```bash
# Windows: Install WebView2 Runtime
# Download from Microsoft

# macOS: No additional requirements
# Linux: Install webkit2gtk
sudo apt-get install python3-gi python3-gi-cairo gir1.2-gtk-3.0 gir1.2-webkit2-4.0
```

#### Large Executable Size
```bash
# Use UPX compression
pip install upx-ucl
pyinstaller --onefile --upx-dir=/path/to/upx webview_app.py

# Exclude unnecessary modules
pyinstaller --exclude-module=module_name webview_app.py
```

### Runtime Issues

#### Flask Server Won't Start
- Check if port 5000 is available
- Verify environment variables are set
- Check logs in `logs/hackinggpt.log`

#### Database Errors
- Ensure write permissions in application directory
- Check if `hackinggpt.db` exists and is accessible
- Run database initialization manually

#### API Key Issues
- Verify API keys are valid and have sufficient quota
- Check internet connection
- Review API usage limits

## 🚦 Performance Optimization

### Executable Size Reduction
```bash
# Exclude unused modules
--exclude-module=matplotlib
--exclude-module=pandas
--exclude-module=numpy

# Use UPX compression
--upx

# Strip debug symbols
--strip
```

### Runtime Performance
- Use Redis for session storage in production
- Enable database connection pooling
- Implement caching for frequent requests
- Use CDN for static assets

## 📝 Development

### Setting Up Development Environment
```bash
# Clone repository
git clone https://github.com/yourusername/hackinggpt.git
cd hackinggpt

# Create virtual environment
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows

# Install development dependencies
pip install -r requirements-dev.txt

# Set up pre-commit hooks
pre-commit install

# Run tests
python -m pytest tests/
```

### Testing
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=app tests/

# Run specific test file
pytest tests/test_auth.py
```

## 🔒 Security Considerations

### For Developers
- Always validate user inputs
- Use parameterized queries for database operations
- Implement proper session management
- Keep dependencies updated
- Use HTTPS in production

### For Users
- Only use on authorized targets
- Keep API keys secure
- Review commands before execution
- Monitor resource usage
- Use strong passwords

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

## 🙏 Acknowledgments

- OpenAI for GPT models
- DeepSeek for advanced reasoning models
- Flask community for the web framework
- PyWebView for desktop integration
- All security researchers and ethical hackers

## 📞 Support

- **Documentation**: [Wiki](https://github.com/yourusername/hackinggpt/wiki)
- **Issues**: [GitHub Issues](https://github.com/yourusername/hackinggpt/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/hackinggpt/discussions)
- **Email**: support@hackinggpt.com

## 🗺️ Roadmap

- [ ] Plugin system for custom tools
- [ ] Advanced reporting features
- [ ] Team collaboration features
- [ ] Mobile application
- [ ] Docker containerization
- [ ] Cloud deployment options
- [ ] Integration with more security tools
- [ ] Advanced AI model fine-tuning

---

**⚠️ Disclaimer**: This tool is intended for authorized security testing only. Users are responsible for complying with applicable laws and regulations. The developers are not responsible for any misuse of this software.

**Made with ❤️ by Douglas Rodrigues Aguiar de Oliveira**
