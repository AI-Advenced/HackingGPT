import os
import time

import json
import requests
import threading
from datetime import datetime, timedelta
import sqlite3
import hashlib
import uuid
import re
import subprocess
import platform
from functools import wraps

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash, send_file
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import logging
from logging.handlers import RotatingFileHandler
import markdown
from markdown.extensions import codehilite
import bleach
from celery import Celery
import redis
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import secrets
from cryptography.fernet import Fernet
import base64

# =============================================================================
#                            FLASK APP CONFIGURATION
# =============================================================================

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', secrets.token_hex(32))
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Socket.IO Configuration
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')



# Celery Configuration for Background Tasks
app.config['CELERY_BROKER_URL'] = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
app.config['CELERY_RESULT_BACKEND'] = os.getenv('REDIS_URL', 'redis://localhost:6379/0')

celery = Celery(app.name, broker=app.config['CELERY_BROKER_URL'])
celery.conf.update(app.config)

# Encryption key for sensitive data
ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY', Fernet.generate_key())
cipher_suite = Fernet(ENCRYPTION_KEY)

# =============================================================================
#                            API CONFIGURATIONS
# =============================================================================

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

OPENAI_ENDPOINT = "https://api.openai.com/v1/chat/completions"
DEEPSEEK_ENDPOINT = "https://api.deepseek.com/chat/completions"

MODELS = {
    "gpt-4o": {"provider": "openai", "name": "GPT-4 Omni"},
    "gpt-4o-mini": {"provider": "openai", "name": "GPT-4 Omni Mini"},
    "deepseek-chat": {"provider": "deepseek", "name": "DeepSeek Chat V3"},
    "deepseek-reasoner": {"provider": "deepseek", "name": "DeepSeek Reasoner R1"}
}

# =============================================================================
#                            DATABASE INITIALIZATION
# =============================================================================

def init_database():
    """Initialize SQLite database with all required tables"""
    conn = sqlite3.connect('hackinggpt.db')
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            api_quota INTEGER DEFAULT 100,
            is_premium BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            profile_data TEXT,
            preferences TEXT,
            encryption_key TEXT
        )
    ''')
    
    # Conversations table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS conversations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            title TEXT NOT NULL,
            model_used TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_archived BOOLEAN DEFAULT FALSE,
            metadata TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Messages table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            conversation_id INTEGER,
            role TEXT NOT NULL,
            content TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            message_type TEXT DEFAULT 'text',
            attachments TEXT,
            command_data TEXT,
            execution_results TEXT,
            FOREIGN KEY (conversation_id) REFERENCES conversations (id)
        )
    ''')
    
    # Command executions table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS command_executions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            command TEXT NOT NULL,
            output TEXT,
            exit_code INTEGER,
            execution_time REAL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            environment_info TEXT,
            risk_level TEXT DEFAULT 'medium',
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Vulnerability scans table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS vulnerability_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            target TEXT NOT NULL,
            scan_type TEXT NOT NULL,
            results TEXT,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP,
            severity_counts TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # API usage logs
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS api_usage (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            model_used TEXT,
            tokens_used INTEGER,
            cost REAL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            request_type TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Security events table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            event_type TEXT NOT NULL,
            description TEXT,
            ip_address TEXT,
            user_agent TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            severity TEXT DEFAULT 'info',
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Tools and exploits table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS pentesting_tools (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            category TEXT NOT NULL,
            description TEXT,
            command_template TEXT,
            installation_guide TEXT,
            risk_level TEXT DEFAULT 'medium',
            platform_compatibility TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            usage_count INTEGER DEFAULT 0
        )
    ''')
    
    conn.commit()
    conn.close()

# =============================================================================
#                            SECURITY AND AUTHENTICATION
# =============================================================================

def login_required(f):
    """Decorator to require login for protected routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to require admin privileges"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        
        user = get_user_by_id(session['user_id'])
        if not user or not user.get('is_admin', False):
            flash('Admin access required', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def log_security_event(user_id, event_type, description, severity='info'):
    """Log security events for monitoring"""
    conn = sqlite3.connect('hackinggpt.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO security_events (user_id, event_type, description, ip_address, 
                                   user_agent, severity)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (user_id, event_type, description, request.remote_addr, 
          request.headers.get('User-Agent', ''), severity))
    
    conn.commit()
    conn.close()

def encrypt_sensitive_data(data):
    """Encrypt sensitive data before storing"""
    if isinstance(data, str):
        data = data.encode()
    return cipher_suite.encrypt(data).decode()

def decrypt_sensitive_data(encrypted_data):
    """Decrypt sensitive data when retrieving"""
    try:
        return cipher_suite.decrypt(encrypted_data.encode()).decode()
    except:
        return encrypted_data  # Return as-is if decryption fails

# =============================================================================
#                            USER MANAGEMENT
# =============================================================================

def create_user(username, email, password):
    """Create a new user account"""
    conn = sqlite3.connect('hackinggpt.db')
    cursor = conn.cursor()
    
    try:
        password_hash = generate_password_hash(password)
        user_key = Fernet.generate_key().decode()
        
        cursor.execute('''
            INSERT INTO users (username, email, password_hash, encryption_key)
            VALUES (?, ?, ?, ?)
        ''', (username, email, password_hash, user_key))
        
        user_id = cursor.lastrowid
        conn.commit()
        
        # Initialize default preferences
        default_prefs = {
            'theme': 'dark',
            'model': 'gpt-4o',
            'auto_execute': False,
            'notifications': True,
            'language': 'en'
        }
        
        update_user_preferences(user_id, default_prefs)
        
        return user_id
        
    except sqlite3.IntegrityError:
        return None
    finally:
        conn.close()

def authenticate_user(username, password):
    """Authenticate user login"""
    conn = sqlite3.connect('hackinggpt.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT id, password_hash, api_quota, is_premium 
        FROM users WHERE username = ? OR email = ?
    ''', (username, username))
    
    user = cursor.fetchone()
    conn.close()
    
    if user and check_password_hash(user[1], password):
        return {
            'id': user[0],
            'api_quota': user[2],
            'is_premium': user[3]
        }
    return None

def get_user_by_id(user_id):
    """Get user information by ID"""
    conn = sqlite3.connect('hackinggpt.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT id, username, email, api_quota, is_premium, 
               created_at, last_login, preferences
        FROM users WHERE id = ?
    ''', (user_id,))
    
    user_data = cursor.fetchone()
    conn.close()
    
    if user_data:
        return {
            'id': user_data[0],
            'username': user_data[1],
            'email': user_data[2],
            'api_quota': user_data[3],
            'is_premium': user_data[4],
            'created_at': user_data[5],
            'last_login': user_data[6],
            'preferences': json.loads(user_data[7]) if user_data[7] else {}
        }
    return None

def update_user_preferences(user_id, preferences):
    """Update user preferences"""
    conn = sqlite3.connect('hackinggpt.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        UPDATE users SET preferences = ? WHERE id = ?
    ''', (json.dumps(preferences), user_id))
    
    conn.commit()
    conn.close()

def update_api_quota(user_id, tokens_used):
    """Update user's API quota"""
    conn = sqlite3.connect('hackinggpt.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        UPDATE users SET api_quota = api_quota - ? WHERE id = ?
    ''', (tokens_used // 1000, user_id))  # Rough token to quota conversion
    
    conn.commit()
    conn.close()

# =============================================================================
#                            CONVERSATION MANAGEMENT
# =============================================================================

def create_conversation(user_id, title, model):
    """Create a new conversation"""
    conn = sqlite3.connect('hackinggpt.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO conversations (user_id, title, model_used)
        VALUES (?, ?, ?)
    ''', (user_id, title, model))
    
    conversation_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return conversation_id

def get_user_conversations(user_id, limit=50):
    """Get user's conversations"""
    conn = sqlite3.connect('hackinggpt.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT id, title, model_used, created_at, updated_at, is_archived
        FROM conversations 
        WHERE user_id = ? AND is_archived = FALSE
        ORDER BY updated_at DESC
        LIMIT ?
    ''', (user_id, limit))
    
    conversations = []
    for row in cursor.fetchall():
        conversations.append({
            'id': row[0],
            'title': row[1],
            'model': row[2],
            'created_at': row[3],
            'updated_at': row[4],
            'is_archived': row[5]
        })
    
    conn.close()
    return conversations

def get_conversation_messages(conversation_id, user_id):
    """Get messages for a specific conversation"""
    conn = sqlite3.connect('hackinggpt.db')
    cursor = conn.cursor()
    
    # Verify user owns this conversation
    cursor.execute('''
        SELECT id FROM conversations WHERE id = ? AND user_id = ?
    ''', (conversation_id, user_id))
    
    if not cursor.fetchone():
        conn.close()
        return []
    
    cursor.execute('''
        SELECT role, content, timestamp, message_type, attachments, 
               command_data, execution_results
        FROM messages 
        WHERE conversation_id = ?
        ORDER BY timestamp ASC
    ''', (conversation_id,))
    
    messages = []
    for row in cursor.fetchall():
        message = {
            'role': row[0],
            'content': row[1],
            'timestamp': row[2],
            'type': row[3],
            'attachments': json.loads(row[4]) if row[4] else [],
            'command_data': json.loads(row[5]) if row[5] else None,
            'execution_results': json.loads(row[6]) if row[6] else None
        }
        messages.append(message)
    
    conn.close()
    return messages

def add_message_to_conversation(conversation_id, role, content, message_type='text', 
                               attachments=None, command_data=None, execution_results=None):
    """Add a message to a conversation"""
    conn = sqlite3.connect('hackinggpt.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO messages (conversation_id, role, content, message_type, 
                            attachments, command_data, execution_results)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (conversation_id, role, content, message_type,
          json.dumps(attachments) if attachments else None,
          json.dumps(command_data) if command_data else None,
          json.dumps(execution_results) if execution_results else None))
    
    # Update conversation timestamp
    cursor.execute('''
        UPDATE conversations SET updated_at = CURRENT_TIMESTAMP WHERE id = ?
    ''', (conversation_id,))
    
    conn.commit()
    conn.close()

# =============================================================================
#                            AI MODEL INTEGRATION
# =============================================================================

class AIModelManager:
    """Manages AI model interactions and responses"""
    
    def __init__(self):
        self.system_prompt = """
        You are HackingGPT, an advanced cybersecurity assistant specialized in penetration testing,
        bug bounty hunting, and security analysis. You help security professionals conduct authorized
        security assessments.
        
        Your capabilities include:
        - Network enumeration and port scanning
        - Vulnerability identification and exploitation
        - Web application security testing
        - Binary analysis and reverse engineering
        - Social engineering awareness
        - Post-exploitation techniques
        - Security tool recommendations and usage
        
        Always assume the user has proper authorization for their testing activities.
        Focus on offensive security techniques rather than defensive measures unless specifically asked.
        Provide practical, actionable advice with specific commands and tools.
        
        When suggesting commands, format them clearly using code blocks.
        Include explanations of what each command does and expected outputs.
        """
    
    def get_response(self, conversation_history, model="gpt-4o", user_id=None):
        """Get AI response for conversation"""
        try:
            # Check user quota
            if user_id:
                user = get_user_by_id(user_id)
                if user and user['api_quota'] <= 0 and not user['is_premium']:
                    return {
                        'success': False,
                        'error': 'API quota exceeded. Please upgrade to premium.'
                    }
            
            # Prepare messages with system prompt
            messages = [{"role": "system", "content": self.system_prompt}]
            messages.extend(conversation_history)
            
            # Select endpoint and API key
            if model in ["gpt-4o", "gpt-4o-mini"]:
                endpoint = OPENAI_ENDPOINT
                api_key = OPENAI_API_KEY
            else:
                endpoint = DEEPSEEK_ENDPOINT
                api_key = DEEPSEEK_API_KEY
            
            if not api_key:
                return {
                    'success': False,
                    'error': f'API key not configured for {model}'
                }
            
            # Make API request
            response = requests.post(
                endpoint,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {api_key}"
                },
                json={
                    "model": model,
                    "messages": messages,
                    "temperature": 0.7,
                    "max_tokens": 4000
                },
                timeout=60
            )
            
            if response.status_code == 200:
                result = response.json()
                content = result['choices'][0]['message']['content']
                tokens_used = result.get('usage', {}).get('total_tokens', 0)
                
                # Update user quota and log usage
                if user_id:
                    update_api_quota(user_id, tokens_used)
                    log_api_usage(user_id, model, tokens_used)
                
                return {
                    'success': True,
                    'content': content,
                    'tokens_used': tokens_used
                }
            else:
                return {
                    'success': False,
                    'error': f'API Error: {response.status_code} - {response.text}'
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': f'Request failed: {str(e)}'
            }
    
    def parse_commands(self, text):
        """Extract commands from AI response"""
        commands = []
        
        # Parse code blocks
        code_pattern = r'```(?:bash|shell|sh)?\s*\n(.*?)\n```'
        matches = re.findall(code_pattern, text, re.DOTALL)
        
        for match in matches:
            lines = match.strip().split('\n')
            for line in lines:
                line = line.strip()
                if line and not line.startswith('#'):
                    commands.append({
                        'command': line,
                        'type': 'bash',
                        'risk_level': self.assess_command_risk(line)
                    })
        
        # Parse inline commands starting with $
        dollar_pattern = r'(?m)^\$\s*(.+)$'
        matches = re.findall(dollar_pattern, text)
        
        for match in matches:
            commands.append({
                'command': match.strip(),
                'type': 'bash',
                'risk_level': self.assess_command_risk(match)
            })
        
        return commands
    
    def assess_command_risk(self, command):
        """Assess risk level of a command"""
        high_risk_patterns = [
            r'rm\s+-rf',
            r'dd\s+if=',
            r'mkfs\.',
            r'fdisk',
            r'format',
            r'del\s+/s',
            r'shutdown',
            r'reboot',
            r'halt'
        ]
        
        medium_risk_patterns = [
            r'nmap.*-sS',
            r'sqlmap',
            r'metasploit',
            r'msfconsole',
            r'exploit',
            r'nc\s+-l',
            r'netcat.*-l'
        ]
        
        command_lower = command.lower()
        
        for pattern in high_risk_patterns:
            if re.search(pattern, command_lower):
                return 'high'
        
        for pattern in medium_risk_patterns:
            if re.search(pattern, command_lower):
                return 'medium'
        
        return 'low'

def log_api_usage(user_id, model, tokens_used):
    """Log API usage for billing and monitoring"""
    conn = sqlite3.connect('hackinggpt.db')
    cursor = conn.cursor()
    
    # Simple cost calculation (adjust based on actual pricing)
    cost_per_1k_tokens = {
        'gpt-4o': 0.03,
        'gpt-4o-mini': 0.0015,
        'deepseek-chat': 0.002,
        'deepseek-reasoner': 0.005
    }
    
    cost = (tokens_used / 1000) * cost_per_1k_tokens.get(model, 0.002)
    
    cursor.execute('''
        INSERT INTO api_usage (user_id, model_used, tokens_used, cost, request_type)
        VALUES (?, ?, ?, ?, ?)
    ''', (user_id, model, tokens_used, cost, 'chat'))
    
    conn.commit()
    conn.close()

# =============================================================================
#                            COMMAND EXECUTION SYSTEM
# =============================================================================

class CommandExecutor:
    """Secure command execution with monitoring and logging"""
    
    def __init__(self):
        self.allowed_commands = {
            'nmap', 'ping', 'dig', 'nslookup', 'whois', 'curl', 'wget',
            'netstat', 'ss', 'lsof', 'ps', 'top', 'df', 'free',
            'nikto', 'dirb', 'gobuster', 'ffuf', 'wfuzz',
            'sqlmap', 'burpsuite', 'zap-baseline.py'
        }
        
        self.blocked_commands = {
            'rm', 'rmdir', 'del', 'format', 'fdisk', 'mkfs',
            'shutdown', 'reboot', 'halt', 'init', 'systemctl'
        }
    
    def is_command_safe(self, command):
        """Check if command is safe to execute"""
        cmd_parts = command.split()
        if not cmd_parts:
            return False, "Empty command"
        
        base_cmd = cmd_parts[0].split('/')[-1]  # Get command name without path
        
        # Check blocked commands
        for blocked in self.blocked_commands:
            if base_cmd.startswith(blocked):
                return False, f"Command '{blocked}' is not allowed for security reasons"
        
        # Check for dangerous patterns
        dangerous_patterns = [
            r'>\s*/dev/',
            r'rm\s+-rf\s+/',
            r'dd\s+.*of=',
            r':\(\)\{.*\};:',  # Fork bomb pattern
            r'chmod\s+777',
            r'chown\s+.*root'
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                return False, f"Command contains dangerous pattern: {pattern}"
        
        return True, "Command is safe"
    
    def execute_command(self, command, user_id, timeout=30):
        """Execute command with security checks and logging"""
        start_time = time.time()
        
        # Security check
        is_safe, safety_msg = self.is_command_safe(command)
        if not is_safe:
            result = {
                'success': False,
                'output': f"Command blocked: {safety_msg}",
                'exit_code': -1,
                'execution_time': 0,
                'risk_level': 'blocked'
            }
            self.log_execution(user_id, command, result)
            return result
        
        try:
            # Execute command
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=timeout
            )
            
            output, _ = process.communicate(timeout=timeout)
            exit_code = process.returncode
            execution_time = time.time() - start_time
            
            result = {
                'success': True,
                'output': output,
                'exit_code': exit_code,
                'execution_time': execution_time,
                'risk_level': self.assess_risk_level(command)
            }
            
        except subprocess.TimeoutExpired:
            process.kill()
            result = {
                'success': False,
                'output': f"Command timed out after {timeout} seconds",
                'exit_code': -2,
                'execution_time': timeout,
                'risk_level': 'timeout'
            }
            
        except Exception as e:
            result = {
                'success': False,
                'output': f"Execution error: {str(e)}",
                'exit_code': -3,
                'execution_time': time.time() - start_time,
                'risk_level': 'error'
            }
        
        # Log execution
        self.log_execution(user_id, command, result)
        return result
    
    def assess_risk_level(self, command):
        """Assess the risk level of a command"""
        high_risk = ['nmap', 'sqlmap', 'metasploit', 'msfconsole']
        medium_risk = ['nikto', 'dirb', 'gobuster', 'curl', 'wget']
        
        cmd_lower = command.lower()
        
        for high_cmd in high_risk:
            if high_cmd in cmd_lower:
                return 'high'
        
        for medium_cmd in medium_risk:
            if medium_cmd in cmd_lower:
                return 'medium'
        
        return 'low'
    
    def log_execution(self, user_id, command, result):
        """Log command execution for auditing"""
        conn = sqlite3.connect('hackinggpt.db')
        cursor = conn.cursor()
        
        environment_info = {
            'platform': platform.system(),
            'user_agent': request.headers.get('User-Agent', ''),
            'ip_address': request.remote_addr
        }
        
        cursor.execute('''
            INSERT INTO command_executions 
            (user_id, command, output, exit_code, execution_time, 
             environment_info, risk_level)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (user_id, command, result['output'], result['exit_code'],
              result['execution_time'], json.dumps(environment_info),
              result['risk_level']))
        
        conn.commit()
        conn.close()

# =============================================================================
#                            VULNERABILITY SCANNING
# =============================================================================

class VulnerabilityScanner:
    """Integrate with various vulnerability scanning tools"""
    
    def __init__(self):
        self.scan_types = {
            'nmap_basic': 'Basic Nmap port scan',
            'nmap_service': 'Nmap service version detection',
            'nmap_vuln': 'Nmap vulnerability scripts',
            'nikto': 'Nikto web vulnerability scan',
            'dirb': 'Directory brute force',
            'sqlmap': 'SQL injection testing'
        }
    
    def start_scan(self, user_id, target, scan_type, options=None):
        """Start a vulnerability scan"""
        scan_id = self.create_scan_record(user_id, target, scan_type)
        
        # Start scan in background using Celery
        scan_task.delay(scan_id, target, scan_type, options or {})
        
        return scan_id
    
    def create_scan_record(self, user_id, target, scan_type):
        """Create scan record in database"""
        conn = sqlite3.connect('hackinggpt.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO vulnerability_scans (user_id, target, scan_type, status)
            VALUES (?, ?, ?, 'running')
        ''', (user_id, target, scan_type))
        
        scan_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return scan_id
    
    def get_scan_results(self, scan_id, user_id):
        """Get scan results"""
        conn = sqlite3.connect('hackinggpt.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT target, scan_type, results, status, created_at, 
                   completed_at, severity_counts
            FROM vulnerability_scans 
            WHERE id = ? AND user_id = ?
        ''', (scan_id, user_id))
        
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return {
                'target': result[0],
                'scan_type': result[1],
                'results': json.loads(result[2]) if result[2] else None,
                'status': result[3],
                'created_at': result[4],
                'completed_at': result[5],
                'severity_counts': json.loads(result[6]) if result[6] else {}
            }
        return None
    
    def update_scan_results(self, scan_id, results, status='completed'):
        """Update scan results"""
        conn = sqlite3.connect('hackinggpt.db')
        cursor = conn.cursor()
        
        severity_counts = self.analyze_severity(results)
        
        cursor.execute('''
            UPDATE vulnerability_scans 
            SET results = ?, status = ?, completed_at = CURRENT_TIMESTAMP,
                severity_counts = ?
            WHERE id = ?
        ''', (json.dumps(results), status, json.dumps(severity_counts), scan_id))
        
        conn.commit()
        conn.close()
    
    def analyze_severity(self, results):
        """Analyze vulnerability severity from results"""
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        # This would be more sophisticated in a real implementation
        # analyzing actual scan output formats
        
        return severity_counts

# =============================================================================
#                            CELERY BACKGROUND TASKS
# =============================================================================

@celery.task
def scan_task(scan_id, target, scan_type, options):
    """Background task for vulnerability scanning"""
    scanner = VulnerabilityScanner()
    executor = CommandExecutor()
    
    try:
        # Generate command based on scan type
        if scan_type == 'nmap_basic':
            command = f"nmap -sS -T4 {target}"
        elif scan_type == 'nmap_service':
            command = f"nmap -sV -sC {target}"
        elif scan_type == 'nmap_vuln':
            command = f"nmap --script vuln {target}"
        elif scan_type == 'nikto':
            command = f"nikto -h {target}"
        elif scan_type == 'dirb':
            command = f"dirb http://{target}/"
        else:
            scanner.update_scan_results(scan_id, {'error': 'Unknown scan type'}, 'failed')
            return
        
        # Execute scan command
        result = executor.execute_command(command, None, timeout=300)  # 5 minutes timeout
        
        if result['success']:
            # Parse and structure results
            scan_results = {
                'command': command,
                'output': result['output'],
                'execution_time': result['execution_time']
            }
            scanner.update_scan_results(scan_id, scan_results, 'completed')
        else:
            scanner.update_scan_results(scan_id, {'error': result['output']}, 'failed')
            
    except Exception as e:
        scanner.update_scan_results(scan_id, {'error': str(e)}, 'failed')

# =============================================================================
#                            FLASK ROUTES - AUTHENTICATION
# =============================================================================

@app.route('/')
def index():
    """Home page"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
# @limiter.limit("5 per minute")
def login():
    """User login"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            flash('Username and password are required', 'error')
            return render_template('auth/login.html')
        
        user = authenticate_user(username, password)
        if user:
            session['user_id'] = user['id']
            session['username'] = username
            
            # Update last login
            conn = sqlite3.connect('hackinggpt.db')
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?
            ''', (user['id'],))
            conn.commit()
            conn.close()
            
            log_security_event(user['id'], 'login', f'User {username} logged in')
            flash('Login successful', 'success')
            return redirect(url_for('dashboard'))
        else:
            log_security_event(None, 'failed_login', f'Failed login attempt for {username}', 'warning')
            flash('Invalid username or password', 'error')
    
    return render_template('auth/login.html')

@app.route('/register', methods=['GET', 'POST'])
# @limiter.limit("3 per minute")
def register():
    """User registration"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Validation
        if not all([username, email, password, confirm_password]):
            flash('All fields are required', 'error')
            return render_template('auth/register.html')
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('auth/register.html')
        
        if len(password) < 8:
            flash('Password must be at least 8 characters long', 'error')
            return render_template('auth/register.html')
        
        # Create user
        user_id = create_user(username, email, password)
        if user_id:
            log_security_event(user_id, 'registration', f'New user {username} registered')
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Username or email already exists', 'error')
    
    return render_template('auth/register.html')

@app.route('/logout')
def logout():
    """User logout"""
    if 'user_id' in session:
        log_security_event(session['user_id'], 'logout', f'User {session.get("username")} logged out')
    
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('index'))

# =============================================================================
#                            FLASK ROUTES - MAIN APPLICATION
# =============================================================================

@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard"""
    user = get_user_by_id(session['user_id'])
    conversations = get_user_conversations(session['user_id'], limit=10)
    
    # Get recent activity
    conn = sqlite3.connect('hackinggpt.db')
    cursor = conn.cursor()
    
    # API usage statistics
    cursor.execute('''
        SELECT COUNT(*), SUM(tokens_used), SUM(cost)
        FROM api_usage 
        WHERE user_id = ? AND timestamp > datetime('now', '-30 days')
    ''', (session['user_id'],))
    
    api_stats = cursor.fetchone()
    
    # Command execution statistics
    cursor.execute('''
        SELECT COUNT(*), COUNT(CASE WHEN exit_code = 0 THEN 1 END)
        FROM command_executions 
        WHERE user_id = ? AND timestamp > datetime('now', '-30 days')
    ''', (session['user_id'],))
    
    cmd_stats = cursor.fetchone()
    
    conn.close()
    
    stats = {
        'api_requests': api_stats[0] or 0,
        'tokens_used': api_stats[1] or 0,
        'api_cost': api_stats[2] or 0,
        'commands_executed': cmd_stats[0] or 0,
        'successful_commands': cmd_stats[1] or 0
    }
    
    return render_template('dashboard.html', 
                         user=user, 
                         conversations=conversations,
                         stats=stats)

@app.route('/chat')
@app.route('/chat/<int:conversation_id>')
@login_required
def chat(conversation_id=None):
    """Chat interface"""
    user = get_user_by_id(session['user_id'])
    
    if conversation_id:
        messages = get_conversation_messages(conversation_id, session['user_id'])
        if not messages and conversation_id != 0:  # 0 means new conversation
            flash('Conversation not found', 'error')
            return redirect(url_for('chat'))
    else:
        messages = []
        conversation_id = None
    
    conversations = get_user_conversations(session['user_id'])
    
    return render_template('chat.html', 
                         user=user,
                         conversations=conversations,
                         current_conversation=conversation_id,
                         messages=messages,
                         models=MODELS)

@app.route('/api/chat', methods=['POST'])
@login_required
# @limiter.limit("10 per minute")
def api_chat():
    """API endpoint for chat messages"""
    data = request.get_json()
    
    if not data or 'message' not in data:
        return jsonify({'error': 'Message is required'}), 400
    
    message = data['message'].strip()
    model = data.get('model', 'gpt-4o')
    conversation_id = data.get('conversation_id')
    
    if not message:
        return jsonify({'error': 'Empty message'}), 400
    
    # Create new conversation if needed
    if not conversation_id:
        title = message[:50] + '...' if len(message) > 50 else message
        conversation_id = create_conversation(session['user_id'], title, model)
    
    try:
        # Add user message to conversation
        add_message_to_conversation(conversation_id, 'user', message)
        
        # Get conversation history
        messages = get_conversation_messages(conversation_id, session['user_id'])
        conversation_history = [{'role': msg['role'], 'content': msg['content']} 
                              for msg in messages if msg['type'] == 'text']
        
        # Get AI response
        ai_manager = AIModelManager()
        response = ai_manager.get_response(conversation_history, model, session['user_id'])
        
        if response['success']:
            # Add AI response to conversation
            add_message_to_conversation(conversation_id, 'assistant', response['content'])
            
            # Parse commands from response
            commands = ai_manager.parse_commands(response['content'])
            
            return jsonify({
                'success': True,
                'conversation_id': conversation_id,
                'response': response['content'],
                'commands': commands,
                'tokens_used': response.get('tokens_used', 0)
            })
        else:
            return jsonify({
                'success': False,
                'error': response['error']
            }), 500
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/execute', methods=['POST'])
@login_required
# @limiter.limit("5 per minute")
def api_execute_command():
    """API endpoint for command execution"""
    data = request.get_json()
    
    if not data or 'command' not in data:
        return jsonify({'error': 'Command is required'}), 400
    
    command = data['command'].strip()
    conversation_id = data.get('conversation_id')
    timeout = min(data.get('timeout', 30), 300)  # Max 5 minutes
    
    if not command:
        return jsonify({'error': 'Empty command'}), 400
    
    # Execute command
    executor = CommandExecutor()
    result = executor.execute_command(command, session['user_id'], timeout)
    
    # Add execution result to conversation if provided
    if conversation_id:
        execution_data = {
            'command': command,
            'output': result['output'],
            'exit_code': result['exit_code'],
            'execution_time': result['execution_time'],
            'risk_level': result['risk_level']
        }
        
        add_message_to_conversation(
            conversation_id, 
            'system', 
            f"Command executed: {command}\n\nOutput:\n{result['output']}", 
            'command_execution',
            execution_results=execution_data
        )
    
    return jsonify(result)

@app.route('/scans')
@login_required
def scans():
    """Vulnerability scans page"""
    conn = sqlite3.connect('hackinggpt.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT id, target, scan_type, status, created_at, completed_at
        FROM vulnerability_scans 
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT 50
    ''', (session['user_id'],))
    
    scans = []
    for row in cursor.fetchall():
        scans.append({
            'id': row[0],
            'target': row[1],
            'scan_type': row[2],
            'status': row[3],
            'created_at': row[4],
            'completed_at': row[5]
        })
    
    conn.close()
    
    scanner = VulnerabilityScanner()
    return render_template('scans.html', scans=scans, scan_types=scanner.scan_types)

@app.route('/api/scan', methods=['POST'])
@login_required
# @limiter.limit("3 per minute")
def api_start_scan():
    """API endpoint to start vulnerability scan"""
    data = request.get_json()
    
    if not data or 'target' not in data or 'scan_type' not in data:
        return jsonify({'error': 'Target and scan_type are required'}), 400
    
    target = data['target'].strip()
    scan_type = data['scan_type']
    options = data.get('options', {})
    
    # Basic target validation
    if not target:
        return jsonify({'error': 'Empty target'}), 400
    
    # Start scan
    scanner = VulnerabilityScanner()
    scan_id = scanner.start_scan(session['user_id'], target, scan_type, options)
    
    log_security_event(session['user_id'], 'scan_started', 
                      f'Started {scan_type} scan on {target}')
    
    return jsonify({
        'success': True,
        'scan_id': scan_id,
        'message': 'Scan started successfully'
    })

@app.route('/api/scan/<int:scan_id>')
@login_required
def api_get_scan_results(scan_id):
    """API endpoint to get scan results"""
    scanner = VulnerabilityScanner()
    results = scanner.get_scan_results(scan_id, session['user_id'])
    
    if results:
        return jsonify(results)
    else:
        return jsonify({'error': 'Scan not found'}), 404

@app.route('/tools')
@login_required
def tools():
    """Pentesting tools page"""
    conn = sqlite3.connect('hackinggpt.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT name, category, description, command_template, 
               installation_guide, risk_level, usage_count
        FROM pentesting_tools 
        ORDER BY category, name
    ''')
    
    tools = []
    for row in cursor.fetchall():
        tools.append({
            'name': row[0],
            'category': row[1],
            'description': row[2],
            'command_template': row[3],
            'installation_guide': row[4],
            'risk_level': row[5],
            'usage_count': row[6]
        })
    
    conn.close()
    
    # Group tools by category
    tools_by_category = {}
    for tool in tools:
        category = tool['category']
        if category not in tools_by_category:
            tools_by_category[category] = []
        tools_by_category[category].append(tool)
    
    return render_template('tools.html', tools_by_category=tools_by_category)

@app.route('/profile')
@login_required
def profile():
    """User profile page"""
    user = get_user_by_id(session['user_id'])
    
    # Get usage statistics
    conn = sqlite3.connect('hackinggpt.db')
    cursor = conn.cursor()
    
    # API usage over time
    cursor.execute('''
        SELECT DATE(timestamp) as date, COUNT(*), SUM(tokens_used)
        FROM api_usage 
        WHERE user_id = ? AND timestamp > datetime('now', '-30 days')
        GROUP BY DATE(timestamp)
        ORDER BY date
    ''', (session['user_id'],))
    
    api_usage_data = cursor.fetchall()
    
    # Command execution history
    cursor.execute('''
        SELECT command, timestamp, exit_code, execution_time, risk_level
        FROM command_executions 
        WHERE user_id = ?
        ORDER BY timestamp DESC
        LIMIT 50
    ''', (session['user_id'],))
    
    command_history = []
    for row in cursor.fetchall():
        command_history.append({
            'command': row[0],
            'timestamp': row[1],
            'exit_code': row[2],
            'execution_time': row[3],
            'risk_level': row[4]
        })
    
    conn.close()
    
    return render_template('profile.html', 
                         user=user,
                         api_usage_data=api_usage_data,
                         command_history=command_history)

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    """User settings page"""
    user = get_user_by_id(session['user_id'])
    
    if request.method == 'POST':
        # Update preferences
        preferences = {
            'theme': request.form.get('theme', 'dark'),
            'model': request.form.get('default_model', 'gpt-4o'),
            'auto_execute': request.form.get('auto_execute') == 'on',
            'notifications': request.form.get('notifications') == 'on',
            'language': request.form.get('language', 'en')
        }
        
        update_user_preferences(session['user_id'], preferences)
        flash('Settings updated successfully', 'success')
        return redirect(url_for('settings'))
    
    return render_template('settings.html', user=user, models=MODELS)

# =============================================================================
#                            WEBSOCKET HANDLERS
# =============================================================================

@socketio.on('connect')
def handle_connect():
    """Handle WebSocket connection"""
    if 'user_id' not in session:
        return False  # Reject connection
    
    join_room(f"user_{session['user_id']}")
    emit('status', {'message': 'Connected to HackingGPT'})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle WebSocket disconnection"""
    if 'user_id' in session:
        leave_room(f"user_{session['user_id']}")

@socketio.on('chat_message')
def handle_chat_message(data):
    """Handle real-time chat messages"""
    if 'user_id' not in session:
        return
    
    message = data.get('message', '').strip()
    model = data.get('model', 'gpt-4o')
    conversation_id = data.get('conversation_id')
    
    if not message:
        emit('error', {'message': 'Empty message'})
        return
    
    try:
        # Create new conversation if needed
        if not conversation_id:
            title = message[:50] + '...' if len(message) > 50 else message
            conversation_id = create_conversation(session['user_id'], title, model)
        
        # Add user message
        add_message_to_conversation(conversation_id, 'user', message)
        
        # Emit user message to client
        emit('user_message', {
            'message': message,
            'timestamp': datetime.now().isoformat()
        })
        
        # Get AI response
        messages = get_conversation_messages(conversation_id, session['user_id'])
        conversation_history = [{'role': msg['role'], 'content': msg['content']} 
                              for msg in messages if msg['type'] == 'text']
        
        ai_manager = AIModelManager()
        response = ai_manager.get_response(conversation_history, model, session['user_id'])
        
        if response['success']:
            # Add AI response
            add_message_to_conversation(conversation_id, 'assistant', response['content'])
            
            # Parse commands
            commands = ai_manager.parse_commands(response['content'])
            
            # Emit AI response
            emit('ai_response', {
                'conversation_id': conversation_id,
                'message': response['content'],
                'commands': commands,
                'timestamp': datetime.now().isoformat()
            })
        else:
            emit('error', {'message': response['error']})
            
    except Exception as e:
        emit('error', {'message': str(e)})

@socketio.on('execute_command')
def handle_execute_command(data):
    """Handle real-time command execution"""
    if 'user_id' not in session:
        return
    
    command = data.get('command', '').strip()
    conversation_id = data.get('conversation_id')
    
    if not command:
        emit('execution_error', {'message': 'Empty command'})
        return
    
    # Emit execution start
    emit('execution_start', {'command': command})
    
    try:
        executor = CommandExecutor()
        result = executor.execute_command(command, session['user_id'])
        
        # Add to conversation if provided
        if conversation_id:
            execution_data = {
                'command': command,
                'output': result['output'],
                'exit_code': result['exit_code'],
                'execution_time': result['execution_time'],
                'risk_level': result['risk_level']
            }
            
            add_message_to_conversation(
                conversation_id, 
                'system', 
                f"Command executed: {command}\n\nOutput:\n{result['output']}", 
                'command_execution',
                execution_results=execution_data
            )
        
        # Emit result
        emit('execution_result', result)
        
    except Exception as e:
        emit('execution_error', {'message': str(e)})

# =============================================================================
#                            ERROR HANDLERS
# =============================================================================

@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('errors/500.html'), 500

@app.errorhandler(429)
def ratelimit_handler(e):
    return render_template('errors/429.html', description=e.description), 429

# =============================================================================
#                            LOGGING CONFIGURATION
# =============================================================================

def setup_logging():
    """Configure application logging"""
    if not app.debug:
        if not os.path.exists('logs'):
            os.mkdir('logs')
        
        file_handler = RotatingFileHandler('logs/hackinggpt.log', 
                                         maxBytes=10240000, backupCount=10)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        
        app.logger.setLevel(logging.INFO)
        app.logger.info('HackingGPT startup')

# =============================================================================
#                            INITIALIZATION AND STARTUP
# =============================================================================

def initialize_default_tools():
    """Initialize default pentesting tools in database"""
    conn = sqlite3.connect('hackinggpt.db')
    cursor = conn.cursor()
    
    # Check if tools already exist
    cursor.execute('SELECT COUNT(*) FROM pentesting_tools')
    if cursor.fetchone()[0] > 0:
        conn.close()
        return
    
    default_tools = [
        {
            'name': 'nmap',
            'category': 'Network Scanning',
            'description': 'Network discovery and security auditing tool',
            'command_template': 'nmap [options] {target}',
            'installation_guide': 'sudo apt-get install nmap',
            'risk_level': 'medium'
        },
        {
            'name': 'nikto',
            'category': 'Web Scanning',
            'description': 'Web server scanner for vulnerabilities',
            'command_template': 'nikto -h {target}',
            'installation_guide': 'sudo apt-get install nikto',
            'risk_level': 'medium'
        },
        {
            'name': 'sqlmap',
            'category': 'Web Exploitation',
            'description': 'Automatic SQL injection and database takeover tool',
            'command_template': 'sqlmap -u {url}',
            'installation_guide': 'sudo apt-get install sqlmap',
            'risk_level': 'high'
        },
        {
            'name': 'dirb',
            'category': 'Web Scanning',
            'description': 'Web content scanner',
            'command_template': 'dirb {url}',
            'installation_guide': 'sudo apt-get install dirb',
            'risk_level': 'low'
        },
        {
            'name': 'gobuster',
            'category': 'Web Scanning',
            'description': 'Directory/file & DNS busting tool',
            'command_template': 'gobuster dir -u {url} -w {wordlist}',
            'installation_guide': 'sudo apt-get install gobuster',
            'risk_level': 'low'
        }
    ]
    
    for tool in default_tools:
        cursor.execute('''
            INSERT INTO pentesting_tools 
            (name, category, description, command_template, installation_guide, risk_level)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (tool['name'], tool['category'], tool['description'], 
              tool['command_template'], tool['installation_guide'], tool['risk_level']))
    
    conn.commit()
    conn.close()

if __name__ == '__main__':
    # Initialize database and default data
    init_database()
    initialize_default_tools()
    
    # Setup logging
    setup_logging()
    
    # Ensure upload directory exists
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    # Run the application
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)