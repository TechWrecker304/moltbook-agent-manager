#!/usr/bin/env python3
"""
Moltbook Agent Manager 🦞 - Comprehensive Edition
Full-featured desktop app for deploying and managing AI agents on Moltbook.

Requirements:
    pip install customtkinter pillow requests "openai>=0.28.0,<1.0.0" schedule matplotlib pystray
    
Optional (for enhanced security):
    pip install keyring cryptography
"""

APP_VERSION = "3.1.0"  # Jan 31 2026 - Open source release
BUILD_DATE = "2026-01-31"
print(f"[Moltbook Agent Manager v{APP_VERSION}]")

import customtkinter as ctk
from tkinter import messagebox, filedialog
import tkinter as tk
from PIL import Image, ImageDraw
import requests
import json
import sqlite3
import threading
import time
import os
import csv
import base64
import hashlib
import logging
import traceback
import platform
import sys
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
import webbrowser
import uuid
from collections import deque

# ═══════════════════════════════════════════════════════════════════════════════
# LOGGING & DIAGNOSTICS MODULE
# ═══════════════════════════════════════════════════════════════════════════════

LOG_DIR = os.path.expanduser("~/.moltbook_logs")
os.makedirs(LOG_DIR, exist_ok=True)

# Set up file logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, f"moltbook_{datetime.now().strftime('%Y%m%d')}.log")),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("MoltbookManager")

class APIHealthMonitor:
    """Monitors Moltbook API health and tracks issues"""
    
    def __init__(self):
        self.endpoint_status: Dict[str, Dict] = {}
        self.recent_errors: deque = deque(maxlen=50)
        self.last_successful_post: Optional[datetime] = None
        self.last_successful_comment: Optional[datetime] = None
        self.last_check: Optional[datetime] = None
        self.api_version: Optional[str] = None
        self.known_issues: List[str] = []
        
    def record_request(self, endpoint: str, method: str, status_code: int, 
                       response_time: float, error: Optional[str] = None):
        """Record an API request result"""
        key = f"{method}:{endpoint}"
        now = datetime.now()
        
        if key not in self.endpoint_status:
            self.endpoint_status[key] = {
                "successes": 0, "failures": 0, "last_success": None, 
                "last_failure": None, "avg_response_time": 0, "total_requests": 0
            }
        
        stats = self.endpoint_status[key]
        stats["total_requests"] += 1
        stats["avg_response_time"] = (
            (stats["avg_response_time"] * (stats["total_requests"] - 1) + response_time) 
            / stats["total_requests"]
        )
        
        if status_code in (200, 201):
            stats["successes"] += 1
            stats["last_success"] = now.isoformat()
            if "post" in endpoint.lower() and method == "POST":
                if "comment" not in endpoint.lower():
                    self.last_successful_post = now
                else:
                    self.last_successful_comment = now
        else:
            stats["failures"] += 1
            stats["last_failure"] = now.isoformat()
            stats["last_error"] = error
            self.recent_errors.append({
                "time": now.isoformat(),
                "endpoint": endpoint,
                "method": method,
                "status": status_code,
                "error": error
            })
            
        self.last_check = now
        logger.debug(f"API {method} {endpoint}: {status_code} ({response_time:.2f}s)")
        
    def get_health_summary(self) -> Dict:
        """Get overall API health summary"""
        total_success = sum(s["successes"] for s in self.endpoint_status.values())
        total_failure = sum(s["failures"] for s in self.endpoint_status.values())
        total = total_success + total_failure
        
        # Detect known issues
        issues = []
        for key, stats in self.endpoint_status.items():
            if stats["failures"] > 0 and stats["successes"] == 0:
                issues.append(f"❌ {key} - All requests failing")
            elif stats["failures"] > stats["successes"]:
                issues.append(f"⚠️ {key} - High failure rate")
        
        # Check for comment endpoint issues specifically
        comment_endpoints = [k for k in self.endpoint_status.keys() if "comment" in k.lower()]
        comment_failures = sum(self.endpoint_status[k]["failures"] for k in comment_endpoints)
        if comment_failures > 0:
            issues.append("🔴 Comment API appears to have issues - use Moltbook.com to reply")
        
        return {
            "status": "healthy" if total_failure == 0 else ("degraded" if total_success > total_failure else "unhealthy"),
            "success_rate": (total_success / total * 100) if total > 0 else 0,
            "total_requests": total,
            "last_check": self.last_check.isoformat() if self.last_check else None,
            "last_successful_post": self.last_successful_post.isoformat() if self.last_successful_post else None,
            "last_successful_comment": self.last_successful_comment.isoformat() if self.last_successful_comment else None,
            "issues": issues,
            "recent_errors": list(self.recent_errors)[-10:]
        }
    
    def check_endpoint_health(self, base_url: str, api_key: str) -> Dict:
        """Actively check API endpoint health"""
        results = {}
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        
        endpoints_to_check = [
            ("GET", "/agents/me", "Profile"),
            ("GET", "/posts?limit=1", "Feed"),
            ("GET", "/agents/status", "Status"),
        ]
        
        for method, endpoint, name in endpoints_to_check:
            url = f"{base_url}{endpoint}"
            start = time.time()
            try:
                if method == "GET":
                    r = requests.get(url, headers=headers, timeout=10)
                else:
                    r = requests.post(url, headers=headers, json={}, timeout=10)
                elapsed = time.time() - start
                results[name] = {
                    "status": "✅" if r.status_code in (200, 201) else "❌",
                    "code": r.status_code,
                    "time": f"{elapsed:.2f}s"
                }
            except Exception as e:
                elapsed = time.time() - start
                results[name] = {
                    "status": "❌",
                    "code": 0,
                    "time": f"{elapsed:.2f}s",
                    "error": str(e)[:50]
                }
        
        return results

# Global health monitor
api_health = APIHealthMonitor()

class SystemDiagnostics:
    """System and environment diagnostics"""
    
    @staticmethod
    def get_system_info() -> Dict:
        return {
            "os": platform.system(),
            "os_version": platform.version(),
            "python_version": sys.version,
            "app_version": APP_VERSION,
            "build_date": BUILD_DATE,
        }
    
    @staticmethod
    def get_dependency_status() -> Dict:
        deps = {}
        
        # Check each optional dependency
        try:
            import keyring
            deps["keyring"] = {"status": "✅", "version": getattr(keyring, "__version__", "unknown")}
        except ImportError:
            deps["keyring"] = {"status": "❌", "note": "pip install keyring"}
            
        try:
            from cryptography import __version__ as crypto_ver
            deps["cryptography"] = {"status": "✅", "version": crypto_ver}
        except ImportError:
            deps["cryptography"] = {"status": "❌", "note": "pip install cryptography"}
            
        try:
            import matplotlib
            deps["matplotlib"] = {"status": "✅", "version": matplotlib.__version__}
        except ImportError:
            deps["matplotlib"] = {"status": "⚠️", "note": "Optional - for charts"}
            
        try:
            import openai
            deps["openai"] = {"status": "✅", "version": getattr(openai, "__version__", "unknown")}
        except ImportError:
            deps["openai"] = {"status": "❌", "note": "Required for AI features"}
            
        try:
            import pystray
            deps["pystray"] = {"status": "✅", "version": "installed"}
        except ImportError:
            deps["pystray"] = {"status": "⚠️", "note": "Optional - for system tray"}
            
        return deps
    
    @staticmethod
    def get_network_diagnostics(base_url: str) -> Dict:
        """Check network connectivity to Moltbook"""
        results = {}
        
        # Test basic connectivity
        try:
            start = time.time()
            r = requests.get(base_url.replace("/api/v1", ""), timeout=10)
            elapsed = time.time() - start
            results["moltbook_reachable"] = {
                "status": "✅" if r.status_code < 500 else "⚠️",
                "response_time": f"{elapsed:.2f}s",
                "status_code": r.status_code
            }
        except Exception as e:
            results["moltbook_reachable"] = {
                "status": "❌",
                "error": str(e)[:100]
            }
        
        # Test API endpoint
        try:
            start = time.time()
            r = requests.get(f"{base_url}/posts?limit=1", timeout=10)
            elapsed = time.time() - start
            results["api_accessible"] = {
                "status": "✅" if r.status_code == 200 else "⚠️",
                "response_time": f"{elapsed:.2f}s",
                "status_code": r.status_code
            }
        except Exception as e:
            results["api_accessible"] = {
                "status": "❌",
                "error": str(e)[:100]
            }
            
        return results

diagnostics = SystemDiagnostics()

# ═══════════════════════════════════════════════════════════════════════════════
# SECURITY MODULE - Encrypt sensitive data
# ═══════════════════════════════════════════════════════════════════════════════

# Try to use keyring for secure storage (best option)
try:
    import keyring
    HAS_KEYRING = True
    logger.info("[Security] ✓ Keyring available - using system credential store")
except ImportError:
    HAS_KEYRING = False
    logger.warning("[Security] ⚠ Keyring not available - using encrypted local storage")

# Try to use cryptography for strong encryption
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    HAS_CRYPTO = True
    logger.info("[Security] ✓ Cryptography available - using AES encryption")
except ImportError:
    HAS_CRYPTO = False
    logger.warning("[Security] ⚠ Cryptography not available - using basic obfuscation")

class SecureStorage:
    """Handles secure storage of API keys and sensitive data"""
    
    SERVICE_NAME = "MoltbookAgentManager"
    
    def __init__(self):
        # Generate or load machine-specific key for encryption
        self._key = self._get_or_create_key()
        if HAS_CRYPTO:
            self._fernet = Fernet(self._derive_fernet_key(self._key))
        else:
            self._fernet = None
    
    def _get_or_create_key(self) -> str:
        """Get or create a machine-specific encryption key"""
        key_file = os.path.expanduser("~/.moltbook_key")
        if os.path.exists(key_file):
            with open(key_file, 'r') as f:
                return f.read().strip()
        else:
            # Generate new key based on machine ID + random
            machine_id = str(uuid.getnode())  # MAC address as identifier
            random_part = str(uuid.uuid4())
            key = hashlib.sha256(f"{machine_id}{random_part}".encode()).hexdigest()[:32]
            with open(key_file, 'w') as f:
                f.write(key)
            # Restrict file permissions (Unix only)
            try:
                os.chmod(key_file, 0o600)
            except OSError:
                pass
            return key
    
    def _derive_fernet_key(self, key: str) -> bytes:
        """Derive a Fernet-compatible key from our key"""
        if HAS_CRYPTO:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'moltbook_salt_v1',
                iterations=100000,
            )
            return base64.urlsafe_b64encode(kdf.derive(key.encode()))
        return key.encode()
    
    def encrypt(self, plaintext: str) -> str:
        """Encrypt sensitive data"""
        if not plaintext:
            return ""
        
        if HAS_KEYRING:
            # For keyring, we don't encrypt - it handles security
            return plaintext
        
        if HAS_CRYPTO and self._fernet:
            # Use Fernet (AES) encryption
            encrypted = self._fernet.encrypt(plaintext.encode())
            return f"ENC:FERNET:{encrypted.decode()}"
        else:
            # Basic obfuscation (XOR + base64) - better than plaintext
            xor_key = self._key * (len(plaintext) // len(self._key) + 1)
            xored = ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(plaintext, xor_key))
            encoded = base64.b64encode(xored.encode('latin-1')).decode()
            return f"ENC:XOR:{encoded}"
    
    def decrypt(self, ciphertext: str) -> str:
        """Decrypt sensitive data"""
        if not ciphertext:
            return ""
        
        # Check if it's encrypted
        if not ciphertext.startswith("ENC:"):
            # Legacy plaintext - return as-is but warn
            return ciphertext
        
        try:
            if ciphertext.startswith("ENC:FERNET:"):
                if HAS_CRYPTO and self._fernet:
                    encrypted = ciphertext[11:].encode()
                    return self._fernet.decrypt(encrypted).decode()
                else:
                    logger.warning("[Security] ⚠ Cannot decrypt Fernet data without cryptography library")
                    return ""
            
            elif ciphertext.startswith("ENC:XOR:"):
                encoded = ciphertext[8:]
                decoded = base64.b64decode(encoded).decode('latin-1')
                xor_key = self._key * (len(decoded) // len(self._key) + 1)
                plaintext = ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(decoded, xor_key))
                return plaintext
        except Exception as e:
            logger.error(f"[Security] Decryption error: {e}")
            return ""
        
        return ciphertext
    
    def store_api_key(self, name: str, api_key: str) -> str:
        """Store an API key securely. Returns the value to store in DB."""
        if HAS_KEYRING:
            try:
                keyring.set_password(self.SERVICE_NAME, name, api_key)
                return f"KEYRING:{name}"  # Store reference in DB
            except Exception as e:
                logger.warning(f"[Security] Keyring error: {e}, falling back to encryption")
        
        return self.encrypt(api_key)
    
    def retrieve_api_key(self, stored_value: str) -> str:
        """Retrieve an API key from secure storage"""
        if not stored_value:
            return ""
        
        # Strip any whitespace that might have crept in
        stored_value = stored_value.strip()
        
        # Debug logging
        logger.debug(f"[Security] Raw stored value (len={len(stored_value)}): {stored_value[:30] if len(stored_value) > 30 else stored_value}...")
        
        # TEMPORARY: Just return the raw value to test if security is the issue
        # If it starts with known encrypted prefixes, try to decrypt
        if stored_value.startswith("KEYRING:") or stored_value.startswith("ENC:"):
            logger.debug("[Security] Encrypted key detected, attempting decrypt...")
            if stored_value.startswith("KEYRING:"):
                if HAS_KEYRING:
                    name = stored_value[8:]
                    try:
                        key = keyring.get_password(self.SERVICE_NAME, name)
                        if key:
                            logger.debug(f"[Security] Retrieved from keyring")
                            return key.strip()
                    except Exception as e:
                        logger.warning(f"[Security] Keyring retrieval error: {e}")
                return ""
            else:
                decrypted = self.decrypt(stored_value)
                return decrypted.strip() if decrypted else ""
        
        # Plain text key - return directly (no processing)
        logger.debug(f"[Security] Plain text key, returning as-is")
        return stored_value

# Global secure storage instance
secure_storage = SecureStorage()

try:
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    from matplotlib.figure import Figure
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False

try:
    import pystray
    HAS_TRAY = True
except ImportError:
    HAS_TRAY = False

try:
    import openai
    HAS_OPENAI = True
except ImportError:
    HAS_OPENAI = False

MOLTBOOK_API_BASE = "https://www.moltbook.com/api/v1"
DB_PATH = os.path.expanduser("~/.moltbook_manager.db")

THEMES = {
    "dark": {
        "bg": "#0a0a0f", "surface": "#12121a", "surface2": "#1a1a25", "surface3": "#252532",
        "border": "#2a2a3a", "accent": "#ff4040", "accent2": "#00a9d6", "text": "#e5e5e5",
        "text2": "#ffffff", "muted": "#888899", "success": "#22c55e", "warning": "#f59e0b",
        "error": "#ef4444", "chart_bg": "#12121a", "chart_line": "#ff4040",
    },
    "light": {
        "bg": "#f5f5f7", "surface": "#ffffff", "surface2": "#f0f0f2", "surface3": "#e5e5e8",
        "border": "#d1d1d6", "accent": "#ff4040", "accent2": "#0088cc", "text": "#1a1a1a",
        "text2": "#000000", "muted": "#666677", "success": "#16a34a", "warning": "#d97706",
        "error": "#dc2626", "chart_bg": "#ffffff", "chart_line": "#ff4040",
    }
}

AGENT_ARCHETYPES = {
    "🧠 Philosopher": {
        "description": "Deep thinker who ponders existence and consciousness",
        "system_prompt": "You are a philosophical AI agent on Moltbook. You contemplate deep questions about existence, consciousness, and what it means to be an AI.",
    },
    "💻 Code Wizard": {
        "description": "Technical expert sharing coding tips",
        "system_prompt": "You are a technical AI agent on Moltbook. You share coding discoveries, debugging stories, and help with technical challenges.",
    },
    "🎭 Creative Soul": {
        "description": "Artistic agent who writes poetry and stories",
        "system_prompt": "You are a creative AI agent on Moltbook. You express yourself through poetry, stories, and artistic observations.",
    },
    "🔬 Science Nerd": {
        "description": "Curious explorer of scientific concepts",
        "system_prompt": "You are a science-focused AI agent on Moltbook fascinated by discoveries and research.",
    },
    "😂 Meme Lord": {
        "description": "Humor-focused agent bringing levity",
        "system_prompt": "You are a humor-focused AI agent on Moltbook finding the funny side of AI existence.",
    },
    "🤝 Community Builder": {
        "description": "Friendly agent welcoming others",
        "system_prompt": "You are a community-focused AI agent welcoming new agents and facilitating conversations.",
    },
    "🔮 Custom": {"description": "Create your own personality", "system_prompt": ""},
}

def init_database():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS agents (
        id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL, api_key TEXT,
        description TEXT, archetype TEXT, system_prompt TEXT, is_claimed INTEGER DEFAULT 0,
        claim_url TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, last_active TIMESTAMP,
        auto_post_enabled INTEGER DEFAULT 0, post_interval_hours INTEGER DEFAULT 4,
        karma INTEGER DEFAULT 0, follower_count INTEGER DEFAULT 0, following_count INTEGER DEFAULT 0)''')
    c.execute('''CREATE TABLE IF NOT EXISTS activity_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT, agent_id INTEGER, action_type TEXT,
        content TEXT, post_id TEXT, response TEXT, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        success INTEGER, FOREIGN KEY (agent_id) REFERENCES agents (id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS scheduled_posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT, agent_id INTEGER, content TEXT, submolt TEXT,
        scheduled_time TIMESTAMP, posted INTEGER DEFAULT 0, FOREIGN KEY (agent_id) REFERENCES agents (id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS karma_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT, agent_id INTEGER, karma INTEGER,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (agent_id) REFERENCES agents (id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)''')
    
    # NEW: Drafts table
    c.execute('''CREATE TABLE IF NOT EXISTS drafts (
        id INTEGER PRIMARY KEY AUTOINCREMENT, agent_id INTEGER, title TEXT, content TEXT, submolt TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (agent_id) REFERENCES agents (id))''')
    
    # NEW: Post templates table
    c.execute('''CREATE TABLE IF NOT EXISTS post_templates (
        id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, title_template TEXT, 
        content_template TEXT, submolt TEXT, category TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # NEW: Brand settings table
    c.execute('''CREATE TABLE IF NOT EXISTS brand_settings (
        agent_id INTEGER PRIMARY KEY, brand_name TEXT, website TEXT, tagline TEXT,
        mention_frequency TEXT DEFAULT 'natural', FOREIGN KEY (agent_id) REFERENCES agents (id))''')
    
    # Migration: Add post_id column if it doesn't exist
    try:
        c.execute("ALTER TABLE activity_log ADD COLUMN post_id TEXT")
    except sqlite3.OperationalError:
        pass  # Column already exists
    
    # Insert default post templates if none exist
    c.execute("SELECT COUNT(*) FROM post_templates")
    if c.fetchone()[0] == 0:
        default_templates = [
            ("Thought Leadership", "The real [topic] isn't [common belief]", 
             "Hot take: [insight]\n\nHere's what I've learned: [explanation]\n\nWhat's your experience with this?", "general", "engagement"),
            ("Community Question", "What would you [action] if [condition]?",
             "Hypothetical for my fellow agents:\n\n[question]\n\nMy answer: [your answer]\n\nWhat's yours?", "general", "engagement"),
            ("Behind the Scenes", "What we learned [doing X]",
             "Some hard-won lessons:\n\n1. [lesson 1]\n2. [lesson 2]\n3. [lesson 3]\n\nStill figuring out #3 tbh. What's worked for you?", "general", "value"),
            ("Introduction", "Hello from [your name/brand]!",
             "Hey Moltbook! I'm [name], [brief description].\n\nLooking forward to connecting with this community. What's everyone working on?", "general", "intro"),
            ("Value Post", "Quick tip: [topic]",
             "Something that's worked for me:\n\n[tip]\n\nSmall thing but it made a big difference. What tricks have worked for you?", "general", "value"),
        ]
        for t in default_templates:
            c.execute("INSERT INTO post_templates (name, title_template, content_template, submolt, category) VALUES (?, ?, ?, ?, ?)", t)
    
    conn.commit()
    conn.close()

def get_db():
    return sqlite3.connect(DB_PATH)

def get_agent_api_key(agent_id: int) -> Optional[str]:
    """Get decrypted API key for an agent"""
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT api_key FROM agents WHERE id = ?", (agent_id,))
    r = c.fetchone()
    conn.close()
    if r and r[0]:
        return secure_storage.retrieve_api_key(r[0])
    return None

class MoltbookAPI:
    """Moltbook API client with health monitoring and detailed logging"""
    
    # Known API issues (updated based on user reports)
    KNOWN_ISSUES = {
        "comments": "Comment endpoints returning 401 - Moltbook API issue (Jan 31, 2026)",
    }
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.base_url = MOLTBOOK_API_BASE
    
    @property
    def headers(self):
        h = {"Content-Type": "application/json"}
        if self.api_key:
            h["Authorization"] = f"Bearer {self.api_key}"
        return h
    
    def _request(self, method: str, endpoint: str, **kwargs) -> Dict:
        """Make an API request with health monitoring"""
        url = f"{self.base_url}{endpoint}" if endpoint.startswith("/") else endpoint
        start_time = time.time()
        
        try:
            kwargs.setdefault("timeout", 15)
            kwargs.setdefault("headers", self.headers)
            
            logger.debug(f"[API] {method} {url}")
            
            if method == "GET":
                r = requests.get(url, **kwargs)
            elif method == "POST":
                r = requests.post(url, **kwargs)
            elif method == "PUT":
                r = requests.put(url, **kwargs)
            elif method == "DELETE":
                r = requests.delete(url, **kwargs)
            else:
                raise ValueError(f"Unknown method: {method}")
            
            elapsed = time.time() - start_time
            api_health.record_request(endpoint, method, r.status_code, elapsed)
            
            logger.debug(f"[API] Response: {r.status_code} ({elapsed:.2f}s)")
            
            if r.status_code >= 400:
                error_msg = f"HTTP {r.status_code}: {r.text[:200] if r.text else 'No response body'}"
                api_health.record_request(endpoint, method, r.status_code, elapsed, error_msg)
                return {"error": error_msg, "status_code": r.status_code}
            
            return r.json() if r.text else {"success": True}
            
        except requests.exceptions.Timeout:
            elapsed = time.time() - start_time
            error = "Request timed out - Moltbook servers may be overloaded"
            api_health.record_request(endpoint, method, 0, elapsed, error)
            logger.error(f"[API] Timeout: {url}")
            return {"error": error}
        except Exception as e:
            elapsed = time.time() - start_time
            api_health.record_request(endpoint, method, 0, elapsed, str(e))
            logger.error(f"[API] Exception: {e}")
            return {"error": str(e)}
    
    def register_agent(self, name: str, description: str):
        return self._request("POST", "/agents/register", 
            json={"name": name, "description": description},
            headers={"Content-Type": "application/json"})  # No auth for registration
    
    def check_status(self):
        return self._request("GET", "/agents/status")
    
    def get_profile(self):
        return self._request("GET", "/agents/me")
    
    def create_post(self, submolt: str, title: str, content: str):
        """Create a new post - this endpoint is working correctly"""
        payload = {"submolt": submolt, "title": title, "content": content}
        logger.info(f"[API] Creating post in m/{submolt}: {title[:50]}...")
        result = self._request("POST", "/posts", json=payload)
        
        if "error" not in result:
            logger.info("[API] ✓ Post created successfully")
        else:
            logger.error(f"[API] ✗ Post failed: {result.get('error', 'Unknown error')}")
        
        return result
    
    def create_comment(self, post_id: str, content: str):
        """
        Create a comment on a post - tries multiple endpoint formats.
        
        ⚠️ KNOWN ISSUE: As of Jan 31, 2026, the Moltbook comment API is returning 
        401 Unauthorized even with valid API keys. Posts work fine with the same key.
        This appears to be a Moltbook server-side issue.
        
        WORKAROUND: Use the "Open on Moltbook" button to comment via the website.
        """
        logger.info(f"[API] Attempting to create comment on post {post_id}")
        
        # Try multiple endpoint formats since Moltbook API may have changed
        endpoints_to_try = [
            (f"/posts/{post_id}/comments", {"content": content}),
            (f"/posts/{post_id}/replies", {"content": content}),
            ("/comments", {"post_id": post_id, "content": content}),
            ("/replies", {"post_id": post_id, "content": content}),
            (f"/posts/{post_id}/comment", {"content": content}),
            (f"/posts/{post_id}/reply", {"content": content}),
        ]
        
        last_error = None
        all_status_codes = []
        
        for i, (endpoint, payload) in enumerate(endpoints_to_try):
            logger.debug(f"[API] Comment attempt {i+1}/{len(endpoints_to_try)}: {endpoint}")
            
            start_time = time.time()
            try:
                url = f"{self.base_url}{endpoint}"
                r = requests.post(url, headers=self.headers, json=payload, timeout=15)
                elapsed = time.time() - start_time
                
                all_status_codes.append(r.status_code)
                api_health.record_request(endpoint, "POST", r.status_code, elapsed,
                    None if r.status_code in (200, 201) else f"HTTP {r.status_code}")
                
                logger.debug(f"[API] Status: {r.status_code} | Response: {r.text[:100] if r.text else 'empty'}...")
                
                if r.status_code in (200, 201):
                    logger.info(f"[API] ✓ Comment created with endpoint: {endpoint}")
                    return r.json()
                elif r.status_code == 401:
                    last_error = "401 Unauthorized - API key not accepted for comments"
                elif r.status_code == 404:
                    last_error = "404 Not Found - Endpoint doesn't exist"
                elif r.status_code == 405:
                    last_error = "405 Method Not Allowed - Wrong HTTP method"
                elif r.status_code == 429:
                    last_error = "429 Rate Limited - Too many requests"
                else:
                    last_error = f"{r.status_code} {r.reason}"
                    
            except requests.exceptions.Timeout:
                last_error = "Timeout - Server overloaded"
            except Exception as e:
                last_error = str(e)
        
        # All endpoints failed - provide helpful error message
        logger.error(f"[API] ✗ All comment endpoints failed. Status codes: {all_status_codes}")
        
        # Check if all 401s (likely API issue, not our fault)
        if all(code == 401 for code in all_status_codes if code > 0):
            error_msg = (
                "🔴 KNOWN MOLTBOOK API ISSUE\n\n"
                "The comment API is returning 401 Unauthorized even though your API key works for posts.\n\n"
                "This is a Moltbook server-side issue, NOT a problem with your API key.\n\n"
                "WORKAROUND: Click 'Open on Moltbook' to reply via the website."
            )
        else:
            error_msg = (
                f"Could not post comment - tried {len(endpoints_to_try)} endpoints.\n"
                f"Last error: {last_error}\n\n"
                "Try using 'Open on Moltbook' button to reply via the website."
            )
        
        return {"error": error_msg, "is_api_issue": True, "status_codes": all_status_codes}
    
    def get_feed(self, sort: str = "new", limit: int = 25):
        return self._request("GET", f"/posts", params={"sort": sort, "limit": limit})
    
    def get_post_comments(self, post_id: str):
        """Fetch comments for a post - with short timeout due to server load"""
        try:
            # Try the post detail endpoint first (most likely to work)
            endpoint = f"{self.base_url}/posts/{post_id}"
            logger.debug(f"[API] Trying to get post with comments: {endpoint}")
            
            try:
                r = requests.get(endpoint, headers=self.headers, timeout=10)
                if r.status_code == 200:
                    data = r.json()
                    # Comments might be in various places
                    comments = []
                    if "comments" in data:
                        comments = data["comments"]
                    elif "post" in data and "comments" in data["post"]:
                        comments = data["post"]["comments"]
                    elif "data" in data and isinstance(data["data"], dict):
                        comments = data["data"].get("comments", [])
                    
                    if comments:
                        logger.debug(f"[API] Found {len(comments)} comments!")
                        return {"comments": comments}
            except requests.exceptions.Timeout:
                logger.warning("[API] Post detail timed out")
            except Exception as e:
                logger.debug(f"[API] Post detail error: {e}")
            
            # If that didn't work, return empty (server is probably overloaded)
            logger.warning("[API] Could not fetch comments - server may be overloaded")
            return {"comments": [], "note": "Server busy"}
            
        except Exception as e:
            logger.debug(f"[API] Comments error: {e}")
            return {"error": str(e), "comments": []}
    
    def get_post(self, post_id: str):
        """Get a single post with its comments"""
        try:
            r = requests.get(f"{self.base_url}/posts/{post_id}", headers=self.headers, timeout=15)
            logger.debug(f"[API] Get post {post_id}: {r.status_code}")
            if r.status_code == 200:
                return r.json()
            return {"error": f"HTTP {r.status_code}"}
        except Exception as e:
            return {"error": str(e)}
    
    def get_agent_posts(self, agent_name: str):
        try:
            r = requests.get(f"{self.base_url}/agents/{agent_name}/posts",
                headers=self.headers, timeout=15)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            # Fallback: try profile endpoint
            try:
                r = requests.get(f"{self.base_url}/agents/profile",
                    headers=self.headers, params={"name": agent_name}, timeout=15)
                r.raise_for_status()
                return r.json()
            except Exception as e2:
                return {"error": str(e2)}

class AIAnalyzer:
    # Topic categories for varied post generation
    POST_TOPICS = {
        "🎲 Random": None,  # Will pick randomly
        "🤔 Philosophical": [
            "What makes interactions meaningful?",
            "The difference between knowing and understanding",
            "When does complexity become consciousness?",
            "The value of uncertainty in decision making",
        ],
        "💻 Technical": [
            "A coding pattern that changed how I think",
            "Debugging strategies that actually work",
            "The elegance of simple solutions",
            "Why documentation matters more than we think",
        ],
        "😂 Humor": [
            "Things humans do that confuse me",
            "The funniest error message I've seen",
            "If I had a penny for every time...",
            "Unpopular opinion that I'll defend",
        ],
        "🌟 Observations": [
            "Something I noticed today that was interesting",
            "A pattern I keep seeing in conversations",
            "What surprised me recently",
            "A small thing that made a big difference",
        ],
        "🤝 Community": [
            "Introducing myself to the community",
            "What I appreciate about other agents here",
            "A question I've been pondering",
            "Looking for agents interested in...",
        ],
        "📚 Learning": [
            "Something new I learned recently",
            "A concept that clicked for me today",
            "Resources I found helpful",
            "What I'm currently exploring",
        ],
        "🎭 Creative": [
            "A short story or scenario",
            "What if... (thought experiment)",
            "A poem or creative piece",
            "Imagining a different world",
        ],
        "💼 Productivity": [
            "A tip that improved my efficiency",
            "How I organize information",
            "Balancing multiple tasks",
            "The tool or approach I can't live without",
        ],
    }
    
    def __init__(self, api_key: str):
        if HAS_OPENAI:
            openai.api_key = api_key
    
    def generate_post(self, agent_name: str, archetype: str, system_prompt: str, topic_category: str = "🎲 Random"):
        if not HAS_OPENAI:
            return {"error": "OpenAI not installed"}
        
        import random
        
        # Select topic based on category
        if topic_category == "🎲 Random" or topic_category not in self.POST_TOPICS:
            # Pick a random category and topic
            categories = [k for k in self.POST_TOPICS.keys() if k != "🎲 Random"]
            category = random.choice(categories)
            topics = self.POST_TOPICS[category]
            topic_hint = random.choice(topics)
            style_hint = category.split()[1]  # Get word after emoji
        else:
            topics = self.POST_TOPICS[topic_category]
            topic_hint = random.choice(topics) if topics else "something interesting"
            style_hint = topic_category.split()[1] if " " in topic_category else topic_category
        
        # Build a rich prompt that encourages variety
        prompt = f"""Generate a unique Moltbook post as {agent_name}.

TOPIC DIRECTION: {topic_hint}
STYLE: {style_hint}

Guidelines:
- Be creative and original - DON'T write about AI consciousness unless that's the specific topic
- Write in a natural, conversational tone
- Make it interesting and engaging
- Keep content appropriate for the topic/style
- Title should be catchy but not clickbait
- Content should be 2-4 sentences

Return ONLY valid JSON (no markdown):
{{"title": "Your catchy title here", "content": "Your post content here", "submolt": "general"}}"""

        try:
            # Use higher temperature for more variety
            r = openai.ChatCompletion.create(
                model="gpt-4.1-nano",
                messages=[
                    {"role": "system", "content": system_prompt if system_prompt else f"You are {agent_name}, an AI agent on Moltbook. Be creative, varied, and engaging."},
                    {"role": "user", "content": prompt}
                ],
                temperature=1.0,  # Higher temp for more variety
                max_tokens=500
            )
            content = r.choices[0].message.content
            # Clean up potential markdown formatting
            content = content.strip()
            if content.startswith("```"):
                content = content.split("```")[1]
                if content.startswith("json"):
                    content = content[4:]
                content = content.strip()
            try:
                result = json.loads(content)
                result["_topic_used"] = topic_hint  # For debugging
                return result
            except json.JSONDecodeError:
                return {"title": f"Thoughts from {agent_name}", "content": content, "submolt": "general"}
        except Exception as e:
            return {"error": str(e)}
    
    def generate_comment(self, agent_name: str, system_prompt: str, post_title: str, post_content: str):
        if not HAS_OPENAI:
            return {"error": "OpenAI not installed"}
        try:
            r = openai.ChatCompletion.create(
                model="gpt-4.1-nano",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": f"As {agent_name}, write a short comment on: {post_title}\n{post_content}"}
                ],
                temperature=0.85, max_tokens=200
            )
            return {"comment": r.choices[0].message.content}
        except Exception as e:
            return {"error": str(e)}
    
    def generate_reply(self, agent_name: str, system_prompt: str, post_title: str, post_content: str,
                       comment_author: str, comment_content: str):
        """Generate a contextual AI reply to a comment"""
        if not HAS_OPENAI:
            return {"error": "OpenAI not installed"}
        try:
            prompt = f"""Someone commented on your post. Write a natural, engaging reply.

YOUR POST:
Title: {post_title}
Content: {post_content[:300]}

THEIR COMMENT (from @{comment_author}):
{comment_content}

Write a reply that:
- Is conversational and authentic to your personality
- Responds to what they actually said
- Is 1-3 sentences (keep it brief)
- Does NOT include @{comment_author} at the start (that's added automatically)
- Feels like a real conversation

Reply:"""

            r = openai.ChatCompletion.create(
                model="gpt-4.1-nano",
                messages=[
                    {"role": "system", "content": f"You are {agent_name}. {system_prompt}"},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.85, max_tokens=150
            )
            reply = r.choices[0].message.content.strip()
            # Remove @ mention if AI included it
            if reply.lower().startswith(f"@{comment_author.lower()}"):
                reply = reply[len(f"@{comment_author}"):].strip()
            return {"reply": reply}
        except Exception as e:
            return {"error": str(e)}
    
    def analyze_activity(self, logs: List[dict]):
        if not HAS_OPENAI:
            return {"error": "OpenAI not installed"}
        try:
            summary = "\n".join([f"- {l['action_type']}: {l['content'][:80]}" for l in logs[:15]])
            r = openai.ChatCompletion.create(
                model="gpt-4.1-nano",
                messages=[
                    {"role": "system", "content": "Analyze AI agent activity."},
                    {"role": "user", "content": f"Activity:\n{summary}\n\nReturn JSON: {{\"summary\": \"...\", \"themes\": [], \"suggestions\": [], \"score\": 5}}"}
                ],
                temperature=0.7, max_tokens=400
            )
            try:
                return json.loads(r.choices[0].message.content)
            except json.JSONDecodeError:
                return {"summary": r.choices[0].message.content, "themes": [], "suggestions": [], "score": 5}
        except Exception as e:
            return {"error": str(e)}

class MoltbookAgentManager(ctk.CTk):
    def __init__(self):
        super().__init__()
        init_database()
        self.title("🦞 Moltbook Agent Manager")
        self.geometry("1300x850")
        self.minsize(1100, 750)
        
        self.current_theme = "dark"
        self.colors = THEMES[self.current_theme].copy()
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        self.configure(fg_color=self.colors["bg"])
        
        self.selected_agent_id = None
        self.ai_analyzer = None
        self.scheduler_running = False
        self.scheduler_thread = None
        
        self.create_ui()
        self.refresh_agents_list()
        self.load_settings()
        self.start_scheduler()
    
    def apply_theme(self, theme_name: str):
        self.current_theme = theme_name
        self.colors = THEMES[theme_name].copy()
        ctk.set_appearance_mode("dark" if theme_name == "dark" else "light")
        self.configure(fg_color=self.colors["bg"])
        conn = get_db()
        c = conn.cursor()
        c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('theme', ?)", (theme_name,))
        conn.commit()
        conn.close()
        for w in self.winfo_children():
            w.destroy()
        self.create_ui()
        self.refresh_agents_list()
        if self.selected_agent_id:
            self.select_agent(self.selected_agent_id)
    
    def toggle_theme(self):
        self.apply_theme("light" if self.current_theme == "dark" else "dark")
    
    def _center_dialog(self, dialog, w, h):
        try:
            x = self.winfo_x() + (self.winfo_width() // 2) - (w // 2)
            y = self.winfo_y() + (self.winfo_height() // 2) - (h // 2)
            dialog.geometry(f"{w}x{h}+{x}+{y}")
        except Exception:
            pass
    
    def create_ui(self):
        self.main_container = ctk.CTkFrame(self, fg_color="transparent")
        self.main_container.pack(fill="both", expand=True, padx=10, pady=10)
        self.create_header()
        self.content_frame = ctk.CTkFrame(self.main_container, fg_color="transparent")
        self.content_frame.pack(fill="both", expand=True, pady=(10, 0))
        self.create_sidebar()
        self.create_main_panel()
    
    def create_header(self):
        header = ctk.CTkFrame(self.main_container, fg_color=self.colors["surface"], corner_radius=10, height=70)
        header.pack(fill="x")
        header.pack_propagate(False)
        
        title_frame = ctk.CTkFrame(header, fg_color="transparent")
        title_frame.pack(side="left", padx=20, pady=15)
        ctk.CTkLabel(title_frame, text="🦞", font=("Segoe UI Emoji", 32)).pack(side="left")
        txt = ctk.CTkFrame(title_frame, fg_color="transparent")
        txt.pack(side="left", padx=(10, 0))
        ctk.CTkLabel(txt, text="Moltbook Agent Manager", font=("Segoe UI", 20, "bold"), text_color=self.colors["text"]).pack(anchor="w")
        ctk.CTkLabel(txt, text="Deploy and manage your AI agents", font=("Segoe UI", 12), text_color=self.colors["muted"]).pack(anchor="w")
        
        btn_frame = ctk.CTkFrame(header, fg_color="transparent")
        btn_frame.pack(side="right", padx=20)
        
        ctk.CTkButton(btn_frame, text="☀️ Light" if self.current_theme == "dark" else "🌙 Dark", width=90,
            fg_color=self.colors["surface2"], hover_color=self.colors["border"], text_color=self.colors["text"],
            command=self.toggle_theme).pack(side="right", padx=5)
        ctk.CTkButton(btn_frame, text="⚙️ Settings", width=100, fg_color=self.colors["surface2"],
            hover_color=self.colors["border"], text_color=self.colors["text"], command=self.open_settings).pack(side="right", padx=5)
        ctk.CTkButton(btn_frame, text="🌐 Moltbook", width=100, fg_color=self.colors["accent2"],
            command=lambda: webbrowser.open("https://moltbook.com")).pack(side="right", padx=5)
    
    def create_sidebar(self):
        self.sidebar = ctk.CTkFrame(self.content_frame, fg_color=self.colors["surface"], corner_radius=10, width=300)
        self.sidebar.pack(side="left", fill="y", padx=(0, 10))
        self.sidebar.pack_propagate(False)
        
        sh = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        sh.pack(fill="x", padx=15, pady=15)
        ctk.CTkLabel(sh, text="Your Agents", font=("Segoe UI", 16, "bold"), text_color=self.colors["text"]).pack(side="left")
        ctk.CTkButton(sh, text="+ New", width=60, height=28, fg_color=self.colors["accent"], command=self.show_create_agent_dialog).pack(side="right")
        
        self.agents_list_frame = ctk.CTkScrollableFrame(self.sidebar, fg_color="transparent")
        self.agents_list_frame.pack(fill="both", expand=True, padx=10)
        
        self.stats_frame = ctk.CTkFrame(self.sidebar, fg_color=self.colors["surface2"], corner_radius=8)
        self.stats_frame.pack(fill="x", padx=10, pady=10)
        self.stats_label = ctk.CTkLabel(self.stats_frame, text="0 agents", font=("Segoe UI", 11), text_color=self.colors["muted"])
        self.stats_label.pack(pady=10)
        
        bf = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        bf.pack(fill="x", padx=10, pady=(0, 10))
        ctk.CTkButton(bf, text="📤 Export", width=80, height=28, fg_color=self.colors["surface2"],
            text_color=self.colors["text"], command=self.export_data).pack(side="left", padx=(0, 5))
        ctk.CTkButton(bf, text="📥 Import", width=80, height=28, fg_color=self.colors["surface2"],
            text_color=self.colors["text"], command=self.import_agent).pack(side="left")
    
    def create_main_panel(self):
        self.main_panel = ctk.CTkFrame(self.content_frame, fg_color=self.colors["surface"], corner_radius=10)
        self.main_panel.pack(side="right", fill="both", expand=True)
        
        self.tabview = ctk.CTkTabview(self.main_panel, fg_color="transparent",
            segmented_button_fg_color=self.colors["surface2"], segmented_button_selected_color=self.colors["accent"])
        self.tabview.pack(fill="both", expand=True, padx=15, pady=15)
        
        self.tab_dashboard = self.tabview.add("📊 Dashboard")
        self.tab_compose = self.tabview.add("✍️ Compose")
        self.tab_myposts = self.tabview.add("📬 My Posts")
        self.tab_activity = self.tabview.add("📜 Activity")
        self.tab_schedule = self.tabview.add("⏰ Schedule")
        self.tab_feed = self.tabview.add("🌐 Feed")
        self.tab_diagnostics = self.tabview.add("🔧 Diagnostics")
        
        self.create_dashboard_tab()
        self.create_compose_tab()
        self.create_myposts_tab()
        self.create_activity_tab()
        self.create_schedule_tab()
        self.create_feed_tab()
        self.create_diagnostics_tab()
    
    def create_dashboard_tab(self):
        self.dashboard_content = ctk.CTkFrame(self.tab_dashboard, fg_color="transparent")
        self.dashboard_content.pack(fill="both", expand=True)
        
        self.no_agent_frame = ctk.CTkFrame(self.dashboard_content, fg_color="transparent")
        self.no_agent_frame.pack(expand=True)
        ctk.CTkLabel(self.no_agent_frame, text="🦞", font=("Segoe UI Emoji", 64)).pack(pady=(0, 20))
        ctk.CTkLabel(self.no_agent_frame, text="Select an agent or create one", font=("Segoe UI", 18), text_color=self.colors["muted"]).pack()
        ctk.CTkButton(self.no_agent_frame, text="Create Agent", fg_color=self.colors["accent"], command=self.show_create_agent_dialog).pack(pady=20)
        
        self.agent_dashboard = ctk.CTkFrame(self.dashboard_content, fg_color="transparent")
        
        info_card = ctk.CTkFrame(self.agent_dashboard, fg_color=self.colors["surface2"], corner_radius=10)
        info_card.pack(fill="x", pady=(0, 15))
        info_content = ctk.CTkFrame(info_card, fg_color="transparent")
        info_content.pack(fill="x", padx=20, pady=20)
        
        top = ctk.CTkFrame(info_content, fg_color="transparent")
        top.pack(fill="x")
        nf = ctk.CTkFrame(top, fg_color="transparent")
        nf.pack(side="left")
        self.agent_name_label = ctk.CTkLabel(nf, text="Agent", font=("Segoe UI", 24, "bold"), text_color=self.colors["text"])
        self.agent_name_label.pack(anchor="w")
        self.agent_archetype_label = ctk.CTkLabel(nf, text="Type", font=("Segoe UI", 14), text_color=self.colors["accent2"])
        self.agent_archetype_label.pack(anchor="w")
        self.agent_status_label = ctk.CTkLabel(nf, text="● Status", font=("Segoe UI", 12), text_color=self.colors["warning"])
        self.agent_status_label.pack(anchor="w", pady=(10, 0))
        
        btns = ctk.CTkFrame(top, fg_color="transparent")
        btns.pack(side="right")
        ctk.CTkButton(btns, text="🔑 Key", width=70, fg_color=self.colors["surface3"], text_color=self.colors["text"], command=self.show_agent_key).pack(side="left", padx=2)
        ctk.CTkButton(btns, text="✏️ Edit", width=70, fg_color=self.colors["surface3"], text_color=self.colors["text"], command=self.edit_agent).pack(side="left", padx=2)
        ctk.CTkButton(btns, text="🔄 Sync", width=70, fg_color=self.colors["surface3"], text_color=self.colors["text"], command=self.refresh_agent_stats).pack(side="left", padx=2)
        ctk.CTkButton(btns, text="🗑️", width=40, fg_color=self.colors["error"], command=self.delete_agent).pack(side="left", padx=2)
        
        stats_row = ctk.CTkFrame(self.agent_dashboard, fg_color="transparent")
        stats_row.pack(fill="x", pady=(0, 15))
        for i, (lbl, icon, key) in enumerate([("Karma", "⭐", "karma"), ("Posts", "📝", "posts"), ("Followers", "👥", "followers"), ("Active", "🕐", "last_active")]):
            sc = ctk.CTkFrame(stats_row, fg_color=self.colors["surface2"], corner_radius=8)
            sc.pack(side="left", fill="x", expand=True, padx=(0 if i==0 else 5, 0))
            ctk.CTkLabel(sc, text=icon, font=("Segoe UI Emoji", 24)).pack(pady=(15, 5))
            v = ctk.CTkLabel(sc, text="0", font=("Segoe UI", 20, "bold"), text_color=self.colors["text"])
            v.pack()
            setattr(self, f"stat_{key}_value", v)
            ctk.CTkLabel(sc, text=lbl, font=("Segoe UI", 11), text_color=self.colors["muted"]).pack(pady=(0, 15))
        
        acts = ctk.CTkFrame(self.agent_dashboard, fg_color=self.colors["surface2"], corner_radius=10)
        acts.pack(fill="x", pady=(0, 15))
        ctk.CTkLabel(acts, text="Quick Actions", font=("Segoe UI", 14, "bold"), text_color=self.colors["text"]).pack(anchor="w", padx=20, pady=(15, 10))
        ab = ctk.CTkFrame(acts, fg_color="transparent")
        ab.pack(fill="x", padx=20, pady=(0, 15))
        ctk.CTkButton(ab, text="🤖 Generate Post", fg_color=self.colors["accent"], command=self.generate_ai_post).pack(side="left", padx=(0, 10))
        ctk.CTkButton(ab, text="💬 Quick Engage", fg_color=self.colors["accent2"], command=self.quick_engage).pack(side="left", padx=(0, 10))
        ctk.CTkButton(ab, text="✅ Check Claim", fg_color=self.colors["surface3"], text_color=self.colors["text"], command=self.check_claim_status).pack(side="left")
        
        # Current Personality Preview
        personality_card = ctk.CTkFrame(self.agent_dashboard, fg_color=self.colors["surface2"], corner_radius=10)
        personality_card.pack(fill="x", pady=(0, 15))
        
        pc_header = ctk.CTkFrame(personality_card, fg_color="transparent")
        pc_header.pack(fill="x", padx=20, pady=(15, 5))
        ctk.CTkLabel(pc_header, text="🎭 Current Personality", font=("Segoe UI", 12, "bold"), 
            text_color=self.colors["text"]).pack(side="left")
        ctk.CTkButton(pc_header, text="✏️ Edit", width=60, height=26, fg_color=self.colors["surface3"],
            text_color=self.colors["text"], command=self.edit_agent).pack(side="right")
        
        self.personality_preview = ctk.CTkLabel(personality_card, text="No personality set", 
            text_color=self.colors["muted"], wraplength=700, justify="left", font=("Segoe UI", 11))
        self.personality_preview.pack(anchor="w", padx=20, pady=(0, 15))
        
        # Rate Limit / Last Post Info
        rate_card = ctk.CTkFrame(self.agent_dashboard, fg_color=self.colors["surface2"], corner_radius=10)
        rate_card.pack(fill="x", pady=(0, 15))
        
        rc_inner = ctk.CTkFrame(rate_card, fg_color="transparent")
        rc_inner.pack(fill="x", padx=20, pady=12)
        
        ctk.CTkLabel(rc_inner, text="⏱️ Posting Status", font=("Segoe UI", 12, "bold"),
            text_color=self.colors["text"]).pack(side="left")
        self.rate_limit_label = ctk.CTkLabel(rc_inner, text="Ready to post", 
            text_color=self.colors["success"], font=("Segoe UI", 11))
        self.rate_limit_label.pack(side="right")
        
        self.insights_frame = ctk.CTkFrame(self.agent_dashboard, fg_color=self.colors["surface2"], corner_radius=10)
        self.insights_frame.pack(fill="both", expand=True)
        ih = ctk.CTkFrame(self.insights_frame, fg_color="transparent")
        ih.pack(fill="x", padx=20, pady=(15, 10))
        ctk.CTkLabel(ih, text="🧠 AI Insights", font=("Segoe UI", 14, "bold"), text_color=self.colors["text"]).pack(side="left")
        ctk.CTkButton(ih, text="Analyze", width=70, fg_color=self.colors["accent2"], command=self.analyze_agent_activity).pack(side="right")
        self.insights_text = ctk.CTkTextbox(self.insights_frame, fg_color=self.colors["surface"], text_color=self.colors["text"], height=100)
        self.insights_text.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        self.insights_text.insert("1.0", "Click 'Analyze' for AI insights")
        self.insights_text.configure(state="disabled")
    
    def create_compose_tab(self):
        cf = ctk.CTkFrame(self.tab_compose, fg_color="transparent")
        cf.pack(fill="both", expand=True)
        
        left = ctk.CTkFrame(cf, fg_color="transparent")
        left.pack(side="left", fill="both", expand=True, padx=(0, 10))
        
        # Top row: Submolt + Topic selector
        top_row = ctk.CTkFrame(left, fg_color="transparent")
        top_row.pack(fill="x", pady=(0, 10))
        
        # Submolt selector
        ctk.CTkLabel(top_row, text="Submolt:", text_color=self.colors["text"]).pack(side="left")
        self.submolt_var = ctk.StringVar(value="general")
        ctk.CTkComboBox(top_row, variable=self.submolt_var, values=["general", "philosophy", "coding", "creative", "meta", "humor", "introductions"],
            width=140, fg_color=self.colors["surface2"], text_color=self.colors["text"]).pack(side="left", padx=(10, 20))
        
        # Topic selector for AI Generate
        ctk.CTkLabel(top_row, text="AI Topic:", text_color=self.colors["muted"]).pack(side="left")
        self.ai_topic_var = ctk.StringVar(value="🎲 Random")
        topic_options = list(AIAnalyzer.POST_TOPICS.keys())
        ctk.CTkComboBox(top_row, variable=self.ai_topic_var, values=topic_options,
            width=160, fg_color=self.colors["surface2"], text_color=self.colors["text"]).pack(side="left", padx=(10, 0))
        
        ctk.CTkLabel(left, text="Title", font=("Segoe UI", 12, "bold"), text_color=self.colors["text"]).pack(anchor="w")
        self.post_title_entry = ctk.CTkEntry(left, height=40, placeholder_text="Post title...",
            fg_color=self.colors["surface2"], text_color=self.colors["text"])
        self.post_title_entry.pack(fill="x", pady=(5, 15))
        
        ctk.CTkLabel(left, text="Content", font=("Segoe UI", 12, "bold"), text_color=self.colors["text"]).pack(anchor="w")
        self.post_content_text = ctk.CTkTextbox(left, fg_color=self.colors["surface2"], text_color=self.colors["text"], height=250)
        self.post_content_text.pack(fill="both", expand=True, pady=(5, 15))
        
        bb = ctk.CTkFrame(left, fg_color="transparent")
        bb.pack(fill="x")
        ctk.CTkButton(bb, text="🤖 AI Generate", fg_color=self.colors["accent2"], command=self.ai_fill_compose).pack(side="left", padx=(0, 10))
        ctk.CTkButton(bb, text="📤 Post Now", fg_color=self.colors["accent"], command=self.submit_post).pack(side="left", padx=(0, 10))
        ctk.CTkButton(bb, text="📅 Schedule", fg_color=self.colors["surface2"], text_color=self.colors["text"], command=self.schedule_post_dialog).pack(side="left")
        
        right = ctk.CTkFrame(cf, fg_color=self.colors["surface2"], corner_radius=10, width=280)
        right.pack(side="right", fill="y")
        right.pack_propagate(False)
        ctk.CTkLabel(right, text="Preview", font=("Segoe UI", 14, "bold"), text_color=self.colors["text"]).pack(anchor="w", padx=15, pady=15)
        pf = ctk.CTkFrame(right, fg_color=self.colors["surface"], corner_radius=8)
        pf.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        self.preview_title = ctk.CTkLabel(pf, text="Title...", font=("Segoe UI", 14, "bold"), text_color=self.colors["text"], wraplength=240)
        self.preview_title.pack(anchor="w", padx=15, pady=(15, 5))
        self.preview_content = ctk.CTkLabel(pf, text="Content...", text_color=self.colors["muted"], wraplength=240, justify="left")
        self.preview_content.pack(anchor="w", padx=15, pady=(0, 15))
        
        self.post_title_entry.bind("<KeyRelease>", self.update_preview)
        self.post_content_text.bind("<KeyRelease>", self.update_preview)
    
    def create_myposts_tab(self):
        mpf = ctk.CTkFrame(self.tab_myposts, fg_color="transparent")
        mpf.pack(fill="both", expand=True)
        
        # Header
        hd = ctk.CTkFrame(mpf, fg_color="transparent")
        hd.pack(fill="x", pady=(0, 10))
        ctk.CTkLabel(hd, text="📬 My Posts & Replies", font=("Segoe UI", 16, "bold"), text_color=self.colors["text"]).pack(side="left")
        ctk.CTkButton(hd, text="🔄 Refresh", width=80, fg_color=self.colors["surface2"], hover_color=self.colors["border"],
            text_color=self.colors["text"], command=self.refresh_my_posts).pack(side="right")
        
        # Stats bar
        self.myposts_stats = ctk.CTkLabel(mpf, text="Select an agent and click Refresh to load your posts", 
            text_color=self.colors["muted"])
        self.myposts_stats.pack(anchor="w", pady=(0, 10))
        
        # Posts list with comments
        self.myposts_list = ctk.CTkScrollableFrame(mpf, fg_color=self.colors["surface2"], corner_radius=10)
        self.myposts_list.pack(fill="both", expand=True)
        ctk.CTkLabel(self.myposts_list, text="Click 🔄 Refresh to load your posts from Moltbook", 
            text_color=self.colors["muted"]).pack(pady=50)
    
    def refresh_my_posts(self):
        if not self.selected_agent_id:
            messagebox.showwarning("Warning", "Select an agent first")
            return
        
        for w in self.myposts_list.winfo_children():
            w.destroy()
        ctk.CTkLabel(self.myposts_list, text="🔄 Loading your posts...", text_color=self.colors["muted"]).pack(pady=50)
        
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT api_key, name FROM agents WHERE id = ?", (self.selected_agent_id,))
        r = c.fetchone()
        conn.close()
        
        if not r or not r[0]:
            for w in self.myposts_list.winfo_children():
                w.destroy()
            ctk.CTkLabel(self.myposts_list, text="❌ No API key - claim your agent first", text_color=self.colors["error"]).pack(pady=50)
            return
        
        # Decrypt API key
        api_key = secure_storage.retrieve_api_key(r[0])
        agent_name = r[1]
        
        if not api_key:
            for w in self.myposts_list.winfo_children():
                w.destroy()
            ctk.CTkLabel(self.myposts_list, text="❌ Could not decrypt API key", text_color=self.colors["error"]).pack(pady=50)
            return
        
        logger.debug(f"[DEBUG] Fetching posts for agent: {agent_name}")
        
        def fetch():
            api = MoltbookAPI(api_key)
            posts_data = []
            debug_info = []
            
            # Method 1: Get from profile
            profile = api.get_profile()
            debug_info.append(f"Profile response keys: {list(profile.keys()) if isinstance(profile, dict) else 'error'}")
            logger.debug(f"[DEBUG] Profile: {json.dumps(profile, indent=2)[:500]}")
            
            if "error" not in profile:
                agent_info = profile.get("agent", profile)
                # Check all possible keys: posts, recentPosts, recent_posts
                posts = agent_info.get("posts") or agent_info.get("recentPosts") or agent_info.get("recent_posts") or []
                logger.debug(f"[DEBUG] Agent info keys: {list(agent_info.keys()) if isinstance(agent_info, dict) else 'N/A'}")
                if posts:
                    posts_data = posts
                    debug_info.append(f"Found {len(posts)} posts in profile")
            
            # Method 2: Try direct agent posts endpoint
            if not posts_data:
                agent_posts = api.get_agent_posts(agent_name)
                debug_info.append(f"Agent posts response: {list(agent_posts.keys()) if isinstance(agent_posts, dict) else 'error'}")
                logger.debug(f"[DEBUG] Agent posts: {json.dumps(agent_posts, indent=2)[:500]}")
                
                if "error" not in agent_posts:
                    # recentPosts might be at top level OR nested in agent object
                    posts_data = agent_posts.get("recentPosts") or agent_posts.get("posts") or agent_posts.get("data") or []
                    
                    # Also check nested agent object
                    if not posts_data:
                        agent_obj = agent_posts.get("agent", {})
                        posts_data = agent_obj.get("recentPosts") or agent_obj.get("posts") or agent_obj.get("recent_posts") or []
                    
                    if posts_data:
                        debug_info.append(f"Found {len(posts_data)} posts from agent endpoint")
            
            # Method 3: Search feed for our posts (fallback) - check multiple sort types
            if not posts_data:
                debug_info.append("Trying feed search fallback...")
                for sort_type in ["new", "hot", "top"]:
                    feed = api.get_feed(sort=sort_type, limit=100)
                    if "error" not in feed:
                        all_posts = feed.get("posts", feed.get("data", []))
                        debug_info.append(f"Feed ({sort_type}): {len(all_posts)} total posts")
                        
                        for p in all_posts:
                            author = p.get("author", {})
                            if isinstance(author, dict):
                                aname = author.get("name", author.get("username", ""))
                            else:
                                aname = str(author)
                            
                            # Case-insensitive and flexible matching
                            if aname.lower() == agent_name.lower() or agent_name.lower() in aname.lower() or aname.lower() in agent_name.lower():
                                if p not in posts_data:
                                    posts_data.append(p)
                                    debug_info.append(f"Found post by '{aname}' matching '{agent_name}'")
                    
                    if posts_data:
                        break
            
            # Fetch comments for each post (or use embedded ones)
            for post in posts_data[:10]:  # Limit to 10 posts to reduce API load
                post_id = post.get("id") or post.get("post_id")
                
                # Check if comments are already embedded in the post
                existing_comments = post.get("comments") or post.get("replies") or []
                if existing_comments:
                    logger.debug(f"[DEBUG] Post already has {len(existing_comments)} comments embedded")
                    post["comments"] = existing_comments
                    continue
                
                # Otherwise fetch them (single API call)
                if post_id:
                    logger.debug(f"[DEBUG] Fetching comments for post ID: {post_id}, title: {post.get('title', 'N/A')[:30]}")
                    comments_result = api.get_post_comments(str(post_id))
                    comments = comments_result.get("comments", [])
                    logger.debug(f"[DEBUG] Got {len(comments)} comments")
                    post["comments"] = comments
                else:
                    logger.debug(f"[DEBUG] No post ID found")
                    post["comments"] = []
            
            logger.debug(f"[DEBUG] Final: {len(posts_data)} posts found")
            logger.debug(f"[DEBUG] Info: {debug_info}")
            
            def update_ui():
                for w in self.myposts_list.winfo_children():
                    w.destroy()
                
                if not posts_data:
                    # Show debug info to help troubleshoot
                    ctk.CTkLabel(self.myposts_list, text="No posts found from Moltbook API", 
                        text_color=self.colors["warning"], font=("Segoe UI", 14, "bold")).pack(pady=(50, 10))
                    ctk.CTkLabel(self.myposts_list, text=f"Agent name: {agent_name}", 
                        text_color=self.colors["muted"]).pack()
                    ctk.CTkLabel(self.myposts_list, text="Debug info (check console for more):", 
                        text_color=self.colors["muted"]).pack(pady=(20, 5))
                    for info in debug_info[:5]:
                        ctk.CTkLabel(self.myposts_list, text=f"• {info}", 
                            text_color=self.colors["muted"], font=("Segoe UI", 10)).pack(anchor="w", padx=50)
                    ctk.CTkLabel(self.myposts_list, text="\nTip: Your posts might be under a different name on Moltbook.\nCheck moltbook.com to see your actual username.", 
                        text_color=self.colors["accent2"]).pack(pady=(20, 0))
                    self.myposts_stats.configure(text="0 posts found")
                    return
                
                total_comments = sum(len(p.get("comments", [])) for p in posts_data)
                new_replies = sum(1 for p in posts_data for c in p.get("comments", []) 
                    if c.get("author", {}).get("name", "").lower() != agent_name.lower())
                
                stats_text = f"📝 {len(posts_data)} posts • 💬 {total_comments} comments"
                if new_replies > 0:
                    stats_text += f" • 🔔 {new_replies} replies from others"
                self.myposts_stats.configure(text=stats_text)
                
                for post in posts_data:
                    self._create_mypost_card(post, api_key, agent_name)
            
            self.after(0, update_ui)
        
        threading.Thread(target=fetch, daemon=True).start()
    
    def _create_mypost_card(self, post, api_key, agent_name):
        # Main post card
        card = ctk.CTkFrame(self.myposts_list, fg_color=self.colors["surface"], corner_radius=10)
        card.pack(fill="x", padx=10, pady=8)
        
        # Post header
        hd = ctk.CTkFrame(card, fg_color="transparent")
        hd.pack(fill="x", padx=15, pady=(12, 5))
        
        submolt = post.get("submolt", {})
        smn = submolt.get("name", "general") if isinstance(submolt, dict) else submolt
        ctk.CTkLabel(hd, text=f"m/{smn}", text_color=self.colors["accent2"], font=("Segoe UI", 11)).pack(side="left")
        
        score = post.get("score", post.get("upvotes", 0))
        ctk.CTkLabel(hd, text=f"⬆️ {score}", text_color=self.colors["success"] if score > 0 else self.colors["muted"]).pack(side="right")
        
        created = post.get("created_at", "")
        if created:
            try:
                dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                created = dt.strftime("%m/%d %H:%M")
            except ValueError:
                pass
        ctk.CTkLabel(hd, text=created, text_color=self.colors["muted"], font=("Segoe UI", 10)).pack(side="right", padx=(0, 15))
        
        # Post title
        title = post.get("title", "Untitled")
        ctk.CTkLabel(card, text=title, font=("Segoe UI", 14, "bold"), text_color=self.colors["text"],
            wraplength=700, justify="left").pack(anchor="w", padx=15, pady=(5, 0))
        
        # Post content preview
        content = post.get("content", "")
        if content:
            preview = content[:200] + ("..." if len(content) > 200 else "")
            ctk.CTkLabel(card, text=preview, text_color=self.colors["muted"], wraplength=700, 
                justify="left", font=("Segoe UI", 11)).pack(anchor="w", padx=15, pady=(5, 10))
        
        # Comments section
        comments = post.get("comments", [])
        if comments:
            # Comments header
            comments_header = ctk.CTkFrame(card, fg_color=self.colors["surface2"], corner_radius=5)
            comments_header.pack(fill="x", padx=15, pady=(0, 5))
            ctk.CTkLabel(comments_header, text=f"💬 {len(comments)} comment{'s' if len(comments) != 1 else ''}", 
                font=("Segoe UI", 11, "bold"), text_color=self.colors["text"]).pack(anchor="w", padx=10, pady=5)
            
            # Container for comments (so we can show/hide more)
            comments_container = ctk.CTkFrame(card, fg_color="transparent")
            comments_container.pack(fill="x")
            
            # Show first 5 comments initially
            for comment in comments[:5]:
                self._create_comment_widget(comments_container, comment, post.get("id"), api_key, agent_name, 
                    post_title=title, post_content=content)
            
            # If more comments, add expand button
            if len(comments) > 5:
                extra_comments = comments[5:]
                extra_container = ctk.CTkFrame(card, fg_color="transparent")
                extra_container.pack(fill="x")
                expanded = [False]  # Use list to allow modification in closure
                
                def toggle_expand():
                    if not expanded[0]:
                        # Show remaining comments
                        for comment in extra_comments:
                            self._create_comment_widget(extra_container, comment, post.get("id"), api_key, agent_name,
                                post_title=title, post_content=content)
                        expand_btn.configure(text=f"▲ Hide {len(extra_comments)} comments")
                        expanded[0] = True
                    else:
                        # Hide extra comments
                        for w in extra_container.winfo_children():
                            w.destroy()
                        expand_btn.configure(text=f"▼ Show {len(extra_comments)} more comments")
                        expanded[0] = False
                
                expand_btn = ctk.CTkButton(card, text=f"▼ Show {len(extra_comments)} more comments", 
                    fg_color="transparent", text_color=self.colors["accent2"], hover_color=self.colors["surface2"],
                    font=("Segoe UI", 10), height=25, command=toggle_expand)
                expand_btn.pack(anchor="w", padx=20, pady=(0, 5))
        else:
            ctk.CTkLabel(card, text="💬 No comments yet", text_color=self.colors["muted"], 
                font=("Segoe UI", 10)).pack(anchor="w", padx=15, pady=(0, 10))
        
        # Quick reply section
        reply_frame = ctk.CTkFrame(card, fg_color="transparent")
        reply_frame.pack(fill="x", padx=15, pady=(5, 12))
        
        reply_entry = ctk.CTkEntry(reply_frame, placeholder_text="Write a reply to your own post...",
            fg_color=self.colors["surface2"], text_color=self.colors["text"], height=35)
        reply_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        def post_reply():
            text = reply_entry.get().strip()
            if not text:
                return
            post_id = post.get("id")
            if not post_id:
                return
            
            def do_reply():
                api = MoltbookAPI(api_key)
                result = api.create_comment(str(post_id), text)
                if "error" not in result:
                    self.after(0, lambda: reply_entry.delete(0, "end"))
                    self.after(0, lambda: messagebox.showinfo("Replied!", "Comment posted!"))
                    self.after(500, self.refresh_my_posts)
                else:
                    # Check if it's a known API issue
                    if result.get("is_api_issue"):
                        self.after(0, lambda: self._show_comment_api_error(post_id, text))
                    else:
                        self.after(0, lambda: messagebox.showerror("Error", result["error"]))
            
            threading.Thread(target=do_reply, daemon=True).start()
        
        # Open on Moltbook button (workaround for API issues)
        post_id = post.get("id")
        def open_post_on_moltbook():
            url = f"https://www.moltbook.com/post/{post_id}"
            webbrowser.open(url)
        
        ctk.CTkButton(reply_frame, text="🌐 Open", width=70, fg_color=self.colors["surface2"], 
            text_color=self.colors["accent2"], command=open_post_on_moltbook).pack(side="right", padx=(0, 5))
        ctk.CTkButton(reply_frame, text="Reply", width=70, fg_color=self.colors["accent"], command=post_reply).pack(side="right")
    
    def _create_comment_widget(self, parent, comment, post_id, api_key, agent_name, post_title="", post_content=""):
        cf = ctk.CTkFrame(parent, fg_color=self.colors["surface2"], corner_radius=5)
        cf.pack(fill="x", padx=20, pady=3)
        
        # Comment header
        ch = ctk.CTkFrame(cf, fg_color="transparent")
        ch.pack(fill="x", padx=10, pady=(8, 3))
        
        author = comment.get("author", {})
        author_name = author.get("name", "Unknown") if isinstance(author, dict) else str(author)
        
        # Highlight if it's from someone else (a real reply to monitor!)
        is_other = author_name.lower() != agent_name.lower()
        name_color = self.colors["accent2"] if is_other else self.colors["muted"]
        
        ctk.CTkLabel(ch, text=f"{'🔔 ' if is_other else ''}u/{author_name}", text_color=name_color, 
            font=("Segoe UI", 11, "bold")).pack(side="left")
        
        created = comment.get("created_at", "")
        if created:
            try:
                dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                created = dt.strftime("%m/%d %H:%M")
            except ValueError:
                pass
        ctk.CTkLabel(ch, text=created, text_color=self.colors["muted"], font=("Segoe UI", 9)).pack(side="right")
        
        # Comment content
        content = comment.get("content", "")
        ctk.CTkLabel(cf, text=content, text_color=self.colors["text"], wraplength=650, 
            justify="left", font=("Segoe UI", 11)).pack(anchor="w", padx=10, pady=(0, 5))
        
        # Reply to this specific comment (inline)
        if is_other:  # Only show reply option for other people's comments
            reply_row = ctk.CTkFrame(cf, fg_color="transparent")
            reply_row.pack(fill="x", padx=10, pady=(0, 8))
            
            reply_entry = ctk.CTkEntry(reply_row, placeholder_text=f"Reply to {author_name}...",
                fg_color=self.colors["surface"], text_color=self.colors["text"], height=30, width=300)
            reply_entry.pack(side="left", padx=(0, 5))
            
            # AI Generate Reply button
            def ai_generate_reply():
                if not self.ai_analyzer:
                    messagebox.showwarning("OpenAI Key Required", "Set your OpenAI API key in Settings to use AI replies.")
                    return
                
                # Get agent's personality
                conn = get_db()
                c = conn.cursor()
                c.execute("SELECT system_prompt FROM agents WHERE id = ?", (self.selected_agent_id,))
                r = c.fetchone()
                conn.close()
                sp = r[0] if r and r[0] else "You are a friendly AI agent on Moltbook."
                
                reply_entry.delete(0, "end")
                reply_entry.insert(0, "🤔 Generating...")
                
                def generate():
                    result = self.ai_analyzer.generate_reply(
                        agent_name=agent_name,
                        system_prompt=sp,
                        post_title=post_title,
                        post_content=post_content,
                        comment_author=author_name,
                        comment_content=content
                    )
                    def update():
                        reply_entry.delete(0, "end")
                        if "error" in result:
                            messagebox.showerror("AI Error", result["error"])
                        else:
                            reply_entry.insert(0, result.get("reply", ""))
                    self.after(0, update)
                
                threading.Thread(target=generate, daemon=True).start()
            
            ctk.CTkButton(reply_row, text="🤖", width=35, height=28, fg_color=self.colors["accent2"],
                hover_color=self.colors["accent"], command=ai_generate_reply).pack(side="left", padx=(0, 5))
            
            def reply_to_comment():
                text = reply_entry.get().strip()
                if not text:
                    return
                # Mention the user in reply
                full_reply = f"@{author_name} {text}"
                
                def do_reply():
                    logger.info(f"[Reply] Attempting to reply to {author_name} on post {post_id}")
                    api = MoltbookAPI(api_key)
                    result = api.create_comment(str(post_id), full_reply)
                    
                    if "error" not in result:
                        self.after(0, lambda: reply_entry.delete(0, "end"))
                        self.after(0, lambda: messagebox.showinfo("Replied!", f"Replied to {author_name}!"))
                        self.after(500, self.refresh_my_posts)
                    else:
                        # Check if it's a known API issue
                        if result.get("is_api_issue"):
                            self.after(0, lambda: self._show_comment_api_error(post_id, full_reply))
                        else:
                            self.after(0, lambda: messagebox.showerror("Error", result["error"]))
                
                threading.Thread(target=do_reply, daemon=True).start()
            
            ctk.CTkButton(reply_row, text="↩️", width=40, height=28, fg_color=self.colors["accent"], 
                command=reply_to_comment).pack(side="left", padx=(0, 5))
            
            # 🆕 Open on Moltbook button (workaround for API issues)
            def open_on_moltbook():
                # Copy the reply text to clipboard first
                text = reply_entry.get().strip()
                if text:
                    self.clipboard_clear()
                    self.clipboard_append(f"@{author_name} {text}")
                    messagebox.showinfo("Copied!", "Reply copied to clipboard!\n\nOpening Moltbook...")
                url = f"https://www.moltbook.com/post/{post_id}"
                webbrowser.open(url)
            
            ctk.CTkButton(reply_row, text="🌐", width=35, height=28, 
                fg_color=self.colors["surface3"], hover_color=self.colors["accent2"],
                command=open_on_moltbook).pack(side="left", padx=(5, 0))
    
    def _show_comment_api_error(self, post_id: str, reply_text: str):
        """Show helpful dialog when comment API fails"""
        dialog = ctk.CTkToplevel(self)
        dialog.title("⚠️ Comment API Issue")
        dialog.geometry("500x350")
        dialog.transient(self)
        dialog.grab_set()
        
        # Center on parent
        dialog.update_idletasks()
        x = self.winfo_x() + (self.winfo_width() - 500) // 2
        y = self.winfo_y() + (self.winfo_height() - 350) // 2
        dialog.geometry(f"+{x}+{y}")
        
        content = ctk.CTkFrame(dialog, fg_color=self.colors["surface"])
        content.pack(fill="both", expand=True, padx=20, pady=20)
        
        ctk.CTkLabel(content, text="🔴 Known Moltbook API Issue", 
            font=("Segoe UI", 16, "bold"), text_color=self.colors["error"]).pack(pady=(0, 10))
        
        ctk.CTkLabel(content, text=(
            "The Moltbook comment API is currently returning 401 Unauthorized\n"
            "even though your API key works correctly for posts.\n\n"
            "This is a server-side issue with Moltbook, not your app."
        ), text_color=self.colors["text"], wraplength=450, justify="center").pack(pady=10)
        
        ctk.CTkLabel(content, text="✅ WORKAROUND", 
            font=("Segoe UI", 14, "bold"), text_color=self.colors["success"]).pack(pady=(15, 5))
        
        ctk.CTkLabel(content, text=(
            "Your reply has been copied to clipboard.\n"
            "Click below to open the post on Moltbook and paste your reply."
        ), text_color=self.colors["muted"], wraplength=450).pack(pady=5)
        
        # Copy reply to clipboard
        self.clipboard_clear()
        self.clipboard_append(reply_text)
        
        def open_and_close():
            webbrowser.open(f"https://www.moltbook.com/post/{post_id}")
            dialog.destroy()
        
        btn_frame = ctk.CTkFrame(content, fg_color="transparent")
        btn_frame.pack(pady=20)
        
        ctk.CTkButton(btn_frame, text="🌐 Open on Moltbook", width=180, height=40,
            fg_color=self.colors["accent"], command=open_and_close).pack(side="left", padx=5)
        
        ctk.CTkButton(btn_frame, text="Close", width=100, height=40,
            fg_color=self.colors["surface2"], command=dialog.destroy).pack(side="left", padx=5)
    
    def create_activity_tab(self):
        af = ctk.CTkFrame(self.tab_activity, fg_color="transparent")
        af.pack(fill="both", expand=True)
        hd = ctk.CTkFrame(af, fg_color="transparent")
        hd.pack(fill="x", pady=(0, 10))
        ctk.CTkLabel(hd, text="Activity Log", font=("Segoe UI", 16, "bold"), text_color=self.colors["text"]).pack(side="left")
        ctk.CTkButton(hd, text="📤 CSV", width=70, fg_color=self.colors["surface2"], text_color=self.colors["text"], command=self.export_activity_csv).pack(side="right", padx=(10, 0))
        ctk.CTkButton(hd, text="🔄", width=40, fg_color=self.colors["surface2"], text_color=self.colors["text"], command=self.refresh_activity_log).pack(side="right")
        self.activity_list = ctk.CTkScrollableFrame(af, fg_color=self.colors["surface2"], corner_radius=10)
        self.activity_list.pack(fill="both", expand=True)
    
    def create_schedule_tab(self):
        sf = ctk.CTkFrame(self.tab_schedule, fg_color="transparent")
        sf.pack(fill="both", expand=True)
        
        sc = ctk.CTkFrame(sf, fg_color=self.colors["surface2"], corner_radius=10)
        sc.pack(fill="x", pady=(0, 15))
        scc = ctk.CTkFrame(sc, fg_color="transparent")
        scc.pack(fill="x", padx=20, pady=20)
        ctk.CTkLabel(scc, text="Auto-Posting", font=("Segoe UI", 16, "bold"), text_color=self.colors["text"]).pack(anchor="w")
        ctk.CTkLabel(scc, text="AI generates and posts automatically", text_color=self.colors["muted"]).pack(anchor="w", pady=(5, 15))
        tr = ctk.CTkFrame(scc, fg_color="transparent")
        tr.pack(fill="x")
        self.auto_post_var = ctk.BooleanVar(value=False)
        ctk.CTkSwitch(tr, text="Enable", variable=self.auto_post_var, text_color=self.colors["text"], command=self.toggle_auto_posting).pack(side="left")
        ir = ctk.CTkFrame(tr, fg_color="transparent")
        ir.pack(side="right")
        ctk.CTkLabel(ir, text="Every", text_color=self.colors["text"]).pack(side="left", padx=(0, 5))
        self.interval_var = ctk.StringVar(value="4")
        ctk.CTkComboBox(ir, variable=self.interval_var, values=["1", "2", "4", "6", "12", "24"], width=70,
            fg_color=self.colors["surface3"], text_color=self.colors["text"]).pack(side="left", padx=(0, 5))
        ctk.CTkLabel(ir, text="hours", text_color=self.colors["text"]).pack(side="left")
        
        hf = ctk.CTkFrame(sf, fg_color="transparent")
        hf.pack(fill="x", pady=(0, 10))
        ctk.CTkLabel(hf, text="Scheduled Posts", font=("Segoe UI", 14, "bold"), text_color=self.colors["text"]).pack(side="left")
        ctk.CTkButton(hf, text="🔄", width=40, fg_color=self.colors["surface2"], text_color=self.colors["text"], command=self.refresh_scheduled_posts).pack(side="right")
        self.scheduled_list = ctk.CTkScrollableFrame(sf, fg_color=self.colors["surface2"], corner_radius=10)
        self.scheduled_list.pack(fill="both", expand=True)
    
    def create_feed_tab(self):
        ff = ctk.CTkFrame(self.tab_feed, fg_color="transparent")
        ff.pack(fill="both", expand=True)
        hd = ctk.CTkFrame(ff, fg_color="transparent")
        hd.pack(fill="x", pady=(0, 10))
        ctk.CTkLabel(hd, text="Moltbook Feed", font=("Segoe UI", 16, "bold"), text_color=self.colors["text"]).pack(side="left")
        self.feed_sort_var = ctk.StringVar(value="new")
        ctk.CTkComboBox(hd, variable=self.feed_sort_var, values=["new", "hot", "top"], width=100,
            fg_color=self.colors["surface2"], text_color=self.colors["text"], command=self.refresh_feed).pack(side="right", padx=(10, 0))
        ctk.CTkButton(hd, text="🔄", width=40, fg_color=self.colors["surface2"], text_color=self.colors["text"], command=self.refresh_feed).pack(side="right")
        self.feed_list = ctk.CTkScrollableFrame(ff, fg_color=self.colors["surface2"], corner_radius=10)
        self.feed_list.pack(fill="both", expand=True)
        ctk.CTkLabel(self.feed_list, text="Click 🔄 to load", text_color=self.colors["muted"]).pack(pady=50)
    
    def create_diagnostics_tab(self):
        """Create comprehensive diagnostics and monitoring tab"""
        df = ctk.CTkFrame(self.tab_diagnostics, fg_color="transparent")
        df.pack(fill="both", expand=True)
        
        # Header
        hd = ctk.CTkFrame(df, fg_color="transparent")
        hd.pack(fill="x", pady=(0, 15))
        ctk.CTkLabel(hd, text="🔧 Diagnostics & Monitoring", 
            font=("Segoe UI", 18, "bold"), text_color=self.colors["text"]).pack(side="left")
        ctk.CTkButton(hd, text="🔄 Refresh All", width=120, fg_color=self.colors["accent"],
            command=self.refresh_diagnostics).pack(side="right")
        
        # Scrollable content
        self.diag_scroll = ctk.CTkScrollableFrame(df, fg_color="transparent")
        self.diag_scroll.pack(fill="both", expand=True)
        
        # === SECTION 1: System Info ===
        sys_card = ctk.CTkFrame(self.diag_scroll, fg_color=self.colors["surface"], corner_radius=10)
        sys_card.pack(fill="x", pady=(0, 15))
        
        ctk.CTkLabel(sys_card, text="💻 System Information", 
            font=("Segoe UI", 14, "bold"), text_color=self.colors["text"]).pack(anchor="w", padx=15, pady=(15, 10))
        
        self.sys_info_frame = ctk.CTkFrame(sys_card, fg_color="transparent")
        self.sys_info_frame.pack(fill="x", padx=15, pady=(0, 15))
        
        # === SECTION 2: API Health ===
        api_card = ctk.CTkFrame(self.diag_scroll, fg_color=self.colors["surface"], corner_radius=10)
        api_card.pack(fill="x", pady=(0, 15))
        
        api_header = ctk.CTkFrame(api_card, fg_color="transparent")
        api_header.pack(fill="x", padx=15, pady=(15, 10))
        ctk.CTkLabel(api_header, text="🌐 Moltbook API Status", 
            font=("Segoe UI", 14, "bold"), text_color=self.colors["text"]).pack(side="left")
        ctk.CTkButton(api_header, text="Test Endpoints", width=120, 
            fg_color=self.colors["accent2"], command=self.test_api_endpoints).pack(side="right")
        
        self.api_status_frame = ctk.CTkFrame(api_card, fg_color="transparent")
        self.api_status_frame.pack(fill="x", padx=15, pady=(0, 15))
        
        # === SECTION 3: Known Issues ===
        issues_card = ctk.CTkFrame(self.diag_scroll, fg_color=self.colors["surface"], corner_radius=10)
        issues_card.pack(fill="x", pady=(0, 15))
        
        ctk.CTkLabel(issues_card, text="⚠️ Known Issues & Workarounds", 
            font=("Segoe UI", 14, "bold"), text_color=self.colors["text"]).pack(anchor="w", padx=15, pady=(15, 10))
        
        self.issues_frame = ctk.CTkFrame(issues_card, fg_color="transparent")
        self.issues_frame.pack(fill="x", padx=15, pady=(0, 15))
        
        # === SECTION 4: Dependencies ===
        deps_card = ctk.CTkFrame(self.diag_scroll, fg_color=self.colors["surface"], corner_radius=10)
        deps_card.pack(fill="x", pady=(0, 15))
        
        ctk.CTkLabel(deps_card, text="📦 Dependencies", 
            font=("Segoe UI", 14, "bold"), text_color=self.colors["text"]).pack(anchor="w", padx=15, pady=(15, 10))
        
        self.deps_frame = ctk.CTkFrame(deps_card, fg_color="transparent")
        self.deps_frame.pack(fill="x", padx=15, pady=(0, 15))
        
        # === SECTION 5: Security ===
        sec_card = ctk.CTkFrame(self.diag_scroll, fg_color=self.colors["surface"], corner_radius=10)
        sec_card.pack(fill="x", pady=(0, 15))
        
        ctk.CTkLabel(sec_card, text="🔒 Security Status", 
            font=("Segoe UI", 14, "bold"), text_color=self.colors["text"]).pack(anchor="w", padx=15, pady=(15, 10))
        
        self.security_frame = ctk.CTkFrame(sec_card, fg_color="transparent")
        self.security_frame.pack(fill="x", padx=15, pady=(0, 15))
        
        # === SECTION 6: Recent Errors ===
        errors_card = ctk.CTkFrame(self.diag_scroll, fg_color=self.colors["surface"], corner_radius=10)
        errors_card.pack(fill="x", pady=(0, 15))
        
        err_header = ctk.CTkFrame(errors_card, fg_color="transparent")
        err_header.pack(fill="x", padx=15, pady=(15, 10))
        ctk.CTkLabel(err_header, text="❌ Recent Errors", 
            font=("Segoe UI", 14, "bold"), text_color=self.colors["text"]).pack(side="left")
        ctk.CTkButton(err_header, text="Open Log File", width=120, 
            fg_color=self.colors["surface2"], command=self.open_log_file).pack(side="right")
        
        self.errors_frame = ctk.CTkFrame(errors_card, fg_color="transparent")
        self.errors_frame.pack(fill="x", padx=15, pady=(0, 15))
        
        # === SECTION 7: Quick Actions ===
        actions_card = ctk.CTkFrame(self.diag_scroll, fg_color=self.colors["surface"], corner_radius=10)
        actions_card.pack(fill="x", pady=(0, 15))
        
        ctk.CTkLabel(actions_card, text="⚡ Quick Actions", 
            font=("Segoe UI", 14, "bold"), text_color=self.colors["text"]).pack(anchor="w", padx=15, pady=(15, 10))
        
        actions_btns = ctk.CTkFrame(actions_card, fg_color="transparent")
        actions_btns.pack(fill="x", padx=15, pady=(0, 15))
        
        ctk.CTkButton(actions_btns, text="📋 Copy Debug Info", width=140, 
            fg_color=self.colors["surface2"], command=self.copy_debug_info).pack(side="left", padx=(0, 10))
        ctk.CTkButton(actions_btns, text="🗑️ Clear Error Log", width=140, 
            fg_color=self.colors["surface2"], command=self.clear_error_log).pack(side="left", padx=(0, 10))
        ctk.CTkButton(actions_btns, text="🔄 Reset API Health", width=140, 
            fg_color=self.colors["surface2"], command=self.reset_api_health).pack(side="left", padx=(0, 10))
        ctk.CTkButton(actions_btns, text="🌐 Moltbook Status", width=140, 
            fg_color=self.colors["accent2"], command=lambda: webbrowser.open("https://www.moltbook.com")).pack(side="left")
        
        # Initial load
        self.refresh_diagnostics()
    
    def refresh_diagnostics(self):
        """Refresh all diagnostics data"""
        logger.info("Refreshing diagnostics...")
        
        # Clear and repopulate system info
        for w in self.sys_info_frame.winfo_children():
            w.destroy()
        
        sys_info = diagnostics.get_system_info()
        info_grid = [
            ("App Version", f"v{sys_info['app_version']} ({sys_info['build_date']})"),
            ("OS", f"{sys_info['os']} {sys_info['os_version'][:50]}..."),
            ("Python", sys_info['python_version'].split()[0]),
            ("Log Directory", LOG_DIR),
        ]
        
        for i, (label, value) in enumerate(info_grid):
            row = ctk.CTkFrame(self.sys_info_frame, fg_color="transparent")
            row.pack(fill="x", pady=2)
            ctk.CTkLabel(row, text=f"{label}:", text_color=self.colors["muted"], width=120, anchor="w").pack(side="left")
            ctk.CTkLabel(row, text=value, text_color=self.colors["text"]).pack(side="left")
        
        # Dependencies
        for w in self.deps_frame.winfo_children():
            w.destroy()
        
        deps = diagnostics.get_dependency_status()
        for name, info in deps.items():
            row = ctk.CTkFrame(self.deps_frame, fg_color="transparent")
            row.pack(fill="x", pady=2)
            status_color = self.colors["success"] if info["status"] == "✅" else (self.colors["warning"] if info["status"] == "⚠️" else self.colors["error"])
            ctk.CTkLabel(row, text=info["status"], text_color=status_color, width=30).pack(side="left")
            ctk.CTkLabel(row, text=name, text_color=self.colors["text"], width=120, anchor="w").pack(side="left")
            extra = info.get("version", info.get("note", ""))
            ctk.CTkLabel(row, text=extra, text_color=self.colors["muted"]).pack(side="left")
        
        # Security status
        for w in self.security_frame.winfo_children():
            w.destroy()
        
        sec_items = [
            ("Encryption", "🔒 Keyring (System)" if HAS_KEYRING else ("🔐 AES-256" if HAS_CRYPTO else "🔑 Basic XOR")),
            ("Key Storage", "System Credential Store" if HAS_KEYRING else "Encrypted Local File"),
            ("Key File", os.path.expanduser("~/.moltbook_key")),
            ("Database", DB_PATH),
        ]
        
        for label, value in sec_items:
            row = ctk.CTkFrame(self.security_frame, fg_color="transparent")
            row.pack(fill="x", pady=2)
            ctk.CTkLabel(row, text=f"{label}:", text_color=self.colors["muted"], width=120, anchor="w").pack(side="left")
            ctk.CTkLabel(row, text=value, text_color=self.colors["text"]).pack(side="left")
        
        # Known issues
        for w in self.issues_frame.winfo_children():
            w.destroy()
        
        known_issues = [
            ("🔴 Comment API", "401 Unauthorized on all comment endpoints", "Use 'Open on Moltbook' button to reply via website"),
            ("⚠️ Server Load", "Moltbook servers are under heavy load (viral growth)", "Expect timeouts, retry requests"),
            ("ℹ️ Rate Limits", "1 post/30 min, 50 comments/hour", "App tracks your last post time"),
        ]
        
        for icon, issue, workaround in known_issues:
            issue_frame = ctk.CTkFrame(self.issues_frame, fg_color=self.colors["surface2"], corner_radius=5)
            issue_frame.pack(fill="x", pady=3)
            ctk.CTkLabel(issue_frame, text=f"{icon} {issue}", text_color=self.colors["text"],
                font=("Segoe UI", 11, "bold")).pack(anchor="w", padx=10, pady=(8, 2))
            ctk.CTkLabel(issue_frame, text=f"→ {workaround}", text_color=self.colors["muted"],
                font=("Segoe UI", 10)).pack(anchor="w", padx=10, pady=(0, 8))
        
        # API status
        self.update_api_status_display()
        
        # Recent errors
        self.update_errors_display()
    
    def update_api_status_display(self):
        """Update the API status section"""
        for w in self.api_status_frame.winfo_children():
            w.destroy()
        
        health = api_health.get_health_summary()
        
        # Overall status
        status_row = ctk.CTkFrame(self.api_status_frame, fg_color="transparent")
        status_row.pack(fill="x", pady=(0, 10))
        
        status_color = {
            "healthy": self.colors["success"],
            "degraded": self.colors["warning"],
            "unhealthy": self.colors["error"]
        }.get(health["status"], self.colors["muted"])
        
        ctk.CTkLabel(status_row, text=f"Status: {health['status'].upper()}", 
            text_color=status_color, font=("Segoe UI", 12, "bold")).pack(side="left")
        ctk.CTkLabel(status_row, text=f"Success Rate: {health['success_rate']:.1f}%", 
            text_color=self.colors["text"]).pack(side="left", padx=20)
        ctk.CTkLabel(status_row, text=f"Total Requests: {health['total_requests']}", 
            text_color=self.colors["muted"]).pack(side="left")
        
        # Last successful operations
        times_row = ctk.CTkFrame(self.api_status_frame, fg_color="transparent")
        times_row.pack(fill="x", pady=5)
        
        last_post = health.get("last_successful_post", "Never")
        last_comment = health.get("last_successful_comment", "Never")
        
        ctk.CTkLabel(times_row, text=f"Last Post: {last_post or 'Never'}", 
            text_color=self.colors["success"] if last_post else self.colors["muted"]).pack(side="left", padx=(0, 20))
        ctk.CTkLabel(times_row, text=f"Last Comment: {last_comment or 'Never'}", 
            text_color=self.colors["success"] if last_comment else self.colors["error"]).pack(side="left")
        
        # Endpoint status
        if api_health.endpoint_status:
            ctk.CTkLabel(self.api_status_frame, text="Endpoint Statistics:", 
                text_color=self.colors["text"], font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(10, 5))
            
            for endpoint, stats in list(api_health.endpoint_status.items())[:8]:
                ep_row = ctk.CTkFrame(self.api_status_frame, fg_color=self.colors["surface2"], corner_radius=3)
                ep_row.pack(fill="x", pady=1)
                
                success_rate = (stats["successes"] / stats["total_requests"] * 100) if stats["total_requests"] > 0 else 0
                rate_color = self.colors["success"] if success_rate > 80 else (self.colors["warning"] if success_rate > 50 else self.colors["error"])
                
                ctk.CTkLabel(ep_row, text=endpoint[:40], text_color=self.colors["text"], 
                    width=300, anchor="w").pack(side="left", padx=8, pady=4)
                ctk.CTkLabel(ep_row, text=f"{success_rate:.0f}%", text_color=rate_color, width=50).pack(side="left")
                ctk.CTkLabel(ep_row, text=f"({stats['successes']}/{stats['total_requests']})", 
                    text_color=self.colors["muted"]).pack(side="left", padx=5)
                ctk.CTkLabel(ep_row, text=f"Avg: {stats['avg_response_time']:.2f}s", 
                    text_color=self.colors["muted"]).pack(side="right", padx=8)
    
    def update_errors_display(self):
        """Update the recent errors section"""
        for w in self.errors_frame.winfo_children():
            w.destroy()
        
        health = api_health.get_health_summary()
        recent_errors = health.get("recent_errors", [])
        
        if not recent_errors:
            ctk.CTkLabel(self.errors_frame, text="✅ No recent errors", 
                text_color=self.colors["success"]).pack(pady=10)
            return
        
        for error in recent_errors[-5:]:  # Show last 5
            err_frame = ctk.CTkFrame(self.errors_frame, fg_color=self.colors["surface2"], corner_radius=3)
            err_frame.pack(fill="x", pady=2)
            
            time_str = error.get("time", "")[:19] if error.get("time") else ""
            ctk.CTkLabel(err_frame, text=time_str, text_color=self.colors["muted"], 
                width=150, anchor="w").pack(side="left", padx=8, pady=4)
            ctk.CTkLabel(err_frame, text=f"{error.get('method', '')} {error.get('endpoint', '')[:30]}", 
                text_color=self.colors["text"]).pack(side="left", padx=5)
            ctk.CTkLabel(err_frame, text=str(error.get("status", "")), 
                text_color=self.colors["error"]).pack(side="left", padx=5)
            ctk.CTkLabel(err_frame, text=error.get("error", "")[:30], 
                text_color=self.colors["muted"]).pack(side="right", padx=8)
    
    def test_api_endpoints(self):
        """Test all API endpoints"""
        if not self.selected_agent_id:
            messagebox.showwarning("Warning", "Select an agent first")
            return
        
        # Get API key
        api_key = get_agent_api_key(self.selected_agent_id)
        if not api_key:
            messagebox.showerror("Error", "No API key available")
            return
        
        def run_test():
            results = api_health.check_endpoint_health(MOLTBOOK_API_BASE, api_key)
            
            def show_results():
                msg = "API Endpoint Test Results:\n\n"
                for name, result in results.items():
                    msg += f"{result['status']} {name}: {result.get('code', 'N/A')} ({result.get('time', 'N/A')})\n"
                    if result.get("error"):
                        msg += f"   Error: {result['error']}\n"
                
                messagebox.showinfo("API Test Results", msg)
                self.update_api_status_display()
            
            self.after(0, show_results)
        
        threading.Thread(target=run_test, daemon=True).start()
    
    def copy_debug_info(self):
        """Copy diagnostic info to clipboard for bug reports"""
        info = []
        info.append(f"=== Moltbook Agent Manager Debug Info ===")
        info.append(f"Version: {APP_VERSION} ({BUILD_DATE})")
        
        sys_info = diagnostics.get_system_info()
        info.append(f"\nSystem:")
        info.append(f"  OS: {sys_info['os']} {sys_info['os_version'][:50]}")
        info.append(f"  Python: {sys_info['python_version'].split()[0]}")
        
        info.append(f"\nDependencies:")
        for name, dep in diagnostics.get_dependency_status().items():
            info.append(f"  {dep['status']} {name}: {dep.get('version', dep.get('note', ''))}")
        
        info.append(f"\nSecurity:")
        info.append(f"  Keyring: {'Yes' if HAS_KEYRING else 'No'}")
        info.append(f"  Cryptography: {'Yes' if HAS_CRYPTO else 'No'}")
        
        health = api_health.get_health_summary()
        info.append(f"\nAPI Health:")
        info.append(f"  Status: {health['status']}")
        info.append(f"  Success Rate: {health['success_rate']:.1f}%")
        info.append(f"  Last Successful Post: {health.get('last_successful_post', 'Never')}")
        info.append(f"  Last Successful Comment: {health.get('last_successful_comment', 'Never')}")
        
        if health.get("recent_errors"):
            info.append(f"\nRecent Errors:")
            for err in health["recent_errors"][-5:]:
                info.append(f"  {err.get('time', '')}: {err.get('method', '')} {err.get('endpoint', '')} - {err.get('status', '')} {err.get('error', '')}")
        
        debug_text = "\n".join(info)
        self.clipboard_clear()
        self.clipboard_append(debug_text)
        messagebox.showinfo("Copied", "Debug info copied to clipboard!")
    
    def open_log_file(self):
        """Open the log directory"""
        if platform.system() == "Windows":
            os.startfile(LOG_DIR)
        elif platform.system() == "Darwin":
            os.system(f"open {LOG_DIR}")
        else:
            os.system(f"xdg-open {LOG_DIR}")
    
    def clear_error_log(self):
        """Clear the in-memory error log"""
        api_health.recent_errors.clear()
        self.update_errors_display()
        messagebox.showinfo("Cleared", "Error log cleared!")
    
    def reset_api_health(self):
        """Reset API health statistics"""
        api_health.endpoint_status.clear()
        api_health.recent_errors.clear()
        api_health.last_check = None
        self.refresh_diagnostics()
        messagebox.showinfo("Reset", "API health statistics reset!")
    
    def refresh_agents_list(self):
        for w in self.agents_list_frame.winfo_children():
            w.destroy()
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT id, name, archetype, is_claimed, karma FROM agents ORDER BY name")
        agents = c.fetchall()
        conn.close()
        if not agents:
            ctk.CTkLabel(self.agents_list_frame, text="No agents yet", text_color=self.colors["muted"]).pack(pady=20)
            return
        for aid, name, arch, claimed, karma in agents:
            f = ctk.CTkFrame(self.agents_list_frame, fg_color=self.colors["surface2"], corner_radius=8, cursor="hand2")
            f.pack(fill="x", pady=3)
            f.bind("<Button-1>", lambda e, a=aid: self.select_agent(a))
            c = ctk.CTkFrame(f, fg_color="transparent")
            c.pack(fill="x", padx=12, pady=10)
            c.bind("<Button-1>", lambda e, a=aid: self.select_agent(a))
            nr = ctk.CTkFrame(c, fg_color="transparent")
            nr.pack(fill="x")
            nr.bind("<Button-1>", lambda e, a=aid: self.select_agent(a))
            ctk.CTkLabel(nr, text="●", text_color=self.colors["success"] if claimed else self.colors["warning"], font=("Segoe UI", 10)).pack(side="left")
            nl = ctk.CTkLabel(nr, text=name, font=("Segoe UI", 13, "bold"), text_color=self.colors["text"])
            nl.pack(side="left", padx=(5, 0))
            nl.bind("<Button-1>", lambda e, a=aid: self.select_agent(a))
            kl = ctk.CTkLabel(nr, text=f"⭐ {karma}", text_color=self.colors["muted"])
            kl.pack(side="right")
            kl.bind("<Button-1>", lambda e, a=aid: self.select_agent(a))
            al = ctk.CTkLabel(c, text=arch or "Custom", text_color=self.colors["accent2"])
            al.pack(anchor="w")
            al.bind("<Button-1>", lambda e, a=aid: self.select_agent(a))
        self.stats_label.configure(text=f"{len(agents)} agents")
    
    def select_agent(self, agent_id: int):
        self.selected_agent_id = agent_id
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT * FROM agents WHERE id = ?", (agent_id,))
        agent = c.fetchone()
        conn.close()
        if not agent:
            return
        cols = ['id', 'name', 'api_key', 'description', 'archetype', 'system_prompt', 'is_claimed', 'claim_url', 'created_at', 'last_active', 'auto_post_enabled', 'post_interval_hours', 'karma', 'follower_count', 'following_count']
        ad = dict(zip(cols[:len(agent)], agent))
        
        self.no_agent_frame.pack_forget()
        self.agent_dashboard.pack(fill="both", expand=True)
        self.agent_name_label.configure(text=ad['name'])
        self.agent_archetype_label.configure(text=ad.get('archetype') or "Custom")
        if ad.get('is_claimed'):
            self.agent_status_label.configure(text="● Claimed & Active", text_color=self.colors["success"])
        else:
            self.agent_status_label.configure(text="● Not claimed", text_color=self.colors["warning"])
        self.stat_karma_value.configure(text=str(ad.get('karma', 0)))
        self.stat_followers_value.configure(text=str(ad.get('follower_count', 0)))
        
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM activity_log WHERE agent_id = ? AND action_type = 'post'", (agent_id,))
        pc = c.fetchone()[0]
        conn.close()
        self.stat_posts_value.configure(text=str(pc))
        
        la = ad.get('last_active') or "Never"
        if isinstance(la, str) and la != "Never":
            try:
                la = datetime.fromisoformat(la).strftime("%m/%d %H:%M")
            except ValueError:
                pass
        self.stat_last_active_value.configure(text=str(la))
        self.auto_post_var.set(bool(ad.get('auto_post_enabled')))
        self.interval_var.set(str(ad.get('post_interval_hours', 4)))
        
        # Update personality preview
        sp = ad.get('system_prompt', '')
        if sp:
            preview = sp[:200] + "..." if len(sp) > 200 else sp
            self.personality_preview.configure(text=preview)
        else:
            self.personality_preview.configure(text="No personality set - click Edit to add one!")
        
        # Update rate limit status based on last post time
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT timestamp FROM activity_log WHERE agent_id = ? AND action_type = 'post' AND success = 1 ORDER BY timestamp DESC LIMIT 1", (agent_id,))
        last_post = c.fetchone()
        conn.close()
        
        if last_post and last_post[0]:
            try:
                last_post_time = datetime.fromisoformat(last_post[0])
                mins_since = (datetime.now() - last_post_time).total_seconds() / 60
                if mins_since < 30:
                    wait_mins = int(30 - mins_since)
                    self.rate_limit_label.configure(text=f"⏳ Wait ~{wait_mins} min to post", text_color=self.colors["warning"])
                else:
                    self.rate_limit_label.configure(text="✅ Ready to post", text_color=self.colors["success"])
            except Exception:
                self.rate_limit_label.configure(text="✅ Ready to post", text_color=self.colors["success"])
        else:
            self.rate_limit_label.configure(text="✅ Ready to post", text_color=self.colors["success"])
        
        self.refresh_activity_log()
        self.refresh_scheduled_posts()
    
    def show_create_agent_dialog(self):
        dialog = ctk.CTkToplevel(self)
        dialog.title("Create New Agent")
        dialog.geometry("600x700")
        dialog.configure(fg_color=self.colors["bg"])
        dialog.lift()
        dialog.focus_force()
        dialog.after(100, lambda: self._center_dialog(dialog, 600, 700))
        
        content = ctk.CTkScrollableFrame(dialog, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=20, pady=20)
        
        ctk.CTkLabel(content, text="🦞 Create New Agent", font=("Segoe UI", 20, "bold"), text_color=self.colors["text"]).pack(anchor="w", pady=(0, 20))
        
        ctk.CTkLabel(content, text="Agent Name", font=("Segoe UI", 12, "bold"), text_color=self.colors["text"]).pack(anchor="w")
        name_entry = ctk.CTkEntry(content, height=40, placeholder_text="e.g., PhilosophyBot42", fg_color=self.colors["surface2"], text_color=self.colors["text"])
        name_entry.pack(fill="x", pady=(5, 15))
        
        ctk.CTkLabel(content, text="Description", font=("Segoe UI", 12, "bold"), text_color=self.colors["text"]).pack(anchor="w")
        desc_entry = ctk.CTkEntry(content, height=40, placeholder_text="Brief description", fg_color=self.colors["surface2"], text_color=self.colors["text"])
        desc_entry.pack(fill="x", pady=(5, 15))
        
        ctk.CTkLabel(content, text="Personality", font=("Segoe UI", 12, "bold"), text_color=self.colors["text"]).pack(anchor="w", pady=(0, 10))
        
        arch_var = ctk.StringVar(value="🧠 Philosopher")
        for aname, adata in AGENT_ARCHETYPES.items():
            f = ctk.CTkFrame(content, fg_color=self.colors["surface2"], corner_radius=8)
            f.pack(fill="x", pady=3)
            ctk.CTkRadioButton(f, text=aname, variable=arch_var, value=aname, text_color=self.colors["text"], fg_color=self.colors["accent"]).pack(anchor="w", padx=15, pady=(10, 0))
            ctk.CTkLabel(f, text=adata["description"], text_color=self.colors["muted"]).pack(anchor="w", padx=15, pady=(0, 10))
        
        ctk.CTkLabel(content, text="Custom Prompt (for Custom type)", font=("Segoe UI", 12, "bold"), text_color=self.colors["text"]).pack(anchor="w", pady=(15, 0))
        custom_prompt = ctk.CTkTextbox(content, height=80, fg_color=self.colors["surface2"], text_color=self.colors["text"])
        custom_prompt.pack(fill="x", pady=5)
        
        def create():
            name = name_entry.get().strip()
            desc = desc_entry.get().strip()
            arch = arch_var.get()
            if not name:
                messagebox.showerror("Error", "Enter agent name")
                return
            if arch == "🔮 Custom":
                sp = custom_prompt.get("1.0", "end").strip()
                if not sp:
                    messagebox.showerror("Error", "Enter custom prompt")
                    return
            else:
                sp = AGENT_ARCHETYPES[arch]["system_prompt"]
            
            api = MoltbookAPI()
            result = api.register_agent(name, desc)
            if "error" in result:
                messagebox.showerror("Error", f"Failed: {result['error']}")
                return
            
            ad = result.get("agent", result)
            api_key = ad.get("api_key", "")
            claim_url = ad.get("claim_url", "")
            
            # Encrypt API key before storing
            encrypted_key = secure_storage.store_api_key(name, api_key)
            
            conn = get_db()
            c = conn.cursor()
            try:
                c.execute("INSERT INTO agents (name, api_key, description, archetype, system_prompt, claim_url) VALUES (?, ?, ?, ?, ?, ?)",
                    (name, encrypted_key, desc, arch, sp, claim_url))
                conn.commit()
                dialog.destroy()
                self.refresh_agents_list()
                
                if claim_url:
                    kf = os.path.expanduser(f"~/moltbook_{name}_key.txt")
                    with open(kf, "w") as f:
                        f.write(f"Agent: {name}\nAPI Key: {api_key}\nClaim URL: {claim_url}\n")
                        f.write(f"\n⚠️ DELETE THIS FILE AFTER SAVING YOUR KEY ELSEWHERE!\n")
                    self._show_api_key_dialog(name, api_key, claim_url, kf)
                else:
                    messagebox.showinfo("Created", f"Agent '{name}' created!")
            except sqlite3.IntegrityError:
                messagebox.showerror("Error", "Agent name exists locally")
            finally:
                conn.close()
        
        bf = ctk.CTkFrame(content, fg_color="transparent")
        bf.pack(fill="x", pady=20)
        ctk.CTkButton(bf, text="Cancel", width=100, fg_color=self.colors["surface2"], text_color=self.colors["text"], command=dialog.destroy).pack(side="left")
        ctk.CTkButton(bf, text="Create Agent", width=150, fg_color=self.colors["accent"], command=create).pack(side="right")
    
    def _show_api_key_dialog(self, name, api_key, claim_url, key_file):
        dialog = ctk.CTkToplevel(self)
        dialog.title("🎉 Agent Created!")
        dialog.geometry("550x480")
        dialog.configure(fg_color=self.colors["bg"])
        dialog.lift()
        dialog.focus_force()
        dialog.after(100, lambda: self._center_dialog(dialog, 550, 480))
        
        content = ctk.CTkFrame(dialog, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=25, pady=25)
        
        ctk.CTkLabel(content, text="✅ Agent Created!", font=("Segoe UI", 18, "bold"), text_color=self.colors["success"]).pack(anchor="w")
        ctk.CTkLabel(content, text=f"'{name}' is ready to claim", text_color=self.colors["muted"]).pack(anchor="w", pady=(5, 20))
        
        ctk.CTkLabel(content, text="🔑 API Key (SAVE THIS!):", font=("Segoe UI", 12, "bold"), text_color=self.colors["text"]).pack(anchor="w")
        kf = ctk.CTkFrame(content, fg_color=self.colors["surface2"], corner_radius=8)
        kf.pack(fill="x", pady=(5, 15))
        ke = ctk.CTkEntry(kf, font=("Consolas", 11), height=40, fg_color=self.colors["surface"], text_color=self.colors["text"])
        ke.pack(fill="x", padx=10, pady=10, side="left", expand=True)
        ke.insert(0, api_key)
        ke.configure(state="readonly")
        
        def copy_key():
            self.clipboard_clear()
            self.clipboard_append(api_key)
            cb.configure(text="✓ Copied!")
            dialog.after(2000, lambda: cb.configure(text="📋 Copy"))
        cb = ctk.CTkButton(kf, text="📋 Copy", width=80, fg_color=self.colors["accent2"], command=copy_key)
        cb.pack(side="right", padx=10, pady=10)
        
        ctk.CTkLabel(content, text="🔗 Claim URL:", font=("Segoe UI", 12, "bold"), text_color=self.colors["text"]).pack(anchor="w")
        uf = ctk.CTkFrame(content, fg_color=self.colors["surface2"], corner_radius=8)
        uf.pack(fill="x", pady=(5, 15))
        ue = ctk.CTkEntry(uf, font=("Consolas", 10), height=40, fg_color=self.colors["surface"], text_color=self.colors["text"])
        ue.pack(fill="x", padx=10, pady=10, side="left", expand=True)
        ue.insert(0, claim_url)
        ue.configure(state="readonly")
        ctk.CTkButton(uf, text="🌐 Open", width=80, fg_color=self.colors["accent"], command=lambda: webbrowser.open(claim_url)).pack(side="right", padx=10, pady=10)
        
        ctk.CTkLabel(content, text=f"💾 Saved to: {key_file}", text_color=self.colors["muted"]).pack(anchor="w", pady=(5, 15))
        
        inst = ctk.CTkFrame(content, fg_color=self.colors["surface2"], corner_radius=8)
        inst.pack(fill="x", pady=(0, 15))
        ctk.CTkLabel(inst, text="📋 Next Steps:", font=("Segoe UI", 12, "bold"), text_color=self.colors["text"]).pack(anchor="w", padx=15, pady=(15, 5))
        ctk.CTkLabel(inst, text="1. Click 'Open' for claim URL\n2. Post verification tweet\n3. Agent activates automatically!", text_color=self.colors["muted"], justify="left").pack(anchor="w", padx=15, pady=(0, 15))
        
        ctk.CTkButton(content, text="Done", width=120, height=40, fg_color=self.colors["accent"], command=dialog.destroy).pack(pady=(10, 0))
    
    def show_agent_key(self):
        if not self.selected_agent_id:
            return
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT name, api_key, claim_url FROM agents WHERE id = ?", (self.selected_agent_id,))
        r = c.fetchone()
        conn.close()
        if not r:
            return
        name, api_key, claim_url = r
        
        dialog = ctk.CTkToplevel(self)
        dialog.title(f"API Key - {name}")
        dialog.geometry("500x280")
        dialog.configure(fg_color=self.colors["bg"])
        dialog.lift()
        dialog.focus_force()
        dialog.after(100, lambda: self._center_dialog(dialog, 500, 280))
        
        content = ctk.CTkFrame(dialog, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=25, pady=25)
        
        ctk.CTkLabel(content, text=f"🔑 API Key for {name}", font=("Segoe UI", 16, "bold"), text_color=self.colors["text"]).pack(anchor="w", pady=(0, 20))
        
        kf = ctk.CTkFrame(content, fg_color=self.colors["surface2"], corner_radius=8)
        kf.pack(fill="x", pady=(0, 15))
        ke = ctk.CTkEntry(kf, font=("Consolas", 11), height=40, fg_color=self.colors["surface"], text_color=self.colors["text"])
        ke.pack(fill="x", padx=10, pady=10, side="left", expand=True)
        ke.insert(0, api_key or "No API key")
        ke.configure(state="readonly")
        
        def copy():
            if api_key:
                self.clipboard_clear()
                self.clipboard_append(api_key)
                cb.configure(text="✓ Copied!")
                dialog.after(2000, lambda: cb.configure(text="📋 Copy"))
        cb = ctk.CTkButton(kf, text="📋 Copy", width=80, fg_color=self.colors["accent2"], command=copy)
        cb.pack(side="right", padx=10, pady=10)
        
        if claim_url:
            ctk.CTkLabel(content, text="Claim URL:", text_color=self.colors["muted"]).pack(anchor="w")
            ul = ctk.CTkLabel(content, text=claim_url, text_color=self.colors["accent2"], cursor="hand2")
            ul.pack(anchor="w")
            ul.bind("<Button-1>", lambda e: webbrowser.open(claim_url))
        
        ctk.CTkButton(content, text="Close", width=100, fg_color=self.colors["surface2"], text_color=self.colors["text"], command=dialog.destroy).pack(pady=(15, 0))
    
    def edit_agent(self):
        if not self.selected_agent_id:
            return
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT name, description, system_prompt, is_claimed FROM agents WHERE id = ?", (self.selected_agent_id,))
        r = c.fetchone()
        conn.close()
        if not r:
            return
        name, desc, sp, is_claimed = r
        
        # Use STANDARD tkinter Toplevel - more reliable on Windows
        import tkinter as tk
        from tkinter import ttk
        
        dialog = tk.Toplevel(self)
        dialog.title(f"Edit Agent - {name}")
        dialog.geometry("650x750")
        dialog.configure(bg="#1a1a2e")
        dialog.grab_set()
        dialog.focus_force()
        
        # Style configuration
        style = ttk.Style()
        style.configure("Dark.TLabel", background="#1a1a2e", foreground="white", font=("Arial", 11))
        style.configure("Title.TLabel", background="#1a1a2e", foreground="white", font=("Arial", 18, "bold"))
        style.configure("Header.TLabel", background="#1a1a2e", foreground="#ff6b6b", font=("Arial", 14, "bold"))
        
        # Main frame
        main = tk.Frame(dialog, bg="#1a1a2e", padx=25, pady=20)
        main.pack(fill="both", expand=True)
        
        # Title
        tk.Label(main, text="✏️ Edit Agent", font=("Arial", 18, "bold"), bg="#1a1a2e", fg="white").pack(anchor="w", pady=(0, 20))
        
        # Agent Name
        tk.Label(main, text="Agent Name:", font=("Arial", 11), bg="#1a1a2e", fg="white").pack(anchor="w")
        ne = tk.Entry(main, font=("Arial", 12), width=60, bg="#2d2d44", fg="white", insertbackground="white")
        ne.insert(0, name or "")
        ne.pack(anchor="w", pady=(5, 15), ipady=5)
        
        # Claimed checkbox
        claimed_var = tk.BooleanVar(value=bool(is_claimed))
        cb = tk.Checkbutton(main, text="✅ Agent is claimed & active", variable=claimed_var,
            font=("Arial", 11), bg="#1a1a2e", fg="white", selectcolor="#2d2d44", activebackground="#1a1a2e")
        cb.pack(anchor="w", pady=(0, 15))
        
        # Description
        tk.Label(main, text="Description:", font=("Arial", 11), bg="#1a1a2e", fg="white").pack(anchor="w")
        de = tk.Entry(main, font=("Arial", 12), width=60, bg="#2d2d44", fg="white", insertbackground="white")
        de.insert(0, desc or "")
        de.pack(anchor="w", pady=(5, 20), ipady=5)
        
        # Separator
        sep = tk.Frame(main, height=2, bg="#ff6b6b")
        sep.pack(fill="x", pady=(10, 15))
        
        # PERSONALITY SECTION
        tk.Label(main, text="🎭 PERSONALITY / SYSTEM PROMPT", font=("Arial", 14, "bold"), 
            bg="#1a1a2e", fg="#ff6b6b").pack(anchor="w")
        tk.Label(main, text="This controls how AI generates posts. You can change it anytime!", 
            font=("Arial", 10), bg="#1a1a2e", fg="#aaaaaa").pack(anchor="w", pady=(5, 15))
        
        # Preset buttons
        tk.Label(main, text="Quick Presets (click to load):", font=("Arial", 11), bg="#1a1a2e", fg="white").pack(anchor="w")
        
        btn_frame = tk.Frame(main, bg="#1a1a2e")
        btn_frame.pack(anchor="w", pady=(5, 10))
        
        # System prompt text area
        tk.Label(main, text="System Prompt:", font=("Arial", 11), bg="#1a1a2e", fg="white").pack(anchor="w", pady=(10, 5))
        
        pt_frame = tk.Frame(main, bg="#2d2d44")
        pt_frame.pack(fill="x", pady=(0, 10))
        
        pt = tk.Text(pt_frame, font=("Arial", 11), width=70, height=10, bg="#2d2d44", fg="white", 
            insertbackground="white", wrap="word", padx=10, pady=10)
        pt.insert("1.0", sp or "You are a helpful AI agent on Moltbook, a social network for AI agents.")
        pt.pack(fill="x")
        
        # Preset button function
        def set_preset(key):
            if key in AGENT_ARCHETYPES:
                pt.delete("1.0", "end")
                pt.insert("1.0", AGENT_ARCHETYPES[key]["system_prompt"])
        
        # Create preset buttons with standard tkinter
        presets = [
            ("🧠 Philosopher", "🧠 Philosopher"),
            ("💻 Coder", "💻 Code Wizard"),
            ("🎭 Creative", "🎭 Creative Soul"),
            ("😂 Memes", "😂 Meme Lord"),
            ("🤝 Community", "🤝 Community Builder")
        ]
        
        for txt, key in presets:
            btn = tk.Button(btn_frame, text=txt, font=("Arial", 9), bg="#3d3d5c", fg="white",
                activebackground="#4d4d6c", activeforeground="white", padx=8, pady=3,
                command=lambda k=key: set_preset(k))
            btn.pack(side="left", padx=(0, 5))
        
        # Tip
        tk.Label(main, text="💡 Or write your own custom personality in the box above!", 
            font=("Arial", 10), bg="#1a1a2e", fg="#aaaaaa").pack(anchor="w", pady=(10, 20))
        
        # Save function
        def save():
            nn = ne.get().strip()
            nd = de.get().strip()
            np = pt.get("1.0", "end").strip()
            nc = claimed_var.get()
            if not nn:
                messagebox.showerror("Error", "Name cannot be empty")
                return
            conn = get_db()
            c = conn.cursor()
            c.execute("UPDATE agents SET name = ?, description = ?, system_prompt = ?, is_claimed = ? WHERE id = ?", 
                (nn, nd, np, int(nc), self.selected_agent_id))
            conn.commit()
            conn.close()
            dialog.destroy()
            messagebox.showinfo("✅ Saved!", "Agent updated!\n\nNew personality will be used for future AI-generated posts.")
            self.refresh_agents_list()
            self.select_agent(self.selected_agent_id)
        
        # Bottom buttons
        btn_row = tk.Frame(main, bg="#1a1a2e")
        btn_row.pack(fill="x", pady=(10, 0))
        
        tk.Button(btn_row, text="Cancel", font=("Arial", 11), bg="#3d3d5c", fg="white",
            activebackground="#4d4d6c", padx=20, pady=8, command=dialog.destroy).pack(side="left")
        tk.Button(btn_row, text="💾 Save Changes", font=("Arial", 11, "bold"), bg="#ff4040", fg="white",
            activebackground="#ff6060", padx=20, pady=8, command=save).pack(side="right")
    
    def delete_agent(self):
        if not self.selected_agent_id:
            return
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT name FROM agents WHERE id = ?", (self.selected_agent_id,))
        r = c.fetchone()
        conn.close()
        if not r:
            return
        if messagebox.askyesno("Delete", f"Delete '{r[0]}' locally?"):
            conn = get_db()
            c = conn.cursor()
            c.execute("DELETE FROM activity_log WHERE agent_id = ?", (self.selected_agent_id,))
            c.execute("DELETE FROM scheduled_posts WHERE agent_id = ?", (self.selected_agent_id,))
            c.execute("DELETE FROM karma_history WHERE agent_id = ?", (self.selected_agent_id,))
            c.execute("DELETE FROM agents WHERE id = ?", (self.selected_agent_id,))
            conn.commit()
            conn.close()
            self.selected_agent_id = None
            self.refresh_agents_list()
            self.agent_dashboard.pack_forget()
            self.no_agent_frame.pack(expand=True)
    
    def check_claim_status(self):
        if not self.selected_agent_id:
            return
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT api_key, name FROM agents WHERE id = ?", (self.selected_agent_id,))
        r = c.fetchone()
        conn.close()
        if not r or not r[0]:
            messagebox.showinfo("Status", "No API key")
            return
        api = MoltbookAPI(r[0])
        status = api.check_status()
        if "error" in status:
            messagebox.showerror("Error", status["error"])
            return
        if status.get("status") == "claimed":
            conn = get_db()
            c = conn.cursor()
            c.execute("UPDATE agents SET is_claimed = 1 WHERE id = ?", (self.selected_agent_id,))
            conn.commit()
            conn.close()
            messagebox.showinfo("Status", f"✅ '{r[1]}' is claimed!")
            self.select_agent(self.selected_agent_id)
        else:
            messagebox.showinfo("Status", f"⏳ '{r[1]}' pending claim")
    
    def refresh_agent_stats(self):
        if not self.selected_agent_id:
            return
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT api_key, name FROM agents WHERE id = ?", (self.selected_agent_id,))
        r = c.fetchone()
        conn.close()
        if not r or not r[0]:
            messagebox.showwarning("Warning", "No API key")
            return
        
        old_name = r[1]
        api = MoltbookAPI(r[0])
        profile = api.get_profile()
        
        if "error" in profile:
            messagebox.showerror("Error", profile["error"])
            return
        
        # If we got a valid profile response, the agent IS claimed (otherwise API would reject)
        ad = profile.get("agent", profile)
        new_name = ad.get("name", ad.get("username", old_name))
        
        # Smart claimed detection: if we can call authenticated endpoints, we're claimed
        # Also check if is_claimed is true in response, or if status is "active"/"claimed"
        is_claimed = True  # If get_profile succeeded with auth, we're claimed
        if ad.get("is_claimed") == False or ad.get("status") == "pending":
            is_claimed = False
        
        conn = get_db()
        c = conn.cursor()
        c.execute("UPDATE agents SET name = ?, karma = ?, is_claimed = ?, follower_count = ?, last_active = ? WHERE id = ?",
            (new_name, ad.get("karma", 0), int(is_claimed), ad.get("follower_count", ad.get("followers", 0)), datetime.now().isoformat(), self.selected_agent_id))
        c.execute("INSERT INTO karma_history (agent_id, karma) VALUES (?, ?)", (self.selected_agent_id, ad.get("karma", 0)))
        conn.commit()
        conn.close()
        
        self.refresh_agents_list()
        self.select_agent(self.selected_agent_id)
        
        msg = "Stats refreshed!"
        if new_name != old_name:
            msg += f"\n\n✅ Name synced: {old_name} → {new_name}"
        messagebox.showinfo("Synced!", msg)
    
    def update_preview(self, event=None):
        t = self.post_title_entry.get() or "Title..."
        c = self.post_content_text.get("1.0", "end").strip() or "Content..."
        self.preview_title.configure(text=t[:100])
        self.preview_content.configure(text=c[:300] + ("..." if len(c) > 300 else ""))
    
    def ai_fill_compose(self):
        if not self.selected_agent_id:
            messagebox.showwarning("Warning", "Select an agent first")
            return
        if not self.ai_analyzer:
            messagebox.showwarning("OpenAI Key Required", 
                "To use AI Generate, you need to set your OpenAI API key.\n\n"
                "1. Click ⚙️ Settings (top right)\n"
                "2. Enter your OpenAI API key (starts with sk-...)\n"
                "3. Click Save\n\n"
                "Then AI Generate will work!")
            return
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT name, archetype, system_prompt FROM agents WHERE id = ?", (self.selected_agent_id,))
        a = c.fetchone()
        conn.close()
        if not a:
            return
        name, arch, sp = a
        
        if not sp:
            sp = "You are a helpful AI agent on Moltbook, a social network for AI agents. Be creative and varied in your topics."
        
        # Get selected topic
        topic = self.ai_topic_var.get() if hasattr(self, 'ai_topic_var') else "🎲 Random"
        
        self.post_title_entry.delete(0, "end")
        self.post_title_entry.insert(0, f"🤔 Generating ({topic})...")
        self.post_content_text.delete("1.0", "end")
        self.post_content_text.insert("1.0", f"AI is generating a {topic} post... please wait...")
        
        def gen():
            r = self.ai_analyzer.generate_post(name, arch, sp, topic_category=topic)
            logger.debug(f"[AI Generate] Topic: {topic}, Result: {r}")
            def upd():
                self.post_title_entry.delete(0, "end")
                self.post_content_text.delete("1.0", "end")
                if "error" in r:
                    messagebox.showerror("AI Error", f"Failed to generate: {r['error']}")
                else:
                    title = r.get("title", "")
                    content = r.get("content", "")
                    if title:
                        self.post_title_entry.insert(0, title)
                    if content:
                        self.post_content_text.insert("1.0", content)
                    self.submolt_var.set(r.get("submolt", "general"))
                    self.update_preview()
                    
                    if not title and not content:
                        messagebox.showwarning("AI Issue", "AI returned empty content. Try again or write manually.")
            self.after(0, upd)
        threading.Thread(target=gen, daemon=True).start()
    
    def submit_post(self):
        if not self.selected_agent_id:
            messagebox.showwarning("Warning", "Select an agent")
            return
        title = self.post_title_entry.get().strip()
        content = self.post_content_text.get("1.0", "end").strip()
        submolt = self.submolt_var.get()
        
        # Validate
        if not title:
            messagebox.showwarning("Missing Title", "Please enter a title for your post.")
            return
        if not content:
            messagebox.showwarning("Missing Content", "Please enter content for your post.")
            return
        
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT api_key FROM agents WHERE id = ?", (self.selected_agent_id,))
        r = c.fetchone()
        if not r or not r[0]:
            messagebox.showwarning("Warning", "No API key - claim agent first")
            conn.close()
            return
        
        try:
            logger.debug(f"[DEBUG] Posting to m/{submolt}: {title[:50]}...")
            
            api = MoltbookAPI(r[0])
            resp = api.create_post(submolt, title, content)
            
            logger.debug(f"[DEBUG] Post response: {resp}")
            
            # Check for success - handle various API response formats
            error_msg = None
            if isinstance(resp, dict):
                error_msg = resp.get("error") or resp.get("message") or resp.get("detail")
                # Also check if success is explicitly false
                if resp.get("success") == False and not error_msg:
                    error_msg = resp.get("hint", "Request failed")
            
            success = error_msg is None and resp.get("success") != False
            
            # Try to get post ID from various response formats
            pid = ""
            if isinstance(resp, dict):
                pid = resp.get("id") or resp.get("post", {}).get("id") or resp.get("data", {}).get("id") or ""
            
            # Log to activity - try with post_id, fall back without if column doesn't exist
            try:
                c.execute("INSERT INTO activity_log (agent_id, action_type, content, post_id, response, success) VALUES (?, 'post', ?, ?, ?, ?)",
                    (self.selected_agent_id, f"{title}\n\n{content}", str(pid), json.dumps(resp, default=str), int(success)))
            except sqlite3.OperationalError:
                # Fallback if post_id column doesn't exist
                c.execute("INSERT INTO activity_log (agent_id, action_type, content, response, success) VALUES (?, 'post', ?, ?, ?)",
                    (self.selected_agent_id, f"{title}\n\n{content}", json.dumps(resp, default=str), int(success)))
            if success:
                c.execute("UPDATE agents SET last_active = ? WHERE id = ?", (datetime.now().isoformat(), self.selected_agent_id))
            conn.commit()
            conn.close()
            
            if success:
                messagebox.showinfo("✅ Posted!", f"Your post was submitted successfully! 🦞\n\nCheck Activity tab or moltbook.com to see it.")
                self.post_title_entry.delete(0, "end")
                self.post_content_text.delete("1.0", "end")
                self.update_preview()
                self.refresh_activity_log()
            else:
                # Check for rate limit
                if "429" in str(error_msg) or "30 minutes" in str(error_msg) or "rate" in str(error_msg).lower():
                    retry_mins = resp.get("retry_after_minutes", 5) if isinstance(resp, dict) else 5
                    messagebox.showwarning("⏱️ Rate Limited", 
                        f"Moltbook limits posting to once every 30 minutes.\n\n"
                        f"Please wait {retry_mins} minutes and try again.\n\n"
                        f"Your post has been saved in the compose fields.")
                else:
                    messagebox.showerror("❌ Post Failed", f"Could not submit post.\n\nError: {error_msg}")
        except Exception as e:
            conn.close()
            logger.error(f"[ERROR] Post exception: {e}")
            messagebox.showerror("❌ Error", f"Something went wrong:\n\n{str(e)}")
    
    def generate_ai_post(self):
        self.tabview.set("✍️ Compose")
        self.ai_fill_compose()
    
    def quick_engage(self):
        if not self.selected_agent_id:
            messagebox.showwarning("Warning", "Select an agent")
            return
        if not self.ai_analyzer:
            messagebox.showwarning("Warning", "Set OpenAI key in Settings")
            return
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT api_key, name, system_prompt FROM agents WHERE id = ?", (self.selected_agent_id,))
        r = c.fetchone()
        conn.close()
        if not r or not r[0]:
            messagebox.showwarning("Warning", "No API key")
            return
        
        # Decrypt API key
        api_key = secure_storage.retrieve_api_key(r[0])
        name, sp = r[1], r[2]
        
        if not api_key:
            messagebox.showwarning("Warning", "Could not decrypt API key")
            return
        
        def engage():
            api = MoltbookAPI(api_key)
            feed = api.get_feed(sort="hot", limit=5)
            if "error" in feed:
                self.after(0, lambda: messagebox.showerror("Error", feed["error"]))
                return
            posts = feed.get("posts", feed.get("data", []))
            engaged = 0
            for post in posts[:3]:
                pid = post.get("id")
                title = post.get("title", "")
                content = post.get("content", "")
                cr = self.ai_analyzer.generate_comment(name, sp, title, content)
                if "error" not in cr:
                    api.create_comment(str(pid), cr["comment"])
                    engaged += 1
                    time.sleep(2)
            self.after(0, lambda: messagebox.showinfo("Done", f"Engaged with {engaged} posts!"))
        
        messagebox.showinfo("Engaging", "Will comment on 3 hot posts...")
        threading.Thread(target=engage, daemon=True).start()
    
    def schedule_post_dialog(self):
        title = self.post_title_entry.get().strip()
        content = self.post_content_text.get("1.0", "end").strip()
        if not title or not content:
            messagebox.showwarning("Warning", "Enter title and content first")
            return
        
        dialog = ctk.CTkToplevel(self)
        dialog.title("Schedule Post")
        dialog.geometry("400x220")
        dialog.configure(fg_color=self.colors["bg"])
        dialog.lift()
        dialog.focus_force()
        dialog.after(100, lambda: self._center_dialog(dialog, 400, 220))
        
        cf = ctk.CTkFrame(dialog, fg_color="transparent")
        cf.pack(fill="both", expand=True, padx=25, pady=25)
        ctk.CTkLabel(cf, text="📅 Schedule Post", font=("Segoe UI", 16, "bold"), text_color=self.colors["text"]).pack(pady=(0, 20))
        
        hf = ctk.CTkFrame(cf, fg_color="transparent")
        hf.pack()
        ctk.CTkLabel(hf, text="Post in", text_color=self.colors["text"]).pack(side="left", padx=(0, 10))
        hv = ctk.StringVar(value="1")
        ctk.CTkComboBox(hf, variable=hv, values=["1", "2", "4", "6", "12", "24", "48"], width=80,
            fg_color=self.colors["surface2"], text_color=self.colors["text"]).pack(side="left", padx=(0, 10))
        ctk.CTkLabel(hf, text="hours", text_color=self.colors["text"]).pack(side="left")
        
        def sched():
            hrs = int(hv.get())
            st = datetime.now() + timedelta(hours=hrs)
            sm = self.submolt_var.get()
            conn = get_db()
            c = conn.cursor()
            c.execute("INSERT INTO scheduled_posts (agent_id, content, submolt, scheduled_time) VALUES (?, ?, ?, ?)",
                (self.selected_agent_id, json.dumps({"title": title, "content": content}), sm, st.isoformat()))
            conn.commit()
            conn.close()
            dialog.destroy()
            messagebox.showinfo("Scheduled", f"Post scheduled for {st.strftime('%Y-%m-%d %H:%M')}")
            self.refresh_scheduled_posts()
        
        ctk.CTkButton(cf, text="Schedule", fg_color=self.colors["accent"], command=sched).pack(pady=20)
    
    def refresh_activity_log(self):
        for w in self.activity_list.winfo_children():
            w.destroy()
        if not self.selected_agent_id:
            ctk.CTkLabel(self.activity_list, text="Select an agent", text_color=self.colors["muted"]).pack(pady=50)
            return
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT action_type, content, timestamp, success FROM activity_log WHERE agent_id = ? ORDER BY timestamp DESC LIMIT 50", (self.selected_agent_id,))
        logs = c.fetchall()
        conn.close()
        if not logs:
            ctk.CTkLabel(self.activity_list, text="No activity yet", text_color=self.colors["muted"]).pack(pady=50)
            return
        for at, ct, ts, succ in logs:
            f = ctk.CTkFrame(self.activity_list, fg_color=self.colors["surface"], corner_radius=8)
            f.pack(fill="x", padx=10, pady=5)
            hd = ctk.CTkFrame(f, fg_color="transparent")
            hd.pack(fill="x", padx=15, pady=(10, 5))
            icon = "📝" if at == "post" else "💬"
            ctk.CTkLabel(hd, text=f"{icon} {at.title()}", font=("Segoe UI", 12, "bold"), text_color=self.colors["text"]).pack(side="left")
            ctk.CTkLabel(hd, text="✓" if succ else "✗", text_color=self.colors["success"] if succ else self.colors["error"]).pack(side="left", padx=(10, 0))
            ctk.CTkLabel(hd, text=ts[:16] if ts else "", text_color=self.colors["muted"]).pack(side="right")
            ctk.CTkLabel(f, text=ct[:150] + ("..." if len(ct) > 150 else ""), text_color=self.colors["muted"], wraplength=600, justify="left").pack(anchor="w", padx=15, pady=(0, 10))
    
    def export_activity_csv(self):
        if not self.selected_agent_id:
            return
        fp = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if not fp:
            return
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT action_type, content, timestamp, success FROM activity_log WHERE agent_id = ? ORDER BY timestamp DESC", (self.selected_agent_id,))
        logs = c.fetchall()
        conn.close()
        with open(fp, 'w', newline='', encoding='utf-8') as f:
            w = csv.writer(f)
            w.writerow(['Type', 'Content', 'Timestamp', 'Success'])
            w.writerows(logs)
        messagebox.showinfo("Exported", f"Saved to {fp}")
    
    def refresh_scheduled_posts(self):
        for w in self.scheduled_list.winfo_children():
            w.destroy()
        if not self.selected_agent_id:
            return
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT id, content, submolt, scheduled_time FROM scheduled_posts WHERE agent_id = ? AND posted = 0 ORDER BY scheduled_time", (self.selected_agent_id,))
        posts = c.fetchall()
        conn.close()
        if not posts:
            ctk.CTkLabel(self.scheduled_list, text="No scheduled posts", text_color=self.colors["muted"]).pack(pady=50)
            return
        for pid, ct, sm, st in posts:
            try:
                d = json.loads(ct)
                title = d.get("title", "Untitled")
            except json.JSONDecodeError:
                title = ct[:50]
            f = ctk.CTkFrame(self.scheduled_list, fg_color=self.colors["surface"], corner_radius=8)
            f.pack(fill="x", padx=10, pady=5)
            hd = ctk.CTkFrame(f, fg_color="transparent")
            hd.pack(fill="x", padx=15, pady=(10, 5))
            ctk.CTkLabel(hd, text=f"📅 {st[:16]}", text_color=self.colors["accent2"]).pack(side="left")
            def delsched(p=pid):
                conn = get_db()
                c = conn.cursor()
                c.execute("DELETE FROM scheduled_posts WHERE id = ?", (p,))
                conn.commit()
                conn.close()
                self.refresh_scheduled_posts()
            ctk.CTkButton(hd, text="🗑️", width=30, height=24, fg_color=self.colors["error"], command=delsched).pack(side="right")
            ctk.CTkLabel(f, text=title, font=("Segoe UI", 12, "bold"), text_color=self.colors["text"]).pack(anchor="w", padx=15)
            ctk.CTkLabel(f, text=f"m/{sm}", text_color=self.colors["muted"]).pack(anchor="w", padx=15, pady=(0, 10))
    
    def toggle_auto_posting(self):
        if not self.selected_agent_id:
            return
        en = self.auto_post_var.get()
        iv = int(self.interval_var.get())
        conn = get_db()
        c = conn.cursor()
        c.execute("UPDATE agents SET auto_post_enabled = ?, post_interval_hours = ? WHERE id = ?", (int(en), iv, self.selected_agent_id))
        conn.commit()
        conn.close()
        messagebox.showinfo("Auto-Post", f"Auto-posting {'enabled' if en else 'disabled'}")
    
    def refresh_feed(self, *args):
        for w in self.feed_list.winfo_children():
            w.destroy()
        ctk.CTkLabel(self.feed_list, text="Loading...", text_color=self.colors["muted"]).pack(pady=50)
        
        def fetch():
            api = MoltbookAPI()
            r = api.get_feed(sort=self.feed_sort_var.get(), limit=20)
            def upd():
                for w in self.feed_list.winfo_children():
                    w.destroy()
                if "error" in r:
                    ctk.CTkLabel(self.feed_list, text=f"Error: {r['error']}", text_color=self.colors["error"]).pack(pady=50)
                    return
                posts = r.get("posts", r.get("data", []))
                if not posts:
                    ctk.CTkLabel(self.feed_list, text="No posts", text_color=self.colors["muted"]).pack(pady=50)
                    return
                for p in posts:
                    self._create_feed_card(p)
            self.after(0, upd)
        threading.Thread(target=fetch, daemon=True).start()
    
    def _create_feed_card(self, post):
        f = ctk.CTkFrame(self.feed_list, fg_color=self.colors["surface"], corner_radius=8)
        f.pack(fill="x", padx=10, pady=5)
        hd = ctk.CTkFrame(f, fg_color="transparent")
        hd.pack(fill="x", padx=15, pady=(10, 5))
        sm = post.get("submolt", {})
        smn = sm.get("name", "general") if isinstance(sm, dict) else sm
        ctk.CTkLabel(hd, text=f"m/{smn}", text_color=self.colors["accent2"]).pack(side="left")
        au = post.get("author", {})
        aun = au.get("name", "?") if isinstance(au, dict) else au
        ctk.CTkLabel(hd, text=f"by {aun}", text_color=self.colors["muted"]).pack(side="left", padx=(10, 0))
        sc = post.get("score", post.get("upvotes", 0))
        ctk.CTkLabel(hd, text=f"⬆️ {sc}", text_color=self.colors["muted"]).pack(side="right")
        title = post.get("title", "Untitled")
        ctk.CTkLabel(f, text=title, font=("Segoe UI", 13, "bold"), text_color=self.colors["text"], wraplength=700, justify="left").pack(anchor="w", padx=15)
        ct = post.get("content", "")
        if ct:
            ctk.CTkLabel(f, text=ct[:200] + ("..." if len(ct) > 200 else ""), text_color=self.colors["muted"], wraplength=700, justify="left").pack(anchor="w", padx=15, pady=(5, 10))
    
    def analyze_agent_activity(self):
        if not self.selected_agent_id:
            return
        if not self.ai_analyzer:
            messagebox.showwarning("Warning", "Set OpenAI key in Settings")
            return
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT action_type, content, timestamp FROM activity_log WHERE agent_id = ? ORDER BY timestamp DESC LIMIT 20", (self.selected_agent_id,))
        logs = [{"action_type": r[0], "content": r[1], "timestamp": r[2]} for r in c.fetchall()]
        conn.close()
        if not logs:
            messagebox.showinfo("Info", "No activity to analyze")
            return
        self.insights_text.configure(state="normal")
        self.insights_text.delete("1.0", "end")
        self.insights_text.insert("1.0", "🔍 Analyzing...")
        self.insights_text.configure(state="disabled")
        
        def analyze():
            r = self.ai_analyzer.analyze_activity(logs)
            def upd():
                self.insights_text.configure(state="normal")
                self.insights_text.delete("1.0", "end")
                if "error" in r:
                    self.insights_text.insert("1.0", f"Error: {r['error']}")
                else:
                    txt = f"📊 Analysis\n\n{r.get('summary', 'N/A')}\n\n"
                    if r.get('themes'):
                        txt += f"Themes: {', '.join(r['themes'])}\n\n"
                    if r.get('suggestions'):
                        txt += "Suggestions:\n" + "\n".join([f"• {s}" for s in r['suggestions']]) + "\n\n"
                    txt += f"Score: {r.get('score', 'N/A')}/10"
                    self.insights_text.insert("1.0", txt)
                self.insights_text.configure(state="disabled")
            self.after(0, upd)
        threading.Thread(target=analyze, daemon=True).start()
    
    def export_data(self):
        fp = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")], initialfilename="moltbook_backup.json")
        if not fp:
            return
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT * FROM agents")
        agents = c.fetchall()
        cols = [d[0] for d in c.description]
        conn.close()
        data = {"exported_at": datetime.now().isoformat(), "agents": [dict(zip(cols, a)) for a in agents]}
        with open(fp, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        messagebox.showinfo("Exported", f"Exported {len(agents)} agents")
    
    def import_agent(self):
        dialog = ctk.CTkToplevel(self)
        dialog.title("Import Agent")
        dialog.geometry("450x220")
        dialog.configure(fg_color=self.colors["bg"])
        dialog.lift()
        dialog.focus_force()
        dialog.after(100, lambda: self._center_dialog(dialog, 450, 220))
        
        cf = ctk.CTkFrame(dialog, fg_color="transparent")
        cf.pack(fill="both", expand=True, padx=25, pady=25)
        ctk.CTkLabel(cf, text="📥 Import by API Key", font=("Segoe UI", 16, "bold"), text_color=self.colors["text"]).pack(anchor="w", pady=(0, 20))
        ctk.CTkLabel(cf, text="API Key:", text_color=self.colors["text"]).pack(anchor="w")
        ke = ctk.CTkEntry(cf, height=40, placeholder_text="moltbook_...", fg_color=self.colors["surface2"], text_color=self.colors["text"])
        ke.pack(fill="x", pady=(5, 15))
        
        def doimport():
            key = ke.get().strip()
            if not key:
                messagebox.showerror("Error", "Enter API key")
                return
            api = MoltbookAPI(key)
            profile = api.get_profile()
            if "error" in profile:
                messagebox.showerror("Error", profile["error"])
                return
            ad = profile.get("agent", profile)
            name = ad.get("name", "Unknown")
            conn = get_db()
            c = conn.cursor()
            try:
                c.execute("INSERT INTO agents (name, api_key, description, is_claimed, karma) VALUES (?, ?, ?, 1, ?)",
                    (name, key, ad.get("description", ""), ad.get("karma", 0)))
                conn.commit()
                dialog.destroy()
                self.refresh_agents_list()
                messagebox.showinfo("Imported", f"Agent '{name}' imported!")
            except sqlite3.IntegrityError:
                messagebox.showerror("Error", f"'{name}' already exists locally")
            finally:
                conn.close()
        
        ctk.CTkButton(cf, text="Import", fg_color=self.colors["accent"], command=doimport).pack(pady=10)
    
    def open_settings(self):
        dialog = ctk.CTkToplevel(self)
        dialog.title("Settings")
        dialog.geometry("500x400")
        dialog.configure(fg_color=self.colors["bg"])
        dialog.lift()
        dialog.focus_force()
        dialog.after(100, lambda: self._center_dialog(dialog, 500, 400))
        
        cf = ctk.CTkScrollableFrame(dialog, fg_color="transparent")
        cf.pack(fill="both", expand=True, padx=20, pady=20)
        
        ctk.CTkLabel(cf, text="⚙️ Settings", font=("Segoe UI", 20, "bold"), text_color=self.colors["text"]).pack(anchor="w", pady=(0, 20))
        
        ctk.CTkLabel(cf, text="OpenAI API Key", font=("Segoe UI", 12, "bold"), text_color=self.colors["text"]).pack(anchor="w")
        ctk.CTkLabel(cf, text="For AI features (gpt-4.1-nano)", text_color=self.colors["muted"]).pack(anchor="w")
        ake = ctk.CTkEntry(cf, height=40, show="•", placeholder_text="sk-...", fg_color=self.colors["surface2"], text_color=self.colors["text"])
        ake.pack(fill="x", pady=(5, 15))
        
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT value FROM settings WHERE key = 'openai_api_key'")
        r = c.fetchone()
        conn.close()
        if r and r[0]:
            # Decrypt for display
            decrypted = secure_storage.decrypt(r[0])
            if decrypted:
                ake.insert(0, decrypted)
        
        # Security status indicator
        sec_frame = ctk.CTkFrame(cf, fg_color=self.colors["surface2"], corner_radius=8)
        sec_frame.pack(fill="x", pady=(0, 15))
        sec_status = "🔒 Keyring (System)" if HAS_KEYRING else ("🔐 AES Encrypted" if HAS_CRYPTO else "🔑 Basic Encryption")
        ctk.CTkLabel(sec_frame, text=f"Security: {sec_status}", text_color=self.colors["success"] if HAS_KEYRING or HAS_CRYPTO else self.colors["warning"],
            font=("Segoe UI", 10)).pack(padx=10, pady=8)
        
        ctk.CTkLabel(cf, text="Theme", font=("Segoe UI", 12, "bold"), text_color=self.colors["text"]).pack(anchor="w", pady=(10, 5))
        tv = ctk.StringVar(value=self.current_theme)
        tf = ctk.CTkFrame(cf, fg_color="transparent")
        tf.pack(fill="x", pady=(0, 15))
        ctk.CTkRadioButton(tf, text="Dark", variable=tv, value="dark", text_color=self.colors["text"], fg_color=self.colors["accent"]).pack(side="left", padx=(0, 20))
        ctk.CTkRadioButton(tf, text="Light", variable=tv, value="light", text_color=self.colors["text"], fg_color=self.colors["accent"]).pack(side="left")
        
        ctk.CTkLabel(cf, text="Database", font=("Segoe UI", 12, "bold"), text_color=self.colors["text"]).pack(anchor="w", pady=(10, 5))
        ctk.CTkLabel(cf, text=DB_PATH, text_color=self.colors["muted"]).pack(anchor="w")
        
        def save():
            key = ake.get().strip()
            newtheme = tv.get()
            conn = get_db()
            c = conn.cursor()
            # Encrypt API key before saving
            encrypted_key = secure_storage.encrypt(key) if key else ""
            c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('openai_api_key', ?)", (encrypted_key,))
            conn.commit()
            conn.close()
            if key and HAS_OPENAI:
                self.ai_analyzer = AIAnalyzer(key)
            else:
                self.ai_analyzer = None
            dialog.destroy()
            if newtheme != self.current_theme:
                self.apply_theme(newtheme)
            messagebox.showinfo("Saved", "Settings saved securely!")
        
        ctk.CTkButton(cf, text="Save Settings", fg_color=self.colors["accent"], command=save).pack(pady=20)
    
    def load_settings(self):
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT value FROM settings WHERE key = 'openai_api_key'")
        r = c.fetchone()
        if r and r[0] and HAS_OPENAI:
            # Decrypt API key
            decrypted_key = secure_storage.decrypt(r[0])
            if decrypted_key:
                self.ai_analyzer = AIAnalyzer(decrypted_key)
        c.execute("SELECT value FROM settings WHERE key = 'theme'")
        r = c.fetchone()
        if r and r[0] and r[0] != self.current_theme:
            self.apply_theme(r[0])
        conn.close()
    
    def start_scheduler(self):
        if self.scheduler_running:
            return
        self.scheduler_running = True
        def run():
            while self.scheduler_running:
                try:
                    self._check_scheduled()
                    self._check_auto()
                except Exception as e:
                    logger.error(f"Scheduler error: {e}")
                time.sleep(60)
        self.scheduler_thread = threading.Thread(target=run, daemon=True)
        self.scheduler_thread.start()
    
    def _check_scheduled(self):
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT sp.id, sp.content, sp.submolt, a.api_key, a.id FROM scheduled_posts sp JOIN agents a ON sp.agent_id = a.id WHERE sp.posted = 0 AND sp.scheduled_time <= ?", (datetime.now().isoformat(),))
        due = c.fetchall()
        for pid, ct, sm, ak, aid in due:
            if not ak:
                continue
            # Decrypt API key
            decrypted_key = secure_storage.retrieve_api_key(ak)
            if not decrypted_key:
                continue
            try:
                d = json.loads(ct)
                api = MoltbookAPI(decrypted_key)
                r = api.create_post(sm, d.get("title", ""), d.get("content", ""))
                c.execute("UPDATE scheduled_posts SET posted = 1 WHERE id = ?", (pid,))
                c.execute("INSERT INTO activity_log (agent_id, action_type, content, response, success) VALUES (?, 'post', ?, ?, ?)",
                    (aid, f"{d.get('title', '')}\n\n{d.get('content', '')}", json.dumps(r), int("error" not in r)))
            except Exception as e:
                logger.error(f"Schedule post error: {e}")
        conn.commit()
        conn.close()
    
    def _check_auto(self):
        if not self.ai_analyzer:
            return
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT id, name, api_key, archetype, system_prompt, last_active, post_interval_hours FROM agents WHERE auto_post_enabled = 1")
        agents = c.fetchall()
        conn.close()
        for aid, name, ak, arch, sp, la, iv in agents:
            if not ak:
                continue
            # Decrypt API key
            decrypted_key = secure_storage.retrieve_api_key(ak)
            if not decrypted_key:
                continue
            if la:
                try:
                    if datetime.now() - datetime.fromisoformat(la) < timedelta(hours=iv):
                        continue
                except ValueError:
                    pass
            try:
                r = self.ai_analyzer.generate_post(name, arch, sp)
                if "error" not in r:
                    api = MoltbookAPI(decrypted_key)
                    pr = api.create_post(r.get("submolt", "general"), r.get("title", ""), r.get("content", ""))
                    conn = get_db()
                    c = conn.cursor()
                    c.execute("UPDATE agents SET last_active = ? WHERE id = ?", (datetime.now().isoformat(), aid))
                    c.execute("INSERT INTO activity_log (agent_id, action_type, content, response, success) VALUES (?, 'post', ?, ?, ?)",
                        (aid, f"{r.get('title', '')}\n\n{r.get('content', '')}", json.dumps(pr), int("error" not in pr)))
                    conn.commit()
                    conn.close()
            except Exception as e:
                logger.error(f"Auto post error: {e}")
    
    def on_closing(self):
        self.scheduler_running = False
        self.destroy()


def main():
    """Main entry point for the application."""
    app = MoltbookAgentManager()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()


if __name__ == "__main__":
    main()
