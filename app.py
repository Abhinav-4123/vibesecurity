"""
VibeSecurity - AI-Powered Security Analysis Platform
Landing page + Auth + API
"""
import os
import json
import uuid
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional, List, Dict
from dataclasses import dataclass, field, asdict

from fastapi import FastAPI, HTTPException, Request, Form, Depends
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from pydantic import BaseModel


# ============== INLINE AUTH SYSTEM ==============

@dataclass
class User:
    id: str
    email: str
    password_hash: str
    name: str = ""
    company: str = ""
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    verified: bool = False
    api_keys: List[str] = field(default_factory=list)
    plan: str = "free"
    usage: Dict = field(default_factory=lambda: {"scans": 0, "api_calls": 0})


class AuthSystem:
    def __init__(self, data_file: str = "users.json"):
        self.data_file = data_file
        self.users: Dict[str, User] = {}
        self.api_keys: Dict[str, dict] = {}
        self.sessions: Dict[str, Dict] = {}
        self._load_data()

    def _load_data(self):
        if os.path.exists(self.data_file):
            try:
                with open(self.data_file, 'r') as f:
                    data = json.load(f)
                    for uid, udata in data.get("users", {}).items():
                        self.users[uid] = User(**udata)
                    self.api_keys = data.get("api_keys", {})
            except:
                pass

    def _save_data(self):
        data = {
            "users": {uid: asdict(u) for uid, u in self.users.items()},
            "api_keys": self.api_keys
        }
        with open(self.data_file, 'w') as f:
            json.dump(data, f, indent=2)

    def _hash_password(self, password: str, salt: str = None) -> tuple:
        if salt is None:
            salt = secrets.token_hex(16)
        hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex()
        return f"{salt}:{hashed}", salt

    def _verify_password(self, password: str, stored_hash: str) -> bool:
        try:
            salt, _ = stored_hash.split(':')
            new_hash, _ = self._hash_password(password, salt)
            return new_hash == stored_hash
        except:
            return False

    def signup(self, email: str, password: str, name: str = "", company: str = "") -> Dict:
        for user in self.users.values():
            if user.email.lower() == email.lower():
                return {"success": False, "error": "Email already registered"}
        if len(password) < 8:
            return {"success": False, "error": "Password must be at least 8 characters"}

        user_id = f"user_{uuid.uuid4().hex[:12]}"
        password_hash, _ = self._hash_password(password)
        user = User(id=user_id, email=email.lower(), password_hash=password_hash, name=name, company=company)
        self.users[user_id] = user
        api_key = self.generate_api_key(user_id, "Default Key")
        self._save_data()
        return {"success": True, "user_id": user_id, "api_key": api_key["key"]}

    def login(self, email: str, password: str) -> Dict:
        user = None
        for u in self.users.values():
            if u.email.lower() == email.lower():
                user = u
                break
        if not user or not self._verify_password(password, user.password_hash):
            return {"success": False, "error": "Invalid email or password"}

        session_token = secrets.token_urlsafe(32)
        self.sessions[session_token] = {"user_id": user.id, "expires_at": (datetime.now() + timedelta(days=7)).isoformat()}
        return {"success": True, "user_id": user.id, "email": user.email, "name": user.name, "session_token": session_token, "plan": user.plan}

    def logout(self, session_token: str) -> bool:
        if session_token in self.sessions:
            del self.sessions[session_token]
            return True
        return False

    def get_user_from_session(self, session_token: str) -> Optional[User]:
        session = self.sessions.get(session_token)
        if not session:
            return None
        if datetime.fromisoformat(session["expires_at"]) < datetime.now():
            del self.sessions[session_token]
            return None
        return self.users.get(session["user_id"])

    def generate_api_key(self, user_id: str, name: str = "API Key") -> Dict:
        if user_id not in self.users:
            return {"success": False, "error": "User not found"}
        key = f"vs_live_{secrets.token_urlsafe(24)}"
        self.api_keys[key] = {"key": key, "user_id": user_id, "name": name, "created_at": datetime.now().isoformat(), "active": True}
        self.users[user_id].api_keys.append(key)
        self._save_data()
        return {"success": True, "key": key, "name": name}

    def validate_api_key(self, key: str) -> Optional[Dict]:
        api_key = self.api_keys.get(key)
        if not api_key or not api_key.get("active"):
            return None
        user = self.users.get(api_key["user_id"])
        if not user:
            return None
        user.usage["api_calls"] = user.usage.get("api_calls", 0) + 1
        self._save_data()
        return {"user_id": user.id, "email": user.email, "plan": user.plan}

    def get_user_api_keys(self, user_id: str) -> List[Dict]:
        keys = []
        for key, api_key in self.api_keys.items():
            if api_key.get("user_id") == user_id:
                keys.append({"key": f"{key[:12]}...{key[-4:]}", "name": api_key.get("name", "Key"), "created_at": api_key.get("created_at"), "active": api_key.get("active", True)})
        return keys

    def get_stats(self) -> Dict:
        return {
            "total_users": len(self.users),
            "total_scans": sum(u.usage.get("scans", 0) for u in self.users.values()),
            "total_api_calls": sum(u.usage.get("api_calls", 0) for u in self.users.values())
        }

    def increment_scan_usage(self, user_id: str) -> bool:
        if user_id not in self.users:
            return False
        self.users[user_id].usage["scans"] = self.users[user_id].usage.get("scans", 0) + 1
        self._save_data()
        return True


auth_system = AuthSystem()

app = FastAPI(title="VibeSecurity", version="1.0.0")

# ============== LANDING PAGE ==============

LANDING_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VibeSecurity - AI-Powered Security Analysis</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Inter', sans-serif; background: #0a0a0f; color: #fff; }

        /* Gradient text */
        .gradient-text { background: linear-gradient(135deg, #00ff88, #00ccff); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }

        /* Navigation */
        nav { position: fixed; top: 0; width: 100%; padding: 20px 50px; display: flex; justify-content: space-between; align-items: center; z-index: 100; background: rgba(10, 10, 15, 0.9); backdrop-filter: blur(10px); }
        .logo { font-size: 24px; font-weight: 800; }
        .nav-links { display: flex; gap: 30px; }
        .nav-links a { color: #888; text-decoration: none; font-size: 14px; transition: color 0.3s; }
        .nav-links a:hover { color: #fff; }
        .nav-cta { display: flex; gap: 15px; }
        .btn { padding: 10px 24px; border-radius: 8px; font-size: 14px; font-weight: 600; cursor: pointer; transition: all 0.3s; text-decoration: none; }
        .btn-ghost { background: transparent; border: 1px solid #333; color: #fff; }
        .btn-ghost:hover { border-color: #00ff88; color: #00ff88; }
        .btn-primary { background: linear-gradient(135deg, #00ff88, #00ccff); border: none; color: #000; }
        .btn-primary:hover { transform: translateY(-2px); box-shadow: 0 10px 30px rgba(0, 255, 136, 0.3); }

        /* Hero */
        .hero { min-height: 100vh; display: flex; flex-direction: column; justify-content: center; align-items: center; text-align: center; padding: 120px 20px 80px; position: relative; overflow: hidden; }
        .hero::before { content: ''; position: absolute; top: 50%; left: 50%; width: 800px; height: 800px; background: radial-gradient(circle, rgba(0, 255, 136, 0.1) 0%, transparent 70%); transform: translate(-50%, -50%); }
        .hero-badge { background: rgba(0, 255, 136, 0.1); border: 1px solid rgba(0, 255, 136, 0.3); padding: 8px 16px; border-radius: 50px; font-size: 13px; color: #00ff88; margin-bottom: 30px; }
        .hero h1 { font-size: 64px; font-weight: 800; line-height: 1.1; max-width: 800px; margin-bottom: 24px; }
        .hero p { font-size: 20px; color: #888; max-width: 600px; margin-bottom: 40px; line-height: 1.6; }
        .hero-cta { display: flex; gap: 16px; }
        .hero-stats { display: flex; gap: 60px; margin-top: 80px; }
        .stat { text-align: center; }
        .stat-value { font-size: 36px; font-weight: 700; }
        .stat-label { font-size: 14px; color: #666; margin-top: 4px; }

        /* Features */
        .features { padding: 120px 50px; }
        .section-header { text-align: center; margin-bottom: 60px; }
        .section-header h2 { font-size: 42px; font-weight: 700; margin-bottom: 16px; }
        .section-header p { color: #888; font-size: 18px; }
        .features-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 30px; max-width: 1200px; margin: 0 auto; }
        .feature-card { background: #111; border: 1px solid #222; border-radius: 16px; padding: 40px; transition: all 0.3s; }
        .feature-card:hover { border-color: #00ff88; transform: translateY(-5px); }
        .feature-icon { width: 48px; height: 48px; background: linear-gradient(135deg, rgba(0, 255, 136, 0.2), rgba(0, 204, 255, 0.2)); border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 24px; margin-bottom: 20px; }
        .feature-card h3 { font-size: 20px; font-weight: 600; margin-bottom: 12px; }
        .feature-card p { color: #888; font-size: 15px; line-height: 1.6; }

        /* Security Frameworks */
        .frameworks { padding: 120px 50px; background: #0d0d12; }
        .framework-list { display: grid; grid-template-columns: repeat(5, 1fr); gap: 20px; max-width: 1200px; margin: 0 auto; }
        .framework { background: #111; border: 1px solid #222; border-radius: 12px; padding: 30px; text-align: center; transition: all 0.3s; }
        .framework:hover { border-color: #00ccff; }
        .framework h4 { font-size: 16px; font-weight: 600; margin-bottom: 8px; }
        .framework p { font-size: 12px; color: #666; }

        /* Pricing */
        .pricing { padding: 120px 50px; }
        .pricing-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 30px; max-width: 1000px; margin: 0 auto; }
        .price-card { background: #111; border: 1px solid #222; border-radius: 16px; padding: 40px; text-align: center; }
        .price-card.featured { border-color: #00ff88; position: relative; }
        .price-card.featured::before { content: 'POPULAR'; position: absolute; top: -12px; left: 50%; transform: translateX(-50%); background: linear-gradient(135deg, #00ff88, #00ccff); color: #000; padding: 4px 16px; border-radius: 50px; font-size: 11px; font-weight: 700; }
        .price-card h3 { font-size: 24px; margin-bottom: 8px; }
        .price-card .price { font-size: 48px; font-weight: 700; margin: 20px 0; }
        .price-card .price span { font-size: 16px; color: #888; }
        .price-card ul { list-style: none; margin: 30px 0; text-align: left; }
        .price-card li { padding: 10px 0; color: #888; font-size: 14px; border-bottom: 1px solid #222; }
        .price-card li::before { content: '✓'; color: #00ff88; margin-right: 10px; }

        /* CTA */
        .cta { padding: 120px 50px; text-align: center; background: linear-gradient(180deg, #0a0a0f 0%, #0d1a15 100%); }
        .cta h2 { font-size: 48px; font-weight: 700; margin-bottom: 20px; }
        .cta p { color: #888; font-size: 18px; margin-bottom: 40px; }

        /* Footer */
        footer { padding: 60px 50px; border-top: 1px solid #222; display: flex; justify-content: space-between; align-items: center; }
        footer p { color: #666; font-size: 14px; }

        /* Auth Modal */
        .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.8); z-index: 1000; align-items: center; justify-content: center; }
        .modal.active { display: flex; }
        .modal-content { background: #111; border: 1px solid #222; border-radius: 16px; padding: 40px; width: 400px; }
        .modal-content h2 { margin-bottom: 24px; }
        .form-group { margin-bottom: 16px; }
        .form-group label { display: block; font-size: 13px; color: #888; margin-bottom: 6px; }
        .form-group input { width: 100%; padding: 12px 16px; background: #0a0a0f; border: 1px solid #333; border-radius: 8px; color: #fff; font-size: 14px; }
        .form-group input:focus { outline: none; border-color: #00ff88; }
        .modal-close { position: absolute; top: 20px; right: 20px; background: none; border: none; color: #888; font-size: 24px; cursor: pointer; }

        @media (max-width: 768px) {
            .hero h1 { font-size: 36px; }
            .features-grid, .pricing-grid { grid-template-columns: 1fr; }
            .framework-list { grid-template-columns: repeat(2, 1fr); }
        }
    </style>
</head>
<body>
    <nav>
        <div class="logo"><span class="gradient-text">Vibe</span>Security</div>
        <div class="nav-links">
            <a href="#features">Features</a>
            <a href="#frameworks">Frameworks</a>
            <a href="#pricing">Pricing</a>
            <a href="/docs">API Docs</a>
        </div>
        <div class="nav-cta">
            <a href="#" class="btn btn-ghost" onclick="openModal('login')">Login</a>
            <a href="#" class="btn btn-primary" onclick="openModal('signup')">Get Started Free</a>
        </div>
    </nav>

    <section class="hero">
        <div class="hero-badge">🚀 Powered by Shannon AI Pentester</div>
        <h1>Autonomous <span class="gradient-text">Security Analysis</span> for Modern Apps</h1>
        <p>AI-powered penetration testing that finds and proves real vulnerabilities. VAPT, ISO 27001, OWASP Top 10 compliance in minutes, not months.</p>
        <div class="hero-cta">
            <a href="#" class="btn btn-primary" onclick="openModal('signup')">Start Free Security Scan</a>
            <a href="#demo" class="btn btn-ghost">Watch Demo</a>
        </div>
        <div class="hero-stats">
            <div class="stat">
                <div class="stat-value gradient-text">{total_users}</div>
                <div class="stat-label">Users</div>
            </div>
            <div class="stat">
                <div class="stat-value gradient-text">{total_scans}</div>
                <div class="stat-label">Scans Completed</div>
            </div>
            <div class="stat">
                <div class="stat-value gradient-text">96.15%</div>
                <div class="stat-label">Detection Rate</div>
            </div>
        </div>
    </section>

    <section class="features" id="features">
        <div class="section-header">
            <h2>Enterprise Security, <span class="gradient-text">Simplified</span></h2>
            <p>Everything you need to secure your applications</p>
        </div>
        <div class="features-grid">
            <div class="feature-card">
                <div class="feature-icon">🤖</div>
                <h3>Autonomous Pentesting</h3>
                <p>AI agents that think like hackers. Discovers and exploits real vulnerabilities with zero false positives.</p>
            </div>
            <div class="feature-card">
                <div class="feature-icon">⚡</div>
                <h3>Real-Time Scanning</h3>
                <p>Continuous security monitoring. Get alerted the moment a vulnerability is introduced.</p>
            </div>
            <div class="feature-card">
                <div class="feature-icon">📊</div>
                <h3>Compliance Reports</h3>
                <p>Auto-generated reports for VAPT, ISO 27001, SOC 2, PCI DSS. Audit-ready in minutes.</p>
            </div>
            <div class="feature-card">
                <div class="feature-icon">🔑</div>
                <h3>API Security</h3>
                <p>Deep API testing with automatic auth handling, schema validation, and injection testing.</p>
            </div>
            <div class="feature-card">
                <div class="feature-icon">🛡️</div>
                <h3>OWASP Top 10</h3>
                <p>Complete coverage of OWASP Top 10. SQL injection, XSS, SSRF, auth bypass, and more.</p>
            </div>
            <div class="feature-card">
                <div class="feature-icon">📝</div>
                <h3>Proof of Exploit</h3>
                <p>Every finding comes with reproducible proof-of-concept. No more chasing false positives.</p>
            </div>
        </div>
    </section>

    <section class="frameworks" id="frameworks">
        <div class="section-header">
            <h2>Security <span class="gradient-text">Frameworks</span></h2>
            <p>Comprehensive coverage across industry standards</p>
        </div>
        <div class="framework-list">
            <div class="framework">
                <h4>VAPT</h4>
                <p>Vulnerability Assessment & Penetration Testing</p>
            </div>
            <div class="framework">
                <h4>ISO 27001</h4>
                <p>Information Security Management</p>
            </div>
            <div class="framework">
                <h4>OWASP Top 10</h4>
                <p>Web Application Security</p>
            </div>
            <div class="framework">
                <h4>PCI DSS</h4>
                <p>Payment Card Security</p>
            </div>
            <div class="framework">
                <h4>SOC 2</h4>
                <p>Service Organization Control</p>
            </div>
        </div>
    </section>

    <section class="pricing" id="pricing">
        <div class="section-header">
            <h2>Simple <span class="gradient-text">Pricing</span></h2>
            <p>Start free, scale as you grow</p>
        </div>
        <div class="pricing-grid">
            <div class="price-card">
                <h3>Free</h3>
                <div class="price">$0<span>/month</span></div>
                <ul>
                    <li>3 scans per month</li>
                    <li>OWASP Top 10 coverage</li>
                    <li>Basic reports</li>
                    <li>Community support</li>
                </ul>
                <a href="#" class="btn btn-ghost" style="width:100%;display:block;text-align:center;" onclick="openModal('signup')">Get Started</a>
            </div>
            <div class="price-card featured">
                <h3>Pro</h3>
                <div class="price">$99<span>/month</span></div>
                <ul>
                    <li>Unlimited scans</li>
                    <li>All security frameworks</li>
                    <li>Compliance reports</li>
                    <li>API access</li>
                    <li>Priority support</li>
                </ul>
                <a href="#" class="btn btn-primary" style="width:100%;display:block;text-align:center;" onclick="openModal('signup')">Start Free Trial</a>
            </div>
            <div class="price-card">
                <h3>Enterprise</h3>
                <div class="price">Custom</div>
                <ul>
                    <li>Dedicated infrastructure</li>
                    <li>Custom integrations</li>
                    <li>SLA guarantee</li>
                    <li>On-premise option</li>
                    <li>24/7 support</li>
                </ul>
                <a href="mailto:enterprise@vibesecurity.in" class="btn btn-ghost" style="width:100%;display:block;text-align:center;">Contact Sales</a>
            </div>
        </div>
    </section>

    <section class="cta">
        <h2>Ready to <span class="gradient-text">Secure</span> Your App?</h2>
        <p>Join developers who ship secure code with confidence</p>
        <a href="#" class="btn btn-primary" onclick="openModal('signup')">Start Your Free Scan</a>
    </section>

    <footer>
        <p>&copy; 2025 VibeSecurity. Powered by Shannon AI.</p>
        <div class="nav-links">
            <a href="/privacy">Privacy</a>
            <a href="/terms">Terms</a>
            <a href="mailto:hello@vibesecurity.in">Contact</a>
        </div>
    </footer>

    <!-- Auth Modals -->
    <div class="modal" id="loginModal">
        <div class="modal-content" style="position:relative;">
            <button class="modal-close" onclick="closeModal('login')">&times;</button>
            <h2>Welcome Back</h2>
            <form action="/api/login" method="POST">
                <div class="form-group">
                    <label>Email</label>
                    <input type="email" name="email" required placeholder="you@company.com">
                </div>
                <div class="form-group">
                    <label>Password</label>
                    <input type="password" name="password" required placeholder="••••••••">
                </div>
                <button type="submit" class="btn btn-primary" style="width:100%;margin-top:16px;">Login</button>
            </form>
            <p style="text-align:center;margin-top:16px;color:#888;font-size:13px;">Don't have an account? <a href="#" onclick="switchModal('login','signup')" style="color:#00ff88;">Sign up</a></p>
        </div>
    </div>

    <div class="modal" id="signupModal">
        <div class="modal-content" style="position:relative;">
            <button class="modal-close" onclick="closeModal('signup')">&times;</button>
            <h2>Create Account</h2>
            <form action="/api/signup" method="POST">
                <div class="form-group">
                    <label>Full Name</label>
                    <input type="text" name="name" required placeholder="John Doe">
                </div>
                <div class="form-group">
                    <label>Email</label>
                    <input type="email" name="email" required placeholder="you@company.com">
                </div>
                <div class="form-group">
                    <label>Company (optional)</label>
                    <input type="text" name="company" placeholder="Acme Inc">
                </div>
                <div class="form-group">
                    <label>Password</label>
                    <input type="password" name="password" required minlength="8" placeholder="Min 8 characters">
                </div>
                <button type="submit" class="btn btn-primary" style="width:100%;margin-top:16px;">Create Account</button>
            </form>
            <p style="text-align:center;margin-top:16px;color:#888;font-size:13px;">Already have an account? <a href="#" onclick="switchModal('signup','login')" style="color:#00ff88;">Login</a></p>
        </div>
    </div>

    <script>
        function openModal(type) {
            document.getElementById(type + 'Modal').classList.add('active');
        }
        function closeModal(type) {
            document.getElementById(type + 'Modal').classList.remove('active');
        }
        function switchModal(from, to) {
            closeModal(from);
            openModal(to);
        }
        // Close modal on outside click
        document.querySelectorAll('.modal').forEach(modal => {
            modal.addEventListener('click', (e) => {
                if (e.target === modal) {
                    modal.classList.remove('active');
                }
            });
        });
    </script>
</body>
</html>"""


# ============== API ROUTES ==============

@app.get("/", response_class=HTMLResponse)
async def landing_page():
    """Serve landing page with dynamic stats"""
    stats = auth_system.get_stats()
    html = LANDING_PAGE.replace("{total_users}", str(stats["total_users"]))
    html = html.replace("{total_scans}", str(stats["total_scans"]))
    return html


@app.post("/api/signup")
async def signup(
    name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    company: str = Form("")
):
    """User signup"""
    result = auth_system.signup(email, password, name, company)
    if result["success"]:
        return RedirectResponse(url="/dashboard", status_code=303)
    return HTMLResponse(f"<script>alert('{result['error']}'); history.back();</script>")


@app.post("/api/login")
async def login(
    email: str = Form(...),
    password: str = Form(...)
):
    """User login"""
    result = auth_system.login(email, password)
    if result["success"]:
        response = RedirectResponse(url="/dashboard", status_code=303)
        response.set_cookie("session", result["session_token"], httponly=True)
        return response
    return HTMLResponse(f"<script>alert('{result['error']}'); history.back();</script>")


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    """User dashboard"""
    session_token = request.cookies.get("session")
    user = auth_system.get_user_from_session(session_token) if session_token else None

    if not user:
        return RedirectResponse(url="/")

    api_keys = auth_system.get_user_api_keys(user.id)
    stats = auth_system.get_stats()

    return f"""<!DOCTYPE html>
<html>
<head>
    <title>Dashboard - VibeSecurity</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Inter', sans-serif; background: #0a0a0f; color: #fff; min-height: 100vh; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 40px 20px; }}
        h1 {{ font-size: 32px; margin-bottom: 8px; }}
        .subtitle {{ color: #888; margin-bottom: 40px; }}
        .grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 40px; }}
        .card {{ background: #111; border: 1px solid #222; border-radius: 12px; padding: 24px; }}
        .card h3 {{ font-size: 13px; color: #888; margin-bottom: 8px; text-transform: uppercase; }}
        .card .value {{ font-size: 32px; font-weight: 700; background: linear-gradient(135deg, #00ff88, #00ccff); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
        .section {{ background: #111; border: 1px solid #222; border-radius: 12px; padding: 24px; margin-bottom: 20px; }}
        .section h2 {{ font-size: 18px; margin-bottom: 16px; }}
        .api-key {{ display: flex; justify-content: space-between; align-items: center; padding: 12px; background: #0a0a0f; border-radius: 8px; margin-bottom: 8px; }}
        .api-key code {{ color: #00ff88; font-family: monospace; }}
        .btn {{ padding: 10px 20px; border-radius: 8px; font-size: 14px; cursor: pointer; border: none; }}
        .btn-primary {{ background: linear-gradient(135deg, #00ff88, #00ccff); color: #000; font-weight: 600; }}
        .btn-danger {{ background: #ff4444; color: #fff; }}
        .btn-ghost {{ background: transparent; border: 1px solid #333; color: #fff; }}
        nav {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 40px; }}
        .logo {{ font-size: 24px; font-weight: 800; }}
        .gradient-text {{ background: linear-gradient(135deg, #00ff88, #00ccff); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
    </style>
</head>
<body>
    <div class="container">
        <nav>
            <div class="logo"><span class="gradient-text">Vibe</span>Security</div>
            <div>
                <span style="color:#888;margin-right:20px;">{user.email}</span>
                <a href="/api/logout" class="btn btn-ghost">Logout</a>
            </div>
        </nav>

        <h1>Welcome, {user.name or user.email.split('@')[0]}</h1>
        <p class="subtitle">Plan: <strong style="color:#00ff88;">{user.plan.upper()}</strong></p>

        <div class="grid">
            <div class="card">
                <h3>Scans Used</h3>
                <div class="value">{user.usage.get('scans', 0)}</div>
            </div>
            <div class="card">
                <h3>API Calls</h3>
                <div class="value">{user.usage.get('api_calls', 0)}</div>
            </div>
            <div class="card">
                <h3>Total Users</h3>
                <div class="value">{stats['total_users']}</div>
            </div>
            <div class="card">
                <h3>Total Scans</h3>
                <div class="value">{stats['total_scans']}</div>
            </div>
        </div>

        <div class="section">
            <h2>API Keys</h2>
            <p style="color:#888;font-size:14px;margin-bottom:16px;">Use these keys to access the VibeSecurity API</p>
            {''.join([f'<div class="api-key"><code>{k["key"]}</code><span style="color:#666;">{k["name"]} | Last used: {k["last_used"] or "Never"}</span></div>' for k in api_keys]) or '<p style="color:#666;">No API keys yet</p>'}
            <form action="/api/keys/generate" method="POST" style="margin-top:16px;">
                <button type="submit" class="btn btn-primary">Generate New API Key</button>
            </form>
        </div>

        <div class="section">
            <h2>Start a Security Scan</h2>
            <form action="/api/scan" method="POST" style="display:flex;gap:12px;margin-top:16px;">
                <input type="url" name="target_url" placeholder="https://your-app.com" style="flex:1;padding:12px;background:#0a0a0f;border:1px solid #333;border-radius:8px;color:#fff;">
                <button type="submit" class="btn btn-primary">Start Scan</button>
            </form>
        </div>
    </div>
</body>
</html>"""


@app.get("/api/logout")
async def logout(request: Request):
    """Logout user"""
    session_token = request.cookies.get("session")
    if session_token:
        auth_system.logout(session_token)
    response = RedirectResponse(url="/")
    response.delete_cookie("session")
    return response


@app.post("/api/keys/generate")
async def generate_key(request: Request):
    """Generate new API key"""
    session_token = request.cookies.get("session")
    user = auth_system.get_user_from_session(session_token) if session_token else None

    if not user:
        return RedirectResponse(url="/")

    auth_system.generate_api_key(user.id, f"Key-{datetime.now().strftime('%Y%m%d')}")
    return RedirectResponse(url="/dashboard", status_code=303)


@app.get("/api/stats")
async def get_stats():
    """Get platform statistics"""
    return auth_system.get_stats()


# ============== SCAN API ==============

# Inline scanner for VibeSecurity
import asyncio
import aiohttp
import ssl
import socket
from urllib.parse import urlparse

scan_results: Dict[str, Dict] = {}
scan_counter = 0


def generate_scan_id() -> str:
    global scan_counter
    scan_counter += 1
    return f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{scan_counter}"


async def check_ssl(url: str) -> Optional[Dict]:
    """Check SSL/TLS configuration"""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        if parsed.scheme != "https":
            return {
                "id": "SSL-001",
                "title": "No HTTPS",
                "description": f"Site {url} is not using HTTPS",
                "severity": "high",
                "category": "Transport Security",
                "framework": "OWASP A02:2021"
            }

        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

    except ssl.SSLCertVerificationError as e:
        return {
            "id": "SSL-002",
            "title": "Invalid SSL Certificate",
            "description": str(e)[:100],
            "severity": "high",
            "category": "Transport Security",
            "framework": "OWASP A02:2021"
        }
    except Exception:
        pass
    return None


async def check_security_headers(url: str) -> List[Dict]:
    """Check security headers"""
    findings = []
    required_headers = {
        "Strict-Transport-Security": {"severity": "medium", "description": "HSTS header missing"},
        "X-Content-Type-Options": {"severity": "low", "description": "X-Content-Type-Options missing"},
        "X-Frame-Options": {"severity": "medium", "description": "X-Frame-Options missing - clickjacking risk"},
        "Content-Security-Policy": {"severity": "medium", "description": "CSP header missing"},
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
                headers = resp.headers
                for header, info in required_headers.items():
                    if header not in headers:
                        findings.append({
                            "id": f"HDR-{header[:3].upper()}",
                            "title": f"Missing {header}",
                            "description": info["description"],
                            "severity": info["severity"],
                            "category": "Security Headers",
                            "framework": "OWASP A05:2021"
                        })
    except Exception as e:
        findings.append({
            "id": "HDR-ERR",
            "title": "Header Check Failed",
            "description": str(e)[:100],
            "severity": "info",
            "category": "Security Headers"
        })
    return findings


async def check_common_misconfigs(url: str) -> List[Dict]:
    """Check for common security misconfigurations"""
    findings = []
    sensitive_paths = [
        ("/.env", "Environment file exposed"),
        ("/.git/config", "Git repository exposed"),
        ("/config.php", "Config file exposed"),
        ("/phpinfo.php", "PHP info exposed"),
        ("/.htaccess", "htaccess file exposed"),
        ("/server-status", "Apache status exposed"),
    ]

    try:
        async with aiohttp.ClientSession() as session:
            for path, issue in sensitive_paths:
                try:
                    check_url = url.rstrip("/") + path
                    async with session.get(check_url, timeout=aiohttp.ClientTimeout(total=3), allow_redirects=False, ssl=False) as resp:
                        if resp.status == 200:
                            findings.append({
                                "id": f"CFG-{path[1:4].upper()}",
                                "title": issue,
                                "description": f"Sensitive file found at {path}",
                                "severity": "high" if ".env" in path or ".git" in path else "medium",
                                "category": "Security Misconfiguration",
                                "framework": "OWASP A05:2021",
                                "url": check_url
                            })
                except:
                    pass
    except:
        pass
    return findings


async def run_quick_scan(scan_id: str, target_url: str, user_id: str):
    """Run a quick security scan"""
    scan_results[scan_id]["status"] = "running"

    vulnerabilities = []

    # SSL Check
    ssl_result = await check_ssl(target_url)
    if ssl_result:
        vulnerabilities.append(ssl_result)

    # Security Headers
    headers_result = await check_security_headers(target_url)
    vulnerabilities.extend(headers_result)

    # Common Misconfigs
    config_result = await check_common_misconfigs(target_url)
    vulnerabilities.extend(config_result)

    # Update results
    scan_results[scan_id].update({
        "status": "completed",
        "completed_at": datetime.now().isoformat(),
        "vulnerabilities": vulnerabilities,
        "summary": {
            "total": len(vulnerabilities),
            "critical": len([v for v in vulnerabilities if v.get("severity") == "critical"]),
            "high": len([v for v in vulnerabilities if v.get("severity") == "high"]),
            "medium": len([v for v in vulnerabilities if v.get("severity") == "medium"]),
            "low": len([v for v in vulnerabilities if v.get("severity") == "low"]),
            "info": len([v for v in vulnerabilities if v.get("severity") == "info"])
        }
    })


class ScanRequest(BaseModel):
    target_url: str
    repo_url: Optional[str] = None


@app.post("/api/scan")
async def start_scan_form(request: Request, target_url: str = Form(...)):
    """Start a security scan (form submission)"""
    session_token = request.cookies.get("session")
    user = auth_system.get_user_from_session(session_token) if session_token else None

    if not user:
        return RedirectResponse(url="/")

    scan_id = generate_scan_id()
    scan_results[scan_id] = {
        "id": scan_id,
        "target": target_url,
        "user_id": user.id,
        "status": "queued",
        "started_at": datetime.now().isoformat(),
        "vulnerabilities": [],
        "summary": {}
    }

    auth_system.increment_scan_usage(user.id)
    asyncio.create_task(run_quick_scan(scan_id, target_url, user.id))

    return RedirectResponse(url=f"/scan/{scan_id}", status_code=303)


@app.post("/api/v1/scan")
async def start_scan_api(request: Request, scan: ScanRequest):
    """Start a security scan (API endpoint)"""
    api_key = request.headers.get("X-API-Key") or request.headers.get("Authorization", "").replace("Bearer ", "")
    user_info = auth_system.validate_api_key(api_key)

    if not user_info:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")

    scan_id = generate_scan_id()
    scan_results[scan_id] = {
        "id": scan_id,
        "target": scan.target_url,
        "user_id": user_info["user_id"],
        "status": "queued",
        "started_at": datetime.now().isoformat(),
        "vulnerabilities": [],
        "summary": {}
    }

    auth_system.increment_scan_usage(user_info["user_id"])
    asyncio.create_task(run_quick_scan(scan_id, scan.target_url, user_info["user_id"]))

    return {
        "status": "queued",
        "scan_id": scan_id,
        "target": scan.target_url,
        "message": "Scan started. Poll /api/v1/scan/{scan_id} for results."
    }


@app.get("/api/v1/scan/{scan_id}")
async def get_scan_api(scan_id: str, request: Request):
    """Get scan results (API endpoint)"""
    api_key = request.headers.get("X-API-Key") or request.headers.get("Authorization", "").replace("Bearer ", "")
    user_info = auth_system.validate_api_key(api_key)

    if not user_info:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")

    scan = scan_results.get(scan_id)
    if not scan or scan.get("user_id") != user_info["user_id"]:
        raise HTTPException(status_code=404, detail="Scan not found")

    return scan


@app.get("/scan/{scan_id}", response_class=HTMLResponse)
async def scan_results_page(scan_id: str, request: Request):
    """View scan results page"""
    session_token = request.cookies.get("session")
    user = auth_system.get_user_from_session(session_token) if session_token else None

    if not user:
        return RedirectResponse(url="/")

    scan = scan_results.get(scan_id)
    if not scan or scan.get("user_id") != user.id:
        return RedirectResponse(url="/dashboard")

    status_color = {"queued": "#888", "running": "#ffcc00", "completed": "#00ff88", "failed": "#ff4444"}.get(scan["status"], "#888")

    vulns_html = ""
    for v in scan.get("vulnerabilities", []):
        sev_color = {"critical": "#ff0000", "high": "#ff4444", "medium": "#ffcc00", "low": "#00ccff", "info": "#888"}.get(v.get("severity", "info"), "#888")
        vulns_html += f'''<div style="background:#111;border:1px solid #222;border-radius:8px;padding:16px;margin-bottom:12px;border-left:3px solid {sev_color};">
            <div style="display:flex;justify-content:space-between;align-items:center;">
                <h4 style="font-size:14px;">{v.get("title", "Unknown")}</h4>
                <span style="background:{sev_color};color:#000;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;">{v.get("severity", "info").upper()}</span>
            </div>
            <p style="color:#888;font-size:13px;margin-top:8px;">{v.get("description", "")}</p>
            <p style="color:#666;font-size:11px;margin-top:4px;">Category: {v.get("category", "Unknown")} | Framework: {v.get("framework", "N/A")}</p>
        </div>'''

    if not vulns_html:
        vulns_html = '<div style="text-align:center;padding:40px;color:#666;">No vulnerabilities found yet...</div>' if scan["status"] != "completed" else '<div style="text-align:center;padding:40px;color:#00ff88;">No vulnerabilities found!</div>'

    summary = scan.get("summary", {})

    return f"""<!DOCTYPE html>
<html>
<head>
    <title>Scan Results - VibeSecurity</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    {'<meta http-equiv="refresh" content="5">' if scan["status"] in ["queued", "running"] else ""}
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Inter', sans-serif; background: #0a0a0f; color: #fff; min-height: 100vh; }}
        .container {{ max-width: 1000px; margin: 0 auto; padding: 40px 20px; }}
        nav {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 40px; }}
        .logo {{ font-size: 24px; font-weight: 800; }}
        .gradient-text {{ background: linear-gradient(135deg, #00ff88, #00ccff); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
        .btn {{ padding: 10px 20px; border-radius: 8px; font-size: 14px; cursor: pointer; border: none; text-decoration: none; }}
        .btn-ghost {{ background: transparent; border: 1px solid #333; color: #fff; }}
        .summary {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 16px; margin-bottom: 30px; }}
        .summary-card {{ background: #111; border: 1px solid #222; border-radius: 8px; padding: 16px; text-align: center; }}
        .summary-card h4 {{ font-size: 11px; color: #888; text-transform: uppercase; margin-bottom: 8px; }}
        .summary-card .value {{ font-size: 28px; font-weight: 700; }}
    </style>
</head>
<body>
    <div class="container">
        <nav>
            <div class="logo"><span class="gradient-text">Vibe</span>Security</div>
            <a href="/dashboard" class="btn btn-ghost">Back to Dashboard</a>
        </nav>

        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:30px;">
            <div>
                <h1 style="font-size:24px;margin-bottom:8px;">Scan Results</h1>
                <p style="color:#888;">Target: <code style="color:#00ccff;">{scan["target"]}</code></p>
            </div>
            <div style="display:flex;align-items:center;gap:12px;">
                <span style="color:{status_color};font-weight:600;">{scan["status"].upper()}</span>
                {f'<div style="width:16px;height:16px;border:2px solid {status_color};border-top-color:transparent;border-radius:50%;animation:spin 1s linear infinite;"></div>' if scan["status"] == "running" else ""}
            </div>
        </div>

        <div class="summary">
            <div class="summary-card">
                <h4>Total</h4>
                <div class="value" style="color:#fff;">{summary.get("total", 0)}</div>
            </div>
            <div class="summary-card">
                <h4>Critical</h4>
                <div class="value" style="color:#ff0000;">{summary.get("critical", 0)}</div>
            </div>
            <div class="summary-card">
                <h4>High</h4>
                <div class="value" style="color:#ff4444;">{summary.get("high", 0)}</div>
            </div>
            <div class="summary-card">
                <h4>Medium</h4>
                <div class="value" style="color:#ffcc00;">{summary.get("medium", 0)}</div>
            </div>
            <div class="summary-card">
                <h4>Low</h4>
                <div class="value" style="color:#00ccff;">{summary.get("low", 0)}</div>
            </div>
        </div>

        <h2 style="font-size:18px;margin-bottom:16px;">Findings</h2>
        {vulns_html}
    </div>

    <style>
        @keyframes spin {{ 0% {{ transform: rotate(0deg); }} 100% {{ transform: rotate(360deg); }} }}
    </style>
</body>
</html>"""


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
