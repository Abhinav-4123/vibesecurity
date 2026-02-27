"""
Test suite for VibeSecurity (Repo 1)
Tests: startup, health, auth, scanning, dashboard, API, security checks
"""
import asyncio
import httpx
import json
import re
import time
import sys
from datetime import datetime

BASE = "http://127.0.0.1:8000"
RESULTS = []
PASS = 0
FAIL = 0


def log(test_name, passed, detail=""):
    global PASS, FAIL
    status = "PASS" if passed else "FAIL"
    if passed:
        PASS += 1
    else:
        FAIL += 1
    RESULTS.append({"test": test_name, "status": status, "detail": detail})
    print(f"  [{status}] {test_name}" + (f" - {detail}" if detail else ""))


def extract_csrf(html):
    match = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
    return match.group(1) if match else ""


async def run_tests():
    print(f"\n{'='*60}")
    print(f"VibeSecurity (Repo 1) Test Suite")
    print(f"Started: {datetime.now().isoformat()}")
    print(f"{'='*60}\n")

    # Use a client that does NOT follow redirects for form posts
    # and one that does for page loads
    async with httpx.AsyncClient(timeout=15, follow_redirects=False) as raw_client:
        async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:

            # 1. Landing page
            print("[Section] Landing Page")
            try:
                r = await client.get(f"{BASE}/")
                log("GET / returns 200", r.status_code == 200, f"status={r.status_code}")
                log("Landing has HTML content", "text/html" in r.headers.get("content-type", ""))
                log("Landing contains VibeSecurity", "VibeSecurity" in r.text or "vibesecurity" in r.text.lower())
            except Exception as e:
                log("GET / landing page", False, str(e))

            # 2. Stats endpoint
            print("\n[Section] Public Stats")
            try:
                r = await client.get(f"{BASE}/api/stats")
                log("GET /api/stats returns 200", r.status_code == 200, f"status={r.status_code}")
                data = r.json()
                log("Stats has total_users", "total_users" in data)
                log("Stats has total_scans", "total_scans" in data)
            except Exception as e:
                log("GET /api/stats", False, str(e))

            # 3. Signup
            print("\n[Section] Auth - Signup")
            test_email = f"test_{int(time.time())}@test.com"
            try:
                r = await raw_client.post(f"{BASE}/api/signup", data={
                    "name": "Test User",
                    "email": test_email,
                    "password": "TestPass123!",
                    "company": "TestCo"
                })
                log("POST /api/signup returns 303 redirect", r.status_code == 303, f"status={r.status_code}")
                redirect_to = r.headers.get("location", "")
                log("Redirects to /dashboard", "/dashboard" in redirect_to, f"location={redirect_to}")
                # Extract session cookie
                session_cookie = None
                for h in r.headers.get_list("set-cookie"):
                    if "session=" in h:
                        session_cookie = h.split("session=")[1].split(";")[0]
                log("Sets session cookie", session_cookie is not None)
                log("Cookie has httponly flag", "httponly" in (r.headers.get("set-cookie") or "").lower())
                log("Cookie has secure flag", "secure" in (r.headers.get("set-cookie") or "").lower())

                if session_cookie:
                    raw_client.cookies.set("session", session_cookie)
                    client.cookies.set("session", session_cookie)
            except Exception as e:
                log("POST /api/signup", False, str(e))

            # 4. Dashboard (requires session)
            print("\n[Section] Dashboard")
            try:
                r = await client.get(f"{BASE}/dashboard")
                log("GET /dashboard returns 200", r.status_code == 200, f"status={r.status_code}")
                log("Dashboard has HTML content", "text/html" in r.headers.get("content-type", ""))
                log("Dashboard has CSRF token", 'name="csrf_token"' in r.text)
                csrf = extract_csrf(r.text)
                log("CSRF token extracted", len(csrf) > 10, f"len={len(csrf)}")
            except Exception as e:
                log("GET /dashboard", False, str(e))

            # 5. Duplicate signup blocked
            print("\n[Section] Auth - Duplicate Signup")
            try:
                r = await raw_client.post(f"{BASE}/api/signup", data={
                    "name": "Test User",
                    "email": test_email,
                    "password": "TestPass123!",
                    "company": "TestCo"
                })
                redirect_to = r.headers.get("location", "")
                log("Duplicate signup rejected", "error" in redirect_to, f"location={redirect_to}")
            except Exception as e:
                log("Duplicate signup", False, str(e))

            # 6. Login
            print("\n[Section] Auth - Login")
            try:
                # Clear cookies first
                raw_client.cookies.clear()
                client.cookies.clear()

                r = await raw_client.post(f"{BASE}/api/login", data={
                    "email": test_email,
                    "password": "TestPass123!"
                })
                log("POST /api/login returns 303", r.status_code == 303, f"status={r.status_code}")
                redirect_to = r.headers.get("location", "")
                log("Redirects to /dashboard", "/dashboard" in redirect_to)

                session_cookie = None
                for h in r.headers.get_list("set-cookie"):
                    if "session=" in h:
                        session_cookie = h.split("session=")[1].split(";")[0]
                log("Login sets session cookie", session_cookie is not None)

                if session_cookie:
                    raw_client.cookies.set("session", session_cookie)
                    client.cookies.set("session", session_cookie)

                # Get fresh CSRF
                r = await client.get(f"{BASE}/dashboard")
                csrf = extract_csrf(r.text)
            except Exception as e:
                log("POST /api/login", False, str(e))

            # 7. Wrong password login
            print("\n[Section] Auth - Wrong Password")
            try:
                r = await raw_client.post(f"{BASE}/api/login", data={
                    "email": test_email,
                    "password": "WrongPassword!"
                })
                redirect_to = r.headers.get("location", "")
                log("Wrong password rejected", "error" in redirect_to, f"location={redirect_to}")
            except Exception as e:
                log("Wrong password", False, str(e))

            # 8. API Key generation
            print("\n[Section] API Key Generation")
            try:
                r = await raw_client.post(f"{BASE}/api/keys/generate", data={
                    "csrf_token": csrf
                })
                log("POST /api/keys/generate returns 303", r.status_code == 303, f"status={r.status_code}")
            except Exception as e:
                log("API key generation", False, str(e))

            # 9. SSRF protection
            print("\n[Section] Security - SSRF Protection")
            try:
                r = await raw_client.post(f"{BASE}/api/scan", data={
                    "target_url": "http://127.0.0.1/admin",
                    "csrf_token": csrf
                })
                redirect_to = r.headers.get("location", "")
                log("Blocks localhost scan", "error" in redirect_to, f"location={redirect_to}")
            except Exception as e:
                log("SSRF localhost", False, str(e))

            try:
                r = await raw_client.post(f"{BASE}/api/scan", data={
                    "target_url": "http://169.254.169.254/latest/meta-data/",
                    "csrf_token": csrf
                })
                redirect_to = r.headers.get("location", "")
                log("Blocks cloud metadata endpoint", "error" in redirect_to, f"location={redirect_to}")
            except Exception as e:
                log("SSRF metadata", False, str(e))

            try:
                r = await raw_client.post(f"{BASE}/api/scan", data={
                    "target_url": "http://10.0.0.1/internal",
                    "csrf_token": csrf
                })
                redirect_to = r.headers.get("location", "")
                log("Blocks private IP (10.x)", "error" in redirect_to, f"location={redirect_to}")
            except Exception as e:
                log("SSRF private IP", False, str(e))

            try:
                r = await raw_client.post(f"{BASE}/api/scan", data={
                    "target_url": "ftp://evil.com/payload",
                    "csrf_token": csrf
                })
                redirect_to = r.headers.get("location", "")
                log("Blocks non-HTTP scheme", "error" in redirect_to, f"location={redirect_to}")
            except Exception as e:
                log("SSRF scheme", False, str(e))

            # 10. Valid scan
            print("\n[Section] Scan - Valid Target")
            try:
                r = await raw_client.post(f"{BASE}/api/scan", data={
                    "target_url": "https://example.com",
                    "csrf_token": csrf
                })
                log("POST /api/scan returns 303", r.status_code == 303, f"status={r.status_code}")
                redirect_to = r.headers.get("location", "")
                log("Redirects to /scan/ result page", "/scan/" in redirect_to, f"location={redirect_to}")
            except Exception as e:
                log("Valid scan", False, str(e))

            # 11. Logout
            print("\n[Section] Auth - Logout")
            try:
                r = await raw_client.get(f"{BASE}/api/logout")
                log("GET /api/logout returns redirect", r.status_code in [301, 302, 307], f"status={r.status_code}")
                raw_client.cookies.clear()
                client.cookies.clear()

                # After logout, dashboard should redirect to /
                r = await raw_client.get(f"{BASE}/dashboard")
                log("Dashboard redirects after logout", r.status_code in [301, 302, 307], f"status={r.status_code}")
            except Exception as e:
                log("Logout", False, str(e))

            # 12. CSRF protection test
            print("\n[Section] Security - CSRF Protection")
            try:
                # Login first
                r = await raw_client.post(f"{BASE}/api/login", data={
                    "email": test_email,
                    "password": "TestPass123!"
                })
                session_cookie = None
                for h in r.headers.get_list("set-cookie"):
                    if "session=" in h:
                        session_cookie = h.split("session=")[1].split(";")[0]
                if session_cookie:
                    raw_client.cookies.set("session", session_cookie)

                # Try scan without CSRF token
                r = await raw_client.post(f"{BASE}/api/scan", data={
                    "target_url": "https://example.com",
                    "csrf_token": ""
                })
                log("Empty CSRF token rejected", r.status_code in [403, 422], f"status={r.status_code}")

                # Try scan with wrong CSRF token
                r = await raw_client.post(f"{BASE}/api/scan", data={
                    "target_url": "https://example.com",
                    "csrf_token": "wrong_token_12345"
                })
                log("Wrong CSRF token rejected", r.status_code == 403, f"status={r.status_code}")
            except Exception as e:
                log("CSRF protection", False, str(e))

    # Summary
    print(f"\n{'='*60}")
    print(f"RESULTS: {PASS} passed, {FAIL} failed, {PASS+FAIL} total")
    print(f"{'='*60}\n")

    return {
        "repo": "vibesecurity",
        "timestamp": datetime.now().isoformat(),
        "total": PASS + FAIL,
        "passed": PASS,
        "failed": FAIL,
        "results": RESULTS
    }


if __name__ == "__main__":
    result = asyncio.run(run_tests())
    with open("test_results/repo1_results.json", "w") as f:
        json.dump(result, f, indent=2)
    print(f"Results saved to test_results/repo1_results.json")
    sys.exit(0 if FAIL == 0 else 1)
