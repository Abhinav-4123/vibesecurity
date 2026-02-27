"""
Test suite for TestGuard AI (Repo 3)
Tests: startup, health, API key, tests, security scans, stats, SSRF protection
"""
import asyncio
import httpx
import json
import time
import sys
from datetime import datetime

BASE = "http://127.0.0.1:8001"
RESULTS = []
PASS = 0
FAIL = 0
API_KEY = None


def log(test_name, passed, detail=""):
    global PASS, FAIL
    status = "PASS" if passed else "FAIL"
    if passed:
        PASS += 1
    else:
        FAIL += 1
    RESULTS.append({"test": test_name, "status": status, "detail": detail})
    print(f"  [{status}] {test_name}" + (f" - {detail}" if detail else ""))


async def run_tests():
    global API_KEY
    print(f"\n{'='*60}")
    print(f"TestGuard AI (Repo 3) Test Suite")
    print(f"Started: {datetime.now().isoformat()}")
    print(f"{'='*60}\n")

    async with httpx.AsyncClient(timeout=15) as client:

        # 1. Root endpoint
        print("[Section] Root & Health")
        try:
            r = await client.get(f"{BASE}/")
            log("GET / returns 200", r.status_code == 200, f"status={r.status_code}")
            data = r.json()
            log("Root has service info", "service" in data, str(data.get("service")))
        except Exception as e:
            log("GET /", False, str(e))

        # 2. Health check
        try:
            r = await client.get(f"{BASE}/health")
            log("GET /health returns 200", r.status_code == 200)
            data = r.json()
            log("Health status is healthy", data.get("status") == "healthy")
        except Exception as e:
            log("GET /health", False, str(e))

        # 3. API Key generation
        print("\n[Section] API Key Management")
        try:
            r = await client.post(f"{BASE}/api/keys/generate")
            log("POST /api/keys/generate returns 200", r.status_code == 200, f"status={r.status_code}")
            data = r.json()
            API_KEY = data.get("key")
            log("Key starts with tg_live_", API_KEY and API_KEY.startswith("tg_live_"))
            log("Key has sufficient length", API_KEY and len(API_KEY) > 30, f"len={len(API_KEY) if API_KEY else 0}")
        except Exception as e:
            log("API key generation", False, str(e))

        # 4. Auth required without key
        print("\n[Section] Security - Auth Required")
        try:
            r = await client.get(f"{BASE}/tests")
            log("GET /tests without key returns 401", r.status_code == 401, f"status={r.status_code}")
        except Exception as e:
            log("Auth check /tests", False, str(e))

        try:
            r = await client.get(f"{BASE}/stats")
            log("GET /stats without key returns 401", r.status_code == 401, f"status={r.status_code}")
        except Exception as e:
            log("Auth check /stats", False, str(e))

        try:
            r = await client.get(f"{BASE}/security/scans")
            log("GET /security/scans without key returns 401", r.status_code == 401, f"status={r.status_code}")
        except Exception as e:
            log("Auth check /security/scans", False, str(e))

        # Headers for authenticated requests
        headers = {"X-API-Key": API_KEY}

        # 5. Stats endpoint (with auth)
        print("\n[Section] Stats")
        try:
            r = await client.get(f"{BASE}/stats", headers=headers)
            log("GET /stats with key returns 200", r.status_code == 200, f"status={r.status_code}")
            data = r.json()
            log("Stats has tests section", "tests" in data)
            log("Stats has security section", "security" in data)
        except Exception as e:
            log("GET /stats", False, str(e))

        # 6. Create test - SSRF protection
        print("\n[Section] Security - SSRF Protection")
        try:
            r = await client.post(f"{BASE}/test", headers=headers, json={
                "url": "http://127.0.0.1/admin",
                "objective": "login"
            })
            log("Blocks localhost test URL", r.status_code == 400, f"status={r.status_code}")
        except Exception as e:
            log("SSRF /test localhost", False, str(e))

        try:
            r = await client.post(f"{BASE}/test", headers=headers, json={
                "url": "http://169.254.169.254/latest/",
                "objective": "login"
            })
            log("Blocks metadata endpoint", r.status_code == 400, f"status={r.status_code}")
        except Exception as e:
            log("SSRF /test metadata", False, str(e))

        try:
            r = await client.post(f"{BASE}/test", headers=headers, json={
                "url": "http://10.0.0.1/internal",
                "objective": "login"
            })
            log("Blocks private IP", r.status_code == 400, f"status={r.status_code}")
        except Exception as e:
            log("SSRF /test private IP", False, str(e))

        try:
            r = await client.post(f"{BASE}/security/scan", headers=headers, json={
                "url": "http://localhost:8080/admin"
            })
            log("Blocks localhost scan URL", r.status_code == 400, f"status={r.status_code}")
        except Exception as e:
            log("SSRF /security/scan", False, str(e))

        # 7. Create a valid test
        print("\n[Section] QA Test Creation")
        test_id = None
        try:
            r = await client.post(f"{BASE}/test", headers=headers, json={
                "url": "https://example.com",
                "objective": "login"
            })
            log("POST /test valid URL returns 200", r.status_code == 200, f"status={r.status_code}")
            data = r.json()
            test_id = data.get("test_id")
            log("Returns test_id (UUID format)", test_id and len(test_id) == 36, f"id={test_id}")
            log("Returns pending status", data.get("status") == "pending")
        except Exception as e:
            log("POST /test", False, str(e))

        # 8. Get test by ID
        if test_id:
            try:
                await asyncio.sleep(0.5)  # Allow DB write to complete
                r = await client.get(f"{BASE}/test/{test_id}", headers=headers)
                log("GET /test/{id} returns 200", r.status_code == 200, f"status={r.status_code}")
                data = r.json()
                log("Test data has correct ID", data.get("test_id") == test_id)
            except Exception as e:
                log("GET /test/{id}", False, str(e))

        # 9. List tests
        try:
            r = await client.get(f"{BASE}/tests", headers=headers)
            log("GET /tests returns 200", r.status_code == 200)
            data = r.json()
            log("Returns list of tests", isinstance(data, list))
            log("List contains created test", any(t.get("test_id") == test_id for t in data) if test_id else False)
        except Exception as e:
            log("GET /tests", False, str(e))

        # 10. Security scan - valid
        print("\n[Section] Security Scan")
        scan_id = None
        try:
            r = await client.post(f"{BASE}/security/scan", headers=headers, json={
                "url": "https://example.com",
                "frameworks": ["owasp_top_10"]
            })
            log("POST /security/scan returns 200", r.status_code == 200, f"status={r.status_code}")
            data = r.json()
            scan_id = data.get("scan_id")
            log("Returns scan_id", scan_id is not None, f"id={scan_id}")
            log("Scan ID has prefix sec_", scan_id and scan_id.startswith("sec_"))
        except Exception as e:
            log("POST /security/scan", False, str(e))

        # 11. Get security scan
        if scan_id:
            try:
                r = await client.get(f"{BASE}/security/scan/{scan_id}", headers=headers)
                log("GET /security/scan/{id} returns 200", r.status_code == 200)
            except Exception as e:
                log("GET /security/scan/{id}", False, str(e))

        # 12. List security scans
        try:
            r = await client.get(f"{BASE}/security/scans", headers=headers)
            log("GET /security/scans returns 200", r.status_code == 200)
            data = r.json()
            log("Returns list of scans", isinstance(data, list))
        except Exception as e:
            log("GET /security/scans", False, str(e))

        # 13. Invalid API key
        print("\n[Section] Security - Invalid Key")
        try:
            r = await client.get(f"{BASE}/tests", headers={"X-API-Key": "invalid_key_12345"})
            log("Invalid key returns 403", r.status_code == 403, f"status={r.status_code}")
        except Exception as e:
            log("Invalid key check", False, str(e))

        # 14. Billing plans (public)
        print("\n[Section] Billing")
        try:
            r = await client.get(f"{BASE}/billing/plans")
            log("GET /billing/plans returns 200", r.status_code == 200)
            data = r.json()
            log("Has plans data", "plans" in data)
            log("Has starter plan", "starter" in data.get("plans", {}))
        except Exception as e:
            log("GET /billing/plans", False, str(e))

        # 15. 404 handling
        print("\n[Section] Error Handling")
        try:
            r = await client.get(f"{BASE}/test/nonexistent-id", headers=headers)
            log("Nonexistent test returns 404", r.status_code == 404)
        except Exception as e:
            log("404 handling", False, str(e))

        try:
            r = await client.get(f"{BASE}/security/scan/nonexistent", headers=headers)
            log("Nonexistent scan returns 404", r.status_code == 404)
        except Exception as e:
            log("404 scan handling", False, str(e))

    # Summary
    print(f"\n{'='*60}")
    print(f"RESULTS: {PASS} passed, {FAIL} failed, {PASS+FAIL} total")
    print(f"{'='*60}\n")

    return {
        "repo": "testguard-ai",
        "timestamp": datetime.now().isoformat(),
        "total": PASS + FAIL,
        "passed": PASS,
        "failed": FAIL,
        "results": RESULTS
    }


if __name__ == "__main__":
    result = asyncio.run(run_tests())
    with open("test_results/repo3_results.json", "w") as f:
        json.dump(result, f, indent=2)
    print(f"Results saved to test_results/repo3_results.json")
    sys.exit(0 if FAIL == 0 else 1)
