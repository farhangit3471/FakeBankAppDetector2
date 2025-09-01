# analyzer/apk_analyzer.py

import re
import os
import json
import hashlib
from androguard.core.bytecodes.apk import APK
import requests
from datetime import datetime

# ---------- Configuration ----------
PERMISSION_SCORES = {
    "android.permission.READ_SMS": 200,
    "android.permission.SEND_SMS": 200,
    "android.permission.RECEIVE_SMS": 200,
    "android.permission.CALL_PHONE": 150,
    "android.permission.READ_CONTACTS": 120,
    "android.permission.WRITE_CONTACTS": 120,
    "android.permission.READ_CALL_LOG": 150,
    "android.permission.WRITE_CALL_LOG": 150,
    "android.permission.PROCESS_OUTGOING_CALLS": 150,
    "android.permission.GET_ACCOUNTS": 100,
    "android.permission.AUTHENTICATE_ACCOUNTS": 100,
    "android.permission.CAMERA": 80,
    "android.permission.RECORD_AUDIO": 80,
    "android.permission.ACCESS_FINE_LOCATION": 70,
    "android.permission.ACCESS_COARSE_LOCATION": 70,
    "android.permission.REQUEST_INSTALL_PACKAGES": 90,
    "android.permission.SYSTEM_ALERT_WINDOW": 100,
    "android.permission.WRITE_SETTINGS": 80,
    "android.permission.WRITE_EXTERNAL_STORAGE": 50,
    "android.permission.READ_EXTERNAL_STORAGE": 50,
    "android.permission.INTERNET": 10,
    "android.permission.ACCESS_NETWORK_STATE": 5,
    "android.permission.VIBRATE": 2,
    "android.permission.WAKE_LOCK": 5,
}

# Known malicious patterns in code
MALICIOUS_PATTERNS = {
    "exec\\(": 200,  # Code execution
    "runtime\\.exec": 200,
    "getRuntime\\(\\)\\.exec": 200,
    "su\\b": 150,  # Root access
    "superuser": 150,
    "root\\b": 150,
    "cryptography": 50,  # Encryption (could be good or bad)
    "encrypt": 50,
    "decrypt": 50,
    "base64": 30,  # Often used for hiding data
    "getDeviceId": 100,  # Device identifier
    "getSubscriberId": 100,
    "getSimSerialNumber": 100,
    "getLine1Number": 100,
}

# Known good domains (reduce false positives)
KNOWN_GOOD_DOMAINS = {
    "google.com", "googleapis.com", "gstatic.com", "firebase.com",
    "facebook.com", "fbcdn.net", "apple.com", "icloud.com",
    "microsoft.com", "azure.com", "amazon.com", "aws.com",
    "twitter.com", "github.com", "android.com", "googletagmanager.com"
}

# Known bad domains (you would populate this from threat intelligence feeds)
KNOWN_BAD_DOMAINS = {
    "malicious-domain.com", "evil-server.net", "data-stealer.org"
}

# ---------- Safe Apps Loading ----------
_safe_apps_cache = None
_safe_apps_last_loaded = None

def load_safe_apps():
    """Load safe apps from JSON file with caching"""
    global _safe_apps_cache, _safe_apps_last_loaded
    
    current_dir = os.path.dirname(os.path.abspath(__file__))
    safe_apps_path = os.path.join(current_dir, "..", "safeapps", "safe_apps.json")
    safe_apps_path = os.path.abspath(safe_apps_path)
    
    # Check if cache is still valid (5 minute cache)
    if (_safe_apps_cache is not None and 
        _safe_apps_last_loaded is not None and
        (datetime.now() - _safe_apps_last_loaded).total_seconds() < 300):
        return _safe_apps_cache
    
    try:
        if os.path.exists(safe_apps_path):
            with open(safe_apps_path, "r", encoding='utf-8') as f:
                safe_apps_json = json.load(f)
                safe_apps = set()
                
                for app in safe_apps_json:
                    package = app.get("package")
                    if package:
                        safe_apps.add(package.lower().strip())
                
                _safe_apps_cache = safe_apps
                _safe_apps_last_loaded = datetime.now()
                return safe_apps
        else:
            print(f"Safe apps file not found at: {safe_apps_path}")
            return set()
    except Exception as e:
        print(f"Error loading safe apps: {e}")
        return set()

# ---------- Risk Assessment Functions ----------
def get_permission_risk(permission):
    score = PERMISSION_SCORES.get(permission, 0)
    if score >= 100:
        return "High Risk"
    elif score >= 50:
        return "Medium Risk"
    return "Low Risk"

def calculate_permission_score(permissions):
    """Calculate a weighted permission score"""
    score = 0
    high_risk_perms = []
    
    for perm in permissions:
        perm_score = PERMISSION_SCORES.get(perm, 0)
        score += perm_score
        if perm_score >= 100:
            high_risk_perms.append(perm)
    
    # Apply non-linear scaling - more high-risk permissions multiply the risk
    risk_multiplier = 1 + (len(high_risk_perms) * 0.2)
    score = score * risk_multiplier
    
    return int(score), high_risk_perms

def analyze_urls(apk):
    """Analyze URLs found in the APK with domain reputation checking"""
    suspicious_urls = []
    url_pattern = re.compile(r'https?://([a-zA-Z0-9.-]+)[/?]')
    
    try:
        for s in apk.get_strings():
            try:
                if isinstance(s, bytes):
                    text = s.decode("utf-8", "ignore")
                else:
                    text = str(s)
                
                urls = url_pattern.findall(text)
                for domain in urls:
                    # Skip very short domains (likely false positives)
                    if len(domain) < 5:
                        continue
                    
                    # Check against known lists
                    if domain in KNOWN_BAD_DOMAINS:
                        suspicious_urls.append({
                            "url": domain,
                            "reason": "Known malicious domain",
                            "score": 200
                        })
                    elif domain not in KNOWN_GOOD_DOMAINS:
                        # Check for suspicious patterns in unknown domains
                        if any(part in domain for part in ["api", "cloud", "server"]):
                            suspicious_urls.append({
                                "url": domain,
                                "reason": "Suspicious external domain",
                                "score": 50
                            })
            except (UnicodeDecodeError, AttributeError):
                continue
    except Exception as e:
        print(f"Error analyzing URLs: {e}")
    
    return suspicious_urls

def analyze_code_patterns(apk_path):
    """Search for suspicious code patterns using string analysis"""
    suspicious_patterns = []
    
    try:
        # Simple string-based analysis instead of DEX parsing
        apk = APK(apk_path)
        
        # Analyze strings from the APK
        for s in apk.get_strings():
            try:
                if isinstance(s, bytes):
                    text = s.decode("utf-8", "ignore")
                else:
                    text = str(s)
                
                for pattern, score in MALICIOUS_PATTERNS.items():
                    if re.search(pattern, text, re.IGNORECASE):
                        suspicious_patterns.append({
                            "pattern": pattern,
                            "score": score,
                            "location": "APK strings"
                        })
            except (UnicodeDecodeError, AttributeError):
                continue
                
    except Exception as e:
        print(f"Error analyzing code patterns: {e}")
    
    return suspicious_patterns

def calculate_certificate_risk(apk):
    """Evaluate certificate risk (self-signed, unknown signer, etc.)"""
    try:
        # Get certificates using the correct method
        certificates = apk.get_certificates()
        if certificates:
            cert = certificates[0]  # Use the first certificate
            
            # Basic certificate check - you can enhance this
            # For now, just check if we have certificates
            return 0, "Certificate found (basic check)"
        
        return 100, "No certificate found"
    
    except Exception as e:
        print(f"Certificate analysis error: {e}")
        return 75, f"Certificate analysis failed: {str(e)}"

def generate_apk_hash(apk_path):
    """Generate SHA256 hash of the APK file"""
    sha256_hash = hashlib.sha256()
    with open(apk_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

# ---------- Main Analysis Function ----------
def analyze_apk(apk_path):
    """Comprehensive APK analysis with multiple risk factors"""
    try:
        # Check if file exists first
        if not os.path.exists(apk_path):
            return {"error": f"APK file not found: {apk_path}"}
        
        # Load APK with proper error handling
        apk = APK(apk_path)
        permissions = apk.get_permissions() or []
        app_name = apk.get_app_name() or "Unknown"
        package_name = apk.get_package() or "Unknown"
        version_name = apk.get_androidversion_name() or "Unknown"
        version_code = apk.get_androidversion_code() or "Unknown"
        
        if package_name == "Unknown":
            return {"error": "Could not extract package name from APK"}

        # Generate unique hash for this APK
        apk_hash = generate_apk_hash(apk_path)
        
        # Load safe apps
        safe_apps = load_safe_apps()
        normalized_package = package_name.lower().strip()
        is_known_safe_app = normalized_package in safe_apps
        
        # Perform comprehensive analysis
        permission_score, high_risk_perms = calculate_permission_score(permissions)
        suspicious_urls = analyze_urls(apk)
        url_score = sum(url['score'] for url in suspicious_urls)
        
        code_patterns = analyze_code_patterns(apk_path)
        code_score = sum(pattern['score'] for pattern in code_patterns)
        
        cert_score, cert_reason = calculate_certificate_risk(apk)
        
        # Calculate total risk score
        total_score = permission_score + url_score + code_score + cert_score
        
        # Apply safe app discount (reduce score but don't eliminate it)
        if is_known_safe_app:
            total_score = max(0, total_score * 0.3)  # Reduce to 30% of original score
            risk_note = "Known safe app (score reduced)"
        else:
            risk_note = "Unknown app"
        
        # Determine risk level
        if total_score > 500:
            risk_level = "Dangerous"
        elif total_score > 200:
            risk_level = "Potentially Risky"
        elif total_score > 50:
            risk_level = "Moderate Risk"
        else:
            risk_level = "Likely Safe"
        
        # Prepare detailed results
        result = {
            "app_name": app_name,
            "package": package_name,
            "version": f"{version_name} ({version_code})",
            "apk_hash": apk_hash,
            "permissions": [{"name": p, "risk": get_permission_risk(p)} for p in permissions],
            "permission_score": permission_score,
            "url_score": url_score,
            "code_analysis_score": code_score,
            "certificate_score": cert_score,
            "certificate_notes": cert_reason,
            "total_score": int(total_score),
            "overall_risk": risk_level,
            "risk_note": risk_note,
            "high_risk_permissions": high_risk_perms,
            "suspicious_urls": suspicious_urls,
            "suspicious_code_patterns": code_patterns,
            "is_known_safe_app": is_known_safe_app,
            "analysis_timestamp": datetime.now().isoformat(),
            "false_positive_reported": False
        }
        
        return result

    except Exception as e:
        print(f"Error analyzing APK: {e}")
        import traceback
        traceback.print_exc()
        return {"error": str(e)}
