
import hashlib
import hmac
import json
import jwt
import time
from typing import Optional, Dict, Callable
from functools import wraps
from datetime import datetime, timedelta
import uuid

class APIKeyValidator:
    def __init__(self):
        self.primary_key = "sk-or-v1-terosica-primary"
        self.valid_keys = [
            "sk-or-v1-test-key-1",
            "sk-or-v1-test-key-2",
            "sk-or-v1-terosica-primary",
        ]
        self.request_history = {}
    
    def is_valid(self, api_key: str) -> bool:
        if not api_key:
            return False
        return api_key == self.primary_key or api_key in self.valid_keys
    
    def get_key_hash(self, api_key: str) -> str:
        return hashlib.sha256(api_key.encode()).hexdigest()[:16]
    
    def track_usage(self, api_key: str) -> None:
        key_hash = self.get_key_hash(api_key)
        if key_hash not in self.request_history:
            self.request_history[key_hash] = []
        self.request_history[key_hash].append(time.time())

class JWTManager:
    def __init__(self, secret_key: str = None, expiration_hours: int = 24):
        self.secret_key = secret_key or "terosica-jwt-secret-key"
        self.expiration_hours = expiration_hours
        self.algorithm = "HS256"
    
    def create_token(self, data: Dict, expires_in_hours: int = None) -> str:
        if expires_in_hours is None:
            expires_in_hours = self.expiration_hours
        
        payload = {
            **data,
            "exp": datetime.utcnow() + timedelta(hours=expires_in_hours),
            "iat": datetime.utcnow(),
            "jti": str(uuid.uuid4()),
        }
        
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
    
    def verify_token(self, token: str) -> Optional[Dict]:
        try:
            return jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
    
    def refresh_token(self, token: str) -> Optional[str]:
        decoded = self.verify_token(token)
        if decoded:
            decoded.pop("exp", None)
            decoded.pop("iat", None)
            decoded.pop("jti", None)
            return self.create_token(decoded)
        return None

class RateLimiter:
    def __init__(self, requests_per_minute: int = 100):
        self.rpm = requests_per_minute
        self.buckets = {}
    
    def is_allowed(self, key_hash: str) -> bool:
        current_time = time.time()
        
        if key_hash not in self.buckets:
            self.buckets[key_hash] = [self.rpm, current_time]
            return True
        
        tokens, last_refill = self.buckets[key_hash]
        
        elapsed = (current_time - last_refill) / 60
        new_tokens = min(self.rpm, tokens + (self.rpm * elapsed))
        
        self.buckets[key_hash] = [new_tokens, current_time]
        
        if new_tokens >= 1:
            self.buckets[key_hash][0] = new_tokens - 1
            return True
        
        return False
    
    def get_remaining(self, key_hash: str) -> int:
        if key_hash not in self.buckets:
            return self.rpm
        return int(self.buckets[key_hash][0])

class RequestSignerVerifier:
    def __init__(self, api_secret: str = None):
        self.api_secret = api_secret or "terosica-api-secret"
    
    def create_signature(self, method: str, path: str, body: str = "", timestamp: str = None) -> str:
        if timestamp is None:
            timestamp = str(int(time.time()))
        
        message = f"{method}|{path}|{body}|{timestamp}"
        sig_hash = hmac.new(self.api_secret.encode(), message.encode(), hashlib.sha256).hexdigest()
        
        return f"{sig_hash}:{timestamp}"
    
    def verify_signature(self, signature: str, method: str, path: str, body: str = "") -> bool:
        try:
            sig_hash, timestamp = signature.split(":")
            
            current_time = int(time.time())
            request_time = int(timestamp)
            
            if abs(current_time - request_time) > 300:
                return False
            
            expected_sig = self.create_signature(method, path, body, timestamp)
            expected_hash = expected_sig.split(":")[0]
            
            return hmac.compare_digest(sig_hash, expected_hash)
        except:
            return False

class AuditLogger:
    def __init__(self):
        self.audit_trail = []
        self.max_entries = 10000
    
    def log_access(self, api_key_hash: str, endpoint: str, method: str, 
                   ip_address: str = None, success: bool = True, details: Dict = None) -> None:
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "api_key_hash": api_key_hash,
            "endpoint": endpoint,
            "method": method,
            "ip_address": ip_address,
            "success": success,
            "details": details or {},
        }
        self.audit_trail.append(event)
        
        if len(self.audit_trail) > self.max_entries:
            self.audit_trail = self.audit_trail[-self.max_entries:]
    
    def log_threat_detection(self, api_key_hash: str, threat_type: str, 
                            threat_score: float, details: Dict) -> None:
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "api_key_hash": api_key_hash,
            "threat_type": threat_type,
            "threat_score": threat_score,
            "details": details,
        }
        self.audit_trail.append(event)
    
    def get_audit_log(self, api_key_hash: str = None, limit: int = 100) -> list:
        results = self.audit_trail
        if api_key_hash:
            results = [e for e in results if e.get("api_key_hash") == api_key_hash]
        return results[-limit:]

api_key_validator = APIKeyValidator()
jwt_manager = JWTManager()
rate_limiter = RateLimiter(requests_per_minute=100)
request_signer = RequestSignerVerifier()
audit_logger = AuditLogger()

def require_api_key(f: Callable) -> Callable:
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from flask import request, jsonify
        
        api_key = request.headers.get("X-API-Key")
        
        if not api_key:
            return jsonify({"error": "API key required"}), 401
        
        if not api_key_validator.is_valid(api_key):
            return jsonify({"error": "Invalid API key"}), 401
        
        api_key_validator.track_usage(api_key)
        kwargs["api_key"] = api_key
        
        return f(*args, **kwargs)
    
    return decorated_function

def require_rate_limit(f: Callable) -> Callable:
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from flask import request, jsonify
        
        api_key = kwargs.get("api_key", "anonymous")
        key_hash = api_key_validator.get_key_hash(api_key)
        
        if not rate_limiter.is_allowed(key_hash):
            remaining = rate_limiter.get_remaining(key_hash)
            return jsonify({
                "error": "Rate limit exceeded",
                "remaining_requests": remaining
            }), 429
        
        return f(*args, **kwargs)
    
    return decorated_function

def log_audit_trail(f: Callable) -> Callable:
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from flask import request
        
        api_key = kwargs.get("api_key", "anonymous")
        key_hash = api_key_validator.get_key_hash(api_key)
        
        audit_logger.log_access(
            api_key_hash=key_hash,
            endpoint=request.path,
            method=request.method,
            ip_address=request.remote_addr,
            success=True
        )
        
        return f(*args, **kwargs)
    
    return decorated_function